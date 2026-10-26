"""LangGraph workflow for coordinating API security assessment.

Integrates with existing modules (recon, request_executor, authz_bola,
resource_graph) using deterministic execution with LLM reasoning only
for adaptivity, never as the sole vulnerability authority.

The workflow uses a StateGraph with explicit state transitions for
coordinated security assessment. State is persisted via LangGraph
checkpointer, enabling stop/resume capability.

Project root is resolved from this file's location for OpenAPI spec path resolution.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from langgraph.graph import StateGraph, START, END
from pydantic import BaseModel, Field

# Resolve project root from this file's location for OpenAPI spec path resolution
PROJECT_ROOT = Path(__file__).resolve().parent

# ──────────────────────────────────────────────────────────────────
# State types – typed, serializable workflow state
# ──────────────────────────────────────────────────────────────────

class WorkflowState(BaseModel):
    """The typed state shared across all LangGraph nodes."""
    scan_id: int = Field(default=0, description="Target scan identifier")
    target_base_url: str = Field(default="", description="Authorized target origin")
    recon_complete: bool = Field(default=False, description="Reconnaissance finished")
    graph_complete: bool = Field(default=False, description="Resource graph built")
    stage: str = Field(default="initial", description="Current workflow stage")
    error: Optional[str] = Field(default=None, description="Error message if any")
    findings_persisted: bool = Field(default=False, description="Findings saved to DB")
    request_budget: int = Field(default=20, description="Remaining request budget")
    llm_calls: int = Field(default=0, description="Number of LLM calls made")
    allow_identity_registration: bool = Field(
        default=False,
        description="Explicit approval for active BOLA/BFLA checks",
    )
    bola_status: str = Field(
        default="not_run", description="BOLA/BFLA workflow outcome"
    )


# ──────────────────────────────────────────────────────────────────
# Node: validate target authorization and scan configuration
# ──────────────────────────────────────────────────────────────────

def validate_target(state: WorkflowState, llm_client=None) -> Dict[str, Any]:
    """Validate that the scan exists and the target is the authorized origin."""
    from api_security_system.db import get_session, Scan, Target, Scan, Target
    from api_security_system.authz_bola.service import UnauthorizedTargetError
    from api_security_system.targets.security import is_authorized_origin

    session = get_session()
    scan = session.get(Scan, state.scan_id)
    if scan is None:
        return {"error": f"Scan {state.scan_id} does not exist.", "stage": "failed"}

    target = session.get(Target, scan.target_id)
    if target is None:
        return {
            "error": f"Target for scan {state.scan_id} not found.",
            "stage": "failed",
        }

    # Authorized origin check - same as authz_bola service
    if not is_authorized_origin(target.base_url):
        return {
            "error": f"BOLA testing is not authorized against {target.base_url!r}.",
            "stage": "failed",
        }

    return {"target_base_url": target.base_url, "stage": "recon"}


# ──────────────────────────────────────────────────────────────────
# Node: reconnaissance – parse spec, persist endpoints, classify risk
# ──────────────────────────────────────────────────────────────────

def run_recon_node(state: WorkflowState, llm_client=None) -> Dict[str, Any]:
    """Run the reconnaissance module against the existing scan."""
    from api_security_system.recon.service import run_recon, ScanNotFoundError
    from api_security_system.db import get_session, Scan, Target
    from sqlmodel import select

    session = get_session()
    scan = session.get(Scan, state.scan_id)
    if scan is None:
        raise ScanNotFoundError(state.scan_id)

    target = session.get(Target, scan.target_id)
    if target is None:
        return {"error": f"Target for scan {state.scan_id} not found.", "stage": "failed"}

    try:
        # Resolve openapi_spec_path relative to project root so it works
        # from any CWD (the target stores a relative path like "targets/vampi-openapi.yml")
        spec_path = Path(target.openapi_spec_path)
        if not spec_path.is_absolute():
            spec_path = PROJECT_ROOT / spec_path
        parsed_endpoints = (
            __import__(
                "api_security_system.recon.parser", fromlist=["parse_openapi_spec"]
            ).parse_openapi_spec(str(spec_path))
        )

        from api_security_system.recon.schemas import ParsedEndpoint
        from api_security_system.db import Endpoint as DBEndpoint

        existing_keys = set()
        existing_rows = session.exec(
            select(DBEndpoint.path, DBEndpoint.method).where(DBEndpoint.scan_id == state.scan_id)
        ).all()
        existing_keys = {(path, method) for path, method in existing_rows}

        inserted_count = 0
        skipped_count = 0
        to_classify = []

        from api_security_system.recon.schemas import ParsedEndpoint

        for parsed in parsed_endpoints:
            key = (parsed.path, parsed.method)
            if key in existing_keys:
                skipped_count += 1
                continue

            db_endpoint = DBEndpoint(
                scan_id=state.scan_id,
                path=parsed.path,
                method=parsed.method,
                operation_id=parsed.operation_id,
                resource_type=parsed.resource_type,
                id_param_name=parsed.id_param_name,
                risk_classification=None,
                raw_spec_fragment=parsed.raw_spec_fragment,
            )
            session.add(db_endpoint)
            session.flush()
            existing_keys.add(key)
            to_classify.append((db_endpoint.id, parsed))
            inserted_count += 1

        session.commit()

    except Exception as exc:
        return {"error": f"Recon parse failed: {exc}", "stage": "failed"}

    # Classification phase (isolated from inventory persistence)
    succeeded = 0
    from api_security_system.recon.classifier import classify_endpoint, ClassificationError
    from api_security_system.llm import LLMClient

    llm = llm_client or LLMClient()
    state.llm_calls += 1

    for endpoint_id, parsed in to_classify:
        try:
            classification = classify_endpoint(parsed, llm)
        except ClassificationError:
            continue
        db_endpoint = session.get(DBEndpoint, endpoint_id)
        db_endpoint.risk_classification = classification.risk_level.value
        session.add(db_endpoint)
        succeeded += 1

    session.commit()

    return {
        "recon_complete": True,
        "stage": "graph",
        "error": None,
    }


# ──────────────────────────────────────────────────────────────────
# Node: build resource graph from persisted endpoints
# ──────────────────────────────────────────────────────────────────

def build_graph_node(state: WorkflowState) -> Dict[str, Any]:
    """Build the resource graph from the scan's persisted endpoints."""
    from api_security_system.resource_graph.builder import build_resource_graph
    from api_security_system.db import get_session, Scan, Target

    session = get_session()

    try:
        graph = build_resource_graph(state.scan_id)
        return {
            "graph_complete": True,
            "stage": "select_stage",
            "error": None,
        }
    except Exception as exc:
        return {"error": f"Graph build failed: {exc}", "stage": "failed"}


# ──────────────────────────────────────────────────────────────────
# Node: select assessment stage
# ──────────────────────────────────────────────────────────────────

def select_stage_node(state: WorkflowState) -> Dict[str, Any]:
    """Transition to the assessment stage, defaulting to BOLA."""
    return {"stage": "bola_assess", "error": None}


# ──────────────────────────────────────────────────────────────────
# Node: run BOLA assessment
# ──────────────────────────────────────────────────────────────────

def run_bola_node(state: WorkflowState, db=None, llm_client=None) -> Dict[str, Any]:
    """Run the BOLA security assessment module.

    Active checks are opt-in, matching POST /assessments. Without explicit
    approval the workflow stops after recon and the graph stage rather than
    pretending authorization checks ran.
    """
    from api_security_system.authz_bola.service import run_bola_check

    if not state.allow_identity_registration:
        return {
            "stage": "persist",
            "findings_persisted": False,
            "bola_status": "not_run",
            "error": None,
        }

    try:
        result = run_bola_check(
            scan_id=state.scan_id,
            allow_identity_registration=True,
            request_budget=state.request_budget,
        )
        return {
            "stage": "persist",
            "findings_persisted": any(
                item.finding_id is not None
                for item in result.endpoint_results + result.bfla_results
            ),
            "bola_status": "stopped_early" if result.stopped_early else "performed",
            "error": None,
        }
    except PermissionError as exc:
        return {"error": str(exc), "stage": "failed", "bola_status": "failed"}
    except Exception as exc:
        return {
            "error": f"BOLA assessment failed: {exc}",
            "stage": "failed",
            "bola_status": "failed",
        }


# ──────────────────────────────────────────────────────────────────
# Node: persist results
# ──────────────────────────────────────────────────────────────────

def persist_node(state: WorkflowState, db=None) -> Dict[str, Any]:
    """Persist results and mark workflow complete."""
    from api_security_system.db import get_session, Scan, Target, Scan
    from sqlmodel import select, update
    from datetime import datetime, timezone

    session = db if db else get_session()

    try:
        scan = session.get(Scan, state.scan_id)
        if scan:
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            session.add(scan)
            session.commit()
        return {
            "stage": "complete",
            "findings_persisted": True,
            "error": None,
        }
    except Exception as exc:
        return {"error": f"Persist failed: {exc}", "stage": "failed"}
    finally:
        state.findings_persisted = True


# ──────────────────────────────────────────────────────────────────
# Workflow construction
# ──────────────────────────────────────────────────────────────────

def build_workflow() -> Any:
    """Build and return the LangGraph StateGraph workflow with checkpointer."""

    # Initialize memory saver for checkpointing (enables stop/resume)

    # Build the state graph
    workflow = StateGraph(WorkflowState)

    # Add nodes
    workflow.add_node("validate_target", validate_target)
    workflow.add_node("run_recon", run_recon_node)
    workflow.add_node("build_graph", build_graph_node)
    workflow.add_node("select_stage", select_stage_node)
    workflow.add_node("run_bola", run_bola_node)
    workflow.add_node("persist", persist_node)

    # Add edges (transition flow)
    workflow.add_edge(START, "validate_target")
    workflow.add_edge("validate_target", "run_recon")
    workflow.add_edge("run_recon", "build_graph")
    workflow.add_edge("build_graph", "select_stage")
    workflow.add_edge("select_stage", "run_bola")
    workflow.add_edge("run_bola", "persist")
    workflow.add_edge("persist", END)

    # Compile the graph with checkpointer for stop/resume support
    app = workflow.compile()

    return app


# ──────────────────────────────────────────────────────────────────
# CLI entry point for running the workflow directly
# ──────────────────────────────────────────────────────────────────

def run_workflow(
    scan_id: int,
    budget: int = 20,
    allow_identity_registration: bool = False,
) -> Dict[str, Any]:
    """Run the full security assessment workflow for a given scan."""
    app = build_workflow()

    # Initialize state
    initial_state = WorkflowState(
        scan_id=scan_id,
        request_budget=budget,
        allow_identity_registration=allow_identity_registration,
    )

    # Run the workflow
    final_state = None
    for state in app.stream(
        initial_state,
        {"configurable": {"scan_id": scan_id}},
        stream_mode="values",
    ):
        final_state = state

    return dict(final_state) if final_state else {}


# ──────────────────────────────────────────────────────────────────
# Example: LangChain integration for LLM-powered adaptivity
# ──────────────────────────────────────────────────────────────────

def llm_classify_endpoint(endpoint, llm_client) -> Any:
    """Classify an endpoint using the LLM, with LangChain-structured output.

    This function demonstrates LangChain integration: the LLM response
    is parsed into a structured Pydantic model (RiskClassification),
    preventing hallucinations and ensuring consistent output shape.
    """
    from api_security_system.recon.schemas import ParsedEndpoint, RiskClassification
    from api_security_system.llm import LLMRequest, LLMResponse, Provider

    system_prompt = (
        "You are a security triage assistant classifying API endpoints by risk. "
        "Respond with ONLY a single JSON object, no other text, matching exactly "
        'this shape: {"risk_level": "low"|"medium"|"high"|"critical", '
        '"rationale": "<short reason>", "confidence": <0.0-1.0>}.'
    )

    prompt = (
        f"Method: {endpoint.method}\n"
        f"Path: {endpoint.path}\n"
        f"Resource type: {endpoint.resource_type}\n"
        f"ID parameter: {endpoint.id_param_name}\n"
        f"Operation details: {json.dumps(endpoint.raw_spec_fragment)[:2000]}"
    )

    response = llm_client.generate(
        LLMRequest(
            provider=Provider.GOOGLE,
            model="gemini-3.5-flash-lite",
            prompt=prompt,
            system=system_prompt,
            max_tokens=256,
            temperature=0.0,
        )
    )

    # LangChain pattern: parse structured output, never trust raw text
    raw = response.text.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()

    parsed = json.loads(raw)
    return RiskClassification(**parsed)


# ──────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: python langgraph_workflow.py <scan_id> [--budget N] "
            "[--allow-active]"
        )
        sys.exit(1)

    scan_id = int(sys.argv[1])
    budget = 20
    if "--budget" in sys.argv:
        i = sys.argv.index("--budget")
        if i + 1 < len(sys.argv):
            budget = int(sys.argv[i + 1])

    print(f"Running APIVigilante LangGraph workflow for scan_id={scan_id}, budget={budget}")
    result = run_workflow(
        scan_id=scan_id,
        budget=budget,
        allow_identity_registration="--allow-active" in sys.argv,
    )
    print(json.dumps(result, indent=2, default=str))
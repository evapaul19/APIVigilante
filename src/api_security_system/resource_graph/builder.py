"""Deterministic Resource Graph construction from persisted endpoints.

No LLM calls, no HTTP requests to the target API - pure in-memory
graph assembly over data Recon already persisted.
"""

import re
from typing import Optional

from sqlmodel import select

from api_security_system.db import Endpoint, Scan, get_session

from .schemas import EdgeRelation, EndpointNode, GraphEdge, ResourceGraph, ResourceNode

_PARAM_PATTERN = re.compile(r"^\{(.+)\}$")
_VERSION_SEGMENT = re.compile(r"^v\d+$", re.IGNORECASE)


class ScanNotFoundError(Exception):
    """Raised when build_resource_graph is called with a scan_id that doesn't exist."""

    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        super().__init__(f"Scan {scan_id} does not exist.")


def _singularize(segment: str) -> str:
    return segment.rstrip("s") if segment.endswith("s") and not segment.endswith("ss") else segment


def _resource_type_before(segments: list[str], index: int) -> Optional[str]:
    """Search backward from `index` for the nearest non-parameter,
    non-version segment - matches Recon's own heuristic (parser.py),
    applied here per-parameter rather than only for the last one."""
    for i in range(index - 1, -1, -1):
        segment = segments[i]
        if _PARAM_PATTERN.match(segment) or _VERSION_SEGMENT.match(segment):
            continue
        return _singularize(segment)
    return None


def _extract_resource_bindings(path: str) -> list[tuple[str, str]]:
    """Return every (resource_type, id_param_name) pair found in a path,
    in path order. Unlike Recon's own stored columns, which only
    retain the last parameter, this captures nested resources too.
    """
    segments = [s for s in path.strip("/").split("/") if s]
    bindings: list[tuple[str, str]] = []

    for i, segment in enumerate(segments):
        match = _PARAM_PATTERN.match(segment)
        if not match:
            continue
        resource_type = _resource_type_before(segments, i)
        if resource_type:
            bindings.append((resource_type, match.group(1)))

    return bindings


def _path_prefix_candidate(path: str) -> Optional[str]:
    """Best-effort resource-family guess for endpoints with no path
    parameter, used only to decide eligibility for a MAY_RELATE edge.
    Never produces an IDENTIFIES edge."""
    segments = [s for s in path.strip("/").split("/") if s]
    for segment in segments:
        if _VERSION_SEGMENT.match(segment):
            continue
        return _singularize(segment)
    return None


def build_resource_graph_from_endpoints(scan_id: int, endpoints: list[Endpoint]) -> ResourceGraph:
    """Build a ResourceGraph from an already-loaded list of Endpoint rows.

    Pure function - no database access, no network calls.
    """
    graph = ResourceGraph(scan_id=scan_id)

    for endpoint in endpoints:
        graph.endpoints[endpoint.id] = EndpointNode(
            id=endpoint.id,
            method=endpoint.method,
            path=endpoint.path,
            operation_id=endpoint.operation_id,
            risk_classification=endpoint.risk_classification,
        )

    # Pass 1: IDENTIFIES edges + resource node creation from confirmed
    # path-parameter bindings. This also establishes which resource
    # types "exist" for pass 2's MAY_RELATE matching.
    for endpoint in endpoints:
        bindings = _extract_resource_bindings(endpoint.path)

        for resource_type, _id_param in bindings:
            if resource_type not in graph.resources:
                graph.resources[resource_type] = ResourceNode(resource_type=resource_type)
            node = graph.resources[resource_type]
            if endpoint.id not in node.endpoint_ids:
                node.endpoint_ids.append(endpoint.id)

            graph.edges.append(
                GraphEdge(
                    source=f"endpoint:{endpoint.id}",
                    target=resource_type,
                    relation=EdgeRelation.IDENTIFIES,
                )
            )

        # NESTED_UNDER: consecutive resource bindings in path order imply
        # nesting. Inferred from URL structure only - does not confirm an
        # actual data-model relationship (e.g. a foreign key).
        for (child_type, _child_id), (parent_type, _parent_id) in zip(bindings[1:], bindings[:-1]):
            edge = GraphEdge(
                source=child_type,
                target=parent_type,
                relation=EdgeRelation.NESTED_UNDER,
                note=(
                    f"Inferred from path nesting in '{endpoint.path}'. "
                    "Reflects URL structure only, not a confirmed data-model relationship."
                ),
            )
            if edge not in graph.edges:
                graph.edges.append(edge)

    # Pass 2: MAY_RELATE edges, only for endpoints with no path
    # parameter at all, and only when their path-prefix candidate
    # matches a resource type pass 1 already confirmed exists.
    # Endpoints with no match (e.g. /me, /createdb, /) stay
    # represented as standalone nodes with no edge.
    for endpoint in endpoints:
        if _extract_resource_bindings(endpoint.path):
            continue  # already has IDENTIFIES edge(s) from pass 1

        candidate = _path_prefix_candidate(endpoint.path)
        if candidate and candidate in graph.resources:
            graph.resources[candidate].endpoint_ids.append(endpoint.id)
            graph.edges.append(
                GraphEdge(
                    source=f"endpoint:{endpoint.id}",
                    target=candidate,
                    relation=EdgeRelation.MAY_RELATE,
                    note=(
                        f"Heuristic: path prefix of '{endpoint.path}' matches resource "
                        f"'{candidate}'. Not a confirmed object-level access path."
                    ),
                )
            )

    return graph


def build_resource_graph(scan_id: int) -> ResourceGraph:
    """Build a ResourceGraph for an existing scan from its persisted endpoints.

    Raises ScanNotFoundError if scan_id does not exist.
    """
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ScanNotFoundError(scan_id)

        endpoints = session.exec(select(Endpoint).where(Endpoint.scan_id == scan_id)).all()

    return build_resource_graph_from_endpoints(scan_id, list(endpoints))
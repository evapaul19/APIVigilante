"""Deterministic selection of BOLA-testable endpoints from the Resource
Graph. Only confirmed (IDENTIFIES) object-level 'user' endpoints that
explicitly require authentication (security: [{bearerAuth: []}] per
the verified OpenAPI spec) are eligible - an endpoint with no auth
requirement has no authorization boundary to test for bypass, so it
is excluded rather than misclassified.
"""

from sqlmodel import select

from api_security_system.db import Endpoint, get_session
from api_security_system.resource_graph import build_resource_graph

from .schemas import BolaCandidate


def select_bola_candidates(scan_id: int, resource_type: str = "user") -> list[BolaCandidate]:
    graph = build_resource_graph(scan_id)
    object_level = graph.get_object_level_endpoints(resource_type)
    candidate_ids = {ep.id for ep in object_level}
    if not candidate_ids:
        return []

    candidates: list[BolaCandidate] = []
    with get_session() as session:
        rows = session.exec(select(Endpoint).where(Endpoint.id.in_(candidate_ids))).all()
        for row in rows:
            if not row.raw_spec_fragment.get("security"):
                continue  # no auth requirement - not a BOLA-testable boundary
            if not row.id_param_name:
                continue  # defensive - should not occur for IDENTIFIES edges
            candidates.append(
                BolaCandidate(
                    endpoint_id=row.id,
                    method=row.method,
                    path=row.path,
                    operation_id=row.operation_id,
                    id_param_name=row.id_param_name,
                )
            )
    return candidates
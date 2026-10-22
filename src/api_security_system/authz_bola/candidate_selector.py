"""Deterministic selection of BOLA- and BFLA-testable endpoints.

BOLA candidates come from the Resource Graph: only confirmed
(IDENTIFIES) object-level 'user' endpoints that explicitly require
authentication are eligible.

BFLA candidates are selected independently: an endpoint is eligible
when it requires authentication and its OpenAPI summary/description
states that it is restricted to administrators. BFLA deliberately does
not depend on an IDENTIFIES edge - the privilege boundary is functional,
not object-level (e.g. DELETE /users/{username} or GET /me).
"""

import re

from sqlmodel import select

from api_security_system.db import Endpoint, get_session
from api_security_system.resource_graph import build_resource_graph

from .schemas import BflaCandidate, BolaCandidate

_PATH_TEMPLATE_PARAMETER = re.compile(r"\{([^{}]+)\}")

# Parameters for which a provisioned identity's username is itself the
# object identifier. Numeric/UUID identifiers are handled separately: they
# require a verified identifier from the identity's own response.
_USERNAME_IDENTIFIER_NAMES = {
    "username",
    "user_name",
    "user",
    "login",
    "userlogin",
}
_NORMALIZED_USERNAME_IDENTIFIER_NAMES = frozenset(
    re.sub(r"[^a-z0-9]", "", name)
    for name in _USERNAME_IDENTIFIER_NAMES
)

_ADMIN_ONLY_SIGNAL = re.compile(
    r"\b("
    r"only\s+admins?"
    r"|admins?\s+only"
    r"|requires?\s+(?:an?\s+)?admin(?:istrator)?s?"
    r"|administrator\s+only"
    r"|only\s+administrators?"
    r")\b",
    re.IGNORECASE,
)


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
                    summary=(
                        str(row.raw_spec_fragment.get("summary"))
                        if row.raw_spec_fragment.get("summary") is not None
                        else None
                    ),
                    description=(
                        str(row.raw_spec_fragment.get("description"))
                        if row.raw_spec_fragment.get("description") is not None
                        else None
                    ),
                )
            )
    return candidates


def is_read_candidate(candidate: BolaCandidate) -> bool:
    """A read-only BOLA candidate: a GET with exactly one substitutable
    path identifier. Reads never mutate the target, so they can be
    tested without the side-effect constraints that apply to writes."""
    if candidate.method.upper() != "GET" or not candidate.id_param_name:
        return False
    return _PATH_TEMPLATE_PARAMETER.findall(candidate.path) == [
        candidate.id_param_name
    ]


def identifier_is_username(id_param_name: str | None) -> bool:
    """True when a path parameter is conventionally a username.

    Username identifiers can be substituted directly from a provisioned
    identity. Numeric/UUID identifiers cannot: they must be resolved from
    that identity's own authenticated response before any cross-identity
    request is safe to attempt.
    """
    if not id_param_name:
        return False
    normalized = re.sub(r"[^a-z0-9]", "", id_param_name.lower())
    return normalized in _NORMALIZED_USERNAME_IDENTIFIER_NAMES


def select_bfla_candidates(scan_id: int) -> list[BflaCandidate]:
    """Select authenticated operations documented as administrator-only.

    The signal is the OpenAPI summary/description text. This is endpoint
    semantics from the target's own contract, not a name guess or an LLM
    prediction. The execution runner must still establish the privilege
    differential before reporting a result.
    """
    with get_session() as session:
        rows = session.exec(
            select(Endpoint).where(Endpoint.scan_id == scan_id)
        ).all()

    candidates: list[BflaCandidate] = []
    for row in rows:
        fragment = row.raw_spec_fragment or {}
        if not fragment.get("security"):
            continue  # unauthenticated operations have no privilege boundary

        text = " ".join(
            str(fragment.get(field) or "")
            for field in ("summary", "description")
        ).strip()
        match = _ADMIN_ONLY_SIGNAL.search(text)
        if match is None:
            continue

        candidates.append(
            BflaCandidate(
                endpoint_id=row.id,
                method=row.method,
                path=row.path,
                operation_id=row.operation_id,
                id_param_name=row.id_param_name,
                signal=match.group(0),
                rationale=text[:300],
            )
        )

    return candidates
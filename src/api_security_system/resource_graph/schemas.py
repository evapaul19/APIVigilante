"""Pydantic schemas for the Resource Graph module."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EdgeRelation(str, Enum):
    """How an edge in the Resource Graph was established.

    IDENTIFIES: the endpoint has an explicit path parameter bound to
        this resource type - a confirmed object-level access path,
        the kind of edge the future BOLA agent should treat as a
        real test candidate.
    MAY_RELATE: a heuristic association based on path-prefix overlap
        with an existing resource (e.g. GET /users/v1/register shares
        a prefix with the 'user' resource). NOT an object-level
        access path and never implies a confirmed identifier.
    NESTED_UNDER: inferred purely from path nesting (e.g.
        /orgs/{org_id}/users/{user_id} implies user is nested under
        org). Reflects URL structure only and does NOT prove an
        underlying data-model relationship.
    """

    IDENTIFIES = "identifies"
    MAY_RELATE = "may_relate"
    NESTED_UNDER = "nested_under"


class EndpointNode(BaseModel):
    """A single endpoint as represented in the graph."""

    id: int
    method: str
    path: str
    operation_id: Optional[str] = None
    risk_classification: Optional[str] = None


class ResourceNode(BaseModel):
    """A resource type (e.g. 'user', 'book') inferred from endpoint paths."""

    resource_type: str
    endpoint_ids: list[int] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """A relationship between an endpoint and a resource, or between
    two resources (NESTED_UNDER only)."""

    source: str  # "endpoint:<id>" or a resource_type
    target: str  # a resource_type
    relation: EdgeRelation
    note: Optional[str] = None


class ResourceGraph(BaseModel):
    """The full in-memory resource graph for one scan."""

    scan_id: int
    resources: dict[str, ResourceNode] = Field(default_factory=dict)
    endpoints: dict[int, EndpointNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)

    def get_object_level_endpoints(self, resource_type: str) -> list[EndpointNode]:
        """Return endpoints with a confirmed (IDENTIFIES) binding to this resource.

        MAY_RELATE associations are deliberately excluded since they
        are not confirmed object-level access paths.
        """
        endpoint_ids = {
            int(edge.source.split(":", 1)[1])
            for edge in self.edges
            if edge.relation == EdgeRelation.IDENTIFIES and edge.target == resource_type
        }
        return [self.endpoints[eid] for eid in endpoint_ids if eid in self.endpoints]
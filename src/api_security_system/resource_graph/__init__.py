"""Resource Graph: deterministic, in-memory graph of resources and
endpoint relationships built from Recon's persisted endpoint inventory.

No LLM calls, no HTTP requests to the target API.
"""

from .builder import ScanNotFoundError, build_resource_graph, build_resource_graph_from_endpoints
from .schemas import EdgeRelation, EndpointNode, GraphEdge, ResourceGraph, ResourceNode

__all__ = [
    "build_resource_graph",
    "build_resource_graph_from_endpoints",
    "ScanNotFoundError",
    "ResourceGraph",
    "ResourceNode",
    "EndpointNode",
    "GraphEdge",
    "EdgeRelation",
]
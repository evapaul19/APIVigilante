"""Tests for deterministic Resource Graph construction (builder.py).

These tests use in-memory Endpoint rows only: no database, no network
requests, and no live API contact.
"""

import pytest

from api_security_system.db import Endpoint
from api_security_system.resource_graph import (
    EdgeRelation,
    ScanNotFoundError,
    build_resource_graph,
    build_resource_graph_from_endpoints,
)


def _endpoint(
    endpoint_id: int,
    path: str,
    *,
    method: str = "GET",
    operation_id: str | None = None,
    risk_classification: str | None = None,
) -> Endpoint:
    return Endpoint(
        id=endpoint_id,
        scan_id=1,
        path=path,
        method=method,
        operation_id=operation_id,
        risk_classification=risk_classification,
    )


def _edges(graph, relation):
    return [edge for edge in graph.edges if edge.relation == relation]


def test_creates_resource_and_identifies_edge_from_path_parameter():
    graph = build_resource_graph_from_endpoints(
        7,
        [
            _endpoint(
                1,
                "/users/{username}",
                operation_id="get_user",
                risk_classification="high",
            )
        ],
    )

    assert graph.scan_id == 7
    assert set(graph.resources) == {"user"}
    assert graph.resources["user"].endpoint_ids == [1]
    assert graph.endpoints[1].operation_id == "get_user"
    assert graph.endpoints[1].risk_classification == "high"

    identifies = _edges(graph, EdgeRelation.IDENTIFIES)
    assert len(identifies) == 1
    assert identifies[0].source == "endpoint:1"
    assert identifies[0].target == "user"
    assert identifies[0].note is None


def test_builds_nested_under_edge_for_consecutive_resource_bindings():
    graph = build_resource_graph_from_endpoints(
        8,
        [_endpoint(2, "/orgs/{org_id}/users/{user_id}")],
    )

    assert set(graph.resources) == {"org", "user"}
    assert graph.resources["org"].endpoint_ids == [2]
    assert graph.resources["user"].endpoint_ids == [2]

    identifies = _edges(graph, EdgeRelation.IDENTIFIES)
    assert {(edge.source, edge.target) for edge in identifies} == {
        ("endpoint:2", "org"),
        ("endpoint:2", "user"),
    }

    nested = _edges(graph, EdgeRelation.NESTED_UNDER)
    assert len(nested) == 1
    assert nested[0].source == "user"
    assert nested[0].target == "org"
    assert "path nesting" in (nested[0].note or "")


def test_identifier_links_exclude_may_relate_heuristics():
    graph = build_resource_graph_from_endpoints(
        9,
        [
            _endpoint(1, "/v1/users/{username}"),
            _endpoint(2, "/v1/users/register"),
            _endpoint(3, "/me"),
        ],
    )

    assert set(graph.resources) == {"user"}
    assert graph.resources["user"].endpoint_ids == [1, 2]

    identifies = _edges(graph, EdgeRelation.IDENTIFIES)
    assert [(edge.source, edge.target) for edge in identifies] == [
        ("endpoint:1", "user")
    ]

    may_relate = _edges(graph, EdgeRelation.MAY_RELATE)
    assert [(edge.source, edge.target) for edge in may_relate] == [
        ("endpoint:2", "user")
    ]
    assert [endpoint.id for endpoint in graph.get_object_level_endpoints("user")] == [1]
    assert 3 in graph.endpoints
    assert not [
        edge
        for edge in graph.edges
        if edge.source == "endpoint:3"
    ]


def test_empty_endpoint_list_returns_empty_graph():
    graph = build_resource_graph_from_endpoints(10, [])

    assert graph.scan_id == 10
    assert graph.resources == {}
    assert graph.endpoints == {}
    assert graph.edges == []


def test_malformed_and_parameterless_paths_do_not_create_resources():
    endpoints = [
        _endpoint(1, ""),
        _endpoint(2, "/"),
        _endpoint(3, "/{id}"),
        _endpoint(4, "/v1/{id}"),
        _endpoint(5, "/users/{}/profile"),
        _endpoint(6, "/users/{username"),
        _endpoint(7, "/users/username}"),
    ]

    graph = build_resource_graph_from_endpoints(11, endpoints)

    assert len(graph.endpoints) == len(endpoints)
    assert graph.resources == {}
    assert graph.edges == []


def test_missing_scan_raises_without_database_access(monkeypatch):
    class EmptySession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, model, key):
            return None

    monkeypatch.setattr(
        "api_security_system.resource_graph.builder.get_session",
        lambda: EmptySession(),
    )

    with pytest.raises(ScanNotFoundError) as exc_info:
        build_resource_graph(999)

    assert exc_info.value.scan_id == 999

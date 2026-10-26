"""Regression coverage for duplicate method/path pairs in LangGraph recon."""

from types import SimpleNamespace

from api_security_system import db
from api_security_system.recon import classifier, parser
from api_security_system.recon.schemas import ParsedEndpoint
from langgraph_workflow import WorkflowState, run_recon_node


class _Result:
    def all(self):
        return []


class _Session:
    def __init__(self):
        self.scan = SimpleNamespace(id=12, target_id=34)
        self.target = SimpleNamespace(openapi_spec_path="targets/spec.yml")
        self.endpoints = {}
        self.added = []
        self.next_id = 1

    def get(self, model, identifier):
        if model is db.Scan:
            return self.scan if identifier == self.scan.id else None
        if model is db.Target:
            return self.target if identifier == self.scan.target_id else None
        if model is db.Endpoint:
            return self.endpoints.get(identifier)
        return None

    def exec(self, _statement):
        return _Result()

    def add(self, value):
        self.added.append(value)
        if isinstance(value, db.Endpoint):
            if value.id is None:
                value.id = self.next_id
                self.next_id += 1
            self.endpoints[value.id] = value

    def flush(self):
        pass

    def commit(self):
        pass


def test_run_recon_node_skips_duplicate_method_path_pairs(monkeypatch):
    session = _Session()
    parsed = [
        ParsedEndpoint(method="GET", path="/users/{user_id}"),
        ParsedEndpoint(method="GET", path="/users/{user_id}"),
        ParsedEndpoint(method="POST", path="/users/{user_id}"),
    ]
    monkeypatch.setattr(db, "get_session", lambda: session)
    monkeypatch.setattr(parser, "parse_openapi_spec", lambda _path: parsed)
    monkeypatch.setattr(
        classifier,
        "classify_endpoint",
        lambda _endpoint, _client: SimpleNamespace(
            risk_level=SimpleNamespace(value="low")
        ),
    )

    result = run_recon_node(WorkflowState(scan_id=12), llm_client=object())

    assert result == {"recon_complete": True, "stage": "graph", "error": None}
    assert [(endpoint.method, endpoint.path) for endpoint in session.endpoints.values()] == [
        ("GET", "/users/{user_id}"),
        ("POST", "/users/{user_id}"),
    ]

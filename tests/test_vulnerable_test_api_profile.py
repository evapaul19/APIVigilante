"""Focused tests for the isolated test API's deliberately vulnerable
authenticated profile read. In-process TestClient only - no network,
no live target, no APIVigilante assessment."""

import sys
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from vulnerable_test_api.app import app

client = TestClient(app)


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:10]}"


def _register_and_token(username: str) -> str:
    response = client.post(
        "/users/v1/register",
        json={
            "username": username,
            "password": "Pw_123456!",
            "email": f"{username}@example.invalid",
        },
    )
    assert response.status_code == 200
    login = client.post(
        "/users/v1/login",
        json={"username": username, "password": "Pw_123456!"},
    )
    assert login.status_code == 200
    return login.json()["auth_token"]


def test_profile_openapi_declares_bearer_security():
    operation = app.openapi()["paths"]["/users/v1/{username}/profile"]["get"]
    assert operation["operationId"] == "api_views.users.get_profile"
    assert operation["security"] == [{"HTTPBearer": []}]


def test_authenticated_user_can_read_own_profile():
    username = _unique("reader")
    token = _register_and_token(username)

    response = client.get(
        f"/users/v1/{username}/profile",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "username": username,
        "email": f"{username}@example.invalid",
    }


def test_authenticated_user_can_read_another_users_profile():
    attacker = _unique("attacker")
    victim = _unique("victim")
    attacker_token = _register_and_token(attacker)
    _register_and_token(victim)

    response = client.get(
        f"/users/v1/{victim}/profile",
        headers={"Authorization": f"Bearer {attacker_token}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "username": victim,
        "email": f"{victim}@example.invalid",
    }


def test_profile_requires_authentication():
    response = client.get("/users/v1/alice/profile")
    assert response.status_code in (401, 403)

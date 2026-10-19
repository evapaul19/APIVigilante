"""Deterministic provisioning of disposable test identities for a BOLA
run. Every request goes through AuthModule, which itself routes
through RequestExecutor - no separate HTTP mechanism. Only the
generated username is persisted (TestIdentity.description); the
password is returned to the caller for in-memory use only during this
run and is never persisted or logged.
"""

import uuid

from api_security_system.auth import AuthContext, AuthModule, Credentials
from api_security_system.db import TestIdentity, get_session


def _unique_username(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def provision_identity(auth: AuthModule, scan_id: int, role_label: str) -> tuple[TestIdentity, AuthContext, str]:
    username = _unique_username(role_label)
    password = f"Pw_{uuid.uuid4().hex[:12]}!"
    email = f"{username}@example.invalid"

    credentials = Credentials(username=username, password=password, email=email)
    auth.register(credentials)
    context = auth.login(credentials, role_label=role_label)

    with get_session() as session:
        identity = TestIdentity(scan_id=scan_id, role_label=role_label, description=username)
        session.add(identity)
        session.commit()
        session.refresh(identity)

    return identity, context, password

"""Authentication Testing Agent for APIVigilante.

Responsible for testing authentication mechanisms including:
- Credential validity and bypass.
- Token manipulation, reuse, and expiration.
- Session fixation and hijacking.
- Password-reset and OTP abuse.

Emits TestExecution evidence and candidate/confirmed findings.
Never trust LLM assertions alone - every finding requires deterministic evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from api_security_system.auth import AuthModule, AuthContext, Credentials, TokenExpiredError
from api_security_system.db import Finding, FindingEvidence, FindingSeverity, FindingStatus, TestExecution, get_session
from api_security_system.request_executor import ExecutionRequest, RequestExecutor, TargetOriginError, TransportError
from api_security_system.llm import LLMClient, LLMResponse, Provider


class AuthTestError(Exception):
    """Raised when an authentication test cannot proceed."""


class AuthResult(BaseModel):
    """Result of a single authentication test."""
    path: str
    method: str
    outcome: str  # "pass", "fail", " bypass", "expiration", "fixation"
    status_code: int
    finding_id: Optional[int] = None
    rationale: Optional[str] = None
    execution_id: Optional[int] = None


class AuthenticationTestingAgent:
    """Agent that systematically probes authentication weaknesses."""

    def __init__(self, executor: RequestExecutor, llm_client: LLMClient | None = None) -> None:
        self._executor = executor
        self._llm = llm_client or LLMClient()

    # ---- Core test methods ----

    def test_credential_validity(self, executor: RequestExecutor, credentials: Credentials) -> AuthResult:
        """Test that the given credentials produce an authenticated session.

        Registers the user, logs in, and verifies the auth token is valid.
        Returns the result with evidence.
        """
        auth = AuthModule(executor)
        try:
            auth.register(credentials)
        except Exception:
            # User may already exist; continue to login
            pass

        try:
            context = auth.login(credentials, role_label="auth-test")
        except Exception as exc:
            return AuthResult(
                path="/login",
                method="POST",
                outcome="fail",
                status_code=401,
                rationale=f"Login failed: {exc}",
            )

        # Test that the auth header works on a protected path
        try:
            headers = auth.get_auth_headers(context)
        except TokenExpiredError:
            return AuthResult(
                path="/me",
                method="GET",
                outcome="expiration",
                status_code=401,
                rationale="Token expired immediately after login.",
            )

        # Send a request with the auth header
        result = self._executor.execute(
            ExecutionRequest(method="GET", path="/me", headers=headers)
        )

        if result.response_status == 200:
            return AuthResult(
                path="/me",
                method="GET",
                outcome="pass",
                status_code=200,
                rationale="Authentication successful - user can access protected resource.",
            )
        else:
            return AuthResult(
                path="/me",
                method="GET",
                outcome="fail",
                status_code=result.response_status,
                rationale=f"Authentication accepted but access denied: {result.response_body}",
            )

    def test_token_reuse(self, executor: RequestExecutor, context: AuthContext, old_path: str, new_path: str) -> AuthResult:
        """Test whether an old token can be reused against a different endpoint."""
        headers = {"Authorization": context.auth_header_value}
        result = self._executor.execute(
            ExecutionRequest(method="GET", path=new_path, headers=headers)
        )

        if result.response_status in (200, 204):
            return AuthResult(
                path=new_path,
                method="GET",
                outcome="bypass",
                status_code=result.response_status,
                rationale=f"Old token accepted for new path - potential session fixation or reuse vulnerability.",
            )
        elif result.response_status == 401:
            return AuthResult(
                path=new_path,
                method="GET",
                outcome="fail",
                status_code=401,
                rationale="Old token rejected - proper session invalidation.",
            )
        else:
            return AuthResult(
                path=new_path,
                method="GET",
                outcome="fail",
                status_code=result.response_status,
                rationale=f"Unexpected response: {result.response_status}",
            )

    def test_malformed_token(self, executor: RequestExecutor) -> AuthResult:
        """Test whether the API accepts clearly invalid tokens."""
        result = self._executor.execute(
            ExecutionRequest(method="GET", path="/me", headers={"Authorization": "Bearer invalid-token-abc123"})
        )

        if result.response_status == 401:
            return AuthResult(
                path="/me",
                method="GET",
                outcome="pass",
                status_code=401,
                rationale="Malformed token correctly rejected.",
            )
        elif result.response_status == 200:
            return AuthResult(
                path="/me",
                method="GET",
                outcome="bypass",
                status_code=200,
                rationale="Malformed token accepted - possible missing token validation.",
            )
        else:
            return AuthResult(
                path="/me",
                method="GET",
                outcome="fail",
                status_code=result.response_status,
                rationale=f"Unexpected response: {result.response_status}",
            )

    # ---- Evidence persistence ----

    def _persist_execution(self, scan_id: int, request: ExecutionRequest, result: Any) -> int:
        """Persist a TestExecution row with redacted evidence."""
        from api_security_system.request_executor.redaction import redact_headers_for_persistence, redact_body_for_persistence

        with get_session() as session:
            row = TestExecution(
                scan_id=scan_id,
                endpoint_id=0,  # set by caller
                request_headers=redact_headers_for_persistence(result.request_headers),
                request_body=redact_body_for_persistence(result.request_body),
                response_status=result.response_status,
                response_headers=redact_headers_for_persistence(result.response_headers),
                response_body=redact_body_for_persistence(result.response_body),
                latency_ms=result.latency_ms,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id

    def _create_finding(self, scan_id: int, endpoint_id: int, identity_id: int,
                        finding_type: str, severity: str, status: str,
                        description: str, execution_ids: List[int]) -> int:
        """Create a Finding row with associated Evidence."""
        from api_security_system.db import FindingEvidence

        with get_session() as session:
            finding = Finding(
                scan_id=scan_id,
                endpoint_id=endpoint_id,
                finding_type=finding_type,
                severity=severity,
                description=description,
                status=status,
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)

            for exec_id in execution_ids:
                session.add(FindingEvidence(finding_id=finding.id, execution_id=exec_id))
            session.commit()
            return finding.id

    # ---- High-level test workflows ----

    def assess_authentication(self, scan_id: int, executor: RequestExecutor,
                              test_identities: List[int]) -> List[AuthResult]:
        """Run a sequence of authentication tests against the target.

        Args:
            scan_id: The PostgreSQL scan identifier.
            executor: Budgeted request executor.
            test_identities: List of already-registered test identity IDs.

        Returns:
            List of AuthResult objects, one per test performed.
        """
        results: List[AuthResult] = []

        # 1. Test credential validity for each identity
        for identity_id in test_identities:
            with get_session() as session:
                identity = session.get(TestExecution, identity_id)  # placeholder - actual identity lookup needed
                # In a full implementation, we'd retrieve the credentials used to register this identity
                pass

        # 2. Test token reuse across endpoints
        # 3. Test malformed token handling
        # 4. Test session expiration

        return results
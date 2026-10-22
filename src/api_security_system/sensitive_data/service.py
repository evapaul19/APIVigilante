"""Sensitive-data exposure detector.

Inspects JSON responses returned by in-scope GET endpoints and records
what the requesting identity actually receives. Detection requires a
sensitive field name AND a value pattern that supports it; masks,
placeholders, own-profile data, and legitimately issued tokens are
ruled out rather than reported.

Reuses the existing RequestExecutor (origin lock, disabled redirects,
timeouts), AuthModule, request-budget gate, identity provisioner,
TestExecution evidence table, Finding model, and persistence redaction.
No separate HTTP stack is introduced. Raw passwords, tokens, private
keys, and personal identifiers are never written to findings, evidence,
or logs - evidence is sanitized before persistence.
"""

import json
import re
from typing import TYPE_CHECKING, Optional

from sqlmodel import select

if TYPE_CHECKING:
    from api_security_system.targets.security import ResolvedTarget

from api_security_system.auth import (
    AuthContext,
    AuthenticationError,
    AuthModule,
)
from api_security_system.authz_bola.identity_provisioner import provision_identity
from api_security_system.authz_bola.schemas import BudgetExceededError
from api_security_system.authz_bola.service import RequestBudget
from api_security_system.db import (
    Endpoint,
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    FindingType,
    Scan,
    Target,
    TestExecution,
    get_session,
)
from api_security_system.db.redaction import (
    REDACTED_VALUE,
    redact_headers_for_persistence,
    sanitize_text_for_persistence,
)
from api_security_system.request_executor import (
    ExecutionRequest,
    ExecutionResult,
    RequestExecutor,
    TargetOriginError,
    TransportError,
)
from api_security_system.safe_gets import get_get_side_effect_reason

from .patterns import (
    PII_CATEGORIES,
    field_category,
    is_masked_or_placeholder,
    is_value_sensitive_standalone,
    normalize_path,
    value_kind,
)
from .schemas import (
    SensitiveDataCheckResult,
    SensitiveEndpointResult,
    SensitiveFieldObservation,
    SensitiveOutcome,
)

DEFAULT_SENSITIVE_REQUEST_BUDGET = 20
MAX_JSON_LEAVES = 10000
MAX_SCHEMA_DEPTH = 12

_PATH_PARAM = re.compile(r"\{([^}]+)\}")
_TOKEN_ISSUANCE = re.compile(
    r"(?i)\b(login|signin|sign[_-]?in|token|register|oauth)\b"
)
_USERNAME_PARAMS = {"username", "user", "user_name", "userid", "user_id"}


class _BudgetedExecutor:
    """Every target request - including provisioning - counts against
    the same cap. Mirrors the BOLA/BFLA executor contract."""

    def __init__(self, executor: RequestExecutor, budget: RequestBudget) -> None:
        self._executor = executor
        self._budget = budget

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self._budget.consume()
        return self._executor.execute(request)

    def close(self) -> None:
        self._executor.close()


def _iter_leaves(body, max_leaves: int = MAX_JSON_LEAVES):
    """Yield (path, key, value) for every scalar leaf in a JSON value."""
    stack = [(body, "$", 0)]
    produced = 0
    while stack and produced < max_leaves:
        current, path, depth = stack.pop()
        if depth > MAX_SCHEMA_DEPTH:
            continue
        if isinstance(current, dict):
            for key, value in current.items():
                child_path = f"{path}.{str(key)[:64]}"
                if isinstance(value, (dict, list)):
                    stack.append((value, child_path, depth + 1))
                else:
                    produced += 1
                    yield child_path, str(key), value
        elif isinstance(current, list):
            for index, value in enumerate(current):
                child_path = f"{path}[{index}]"
                if isinstance(value, (dict, list)):
                    stack.append((value, child_path, depth + 1))
                else:
                    produced += 1
                    yield child_path, "", value


def _collect_subjects(body) -> tuple[set[str], int]:
    subjects: set[str] = set()
    count = 0
    for _path, key, value in _iter_leaves(body):
        if key.lower() in {"username", "user", "owner"} and isinstance(value, str):
            stripped = value.strip()
            if stripped:
                subjects.add(stripped)
                count += 1
    return subjects, count


def inspect_body(
    body,
    *,
    endpoint_path: str,
    operation_id: Optional[str] = None,
    authenticated: bool = False,
    identity_username: Optional[str] = None,
    declared_fields: Optional[set[str]] = None,
    token_issuance: bool = False,
) -> tuple[SensitiveOutcome, list[SensitiveFieldObservation], set[str], str]:
    """Deterministically inspect one response body.

    Pure function (no I/O) so it can be unit-tested; the service layer
    handles requests, persistence, and findings.
    """
    if not isinstance(body, (dict, list)):
        return (
            SensitiveOutcome.UNSUPPORTED,
            [],
            set(),
            "Response was not a JSON object/array; structured fields could not be inspected.",
        )

    declared_fields = declared_fields or set()
    subjects, _subject_occurrences = _collect_subjects(body)
    observations: dict[tuple[str, str, str, bool], SensitiveFieldObservation] = {}

    for path, key, value in _iter_leaves(body):
        category = field_category(key) if key else None
        if category is None:
            # An embedded PEM private key is unambiguous key material even
            # when its field name is generic (e.g. "key" or "value").
            if isinstance(value, str) and "-----BEGIN " in value and "PRIVATE KEY-----" in value:
                category = "private_key"
            else:
                continue

        masked = is_masked_or_placeholder(value)
        if masked:
            kind = "masked"
        else:
            kind = value_kind(category, value)
            if kind is None:
                continue

        normalized = normalize_path(path)
        declared = key in declared_fields
        aggregation_key = (normalized, category, kind, declared)
        existing = observations.get(aggregation_key)
        if existing is None:
            observations[aggregation_key] = SensitiveFieldObservation(
                path=normalized,
                category=category,
                value_kind=kind,
                occurrences=1,
                declared_in_schema=declared,
            )
        else:
            existing.occurrences += 1

    observation_list = list(observations.values())
    real = [o for o in observation_list if o.value_kind != "masked"]

    if not observation_list:
        return (
            SensitiveOutcome.RULED_OUT,
            [],
            subjects,
            "No sensitive field/value combination was found in the inspected response.",
        )

    if not real:
        return (
            SensitiveOutcome.RULED_OUT,
            observation_list,
            subjects,
            "Sensitive-named fields contained only masked or placeholder values; "
            "no disclosure was established.",
        )

    other_subjects = {
        subject for subject in subjects if subject and subject != identity_username
    }
    subject_count = len(subjects)
    is_me_endpoint = endpoint_path.rstrip("/").endswith("/me")
    # Only an authenticated request can return the caller's own profile.
    # For anonymous requests the path parameter is substituted with a probe
    # identity so the request is well-formed, but the response cannot be
    # attributed to that identity and must not be ruled out as "own" data.
    is_self_profile = authenticated and (
        bool(subjects and identity_username and subjects == {identity_username})
        or (is_me_endpoint and not other_subjects)
    )

    confirmed: list[str] = []
    candidates: list[str] = []
    ruled_out: list[str] = []
    declared_notes: list[str] = []

    for observation in real:
        category = observation.category
        kind = observation.value_kind
        field_note = (
            f"{observation.path} ({observation.occurrences} occurrence(s), "
            + (
                "declared in the response schema"
                if observation.declared_in_schema
                else "not declared in the response schema"
            )
            + ")"
        )

        if category == "private_key" and kind == "pem_private_key":
            confirmed.append(
                f"private key material at {field_note}"
            )
            continue

        if category == "password":
            if kind == "plaintext_password":
                if not authenticated:
                    confirmed.append(
                        f"plaintext password values at {field_note}"
                    )
                elif other_subjects:
                    confirmed.append(
                        f"plaintext password values for other identities at {field_note}"
                    )
                else:
                    candidates.append(
                        f"a plaintext password for the requesting identity at {field_note}"
                    )
            elif kind == "password_hash":
                candidates.append(f"password hashes at {field_note}")
            continue

        if category == "token":
            if token_issuance:
                ruled_out.append(
                    f"a token issued directly to the caller by a token-issuance "
                    f"operation at {field_note}"
                )
                continue
            if other_subjects or not authenticated:
                confirmed.append(f"credential-like token values at {field_note}")
            else:
                candidates.append(f"a token value at {field_note}")
            continue

        if category == "generic_secret":
            candidates.append(f"a generic secret value at {field_note}")
            continue

        if category in PII_CATEGORIES:
            if is_self_profile:
                ruled_out.append(
                    f"the requesting identity's own {category} at {field_note}"
                )
                continue
            if not other_subjects and not authenticated:
                candidates.append(f"{category} data returned to an anonymous caller at {field_note}")
            elif other_subjects:
                candidates.append(
                    f"{category} data for identities other than the caller at {field_note}"
                )
            else:
                candidates.append(f"{category} data at {field_note}")
            continue

    confirmed_declared = [
        o.declared_in_schema for o in real if o.category in {"password", "private_key"}
    ]
    if confirmed_declared:
        declared_notes.append(
            "The response schema documents the sensitive field(s), which does "
            "not make disclosure to this caller appropriate."
        )

    method_label = "Authenticated" if authenticated else "Unauthenticated"
    prefix = f"{method_label} GET {endpoint_path}"

    if confirmed:
        rationale = (
            f"{prefix} returned " + "; ".join(confirmed) + ". "
            + (
                "No credentials were supplied, so authentication secrets for "
                "other identities were disclosed. "
                if not authenticated
                else "The response contained secrets not attributable to the "
                "requesting identity. "
            )
            + "Values are redacted in stored evidence."
        )
        return SensitiveOutcome.CONFIRMED, observation_list, subjects, rationale

    if candidates:
        rationale = (
            f"{prefix} returned " + "; ".join(candidates) + ". "
            "The evidence establishes exposure of potentially sensitive data, "
            "but not that this identity was forbidden from receiving it; "
            "reported as a candidate, not a confirmed vulnerability. "
            "Values are redacted in stored evidence."
        )
        return SensitiveOutcome.CANDIDATE, observation_list, subjects, rationale

    rationale = (
        f"{prefix}: " + " ".join(ruled_out) + " No confirmed or candidate "
        "sensitive-data exposure was established."
    )
    return SensitiveOutcome.RULED_OUT, observation_list, subjects, rationale


def sanitize_for_persistence(value, counter=None):
    """Recursively redact sensitive field names and standalone secret
    values. Returns a new object; input is never mutated."""
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_LEAVES * 2:
        return REDACTED_VALUE

    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            if field_category(str(key)) is not None:
                sanitized[key] = REDACTED_VALUE
            else:
                sanitized[key] = sanitize_for_persistence(item, counter)
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_persistence(item, counter) for item in value]
    if is_value_sensitive_standalone(value):
        return REDACTED_VALUE
    return value


# Backward-compatible private name used by earlier unit tests/callers.
_sanitize_for_persistence = sanitize_for_persistence


def _persist_evidence(
    scan_id: int,
    endpoint_id: int,
    identity_id: Optional[int],
    result: ExecutionResult,
    body,
) -> int:
    with get_session() as session:
        row = TestExecution(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            identity_id=identity_id,
            request_headers=redact_headers_for_persistence(result.request_headers),
            request_body=None,
            response_status=result.response_status,
            response_headers=redact_headers_for_persistence(result.response_headers),
            response_body=sanitize_for_persistence(body),
            latency_ms=result.latency_ms,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row.id


def _enum_value(value):
    return getattr(value, "value", value)


def _create_finding(
    scan_id: int,
    endpoint_id: int,
    outcome: SensitiveOutcome,
    description: str,
    execution_id: int,
) -> int:
    if outcome is SensitiveOutcome.CONFIRMED:
        status = FindingStatus.CONFIRMED
        severity = FindingSeverity.HIGH
        confidence = 0.9
    else:
        status = FindingStatus.CANDIDATE
        severity = FindingSeverity.MEDIUM
        confidence = 0.5

    description = (
        sanitize_text_for_persistence(description, max_length=2000) or ""
    )

    with get_session() as session:
        finding = session.exec(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.endpoint_id == endpoint_id,
                Finding.finding_type == FindingType.SENSITIVE_DATA.value,
            )
        ).first()

        requested_status = _enum_value(status)
        if finding is None:
            finding = Finding(
                scan_id=scan_id,
                endpoint_id=endpoint_id,
                finding_type=FindingType.SENSITIVE_DATA,
                severity=severity,
                description=description,
                status=status,
                confidence=confidence,
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
        elif (
            requested_status == FindingStatus.CONFIRMED.value
            and _enum_value(finding.status) != FindingStatus.CONFIRMED.value
        ):
            finding.status = status
            finding.severity = severity
            finding.description = description
            finding.confidence = confidence
            session.add(finding)
            session.commit()

        existing_evidence = {
            link.execution_id
            for link in session.exec(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id == finding.id
                )
            ).all()
        }
        if execution_id not in existing_evidence:
            session.add(
                FindingEvidence(
                    finding_id=finding.id,
                    execution_id=execution_id,
                )
            )
            session.commit()
        return finding.id


def _select_get_endpoints(scan_id: int) -> list[Endpoint]:
    with get_session() as session:
        rows = session.exec(
            select(Endpoint).where(Endpoint.scan_id == scan_id)
        ).all()
    return sorted(
        [row for row in rows if row.method.upper() == "GET"],
        key=lambda row: row.path,
    )


def _required_input_reason(endpoint: Endpoint) -> Optional[str]:
    """Block inspection when required non-path inputs cannot be supplied.

    No parameter values are invented. A required query/header/cookie/body
    parameter, a required request body, or an unresolved parameter
    reference makes the endpoint unsupported for this inspection-only
    detector.
    """
    fragment = endpoint.raw_spec_fragment or {}

    for raw in fragment.get("parameters") or []:
        if not isinstance(raw, dict):
            return "Endpoint has a malformed parameter declaration."
        if raw.get("$ref"):
            return (
                "Endpoint has an unresolved parameter reference; required "
                "inputs cannot be determined safely."
            )
        location = raw.get("in")
        if location == "path":
            continue
        if raw.get("required"):
            return (
                f"Endpoint requires a {location or 'non-path'} parameter that "
                "the inspection-only detector does not synthesize."
            )

    request_body = fragment.get("requestBody")
    if isinstance(request_body, dict):
        if request_body.get("$ref"):
            return (
                "Endpoint has an unresolved request-body reference; required "
                "inputs cannot be determined safely."
            )
        if request_body.get("required"):
            return (
                "Endpoint requires a request body that the inspection-only "
                "detector does not synthesize."
            )

    return None


def _resolve_path(path: str, identity_username: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    params = _PATH_PARAM.findall(path)
    if not params:
        return path, None
    if identity_username is None:
        return None, "Path parameter cannot be resolved without a provisioned identity."
    if not all(param.lower() in _USERNAME_PARAMS for param in params):
        return (
            None,
            "Path parameter(s) "
            + ", ".join(sorted(set(params)))
            + " cannot be resolved safely; the endpoint was not inspected.",
        )
    return _PATH_PARAM.sub(identity_username, path), None


def _parse_json_body(result: ExecutionResult):
    if isinstance(result.response_body, (dict, list)):
        return result.response_body
    if result.response_body_raw:
        try:
            parsed = json.loads(result.response_body_raw)
        except ValueError:
            return None
        return parsed if isinstance(parsed, (dict, list)) else None
    return None


def _collect_schema_fields(schema, names: set[str], depth: int = 0) -> None:
    if depth > MAX_SCHEMA_DEPTH or not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            names.add(str(name))
            _collect_schema_fields(child, names, depth + 1)
    items = schema.get("items")
    if isinstance(items, dict):
        _collect_schema_fields(items, names, depth + 1)
    for key in ("allOf", "oneOf", "anyOf"):
        for child in schema.get(key) or []:
            _collect_schema_fields(child, names, depth + 1)


def _declared_response_fields(endpoint: Endpoint) -> tuple[set[str], bool]:
    fragment = endpoint.raw_spec_fragment or {}
    responses = fragment.get("responses") or {}
    response = None
    for code in ("200", "201", "202", "2XX", "default"):
        if isinstance(responses.get(code), dict):
            response = responses[code]
            break
    if response is None:
        return set(), False

    names: set[str] = set()

    # Swagger 2.0 places the response schema directly on the response.
    swagger_schema = response.get("schema")
    if isinstance(swagger_schema, dict):
        _collect_schema_fields(swagger_schema, names)

    content = response.get("content") or {}
    if isinstance(content, dict) and content:
        media = content.get("application/json")
        if not isinstance(media, dict):
            media = next(
                (item for item in content.values() if isinstance(item, dict)), {}
            )
        schema = media.get("schema") if isinstance(media, dict) else None
        _collect_schema_fields(schema, names)

    return names, bool(names)


def _is_token_issuance(endpoint: Endpoint) -> bool:
    fragment = endpoint.raw_spec_fragment or {}
    text = " ".join(
        str(part or "")
        for part in (
            endpoint.operation_id,
            endpoint.path,
            fragment.get("summary"),
            fragment.get("description"),
        )
    )
    return bool(_TOKEN_ISSUANCE.search(text))


def _unsupported(endpoint: Endpoint, rationale: str, auth_mode: str = "none") -> SensitiveEndpointResult:
    return SensitiveEndpointResult(
        endpoint_id=endpoint.id,
        method=endpoint.method,
        path=endpoint.path,
        operation_id=endpoint.operation_id,
        outcome=SensitiveOutcome.UNSUPPORTED,
        inspected=False,
        auth_mode=auth_mode,
        rationale=rationale,
    )


def run_sensitive_data_check(
    scan_id: int,
    allow_identity_registration: bool = False,
    request_budget: int = DEFAULT_SENSITIVE_REQUEST_BUDGET,
    executor_transport=None,
    resolved_target: Optional["ResolvedTarget"] = None,
) -> SensitiveDataCheckResult:
    """Inspect in-scope GET responses for inappropriate sensitive data.

    Closed by default: raises PermissionError unless identity
    registration (active testing) is explicitly approved.
    """
    if not allow_identity_registration:
        raise PermissionError(
            "Sensitive-data checks send requests to the target. Pass "
            "allow_identity_registration=True to explicitly approve active testing."
        )

    budget = RequestBudget(max_requests=request_budget)

    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} does not exist.")
        target = session.get(Target, scan.target_id)
        base_url = target.base_url

    from api_security_system.targets.security import (
        authorized_origins,
        is_authorized_origin,
        resolve_target,
        validate_resolved_target,
    )

    if not is_authorized_origin(base_url):
        raise TargetOriginError(
            "Sensitive-data checks are only authorized against the explicitly "
            f"allowlisted origins {sorted(authorized_origins())}, got {base_url!r}."
        )

    if executor_transport is None:
        # Reuse the assessment's validated addresses when available. Other
        # callers must resolve once here. Injected test transports remain
        # unchanged.
        if resolved_target is None:
            pinned_addresses = resolve_target(base_url).addresses
        else:
            pinned_addresses = validate_resolved_target(
                base_url, resolved_target
            )
        raw_executor = RequestExecutor(
            base_url=base_url,
            pinned_addresses=pinned_addresses,
        )
    else:
        raw_executor = RequestExecutor(
            base_url=base_url,
            transport=executor_transport,
        )
    executor = _BudgetedExecutor(raw_executor, budget)
    auth = AuthModule(executor)

    result = SensitiveDataCheckResult(
        scan_id=scan_id,
        target_base_url=base_url,
        requests_used=0,
        request_budget=request_budget,
    )

    try:
        identity = None
        identity_ctx: Optional[AuthContext] = None
        try:
            identity, identity_ctx, _ = provision_identity(
                auth, scan_id, "sensitive_data_probe"
            )
        except (AuthenticationError, TransportError, BudgetExceededError) as exc:
            result.reason = (
                "Could not provision an inspection identity ("
                f"{type(exc).__name__}); authenticated endpoints were not inspected."
            )

        endpoints = _select_get_endpoints(scan_id)
        if not endpoints:
            result.status = "not_applicable"
            result.reason = result.reason or "No GET endpoints are available to inspect."
            return result

        stopped_early = False
        for endpoint in endpoints:
            if budget.used >= budget.max_requests:
                stopped_early = True
                result.reason = (
                    f"Request budget of {request_budget} exhausted before inspecting "
                    "all GET endpoints."
                )
                break

            fragment = endpoint.raw_spec_fragment or {}
            restriction = get_get_side_effect_reason(
                endpoint.path,
                operation_id=endpoint.operation_id,
                operation=fragment,
            )
            if restriction:
                result.results.append(_unsupported(endpoint, restriction))
                continue

            required_input_error = _required_input_reason(endpoint)
            if required_input_error:
                result.results.append(_unsupported(endpoint, required_input_error))
                continue

            path, path_error = _resolve_path(
                endpoint.path,
                identity.description if identity is not None else None,
            )
            if path_error:
                result.results.append(_unsupported(endpoint, path_error))
                continue

            auth_required = bool(fragment.get("security"))
            if auth_required and identity_ctx is None:
                result.results.append(
                    _unsupported(
                        endpoint,
                        "Endpoint requires authentication but no inspection identity "
                        "is available.",
                        auth_mode="authenticated",
                    )
                )
                continue

            headers = (
                {"Authorization": identity_ctx.auth_header_value}
                if auth_required and identity_ctx is not None
                else {}
            )
            auth_mode = "authenticated" if auth_required else "anonymous"

            try:
                response = executor.execute(
                    ExecutionRequest(method="GET", path=path, headers=headers)
                )
            except BudgetExceededError:
                stopped_early = True
                result.reason = (
                    f"Request budget of {request_budget} exhausted while inspecting "
                    f"{endpoint.path}."
                )
                break
            except TransportError as exc:
                result.results.append(
                    _unsupported(
                        endpoint,
                        f"Request could not complete ({type(exc).__name__}).",
                        auth_mode=auth_mode,
                    )
                )
                continue

            if not (200 <= response.response_status < 300):
                result.results.append(
                    _unsupported(
                        endpoint,
                        f"Inspection returned HTTP {response.response_status}; "
                        "no response body was evaluated.",
                        auth_mode=auth_mode,
                    )
                )
                continue

            body = _parse_json_body(response)
            if body is None:
                result.results.append(
                    _unsupported(
                        endpoint,
                        "Response was not JSON; structured fields could not be inspected.",
                        auth_mode=auth_mode,
                    )
                )
                continue

            declared_fields, schema_found = _declared_response_fields(endpoint)
            outcome, observations, subjects, rationale = inspect_body(
                body,
                endpoint_path=endpoint.path,
                operation_id=endpoint.operation_id,
                authenticated=bool(headers),
                identity_username=identity.description if identity is not None else None,
                declared_fields=declared_fields,
                token_issuance=_is_token_issuance(endpoint),
            )

            execution_id = _persist_evidence(
                scan_id,
                endpoint.id,
                identity.id if headers and identity is not None else None,
                response,
                body,
            )

            finding_id = None
            if outcome in {SensitiveOutcome.CONFIRMED, SensitiveOutcome.CANDIDATE}:
                finding_id = _create_finding(
                    scan_id, endpoint.id, outcome, rationale, execution_id
                )

            result.results.append(
                SensitiveEndpointResult(
                    endpoint_id=endpoint.id,
                    method=endpoint.method,
                    path=endpoint.path,
                    operation_id=endpoint.operation_id,
                    outcome=outcome,
                    inspected=True,
                    auth_mode=auth_mode,
                    subject_count=len(subjects),
                    fields=sorted({item.path for item in observations}),
                    categories=sorted({item.category for item in observations}),
                    finding_id=finding_id,
                    execution_id=execution_id,
                    rationale=rationale,
                )
            )

        inspected = [item for item in result.results if item.inspected]
        if stopped_early:
            result.status = "stopped_early"
        elif inspected:
            result.status = "performed"
        elif result.results:
            result.status = "unsupported"
            result.reason = result.reason or (
                "No GET endpoint could be inspected safely."
            )
        else:
            result.status = "not_applicable"

    finally:
        executor.close()
        result.requests_used = budget.used

    return result

"""URL validation and SSRF protection for assessment targets.

User-supplied and operator-allowlisted targets must resolve only to public
addresses. The built-in VAmPI origin and explicitly enabled local test
origins are narrow exceptions that must resolve only to loopback addresses.

The target itself is always supplied at runtime. The allowlists below are
security policy, not a fixed assessment target; operators can add exact
origins through environment variables without editing the workflow.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# The default VAmPI-compatible origin remains allowlisted for backwards
# compatibility. Operators can add exact, additional origins without editing
# source code. These are security boundaries, not convenience settings.
DEFAULT_AUTHORIZED_ORIGIN = "http://localhost:5000"
AUTHORIZED_ORIGINS = frozenset({DEFAULT_AUTHORIZED_ORIGIN})
AUTHORIZED_ORIGINS_ENV = "APIVIGILANTE_AUTHORIZED_ORIGINS"
USER_AUTHORIZED_TARGETS_ENV = "APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS"

# Exact loopback origin(s) for isolated test APIs. They are disabled unless
# the explicit opt-in flag is set. The default keeps the bundled test API
# working; APIVIGILANTE_TEST_TARGET_ORIGINS replaces it with a comma-separated
# list of exact origins.
TEST_ONLY_AUTHORIZED_ORIGIN = "http://127.0.0.1:5001"
TEST_ONLY_ORIGIN_ENV = "APIVIGILANTE_ENABLE_TEST_TARGET"
TEST_ONLY_ORIGINS_ENV = "APIVIGILANTE_TEST_TARGET_ORIGINS"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})

_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)


class TargetValidationError(ValueError):
    """Raised when a user-supplied target/spec URL is unsafe or malformed."""


def _split_http_url(url: str):
    if not isinstance(url, str) or not url.strip():
        raise TargetValidationError("URL must be a non-empty string.")

    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError("URL must use http or https.")
    if parts.username is not None or parts.password is not None:
        raise TargetValidationError("URL must not contain embedded credentials.")
    if parts.fragment:
        raise TargetValidationError("URL must not contain a fragment.")
    if not parts.hostname:
        raise TargetValidationError("URL must include a hostname.")

    try:
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError("URL contains an invalid port.") from exc

    segments = [segment for segment in parts.path.split("/") if segment]
    if any(segment in {".", ".."} for segment in segments):
        raise TargetValidationError("URL must not contain dot-segments.")

    return parts, parts.hostname.lower(), port


def origin_of(url: str) -> str:
    """Return the normalized scheme://host:port origin of a validated URL.

    Default ports are omitted so an explicit ``:80``/``:443`` compares equal
    to the same origin without a port.
    """
    parts, hostname, port = _split_http_url(url)
    scheme = parts.scheme.lower()
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    if port is None or port == (443 if scheme == "https" else 80):
        return f"{scheme}://{host_part}"
    return f"{scheme}://{host_part}:{port}"


def _origin_of(url: str) -> str:
    return origin_of(url)


@dataclass(frozen=True)
class ResolvedTarget:
    """A validated target plus the IP addresses that were approved for it."""

    base_url: str
    scheme: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


def _effective_port(scheme: str, port: int | None) -> int:
    return port or (443 if scheme == "https" else 80)


def _canonical_ip(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    ip = _canonical_ip(ip)
    return ip.is_global and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _is_loopback_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    return _canonical_ip(ip).is_loopback


def _is_local_test_origin(origin: str) -> bool:
    """Whether this exact origin is permitted to resolve only to loopback."""
    if origin == DEFAULT_AUTHORIZED_ORIGIN:
        return True
    return test_only_origin_enabled() and origin in test_only_authorized_origins()


def _require_loopback_addresses(
    hostname: str, addresses: tuple[str, ...]
) -> None:
    if not all(_is_loopback_address(address) for address in addresses):
        raise TargetValidationError(
            f"Local test target '{hostname}' resolved to a non-loopback "
            f"address ({', '.join(addresses)}); refusing to connect."
        )


def _validated_ip_addresses(
    hostname: str,
    addresses,
    *,
    allow_private: bool,
) -> tuple[str, ...]:
    if isinstance(addresses, (str, bytes)):
        raise TargetValidationError(
            "Resolved addresses must be a sequence of IP literals."
        )
    try:
        candidates = tuple(addresses)
    except TypeError as exc:
        raise TargetValidationError(
            "Resolved addresses must be a sequence of IP literals."
        ) from exc
    if not candidates:
        raise TargetValidationError(f"Could not resolve host '{hostname}'.")

    approved: list[str] = []
    seen: set[str] = set()
    for raw_address in candidates:
        if not isinstance(raw_address, str) or not raw_address.strip():
            raise TargetValidationError(
                f"Host '{hostname}' has an invalid resolved address."
            )
        try:
            ip = ipaddress.ip_address(raw_address.strip().split("%", 1)[0])
        except ValueError as exc:
            raise TargetValidationError(
                f"Host '{hostname}' resolved to an invalid address."
            ) from exc

        ip = _canonical_ip(ip)
        if not allow_private and not _ip_is_public(ip):
            raise TargetValidationError(
                f"Host '{hostname}' resolves to a non-public address ({ip}); "
                "requests to private, loopback, link-local, or metadata "
                "addresses are not permitted."
            )

        address = str(ip)
        if address not in seen:
            seen.add(address)
            approved.append(address)

    return tuple(approved)


def _resolve_authorized_addresses(
    hostname: str,
    port: int | None,
    scheme: str,
    *,
    local_test_origin: bool,
) -> tuple[str, ...]:
    addresses = _resolve_addresses(
        hostname, port, scheme, allow_private=local_test_origin
    )
    if local_test_origin:
        _require_loopback_addresses(hostname, addresses)
    return addresses


def _resolve_addresses(
    hostname: str,
    port: int | None,
    scheme: str,
    *,
    allow_private: bool,
) -> tuple[str, ...]:
    socket_port = _effective_port(scheme, port)
    try:
        infos = socket.getaddrinfo(hostname, socket_port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetValidationError(f"Could not resolve host '{hostname}'.") from exc

    return _validated_ip_addresses(
        hostname,
        (info[4][0] for info in infos),
        allow_private=allow_private,
    )


def _resolve_and_check(hostname: str, port: int | None, scheme: str) -> None:
    _resolve_addresses(hostname, port, scheme, allow_private=False)


def test_only_origin_enabled() -> bool:
    return (
        os.environ.get(TEST_ONLY_ORIGIN_ENV, "").strip().lower() in _TRUE_VALUES
    )


def user_authorized_targets_enabled() -> bool:
    """Return whether the operator allows per-assessment public targets.

    This is a second, server-side gate. A caller cannot enable active
    testing for a non-allowlisted target merely by setting a request field;
    the operator must also opt in with an environment variable.
    """
    return (
        os.environ.get(USER_AUTHORIZED_TARGETS_ENV, "").strip().lower()
        in _TRUE_VALUES
    )


def is_active_test_authorized(
    url: str,
    *,
    authorized_for_active_testing: bool = False,
) -> bool:
    """Return whether active requests may be sent to ``url``.

    Allowlisted origins keep their existing authorization. Other targets
    become eligible only when both the server-side opt-in is enabled and
    the caller explicitly confirms authorization for this assessment. The
    target must still pass the SSRF/public-address policy during
    ``resolve_target``; this helper does not relax address validation.
    """
    if is_authorized_origin(url):
        return True
    return bool(authorized_for_active_testing) and user_authorized_targets_enabled()


def _configured_origins(raw: str | None) -> frozenset[str]:
    """Parse comma-separated exact origins; invalid entries fail closed."""
    if not raw:
        return frozenset()

    origins: set[str] = set()
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        try:
            parts, _hostname, _port = _split_http_url(candidate)
        except TargetValidationError:
            continue
        if parts.path not in {"", "/"} or parts.query or parts.fragment:
            continue
        origins.add(origin_of(candidate))
    return frozenset(origins)


def extra_authorized_origins() -> frozenset[str]:
    """Return operator-configured exact origins for active testing."""
    return _configured_origins(os.environ.get(AUTHORIZED_ORIGINS_ENV))


def test_only_authorized_origins() -> frozenset[str]:
    """Return exact origins enabled only by explicit test mode.

    If the origins variable is set, it replaces the bundled default; this
    prevents a typo from silently enabling the default test origin.
    """
    raw = os.environ.get(TEST_ONLY_ORIGINS_ENV)
    if raw is not None:
        return _configured_origins(raw)
    return frozenset({TEST_ONLY_AUTHORIZED_ORIGIN})


def authorized_origins() -> frozenset[str]:
    origins = AUTHORIZED_ORIGINS | extra_authorized_origins()
    if test_only_origin_enabled():
        origins = origins | test_only_authorized_origins()
    return origins


def is_authorized_origin(url: str) -> bool:
    return origin_of(url) in authorized_origins()


def validate_resolved_target(
    url: str,
    resolved: ResolvedTarget,
) -> tuple[str, ...]:
    """Return addresses from a previously validated target without resolving.

    This preserves the one-time DNS result for callers that validated a
    target earlier in the same operation. The URL binding and address
    policy are re-checked, so this is not a way to supply an arbitrary
    address list: the addresses must be IP literals for the same
    normalized target and must satisfy the existing public/loopback rule.
    """
    if not isinstance(resolved, ResolvedTarget):
        raise TargetValidationError(
            "Resolved target must be a ResolvedTarget instance."
        )

    parts, hostname, port = _split_http_url(url)
    scheme = parts.scheme.lower()
    origin = origin_of(url)
    path = parts.path.rstrip("/")
    base = origin + path if path else origin
    effective_port = _effective_port(scheme, port)

    if (
        resolved.base_url != base
        or resolved.scheme != scheme
        or resolved.hostname != hostname
        or resolved.port != effective_port
    ):
        raise TargetValidationError(
            "Resolved target does not match the requested target URL."
        )

    local_test_origin = _is_local_test_origin(origin)
    addresses = _validated_ip_addresses(
        hostname,
        resolved.addresses,
        allow_private=local_test_origin,
    )
    if local_test_origin:
        _require_loopback_addresses(hostname, addresses)
    return addresses


def validate_pinned_addresses(url: str, addresses) -> tuple[str, ...]:
    """Apply the complete target-address policy to a raw address sequence.

    This compatibility seam is for internal callers that have addresses but
    not a ``ResolvedTarget``. It performs no DNS lookup, but it still binds
    the addresses to the normalized target URL and enforces the existing
    public/authorized-loopback policy. Prefer ``validate_resolved_target``
    when a previously validated target is available; a raw sequence cannot
    prove its own DNS provenance and must not come from untrusted input.
    """
    if isinstance(addresses, (str, bytes)):
        raise TargetValidationError(
            "Resolved addresses must be a sequence of IP literals."
        )
    try:
        candidates = tuple(addresses)
    except TypeError as exc:
        raise TargetValidationError(
            "Resolved addresses must be a sequence of IP literals."
        ) from exc

    parts, hostname, port = _split_http_url(url)
    scheme = parts.scheme.lower()
    origin = origin_of(url)
    path = parts.path.rstrip("/")
    base = origin + path if path else origin
    resolved = ResolvedTarget(
        base_url=base,
        scheme=scheme,
        hostname=hostname,
        port=_effective_port(scheme, port),
        addresses=candidates,
    )
    return validate_resolved_target(url, resolved)


def resolve_target(url: str, *, resolve_authorized: bool = True) -> ResolvedTarget:
    """Validate a target URL and return the addresses approved for it.

    Authorized origins are exempt from the public-address check because
    they are explicitly allowlisted. When ``resolve_authorized`` is false,
    authorized hostnames are not resolved; this preserves validation-only
    behavior for callers that do not connect.
    """
    parts, hostname, port = _split_http_url(url)
    scheme = parts.scheme.lower()
    origin = origin_of(url)
    path = parts.path.rstrip("/")
    base = origin + path if path else origin
    effective_port = _effective_port(scheme, port)

    if origin in authorized_origins():
        if resolve_authorized:
            addresses = _resolve_authorized_addresses(
                hostname,
                port,
                scheme,
                local_test_origin=_is_local_test_origin(origin),
            )
        else:
            try:
                literal = ipaddress.ip_address(hostname)
            except ValueError:
                addresses = ()
            else:
                addresses = (str(_canonical_ip(literal)),)
        return ResolvedTarget(
            base_url=base,
            scheme=scheme,
            hostname=hostname,
            port=effective_port,
            addresses=addresses,
        )

    if hostname in _BLOCKED_HOSTNAMES:
        raise TargetValidationError(
            f"Host '{hostname}' is a cloud metadata endpoint and is not permitted."
        )

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        literal = _canonical_ip(literal)
        if not _ip_is_public(literal):
            raise TargetValidationError(
                f"Target address {literal} is not a public address."
            )
        addresses = (str(literal),)
    else:
        addresses = _resolve_addresses(
            hostname, port, scheme, allow_private=False
        )

    return ResolvedTarget(
        base_url=base,
        scheme=scheme,
        hostname=hostname,
        port=effective_port,
        addresses=addresses,
    )


def validate_target_url(url: str) -> str:
    """Validate a user-supplied base URL and return its normalized form.

    The returned value preserves any path prefix (e.g.
    ``https://host/api/v3``) because OpenAPI discovery and spec-relative
    paths depend on it. Authorization testing still uses the origin only.
    """
    return resolve_target(url, resolve_authorized=False).base_url


def validate_spec_url(base_url: str, spec_url: str | None) -> str | None:
    """Resolve and validate an optional explicit OpenAPI spec URL.

    The spec URL must share the target's origin, so a user cannot use it
    to make the server fetch an unrelated internal resource.
    """
    if spec_url is None or not str(spec_url).strip():
        return None

    base_origin = origin_of(base_url)
    candidate = str(spec_url).strip()
    if candidate.startswith("/"):
        candidate = base_origin + candidate
    elif not candidate.lower().startswith(("http://", "https://")):
        candidate = base_url.rstrip("/") + "/" + candidate

    spec_origin = origin_of(candidate)
    if spec_origin != base_origin:
        raise TargetValidationError(
            "OpenAPI spec URL must use the same origin as the target base URL "
            f"({base_origin})."
        )

    return candidate

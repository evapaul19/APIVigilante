"""URL validation and SSRF protection for assessment targets.

The system sends HTTP requests only to an explicitly authorized origin
(the local VAmPI instance) plus public internet origins that the user
supplies. Anything that resolves to a private, loopback, link-local,
reserved, multicast, or unspecified address is rejected unless it is
one of the explicitly authorized origins.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# The only origin for which the existing authorization tests are
# enabled. This is a security boundary, not a convenience setting.
DEFAULT_AUTHORIZED_ORIGIN = "http://localhost:5000"
AUTHORIZED_ORIGINS = frozenset({DEFAULT_AUTHORIZED_ORIGIN})

# A single, exact loopback origin for the isolated test API. It is
# disabled unless the explicit opt-in environment flag is set.
TEST_ONLY_AUTHORIZED_ORIGIN = "http://127.0.0.1:5001"
TEST_ONLY_ORIGIN_ENV = "APIVIGILANTE_ENABLE_TEST_TARGET"
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
    """Return the scheme://host:port origin of a validated http(s) URL."""
    parts, hostname, port = _split_http_url(url)
    scheme = parts.scheme.lower()
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    if port is None:
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


def _requires_loopback_resolution(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return _canonical_ip(ip).is_loopback


def _is_loopback_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    return _canonical_ip(ip).is_loopback


def _require_loopback_if_needed(hostname: str, addresses: tuple[str, ...]) -> None:
    if _requires_loopback_resolution(hostname) and not all(
        _is_loopback_address(address) for address in addresses
    ):
        raise TargetValidationError(
            f"Authorized loopback host '{hostname}' resolved to a non-loopback "
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
) -> tuple[str, ...]:
    addresses = _resolve_addresses(hostname, port, scheme, allow_private=True)
    _require_loopback_if_needed(hostname, addresses)
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


def authorized_origins() -> frozenset[str]:
    if test_only_origin_enabled():
        return AUTHORIZED_ORIGINS | frozenset({TEST_ONLY_AUTHORIZED_ORIGIN})
    return AUTHORIZED_ORIGINS


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

    allow_private = origin in authorized_origins()
    addresses = _validated_ip_addresses(
        hostname,
        resolved.addresses,
        allow_private=allow_private,
    )
    if allow_private:
        _require_loopback_if_needed(hostname, addresses)
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
                hostname, port, scheme
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

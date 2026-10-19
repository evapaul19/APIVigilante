
"""Deterministic OpenAPI spec parsing and resource identification.

No LLM calls, no network calls to the target API — pure spec parsing.
"""

import re
from typing import Optional

from prance import ResolvingParser

from .schemas import ParsedEndpoint

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

# Matches a path parameter segment like {user_id}.
_PARAM_PATTERN = re.compile(r"^\{(.+)\}$")

# Matches version segments such as v1, v2, or V12.
_VERSION_SEGMENT = re.compile(r"^v\d+$", re.IGNORECASE)


class SpecParseError(Exception):
    """Raised when the OpenAPI spec cannot be loaded or resolved."""

    def __init__(self, path: str, original: Exception) -> None:
        self.path = path
        self.original = original
        super().__init__(
            f"Failed to parse OpenAPI spec at '{path}': {original}"
        )


def _identify_resource(
    path: str,
) -> tuple[Optional[str], Optional[str]]:
    """Best-effort extraction of resource type and ID parameter.

    Uses the last path parameter as the ID parameter and searches
    backward for the nearest preceding non-parameter, non-version
    segment to identify the resource type.

    This is a heuristic, not a universal REST path parser.
    """
    segments = [s for s in path.strip("/").split("/") if s]

    param_indices = [
        i
        for i, segment in enumerate(segments)
        if _PARAM_PATTERN.match(segment)
    ]

    if not param_indices:
        return None, None

    last_param_idx = param_indices[-1]
    match = _PARAM_PATTERN.match(segments[last_param_idx])

    # Defensive check: the segment was already matched above.
    if match is None:
        return None, None

    id_param_name = match.group(1)
    resource_type = None

    for i in range(last_param_idx - 1, -1, -1):
        segment = segments[i]

        # Skip other path parameters and version prefixes like v1/v2.
        if (
            _PARAM_PATTERN.match(segment)
            or _VERSION_SEGMENT.match(segment)
        ):
            continue

        # Simple plural-to-singular heuristic.
        resource_type = (
            segment.rstrip("s")
            if segment.endswith("s") and not segment.endswith("ss")
            else segment
        )
        break

    return resource_type, id_param_name


def parse_openapi_spec(spec_path: str) -> list[ParsedEndpoint]:
    """Parse an OpenAPI spec into a deterministic endpoint list.

    Raises SpecParseError if loading, validation, or $ref resolution fails.
    Makes no requests to the target API.
    """
    try:
        parser = ResolvingParser(spec_path, strict=False)
    except Exception as exc:
        # Wrap parser, validator, YAML, and reference-resolution failures.
        raise SpecParseError(spec_path, exc) from exc

    paths = parser.specification.get("paths", {})

    seen: set[tuple[str, str]] = set()
    endpoints: list[ParsedEndpoint] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method_lower = method.lower()

            if method_lower not in HTTP_METHODS:
                continue

            if not isinstance(operation, dict):
                continue

            key = (method_lower, path)
            if key in seen:
                continue

            seen.add(key)

            resource_type, id_param_name = _identify_resource(path)

            endpoints.append(
                ParsedEndpoint(
                    method=method_lower.upper(),
                    path=path,
                    operation_id=operation.get("operationId"),
                    resource_type=resource_type,
                    id_param_name=id_param_name,
                    raw_spec_fragment=operation,
                )
            )

    return endpoints

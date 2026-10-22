"""Deterministic OpenAPI spec parsing and resource identification.

No LLM calls, no network calls to the target API. References are resolved
only within the document; external HTTP/file references are deliberately
left unresolved so a target-controlled spec cannot make the process fetch
another resource.
"""

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import yaml
from prance.util.resolver import RESOLVE_INTERNAL, RefResolver

from api_security_system.safe_gets import get_get_side_effect_reason

from .schemas import (
    CoverageIssue,
    NormalizedParameter,
    ParsedEndpoint,
    ParsedSpec,
    ReconCoverage,
)

_SUPPORTED_HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
}
_SPEC_OPERATION_KEYS = _SUPPORTED_HTTP_METHODS | {"trace"}

# Matches a path parameter segment like {user_id}.
_PARAM_PATTERN = re.compile(r"^\{(.+)\}$")
_PATH_TEMPLATE_PARAMETER = re.compile(r"\{([^{}]+)\}")

# Matches version segments such as v1, v2, or V12.
_VERSION_SEGMENT = re.compile(r"^v\d+$", re.IGNORECASE)

MAX_COVERAGE_ISSUES = 100


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


def _add_issue(
    bucket: list[CoverageIssue],
    coverage: ReconCoverage,
    **kwargs: Any,
) -> None:
    if len(bucket) >= MAX_COVERAGE_ISSUES:
        coverage.details_truncated = True
        return
    bucket.append(CoverageIssue(**kwargs))


def _add_limitation(coverage: ReconCoverage, text: str) -> None:
    if text not in coverage.limitations:
        coverage.limitations.append(text)


def _load_and_resolve(spec_path: str) -> dict:
    """Load a JSON/YAML document and resolve only internal references."""
    path = Path(spec_path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SpecParseError(spec_path, exc) from exc

    try:
        document = json.loads(text)
    except ValueError:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecParseError(spec_path, exc) from exc

    if not isinstance(document, dict):
        raise SpecParseError(
            spec_path,
            ValueError("Specification root must be an object."),
        )

    try:
        resolver = RefResolver(
            document,
            path.resolve().as_uri(),
            resolve_types=RESOLVE_INTERNAL,
            strict=False,
        )
        resolver.resolve_references()
    except Exception as exc:  # noqa: BLE001 - wrapped for the API boundary
        raise SpecParseError(spec_path, exc) from exc

    if not isinstance(resolver.specs, dict):
        raise SpecParseError(
            spec_path,
            ValueError("Resolved specification root must be an object."),
        )
    return resolver.specs


def _spec_metadata(
    spec_path: str,
    spec: dict,
    coverage: ReconCoverage,
) -> None:
    if "openapi" in spec:
        coverage.spec_format = "openapi"
        coverage.spec_version = spec.get("openapi")
    elif "swagger" in spec:
        coverage.spec_format = "swagger"
        coverage.spec_version = spec.get("swagger")
    else:
        raise SpecParseError(
            spec_path,
            ValueError("Missing 'openapi' or 'swagger' version field."),
        )

    version = coverage.spec_version
    if not isinstance(version, str) or not (
        version == "2.0" or version.startswith("3.")
    ):
        raise SpecParseError(
            spec_path,
            ValueError(
                "Unsupported OpenAPI/Swagger version "
                f"{version!r}; supported versions are 2.0 and 3.x."
            ),
        )

    base_path = spec.get("basePath")
    if isinstance(base_path, str) and base_path:
        coverage.base_path = base_path
        _add_limitation(
            coverage,
            "Swagger basePath was recorded; Recon applies it only when it can "
            "be combined unambiguously with the target base path.",
        )

    raw_servers = spec.get("servers")
    if isinstance(raw_servers, list):
        for server in raw_servers:
            if isinstance(server, dict):
                url = server.get("url")
                if isinstance(url, str) and url:
                    coverage.servers.append(url)
        if coverage.servers:
            _add_limitation(
                coverage,
                "OpenAPI server URLs were recorded; Recon applies a prefix only "
                "when one same-origin/relative server path is unambiguous and "
                "the target base_url does not already include it.",
            )


def _has_unresolved_reference(value: Any, depth: int = 0) -> bool:
    if depth > 20:
        return False
    if isinstance(value, dict):
        if "$ref" in value:
            return True
        return any(
            _has_unresolved_reference(item, depth + 1)
            for item in value.values()
        )
    if isinstance(value, list):
        return any(
            _has_unresolved_reference(item, depth + 1) for item in value
        )
    return False


def _parameter_items(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _merge_parameters(
    path_parameters: list[dict],
    operation_parameters: list[dict],
) -> list[dict]:
    """Merge path-level and operation-level parameters.

    Operation-level declarations override path-level declarations with the
    same (name, in) pair, as required by OpenAPI. Unresolved/unnamed
    references are retained so they can be reported instead of dropped.
    """
    merged: dict[tuple, dict] = {}
    anonymous = 0

    for raw in [*path_parameters, *operation_parameters]:
        name = raw.get("name")
        location = raw.get("in")
        if (
            isinstance(name, str)
            and name
            and isinstance(location, str)
            and location
            and "$ref" not in raw
        ):
            merged[(location, name)] = raw
        else:
            merged[("__anonymous__", anonymous)] = raw
            anonymous += 1

    return list(merged.values())


def _parameter_schema(raw: dict) -> tuple[Optional[dict], Optional[str]]:
    schema = raw.get("schema")
    if isinstance(schema, dict):
        reference = schema.get("$ref")
        return schema, reference if isinstance(reference, str) else None

    content = raw.get("content")
    if isinstance(content, dict):
        for media_type in sorted(str(key) for key in content):
            media = content.get(media_type)
            if not isinstance(media, dict):
                continue
            candidate = media.get("schema")
            if isinstance(candidate, dict):
                reference = candidate.get("$ref")
                return (
                    candidate,
                    reference if isinstance(reference, str) else None,
                )
    return None, None


def _normalize_parameter(raw: dict) -> NormalizedParameter:
    name = raw.get("name")
    location = raw.get("in")
    reference = raw.get("$ref")
    if not isinstance(reference, str):
        reference = None

    schema, schema_reference = _parameter_schema(raw)
    if schema_reference and not reference:
        reference = schema_reference

    schema_type = None
    schema_format = None
    if schema is not None and reference is None:
        candidate_type = schema.get("type")
        if isinstance(candidate_type, str):
            schema_type = candidate_type
        elif "properties" in schema:
            schema_type = "object"
        elif "items" in schema:
            schema_type = "array"

        candidate_format = schema.get("format")
        if isinstance(candidate_format, str):
            schema_format = candidate_format

    if schema is None:
        legacy_type = raw.get("type")
        if isinstance(legacy_type, str):
            schema_type = legacy_type
        legacy_format = raw.get("format")
        if isinstance(legacy_format, str):
            schema_format = legacy_format

    normalized_location = (
        location if isinstance(location, str) and location else "unknown"
    )
    required = bool(raw.get("required")) or normalized_location == "path"

    return NormalizedParameter(
        name=name if isinstance(name, str) and name else None,
        location=normalized_location,
        required=required,
        schema_type=schema_type,
        schema_format=schema_format,
        has_schema=schema is not None,
        unresolved_reference=reference,
    )


def _request_body_details(
    method: str,
    path: str,
    operation: dict,
    operation_id: Optional[str],
    parameters: list[NormalizedParameter],
    global_consumes: list[str],
    coverage: ReconCoverage,
) -> tuple[bool, list[str]]:
    media_types: set[str] = set()
    required = False

    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        body_reference = request_body.get("$ref")
        if isinstance(body_reference, str):
            _add_issue(
                coverage.required_request_bodies,
                coverage,
                method=method,
                path=path,
                operation_id=operation_id,
                reason=(
                    "requestBody reference was not resolved; its required "
                    "status and schema are unknown."
                ),
            )
        else:
            required = bool(request_body.get("required"))
            content = request_body.get("content")
            if isinstance(content, dict):
                media_types.update(str(key) for key in content)
                for media_type in sorted(str(key) for key in content):
                    media = content.get(media_type)
                    if not isinstance(media, dict):
                        continue
                    schema = media.get("schema")
                    if isinstance(schema, dict) and isinstance(
                        schema.get("$ref"), str
                    ):
                        _add_issue(
                            coverage.required_request_bodies,
                            coverage,
                            method=method,
                            path=path,
                            operation_id=operation_id,
                            reason=(
                                "Request body schema reference was not "
                                f"resolved for {media_type}: {schema['$ref']}"
                            ),
                        )
            if required and not media_types:
                _add_issue(
                    coverage.required_request_bodies,
                    coverage,
                    method=method,
                    path=path,
                    operation_id=operation_id,
                    reason=(
                        "Operation requires a request body but declares no "
                        "content/media type."
                    ),
                )
            if required:
                _add_issue(
                    coverage.required_request_bodies,
                    coverage,
                    method=method,
                    path=path,
                    operation_id=operation_id,
                    reason=(
                        "Operation requires a request body; the inventory "
                        "records it, but current automated GET-based checks "
                        "do not synthesize body values."
                    ),
                )
    elif request_body is not None:
        _add_issue(
            coverage.required_request_bodies,
            coverage,
            method=method,
            path=path,
            operation_id=operation_id,
            reason="requestBody is not an object and could not be normalized.",
        )

    consumes = operation.get("consumes")
    if not isinstance(consumes, list):
        consumes = global_consumes
    for parameter in parameters:
        if parameter.location not in {"body", "formData"}:
            continue
        if parameter.required:
            required = True
            media_types.update(
                str(value) for value in consumes if isinstance(value, str)
            )
            _add_issue(
                coverage.required_request_bodies,
                coverage,
                method=method,
                path=path,
                operation_id=operation_id,
                parameter=parameter.name,
                location=parameter.location,
                reason=(
                    "Required Swagger request body/formData parameter is "
                    "inventoried, but automated checks do not synthesize "
                    "body values."
                ),
            )

    return required, sorted(media_types)


def _operation_slug(method: str, path: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", path.strip("/")).strip("_").lower()
    return f"{method.lower()}_{cleaned or 'root'}"


def _unique_operation_id(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _normalize_operation(
    method: str,
    path: str,
    operation: dict,
    path_parameters: list[dict],
    global_consumes: list[str],
    coverage: ReconCoverage,
) -> tuple[ParsedEndpoint, Optional[str]]:
    operation_id = operation.get("operationId")
    if not isinstance(operation_id, str) or not operation_id.strip():
        operation_id = None
    else:
        operation_id = operation_id.strip()

    merged_parameters = _merge_parameters(
        path_parameters,
        _parameter_items(operation.get("parameters")),
    )

    normalized_parameters: list[NormalizedParameter] = []
    unresolved_required: list[str] = []
    required_count = 0
    optional_count = 0

    for raw in merged_parameters:
        parameter = _normalize_parameter(raw)
        normalized_parameters.append(parameter)

        location = parameter.location
        coverage.parameter_locations[location] = (
            coverage.parameter_locations.get(location, 0) + 1
        )

        if parameter.required:
            required_count += 1
        else:
            optional_count += 1

        if parameter.unresolved_reference:
            label = parameter.name or f"{parameter.location}:<unnamed>"
            _add_issue(
                coverage.unresolved_parameters,
                coverage,
                method=method,
                path=path,
                operation_id=operation_id,
                parameter=parameter.name,
                location=parameter.location,
                reason=(
                    "Parameter reference was not resolved: "
                    f"{parameter.unresolved_reference}"
                ),
            )
            if parameter.required:
                unresolved_required.append(label)

    declared_path_parameters = {
        parameter.name
        for parameter in normalized_parameters
        if parameter.location == "path" and parameter.name
    }
    for name in _PATH_TEMPLATE_PARAMETER.findall(path):
        if name in declared_path_parameters:
            continue
        required_count += 1
        unresolved_required.append(name)
        _add_issue(
            coverage.unresolved_parameters,
            coverage,
            method=method,
            path=path,
            operation_id=operation_id,
            parameter=name,
            location="path",
            reason=(
                f"Path parameter '{name}' is used in the path template but "
                "has no parameter definition."
            ),
        )

    body_required, body_media_types = _request_body_details(
        method,
        path,
        operation,
        operation_id,
        normalized_parameters,
        global_consumes,
        coverage,
    )

    if required_count:
        coverage.operations_with_required_parameters += 1
    if unresolved_required:
        coverage.operations_with_unresolved_required_parameters += 1
    if body_required:
        coverage.operations_requiring_request_body += 1

    fragment = dict(operation)
    fragment["parameters"] = [dict(item) for item in merged_parameters]

    restriction = get_get_side_effect_reason(
        path,
        operation_id=operation_id,
        operation=operation,
        method=method,
    )
    if restriction:
        coverage.operations_execution_restricted += 1
        _add_issue(
            coverage.execution_restrictions,
            coverage,
            method=method.upper(),
            path=path,
            operation_id=operation_id,
            reason=restriction,
        )

    resource_type, id_param_name = _identify_resource(path)

    endpoint = ParsedEndpoint(
        method=method.upper(),
        path=path,
        operation_id=operation_id,
        resource_type=resource_type,
        id_param_name=id_param_name,
        raw_spec_fragment=fragment,
        parameters=normalized_parameters,
        required_parameter_count=required_count,
        optional_parameter_count=optional_count,
        unresolved_required_parameters=unresolved_required,
        request_body_required=body_required,
        request_body_media_types=body_media_types,
    )

    return endpoint, operation_id


def parse_openapi_spec_with_coverage(spec_path: str) -> ParsedSpec:
    """Parse a spec into endpoints while accounting for every operation.

    Supports Swagger/OpenAPI 2.0 and OpenAPI 3.x documents. Internal
    ``$ref`` values are resolved, including reusable parameters and
    schemas. External references are not fetched and are reported when
    they leave a parameter or request body unresolved.
    """
    spec = _load_and_resolve(spec_path)
    coverage = ReconCoverage()
    _spec_metadata(spec_path, spec, coverage)

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        _add_limitation(coverage, "Specification has no usable 'paths' object.")
        return ParsedSpec(endpoints=[], coverage=coverage)

    raw_global_consumes = spec.get("consumes")
    global_consumes = (
        [value for value in raw_global_consumes if isinstance(value, str)]
        if isinstance(raw_global_consumes, list)
        else []
    )

    seen: set[tuple[str, str]] = set()
    records: list[tuple[ParsedEndpoint, Optional[str]]] = []

    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            _add_limitation(
                coverage,
                f"Path {path!r} is not a valid OpenAPI path and was skipped.",
            )
            continue
        if not isinstance(path_item, dict):
            _add_limitation(
                coverage,
                f"Path item for {path!r} is not an object and was skipped.",
            )
            continue

        path_parameters = _parameter_items(path_item.get("parameters"))

        for method_key, operation in path_item.items():
            method = method_key.lower() if isinstance(method_key, str) else ""
            if method not in _SPEC_OPERATION_KEYS:
                continue

            key = (method, path)
            if key in seen:
                continue
            seen.add(key)
            coverage.operations_discovered += 1

            if method not in _SUPPORTED_HTTP_METHODS:
                coverage.operations_unsupported += 1
                _add_issue(
                    coverage.unsupported_operations,
                    coverage,
                    method=method.upper(),
                    path=path,
                    operation_id=(
                        operation.get("operationId")
                        if isinstance(operation, dict)
                        and isinstance(operation.get("operationId"), str)
                        else None
                    ),
                    reason=(
                        f"HTTP method {method.upper()} is outside the "
                        "supported inventory/execution methods."
                    ),
                )
                continue

            if not isinstance(operation, dict):
                coverage.operations_unsupported += 1
                _add_issue(
                    coverage.unsupported_operations,
                    coverage,
                    method=method.upper(),
                    path=path,
                    reason="Operation is not an object and could not be normalized.",
                )
                continue

            endpoint, original_operation_id = _normalize_operation(
                method,
                path,
                operation,
                path_parameters,
                global_consumes,
                coverage,
            )
            coverage.operations_normalized += 1
            records.append((endpoint, original_operation_id))

    original_ids = [
        original for _, original in records if original is not None
    ]
    original_counts = Counter(original_ids)
    used_ids = set(original_ids)
    assigned_original_ids: set[str] = set()

    for endpoint, original in records:
        if original is None:
            coverage.missing_operation_ids += 1
            generated = _unique_operation_id(
                f"auto_{_operation_slug(endpoint.method, endpoint.path)}",
                used_ids,
            )
            endpoint.operation_id = generated
            endpoint.operation_id_generated = True
            coverage.generated_operation_ids += 1
            continue

        if original_counts[original] > 1 and original in assigned_original_ids:
            coverage.duplicate_operation_ids += 1
            generated = _unique_operation_id(
                (
                    f"{original}_{endpoint.method.lower()}_"
                    f"{_operation_slug(endpoint.method, endpoint.path).split('_', 1)[-1]}"
                ),
                used_ids,
            )
            endpoint.operation_id = generated
            endpoint.operation_id_generated = True
            coverage.generated_operation_ids += 1
            continue

        assigned_original_ids.add(original)

    if coverage.missing_operation_ids:
        _add_limitation(
            coverage,
            f"{coverage.missing_operation_ids} operation(s) without an "
            "operationId were assigned deterministic generated IDs.",
        )
    if coverage.duplicate_operation_ids:
        _add_limitation(
            coverage,
            f"{coverage.duplicate_operation_ids} duplicate operationId "
            "value(s) were rewritten deterministically; the first occurrence "
            "retained the original value.",
        )
    if coverage.operations_unsupported:
        _add_limitation(
            coverage,
            f"{coverage.operations_unsupported} operation(s) used unsupported "
            "methods or malformed operation objects and were not inventoried.",
        )
    if coverage.operations_requiring_request_body:
        _add_limitation(
            coverage,
            "Required request bodies are inventoried, but current automated "
            "GET-based checks do not synthesize body values.",
        )
    if _has_unresolved_reference(spec):
        _add_limitation(
            coverage,
            "Only internal $ref values are resolved; unresolved external "
            "HTTP/file references are reported and never fetched.",
        )
    if coverage.details_truncated:
        _add_limitation(
            coverage,
            "Coverage issue lists were capped; counts remain complete.",
        )
    _add_limitation(
        coverage,
        "No operations are excluded from inventory for safety; execution-time "
        "guards still block side-effecting GET requests.",
    )
    if coverage.operations_execution_restricted:
        _add_limitation(
            coverage,
            f"{coverage.operations_execution_restricted} side-effect-prone GET "
            "operation(s) remain inventoried but are marked execution-restricted.",
        )

    return ParsedSpec(endpoints=[item[0] for item in records], coverage=coverage)


def parse_openapi_spec(spec_path: str) -> list[ParsedEndpoint]:
    """Parse an OpenAPI spec into a deterministic endpoint list."""
    return parse_openapi_spec_with_coverage(spec_path).endpoints

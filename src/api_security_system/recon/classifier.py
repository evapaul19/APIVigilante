"""LLM-based endpoint risk classification.

Deterministic endpoint discovery (parser.py) does not depend on this
module succeeding - see service.py for how classification failures
are isolated from the endpoint inventory itself.

LLM classification is best-effort: if credentials are missing, the LLM
fails, or output is malformed, the endpoint record is preserved without
a risk_classification rather than failing the whole scan.
"""
import json
import os
import time
from pathlib import Path
from typing import Optional

from api_security_system.llm import LLMClient, LLMRequest, Provider
from .schemas import ParsedEndpoint, RiskClassification

# Resolve project root for .env loading when classifier is invoked from
# a different CWD than the project root (e.g., tests, workflow runs).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Attempt to load .env from project root so environment variables are
# available regardless of the process CWD.
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=_PROJECT_ROOT / ".env")
except Exception:
    # dotenv is optional; if it fails, we simply rely on os.environ.
    pass

CLASSIFIER_MODELS = {
    "google": os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite"),
    "openrouter": os.environ.get("OPENROUTER_MODEL", "deepseek/deepseek-v4.1-flash"),
}
MAX_ATTEMPTS = 2
RETRY_DELAY_SECONDS = 2

# Provider ordering — used when LLM_PROVIDER is not set explicitly.
PROVIDER_ORDERING = ["google", "openrouter"]
_PROVIDER_KEY_ENV = {
    "google": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}

_SYSTEM_PROMPT = (
    "You are a security triage assistant classifying API endpoints by risk. "
    "Given an HTTP method, path, and OpenAPI operation details, respond with "
    "ONLY a single JSON object, no other text, matching exactly this shape: "
    '{"risk_level": "low"|"medium"|"high"|"critical", "rationale": "<short reason>", '
    '"confidence": <0.0-1.0>}. '
    "Consider authorization risk (BOLA/BFLA potential from path parameters), "
    "data sensitivity, and whether the operation mutates state."
)


class ClassificationError(Exception):
    """Raised when an endpoint could not be classified after all retries
    have been exhausted.

    Callers (service.py) catch this and preserve the endpoint record
    without a risk_classification, rather than failing the whole scan.
    """

    def __init__(self, operation_id: str | None, path: str, original: Exception) -> None:
        self.operation_id = operation_id
        self.path = path
        self.original = original
        super().__init__(f"Failed to classify endpoint '{path}': {original}")


def _build_prompt(endpoint: ParsedEndpoint) -> str:
    return (
        f"Method: {endpoint.method}\n"
        f"Path: {endpoint.path}\n"
        f"Resource type: {endpoint.resource_type}\n"
        f"ID parameter: {endpoint.id_param_name}\n"
        f"Operation details: {json.dumps(endpoint.raw_spec_fragment)[:2000]}"
    )


def _resolve_provider() -> tuple[Provider, str]:
    """Pick a provider: explicit LLM_PROVIDER, else the first with a key.

    If no key is configured, fall back to the first configured ordering
    entry so mocked callers (tests) still exercise the retry logic; the
    real provider will raise a clear missing-key error when called.
    """
    explicit = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if explicit:
        if explicit not in CLASSIFIER_MODELS:
            raise ValueError(
                f"Unsupported LLM_PROVIDER {explicit!r}; "
                f"expected one of {sorted(CLASSIFIER_MODELS)}."
            )
        return Provider(explicit), CLASSIFIER_MODELS[explicit]

    for name in PROVIDER_ORDERING:
        if os.environ.get(_PROVIDER_KEY_ENV[name]):
            return Provider(name), CLASSIFIER_MODELS[name]

    default_name = PROVIDER_ORDERING[0]
    return Provider(default_name), CLASSIFIER_MODELS[default_name]


def _classify_with_provider(
    endpoint: ParsedEndpoint,
    llm_client: LLMClient,
    provider: Provider,
    model: str,
) -> tuple[Optional[RiskClassification], Optional[Exception]]:
    """Run a single classification attempt with the given provider.

    Returns (classification, error) — if classification succeeds, error is None.
    If it fails, error contains the exception details.
    """
    try:
        response = llm_client.generate(
            LLMRequest(
                provider=provider,
                model=model,
                prompt=_build_prompt(endpoint),
                system=_SYSTEM_PROMPT,
                max_tokens=256,
                temperature=0.0,
            )
        )
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()

        parsed = json.loads(raw)
        return RiskClassification(**parsed), None

    except Exception as exc:  # noqa: BLE001 - API errors, JSON errors, schema errors
        return None, exc


def classify_endpoint(endpoint: ParsedEndpoint, llm_client: LLMClient) -> RiskClassification:
    """Classify a single endpoint's risk level via the LLM.

    Retries up to MAX_ATTEMPTS times using the selected provider
    (LLM_PROVIDER, else the first provider with a configured key).
    If all attempts fail, ClassificationError is raised.

    Returns a RiskClassification model instance on success.
    Callers should catch ClassificationError and leave the endpoint's
    risk_classification as None (unclassified) rather than failing the
    whole scan.
    """
    try:
        prov, model = _resolve_provider()
    except (ValueError, IndexError) as exc:
        raise ClassificationError(
            endpoint.operation_id, endpoint.path,
            RuntimeError(
                "No configured LLM provider. Set GEMINI_API_KEY or "
                f"OPENROUTER_API_KEY in your .env file. ({exc})"
            ),
        ) from exc

    last_error: Exception | None = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            classification, error = _classify_with_provider(
                endpoint, llm_client, prov, model
            )
            if classification is not None:
                return classification
            last_error = error
            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_DELAY_SECONDS)
        except ClassificationError:
            raise
        except Exception as exc:
            last_error = exc
            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_DELAY_SECONDS)

    raise ClassificationError(endpoint.operation_id, endpoint.path, last_error)
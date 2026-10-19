"""LLM-assisted rationale for AMBIGUOUS BOLA outcomes only. The LLM's
output is used solely as a human-readable rationale string attached
to a 'candidate' Finding - there is no code path anywhere in this
module that lets an LLM response set a finding to 'confirmed'.
Failures of any kind fall back to a generic message rather than
raising, so a flaky LLM call never crashes a BOLA run.
"""

import json

from api_security_system.llm import LLMClient, LLMRequest, Provider

CLASSIFIER_MODEL = "gemini-3.5-flash-lite"

_SYSTEM_PROMPT = (
    "You are a security triage assistant. You are given sanitized HTTP "
    "evidence (status codes and response bodies; any tokens are already "
    "redacted) from an ambiguous BOLA (Broken Object Level Authorization) "
    "test. Respond with ONLY a single JSON object: "
    '{"rationale": "<one or two sentence explanation>"}. '
    "You provide a rationale only - you are not authorized to confirm or "
    "deny the vulnerability; that determination is made separately by "
    "deterministic verification, never by your output alone."
)


def generate_ambiguous_rationale(evidence_summary: str, llm_client: LLMClient) -> str:
    try:
        response = llm_client.generate(
            LLMRequest(
                provider=Provider.GOOGLE,
                model=CLASSIFIER_MODEL,
                prompt=evidence_summary,
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
        rationale = parsed.get("rationale")
        if not rationale:
            raise ValueError("Missing rationale field")
        return rationale
    except Exception:
        return "Ambiguous result; LLM rationale unavailable (classification failed)."
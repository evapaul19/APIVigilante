"""AuthZ checks: deterministic, budget-capped, identity-isolated BOLA
(object-level) and BFLA (function-level) testing, with LLM rationale
assistance only for outcomes deterministic verification cannot resolve.
No LLM output can set a finding to confirmed.
"""

from .schemas import AttemptOutcome, BflaCandidate, BolaCandidate, BolaCheckResult, BudgetExceededError, EndpointTestResult, UnauthorizedTargetError
from .service import run_bfla_checks, run_bola_check

__all__ = [
    "run_bola_check",
    "run_bfla_checks",
    "BolaCheckResult",
    "EndpointTestResult",
    "AttemptOutcome",
    "BolaCandidate",
    "BflaCandidate",
    "UnauthorizedTargetError",
    "BudgetExceededError",
]
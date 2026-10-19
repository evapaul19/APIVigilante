"""RequestExecutor: the sole, deterministic chokepoint for sending HTTP
requests to a target under test. No LLM calls, no reasoning, no
persistence - pure request execution and evidence capture.
"""

from .executor import RequestExecutor
from .schemas import ExecutionRequest, ExecutionResult, TargetOriginError, TransportError

__all__ = [
    "RequestExecutor",
    "ExecutionRequest",
    "ExecutionResult",
    "TargetOriginError",
    "TransportError",
]
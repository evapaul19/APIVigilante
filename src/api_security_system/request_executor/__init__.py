"""RequestExecutor: the sole, deterministic chokepoint for sending HTTP
requests to a target under test. No LLM calls, no reasoning, no
persistence - pure request execution and evidence capture.
"""

from .executor import MAX_RESPONSE_BYTES, RequestExecutor
from .pinned import PinnedAddressTransport, PinnedNetworkBackend
from .schemas import ExecutionRequest, ExecutionResult, TargetOriginError, TransportError

__all__ = [
    "RequestExecutor",
    "PinnedAddressTransport",
    "PinnedNetworkBackend",
    "ExecutionRequest",
    "ExecutionResult",
    "TargetOriginError",
    "TransportError",
    "MAX_RESPONSE_BYTES",
]
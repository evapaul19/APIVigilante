"""Shared safety classification for GET operations.

The inventory records side-effect-prone GETs so coverage is explicit, while
execution layers use the same classification to avoid sending them.
"""

import re
from typing import Any, Optional

_SIDE_EFFECT_GET = re.compile(
    r"(?<![A-Za-z])(?i:create|creates|created|populate|populates|populated|"
    r"seed|seeds|seeded|reset|resets|resetting|delete|deletes|deleted|"
    r"drop|drops|dropped|truncate|truncates|truncated|update|updates|updated|"
    r"modify|modifies|modified|migrate|migrates|migrated|install|installs|"
    r"installed|remove|removes|removed|purge|purges|purged|wipe|wipes|wiped|"
    r"init|initialize|initialized)(?![a-z])"
)
_UNSAFE_GET_PATH = re.compile(
    r"/(?i:createdb|create|populate|seed|reset|delete|drop|migrate|"
    r"install|remove|purge|wipe)(?![a-z])"
)


def get_get_side_effect_reason(
    path: str,
    operation_id: Optional[str] = None,
    operation: Optional[dict[str, Any]] = None,
    method: str = "GET",
) -> Optional[str]:
    """Return why a GET must not be executed, or None when it is safe."""
    if str(method).upper() != "GET":
        return None
    text = " ".join(
        str(part or "")
        for part in (
            operation_id,
            (operation or {}).get("summary"),
            (operation or {}).get("description"),
        )
    )
    if _UNSAFE_GET_PATH.search(path):
        return (
            "GET path matches a side-effect-prone pattern; it was not executed."
        )
    if _SIDE_EFFECT_GET.search(text):
        return (
            "GET operation has side effects according to its documentation; "
            "it was not executed."
        )
    return None

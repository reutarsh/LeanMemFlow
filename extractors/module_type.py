"""MemProcFS module-name prefix classification for ``module_type``."""

from __future__ import annotations

_PREFIX_DATA = "_data-"
_PREFIX_NOTLINKED = "_notlinked-"
_PREFIX_INJECTED = "_injected-"
_PREFIX_NA = "_na-"
_PREFIX_WOW64 = "_64-"


def parse_module_type(module_name: str | None) -> str:
    """Derive MemProcFS ``VMM_MODULE_TP`` label from a module ``Name`` prefix."""
    if module_name is None or not str(module_name).strip():
        return "NORMAL"

    name = str(module_name).strip()
    if name.lower().startswith(_PREFIX_WOW64):
        name = name[len(_PREFIX_WOW64):]

    lower = name.lower()
    if lower.startswith(_PREFIX_DATA):
        return "DATA"
    if lower.startswith(_PREFIX_NOTLINKED):
        return "NOTLINKED"
    if lower.startswith(_PREFIX_INJECTED):
        return "INJECTED"
    if lower.startswith(_PREFIX_NA):
        return "NA"
    return "NORMAL"

"""Auto-discovery of extractor plugins.

Drop a ``.py`` file into this package that defines a :class:`BaseExtractor`
subclass and it will be picked up automatically — no registration needed.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Dict, List, Type

from extractors.base import BaseExtractor

logger = logging.getLogger(__name__)


def discover_extractors() -> Dict[str, Type[BaseExtractor]]:
    """Import every module in this package and return concrete extractors.

    Returns a ``{name: ExtractorClass}`` mapping, sorted by name.
    Modules that fail to import are logged and skipped.
    """
    registry: Dict[str, Type[BaseExtractor]] = {}

    package_path = __path__  # type: ignore[name-defined]
    for finder, module_name, _is_pkg in pkgutil.iter_modules(package_path):
        if module_name.startswith("_") or module_name == "base":
            continue
        fqn = f"{__name__}.{module_name}"
        try:
            mod = importlib.import_module(fqn)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to import extractor module %s: %s", fqn, exc)
            continue

        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseExtractor)
                and obj is not BaseExtractor
                and getattr(obj, "name", "")
            ):
                registry[obj.name] = obj

    return dict(sorted(registry.items()))


def list_extractor_names() -> List[str]:
    """Return sorted names of all discovered extractors."""
    return sorted(discover_extractors().keys())

"""Extract device objects from the forensic CSV."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult


class DevicesExtractor(BaseExtractor):
    name = "devices"
    output_filename = "devices.csv"
    source = "forensic_csv"

    def extract(self, memprocfs_root: Any, out_dir: Path) -> ExtractResult:
        return self.copy_forensic_csv(Path(memprocfs_root), self.output_filename, out_dir)

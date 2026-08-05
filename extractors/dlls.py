"""Adapt MemProcFS module / DLL listings into canonical MemFlow dlls.csv.

Primary input is ``modules.csv`` (MemProcFS forensic export). ``dlls.csv`` is
used only when ``modules.csv`` is absent (legacy or custom trees).

Intentional blanks from native ``modules.csv`` (typical MemProcFS export):
``module_type`` (internal type not present in the CSV), ``pe_timedatestamp`` /
``pe_checksum`` (not in the standard module table). ``entry_point`` is filled
only when the source row includes ``Entry`` / ``entry``.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult

logger = logging.getLogger(__name__)


class DllsExtractor(BaseExtractor):
    name = "dlls"
    output_filename = "dlls.csv"
    source = "forensic_csv"

    HEADERS = [
        "pid", "process_name", "module_name", "module_path",
        "base_address", "size", "entry_point",
        "is_wow64", "module_type", "pe_timedatestamp", "pe_checksum",
    ]

    @staticmethod
    def _cell(row: dict[str, str], *names: str) -> str:
        for name in names:
            val = row.get(name)
            if val is not None:
                return val
        return ""

    @staticmethod
    def _first_path(row: dict[str, str]) -> str:
        """Prefer user image path; fall back to kernel path (e.g. \\SystemRoot\\…)."""
        p = DllsExtractor._cell(row, "Path", "path", "module_path").strip()
        if p:
            return p
        return DllsExtractor._cell(row, "KernelPath", "kernelpath").strip()

    def _row_from_source(self, row: dict[str, str]) -> list[str]:
        return [
            self._cell(row, "pid", "PID").strip(),
            self._cell(row, "process_name", "Process", "process").strip(),
            self._cell(row, "module_name", "Name", "name").strip(),
            self._first_path(row),
            self._cell(row, "base_address", "Start", "base", "Base").strip(),
            self._cell(row, "size", "Size").strip(),
            self._cell(row, "entry_point", "entry", "Entry").strip(),
            self._cell(row, "is_wow64", "Wow64", "wow64").strip(),
            self._cell(row, "module_type").strip(),
            self._cell(row, "pe_timedatestamp", "timedatestamp", "TimeDateStamp").strip(),
            self._cell(row, "pe_checksum", "checksum", "Checksum").strip(),
        ]

    def extract(self, memprocfs_root: Any, out_dir: Path) -> ExtractResult:
        root = Path(memprocfs_root)
        source = self._resolve_first_forensic_csv(root, "modules.csv", "dlls.csv")
        if source is None:
            return ExtractResult(
                ok=False,
                error="Neither modules.csv nor dlls.csv found under memprocfs root",
            )

        with source.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            source_rows = list(reader)

        if not source_rows and reader.fieldnames is None:
            return ExtractResult(ok=False, error=f"{source} has no header row")

        rows = [self._row_from_source(r) for r in source_rows]
        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

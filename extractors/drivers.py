"""Normalize MemProcFS drivers forensic CSV to canonical MemFlow drivers.csv."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult


class DriversExtractor(BaseExtractor):
    name = "drivers"
    output_filename = "drivers.csv"
    source = "forensic_csv"

    HEADERS = ["offset", "base", "size", "path", "name", "service_name"]

    @staticmethod
    def _cell(row: dict[str, str], *names: str) -> str:
        for name in names:
            val = row.get(name)
            if val is not None:
                return val
        return ""

    def extract(self, memprocfs_root: Any, out_dir: Path) -> ExtractResult:
        root = Path(memprocfs_root)
        source = self._resolve_forensic_csv(root, self.output_filename)
        if source is None:
            return ExtractResult(ok=False, error=f"{self.output_filename} not found under {root}")

        with source.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            rows_in = list(reader)
        if not rows_in and reader.fieldnames is None:
            return ExtractResult(ok=False, error=f"{source} has no header row")

        rows: list[list[str]] = []
        for row in rows_in:
            drv_name = self._cell(row, "DriverName").strip()
            nm = self._cell(row, "name", "Name").strip()
            display_name = drv_name if drv_name else nm
            rows.append([
                self._cell(row, "offset", "ObjectAddress").strip(),
                self._cell(row, "base", "Start").strip(),
                self._cell(row, "size", "Size").strip(),
                self._cell(row, "path", "DriverPath").strip(),
                display_name,
                self._cell(row, "service_name", "ServiceKey").strip(),
            ])

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

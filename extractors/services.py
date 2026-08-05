"""Normalize MemProcFS services forensic CSV to canonical MemFlow services.csv."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult


class ServicesExtractor(BaseExtractor):
    name = "services"
    output_filename = "services.csv"
    source = "forensic_csv"

    HEADERS = [
        "pid", "state", "start_type", "binary_path",
        "service_name", "display_name", "run_as",
    ]

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
            img = self._cell(row, "ImagePath").strip()
            drv = self._cell(row, "DriverpathOrCmdline").strip()
            binary = img if img else drv
            rows.append([
                self._cell(row, "pid", "PID").strip(),
                self._cell(row, "state", "State").strip(),
                self._cell(row, "start_type", "StartType").strip(),
                binary,
                self._cell(row, "service_name", "ServiceName").strip(),
                self._cell(row, "display_name", "DisplayName").strip(),
                self._cell(row, "run_as", "User").strip(),
            ])

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

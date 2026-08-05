"""Normalize MemProcFS scheduled-tasks forensic CSV to canonical MemFlow tasks.csv."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult


class TasksExtractor(BaseExtractor):
    name = "tasks"
    output_filename = "tasks.csv"
    source = "forensic_csv"

    HEADERS = ["name", "path", "command", "arguments", "trigger"]

    @staticmethod
    def _cell(row: dict[str, str], *names: str) -> str:
        for name in names:
            val = row.get(name)
            if val is not None:
                return val
        return ""

    @staticmethod
    def _trigger(row: dict[str, str]) -> str:
        """Synthetic trigger string — MemProcFS has multiple time columns, not one trigger."""
        parts = [
            ("TimeMostRecent", row.get("TimeMostRecent")),
            ("TimeReg", row.get("TimeReg")),
            ("TimeCreate", row.get("TimeCreate")),
            ("TimeLastRun", row.get("TimeLastRun")),
            ("TimeCompleted", row.get("TimeCompleted")),
        ]
        out: list[str] = []
        for label, val in parts:
            if val is None:
                continue
            s = str(val).strip()
            if s and s != "---":
                out.append(f"{label}={s}")
        return "; ".join(out)

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
            rows.append([
                self._cell(row, "name", "TaskName").strip(),
                self._cell(row, "path", "TaskPath").strip(),
                self._cell(row, "command", "CommandLine").strip(),
                self._cell(row, "arguments", "Parameters").strip(),
                self._trigger(row),
            ])

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

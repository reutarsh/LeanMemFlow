"""Adapt an existing process CSV into canonical MemFlow process.csv."""

from __future__ import annotations

import logging
import csv
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult

logger = logging.getLogger(__name__)


class ProcessesExtractor(BaseExtractor):
    name = "processes"
    output_filename = "process.csv"
    source = "forensic_csv"

    HEADERS = [
        "pid", "ppid", "pppid", "name", "parent_name", "grandparent_name",
        "path", "user", "username", "cmdline",
        "state", "create_time", "exit_time", "wow64",
    ]

    @staticmethod
    def _cell(row: dict[str, str], *names: str) -> str:
        for name in names:
            val = row.get(name)
            if val is not None:
                return val
        return ""

    def extract(self, memprocfs_root: Any, out_dir: Path) -> ExtractResult:
        source = self._resolve_forensic_csv(Path(memprocfs_root), self.output_filename)
        if source is None:
            return ExtractResult(ok=False, error=f"{self.output_filename} not found under {memprocfs_root}")

        with source.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            source_rows = list(reader)

        if not source_rows and reader.fieldnames is None:
            return ExtractResult(ok=False, error=f"{source} has no header row")

        pid_info: dict[str, tuple[str, str]] = {}
        for row in source_rows:
            pid = self._cell(row, "pid", "PID").strip()
            if not pid:
                continue
            pid_info[pid] = (
                self._cell(row, "name", "Name").strip(),
                self._cell(row, "ppid", "PPID").strip(),
            )

        rows: list[list[str]] = []
        for row in source_rows:
            pid = self._cell(row, "pid", "PID").strip()
            ppid = self._cell(row, "ppid", "PPID").strip()
            pppid = self._cell(row, "pppid", "PPPID").strip()
            parent_name = self._cell(row, "parent_name", "ParentName").strip()
            grandparent_name = self._cell(row, "grandparent_name", "GrandparentName").strip()

            if not parent_name and ppid in pid_info:
                parent_name = pid_info[ppid][0]
            if not pppid and ppid in pid_info:
                pppid = pid_info[ppid][1]
            if not grandparent_name and pppid in pid_info:
                grandparent_name = pid_info[pppid][0]

            image_path = self._cell(row, "UserPath").strip()
            if not image_path:
                image_path = self._cell(row, "KernelPath").strip()
            if not image_path:
                image_path = self._cell(row, "path", "Path").strip()

            rows.append([
                pid,
                ppid,
                pppid,
                self._cell(row, "name", "Name").strip(),
                parent_name,
                grandparent_name,
                image_path,
                self._cell(row, "user", "User").strip(),
                self._cell(row, "username", "Username").strip(),
                self._cell(row, "cmdline", "CommandLine", "commandline").strip(),
                self._cell(row, "state", "State").strip(),
                self._cell(row, "create_time", "CreateTime").strip(),
                self._cell(row, "exit_time", "ExitTime").strip(),
                self._cell(row, "wow64", "Wow64").strip(),
            ])

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

"""Extract handles.csv and resolve owning ProcessName with a VFS gate.

Keeps MemProcFS columns and appends ProcessName plus ProcessNameStatus.

Ownership gate (default): require MemProcFS VFS
pid/<PID>/handles/handles.txt with Handle+Object matching the CSV row.
Fail closed when the VFS tree is missing. Set allow_csv_only=True
(--handles-allow-csv-only) to skip the VFS gate for CSV-only trees.

After the gate passes, ProcessName comes from pid/<PID>/name.txt, then
forensic process.csv for that PID.
"""

from __future__ import annotations

import csv
import logging
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from extractors.base import BaseExtractor, ExtractResult
from extractors.pid_ownership import VfsContext, normalize_hex_address

logger = logging.getLogger(__name__)

PROCESS_NAME_HEADERS: tuple[str, ...] = (
    "ProcessName",
    "ProcessNameStatus",
)

HandleVfsStatus = Literal["ok", "no_vfs_handle", "object_mismatch"]


def verify_handle_vfs(
    pid: str,
    handle_csv: str,
    object_csv: str,
    ctx: VfsContext,
) -> HandleVfsStatus:
    """Confirm CSV Handle+Object appear in pid/<PID>/handles/handles.txt."""
    if not pid or not handle_csv:
        return "no_vfs_handle"

    index = ctx.get_handle_index(pid)
    if index is None:
        return "no_vfs_handle"

    handle_norm = normalize_hex_address(handle_csv)
    object_norm = normalize_hex_address(object_csv)
    if not handle_norm:
        return "no_vfs_handle"

    if handle_norm not in index:
        return "no_vfs_handle"

    if index[handle_norm] != object_norm:
        return "object_mismatch"
    return "ok"


class HandlesExtractor(BaseExtractor):
    name = "handles"
    output_filename = "handles.csv"
    source = "forensic_csv"

    def __init__(
        self,
        *,
        allow_csv_only: bool = False,
        ctx: VfsContext | None = None,
    ) -> None:
        self.allow_csv_only = allow_csv_only
        self.ctx = ctx

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
            msg = f"{self.output_filename} not found under {root}"
            logger.warning("  [!] %s", msg)
            return ExtractResult(ok=False, error=msg)

        with source.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            source_rows = list(reader)

        if not fieldnames:
            return ExtractResult(ok=False, error=f"{source} has no header row")

        ctx = self.ctx if self.ctx is not None else VfsContext(root)
        status_counts: Counter[str] = Counter()

        output_headers = fieldnames + [
            h for h in PROCESS_NAME_HEADERS if h not in fieldnames
        ]
        output_rows: list[list[str]] = []

        for row in source_rows:
            pid = self._cell(row, "PID", "pid").strip()
            handle = self._cell(row, "Handle", "handle").strip()
            obj = self._cell(row, "Object", "object").strip()

            process_name = ""
            status: str

            if not self.allow_csv_only:
                vfs_status = verify_handle_vfs(pid, handle, obj, ctx)
                if vfs_status != "ok":
                    status = vfs_status
                else:
                    process_name = ctx.resolve_process_name(pid)
                    status = "ok" if process_name else "no_process"
            else:
                # Prefer name.txt when present; otherwise process.csv by PID.
                process_name = ctx.resolve_process_name(pid)
                status = "ok" if process_name else "no_process"

            status_counts[status] += 1
            out_row = [
                row.get(h, "") if row.get(h) is not None else "" for h in fieldnames
            ]
            derived = {
                "ProcessName": process_name,
                "ProcessNameStatus": status,
            }
            for header in PROCESS_NAME_HEADERS:
                if header in fieldnames:
                    out_row[fieldnames.index(header)] = derived[header]
                else:
                    out_row.append(derived[header])
            output_rows.append(out_row)

        if status_counts:
            summary = ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items()))
            logger.info(
                "handles ProcessNameStatus: %s%s",
                summary,
                " (csv-only mode)" if self.allow_csv_only else "",
            )

        self.write_csv(out_dir, self.output_filename, output_headers, output_rows)
        return ExtractResult(
            ok=True,
            rows=len(output_rows),
            files_written=[self.output_filename],
        )

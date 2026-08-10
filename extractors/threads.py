"""Extract threads.csv and resolve thread start VAs to containing modules.

Keeps MemProcFS columns and appends StartModule* plus StartModuleStatus.

Module join: same PID and module.Start <= addr <= module.End (inclusive).
Address preference: nonzero Win32StartAddress, else StartAddress.

Ownership gate (default): require MemProcFS VFS
pid/<PID>/threads/<TID>/info.txt with ETHREAD matching the CSV row.
Fail closed when the VFS tree is missing. Set allow_csv_only=True
(--threads-allow-csv-only) to skip the VFS gate for CSV-only trees.
"""

from __future__ import annotations

import csv
import logging
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from extractors.base import BaseExtractor, ExtractResult
from extractors.pid_ownership import (
    VfsContext,
    normalize_hex_address,
    parse_address,
    parse_info_txt_ethread,
)

logger = logging.getLogger(__name__)

# Re-export for callers/tests that import from this module.
__all__ = [
    "START_MODULE_HEADERS",
    "ThreadsExtractor",
    "find_containing_module",
    "normalize_hex_address",
    "parse_address",
    "parse_info_txt_ethread",
    "resolve_thread_start_address",
    "verify_thread_vfs",
]

START_MODULE_HEADERS: tuple[str, ...] = (
    "StartModuleName",
    "StartModulePath",
    "StartModuleBase",
    "StartModuleStatus",
)

VfsStatus = Literal["ok", "no_vfs_thread", "ethread_mismatch"]


@dataclass(frozen=True)
class _ModuleRange:
    start: int
    end: int
    name: str
    path: str
    base_str: str

    @property
    def span(self) -> int:
        return self.end - self.start


def resolve_thread_start_address(start_address: str, win32_start_address: str) -> int | None:
    """Prefer nonzero Win32StartAddress; fall back to StartAddress."""
    win32 = parse_address(win32_start_address)
    if win32 is not None and win32 != 0:
        return win32
    return parse_address(start_address)


def find_containing_module(
    modules: list[_ModuleRange],
    address: int,
) -> _ModuleRange | None:
    """Return the tightest module range containing *address*, or None.

    *modules* must be sorted by ``(start, span)`` ascending (as produced by
    ``_build_module_index``). Uses bisect on start addresses, then picks the
    smallest spanning match among candidates with ``start <= address``.
    """
    if not modules:
        return None
    starts = [m.start for m in modules]
    idx = bisect_right(starts, address) - 1
    best: _ModuleRange | None = None
    for i in range(idx, -1, -1):
        module = modules[i]
        if module.start > address:
            continue
        if address <= module.end:
            if best is None or module.span < best.span:
                best = module
    return best


def verify_thread_vfs(
    memprocfs_root: Path,
    pid: str,
    tid: str,
    ethread_csv: str,
    ctx: VfsContext | None = None,
) -> VfsStatus:
    """Confirm CSV ETHREAD matches pid/<PID>/threads/<TID>/info.txt."""
    if not pid or not tid:
        return "no_vfs_thread"

    cache = ctx if ctx is not None else VfsContext(Path(memprocfs_root))
    ethread_vfs = cache.get_ethread_vfs(pid, tid)
    if ethread_vfs is None:
        return "no_vfs_thread"

    if normalize_hex_address(ethread_csv) != normalize_hex_address(ethread_vfs):
        return "ethread_mismatch"
    return "ok"


class ThreadsExtractor(BaseExtractor):
    name = "threads"
    output_filename = "threads.csv"
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

    @staticmethod
    def _module_path(row: dict[str, str]) -> str:
        path = ThreadsExtractor._cell(row, "Path", "path").strip()
        if path:
            return path
        return ThreadsExtractor._cell(row, "KernelPath", "kernelpath").strip()

    @classmethod
    def _build_module_index(
        cls, memprocfs_root: Path
    ) -> dict[str, list[_ModuleRange]]:
        modules_csv = cls._resolve_forensic_csv(memprocfs_root, "modules.csv")
        if modules_csv is None:
            return {}

        index: dict[str, list[_ModuleRange]] = {}
        with modules_csv.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                pid = cls._cell(row, "PID", "pid").strip()
                start_str = cls._cell(row, "Start", "start", "base", "Base").strip()
                end_str = cls._cell(row, "End", "end").strip()
                start = parse_address(start_str)
                end = parse_address(end_str)
                if start is None:
                    continue
                if end is None:
                    size = parse_address(cls._cell(row, "Size", "size"))
                    if size is None or size <= 0:
                        continue
                    end = start + size - 1
                if end < start:
                    continue
                index.setdefault(pid, []).append(
                    _ModuleRange(
                        start=start,
                        end=end,
                        name=cls._cell(row, "Name", "name").strip(),
                        path=cls._module_path(row),
                        base_str=start_str,
                    )
                )
        for pid, modules in index.items():
            modules.sort(key=lambda m: (m.start, m.span))
        return index

    def _resolve_module_fields(
        self,
        *,
        pid: str,
        address: int | None,
        module_index: dict[str, list[_ModuleRange]],
    ) -> tuple[str, str, str, str]:
        """Return (name, path, base, status) for a post-ownership-gate row."""
        if address is None:
            return "", "", "", "no_address"

        modules = module_index.get(pid, [])
        if not modules:
            return "", "", "", "no_modules_for_pid"

        match = find_containing_module(modules, address)
        if match is None:
            return "", "", "", "no_module"

        return match.name, match.path, match.base_str, "ok"

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
        module_index = self._build_module_index(root)
        status_counts: Counter[str] = Counter()

        # Column indexes for hot loop (avoid repeated dict/list scans).
        def _col(*names: str) -> str | None:
            for name in names:
                if name in fieldnames:
                    return name
            return None

        pid_col = _col("PID", "pid")
        tid_col = _col("TID", "tid")
        ethread_col = _col("ETHREAD", "ethread")
        start_col = _col("StartAddress", "start_address")
        win32_col = _col("Win32StartAddress", "win32_start_address")

        derived_positions = {
            header: fieldnames.index(header) if header in fieldnames else None
            for header in START_MODULE_HEADERS
        }
        append_derived = [h for h in START_MODULE_HEADERS if h not in fieldnames]

        if not self.allow_csv_only:
            pairs = []
            for row in source_rows:
                pid = (row.get(pid_col, "") if pid_col else "").strip()
                tid = (row.get(tid_col, "") if tid_col else "").strip()
                if pid and tid:
                    pairs.append((pid, tid))
            preloaded = ctx.preload_ethreads(pairs)
            if preloaded:
                logger.info("threads preloaded %d info.txt ETHREAD values", preloaded)

        output_headers = fieldnames + append_derived
        output_rows: list[list[str]] = []

        for row in source_rows:
            pid = (row.get(pid_col, "") if pid_col else "").strip()
            tid = (row.get(tid_col, "") if tid_col else "").strip()
            ethread = (row.get(ethread_col, "") if ethread_col else "").strip()

            module_name = ""
            module_path = ""
            module_base = ""

            if not self.allow_csv_only:
                vfs_status = verify_thread_vfs(root, pid, tid, ethread, ctx=ctx)
                if vfs_status != "ok":
                    status = vfs_status
                else:
                    address = resolve_thread_start_address(
                        row.get(start_col, "") if start_col else "",
                        row.get(win32_col, "") if win32_col else "",
                    )
                    (
                        module_name,
                        module_path,
                        module_base,
                        status,
                    ) = self._resolve_module_fields(
                        pid=pid,
                        address=address,
                        module_index=module_index,
                    )
            else:
                address = resolve_thread_start_address(
                    row.get(start_col, "") if start_col else "",
                    row.get(win32_col, "") if win32_col else "",
                )
                module_name, module_path, module_base, status = self._resolve_module_fields(
                    pid=pid,
                    address=address,
                    module_index=module_index,
                )

            status_counts[status] += 1
            out_row = [row.get(h, "") if row.get(h) is not None else "" for h in fieldnames]
            derived = {
                "StartModuleName": module_name,
                "StartModulePath": module_path,
                "StartModuleBase": module_base,
                "StartModuleStatus": status,
            }
            for header in START_MODULE_HEADERS:
                pos = derived_positions[header]
                if pos is not None:
                    out_row[pos] = derived[header]
                else:
                    out_row.append(derived[header])
            output_rows.append(out_row)

        if status_counts:
            summary = ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items()))
            logger.info(
                "threads StartModuleStatus: %s%s",
                summary,
                " (csv-only mode)" if self.allow_csv_only else "",
            )

        self.write_csv(out_dir, self.output_filename, output_headers, output_rows)
        return ExtractResult(
            ok=True,
            rows=len(output_rows),
            files_written=[self.output_filename],
        )

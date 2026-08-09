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
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from extractors.base import BaseExtractor, ExtractResult

logger = logging.getLogger(__name__)

START_MODULE_HEADERS: tuple[str, ...] = (
    "StartModuleName",
    "StartModulePath",
    "StartModuleBase",
    "StartModuleStatus",
)

VfsStatus = Literal["ok", "no_vfs_thread", "ethread_mismatch"]

_ETHREAD_INFO_RE = re.compile(r"^\s*ETHREAD\s*:\s*(?P<addr>\S+)\s*$", re.IGNORECASE | re.MULTILINE)


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


def parse_address(value: str) -> int | None:
    """Parse a MemProcFS hex/dec address; return None if blank or invalid.

    MemProcFS thread CSV often emits bare hex (``7ff791d2bfd0``) without ``0x``;
    module CSV usually includes the prefix. Treat strings containing a-f as hex.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        lowered = stripped.lower()
        if lowered.startswith("0x"):
            return int(stripped, 16)
        if any(ch in lowered for ch in "abcdef"):
            return int(stripped, 16)
        return int(stripped, 10)
    except ValueError:
        return None


def normalize_hex_address(value: str) -> str:
    """Normalize a hex address for equality checks (no 0x, lower, no leading zeros)."""
    if value is None:
        return ""
    stripped = value.strip().lower()
    if stripped.startswith("0x"):
        stripped = stripped[2:]
    stripped = stripped.lstrip("0")
    return stripped or "0"


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
    """Return the tightest module range containing *address*, or None."""
    best: _ModuleRange | None = None
    for module in modules:
        if module.start <= address <= module.end:
            if best is None or module.span < best.span:
                best = module
    return best


def parse_info_txt_ethread(info_path: Path) -> str | None:
    """Return the ETHREAD address from MemProcFS thread info.txt, or None."""
    try:
        text = info_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _ETHREAD_INFO_RE.search(text)
    if match is None:
        return None
    return match.group("addr").strip()


def verify_thread_vfs(
    memprocfs_root: Path,
    pid: str,
    tid: str,
    ethread_csv: str,
) -> VfsStatus:
    """Confirm CSV ETHREAD matches pid/<PID>/threads/<TID>/info.txt."""
    if not pid or not tid:
        return "no_vfs_thread"

    info_path = Path(memprocfs_root) / "pid" / pid / "threads" / tid / "info.txt"
    if not info_path.is_file():
        return "no_vfs_thread"

    ethread_vfs = parse_info_txt_ethread(info_path)
    if ethread_vfs is None:
        return "no_vfs_thread"

    if normalize_hex_address(ethread_csv) != normalize_hex_address(ethread_vfs):
        return "ethread_mismatch"
    return "ok"


class ThreadsExtractor(BaseExtractor):
    name = "threads"
    output_filename = "threads.csv"
    source = "forensic_csv"

    def __init__(self, *, allow_csv_only: bool = False) -> None:
        self.allow_csv_only = allow_csv_only

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

        module_index = self._build_module_index(root)
        status_counts: Counter[str] = Counter()

        output_headers = fieldnames + [
            h for h in START_MODULE_HEADERS if h not in fieldnames
        ]
        output_rows: list[list[str]] = []

        for row in source_rows:
            pid = self._cell(row, "PID", "pid").strip()
            tid = self._cell(row, "TID", "tid").strip()
            ethread = self._cell(row, "ETHREAD", "ethread").strip()

            module_name = ""
            module_path = ""
            module_base = ""

            if not self.allow_csv_only:
                vfs_status = verify_thread_vfs(root, pid, tid, ethread)
                if vfs_status != "ok":
                    status = vfs_status
                else:
                    address = resolve_thread_start_address(
                        self._cell(row, "StartAddress", "start_address"),
                        self._cell(row, "Win32StartAddress", "win32_start_address"),
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
                    self._cell(row, "StartAddress", "start_address"),
                    self._cell(row, "Win32StartAddress", "win32_start_address"),
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
                if header in fieldnames:
                    out_row[fieldnames.index(header)] = derived[header]
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

"""Adapt MemProcFS module / DLL listings into canonical MemFlow dlls.csv.

Primary input is ``modules.csv`` (MemProcFS forensic export). ``dlls.csv`` is
used only when ``modules.csv`` is absent (legacy or custom trees).

``module_type`` is derived from MemProcFS ``Name`` prefixes when the source
row has no ``module_type`` column. ``entry_point_rva`` (and empty absolute
``entry_point``) are filled from optional dump PE enrichment when
``dump_path`` is supplied. Intentional blanks from native ``modules.csv``:
``pe_timedatestamp`` / ``pe_checksum`` (not in the standard module table).
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult
from extractors.module_type import parse_module_type

logger = logging.getLogger(__name__)

_COL_PID = 0
_COL_BASE = 4
_COL_ENTRY = 6
_COL_ENTRY_RVA = 7


def parse_address(value: str | None) -> int | None:
    """Parse a MemProcFS-style address string into an integer, or return None.

    Digit-only hex without ``0x`` (e.g. ``77000000``) is treated as hex, matching
    MemFlow DLL enrichment key matching. Do not reuse pid_ownership.parse_address.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if all(ch in "0123456789abcdefABCDEF" for ch in text):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _parse_pid(value: str) -> int | None:
    text = value.strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def format_address(value: int) -> str:
    """Format an absolute virtual address for canonical dlls.csv output."""
    return f"0x{value:016x}"


def format_rva(value: int) -> str:
    """Format a PE entry-point RVA (offset from module base)."""
    return f"0x{value:x}"


def merge_enrichment_rows(
    rows: list[list[str]],
    enrichment: dict[tuple[int, int], Any],
) -> tuple[list[list[str]], dict[str, int]]:
    """Fill empty entry_point / entry_point_rva from dump enrichment.

    Does not write pe_timedatestamp or pe_checksum.
    """
    stats = {"matched": 0, "entry_point": 0, "entry_point_rva": 0}

    for row in rows:
        pid = _parse_pid(row[_COL_PID])
        base = parse_address(row[_COL_BASE])
        if pid is None or base is None:
            continue

        item = enrichment.get((pid, base))
        if item is None:
            continue

        stats["matched"] += 1

        rva = getattr(item, "entry_point_rva", None)
        if not row[_COL_ENTRY_RVA].strip() and rva is not None:
            row[_COL_ENTRY_RVA] = format_rva(rva)
            stats["entry_point_rva"] += 1

        if not row[_COL_ENTRY].strip():
            absolute = getattr(item, "entry_point", None)
            if absolute is None and rva is not None and rva != 0:
                absolute = base + rva
            if absolute is not None:
                row[_COL_ENTRY] = format_address(absolute)
                stats["entry_point"] += 1

    return rows, stats


class DllsExtractor(BaseExtractor):
    name = "dlls"
    output_filename = "dlls.csv"
    source = "forensic_csv"

    HEADERS = [
        "pid", "process_name", "module_name", "module_path",
        "base_address", "size", "entry_point", "entry_point_rva",
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
        module_name = self._cell(row, "module_name", "Name", "name").strip()
        module_type = self._cell(row, "module_type").strip()
        if not module_type:
            module_type = parse_module_type(module_name)

        return [
            self._cell(row, "pid", "PID").strip(),
            self._cell(row, "process_name", "Process", "process").strip(),
            module_name,
            self._first_path(row),
            self._cell(row, "base_address", "Start", "base", "Base").strip(),
            self._cell(row, "size", "Size").strip(),
            self._cell(row, "entry_point", "entry", "Entry").strip(),
            self._cell(
                row,
                "entry_point_rva",
                "AddressOfEntryPoint",
                "address_of_entry_point",
            ).strip(),
            self._cell(row, "is_wow64", "Wow64", "wow64").strip(),
            module_type,
            self._cell(row, "pe_timedatestamp", "timedatestamp", "TimeDateStamp").strip(),
            self._cell(row, "pe_checksum", "checksum", "Checksum").strip(),
        ]

    def _collect_valid_pids(self, rows: list[list[str]]) -> set[int]:
        pids: set[int] = set()
        for row in rows:
            pid = _parse_pid(row[_COL_PID])
            if pid is not None:
                pids.add(pid)
        return pids

    def _load_enrichment(
        self,
        dump_path: Path,
        rows: list[list[str]],
    ) -> dict[tuple[int, int], Any]:
        from extractors.module_pe_enrichment import load_enrichment_from_dump

        valid_pids = self._collect_valid_pids(rows)
        return load_enrichment_from_dump(dump_path, pids=valid_pids)

    def extract(
        self,
        memprocfs_root: Any,
        out_dir: Path,
        dump_path: Path | None = None,
    ) -> ExtractResult:
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

        if dump_path is not None:
            enrichment: dict[tuple[int, int], Any] = {}
            try:
                enrichment = self._load_enrichment(dump_path, rows)
            except Exception as exc:
                logger.warning(
                    "DLL entry-point enrichment failed for dump %s: %s",
                    dump_path,
                    exc,
                )
            rows, stats = merge_enrichment_rows(rows, enrichment)
            logger.info(
                "DLL enrichment: matched=%d/%d, entry_point=%d, entry_point_rva=%d",
                stats["matched"],
                len(rows),
                stats["entry_point"],
                stats["entry_point_rva"],
            )

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

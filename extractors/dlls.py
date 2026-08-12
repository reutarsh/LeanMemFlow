"""Adapt MemProcFS module / DLL listings into canonical MemFlow dlls.csv.

Primary input is ``modules.csv`` (MemProcFS forensic export). ``dlls.csv`` is
used only when ``modules.csv`` is absent (legacy or custom trees).

``module_type`` is derived from MemProcFS ``Name`` prefixes when the source
row has no ``module_type`` column. ``entry_point_rva``, empty absolute
``entry_point``, empty ``pe_timedatestamp`` / ``pe_timedatestamp_utc``, and
empty ``pe_checksum`` are filled from optional dump PE enrichment when
``dump_path`` is supplied.
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult
from extractors.module_type import parse_module_type

logger = logging.getLogger(__name__)

_COL_PID = 0
_COL_BASE = 4
_COL_ENTRY = 6
_COL_ENTRY_RVA = 7
_COL_TIMESTAMP = 10
_COL_TIMESTAMP_UTC = 11
_COL_CHECKSUM = 12


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


def format_pe_timedatestamp_utc(value: int | str | None) -> str:
    """Format PE ``TimeDateStamp`` Unix seconds as ``YYYY-MM-DD HH:MM:SS`` UTC.

    Returns empty for blank, non-positive, or unparseable values (``0`` means unset).
    """
    if value is None:
        return ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        try:
            if text.lower().startswith("0x"):
                ts = int(text, 16)
            else:
                ts = int(text, 10)
        except ValueError:
            return ""
    else:
        try:
            ts = int(value)
        except (TypeError, ValueError):
            return ""
    if ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def merge_enrichment_rows(
    rows: list[list[str]],
    enrichment: dict[tuple[int, int], Any],
) -> tuple[list[list[str]], dict[str, int]]:
    """Fill empty entry_point / entry_point_rva / PE stamp fields from dump enrichment.

    ``0`` is valid for pe_timedatestamp and pe_checksum and is written.
    pe_timedatestamp_utc is derived when empty; ``0`` leaves the date blank.
    """
    stats = {
        "matched": 0,
        "entry_point": 0,
        "entry_point_rva": 0,
        "pe_timedatestamp": 0,
        "pe_checksum": 0,
    }

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

        timestamp = getattr(item, "pe_timedatestamp", None)
        if not row[_COL_TIMESTAMP].strip() and timestamp is not None:
            row[_COL_TIMESTAMP] = str(timestamp)
            stats["pe_timedatestamp"] += 1

        if not row[_COL_TIMESTAMP_UTC].strip() and row[_COL_TIMESTAMP].strip():
            row[_COL_TIMESTAMP_UTC] = format_pe_timedatestamp_utc(row[_COL_TIMESTAMP])

        checksum = getattr(item, "pe_checksum", None)
        if not row[_COL_CHECKSUM].strip() and checksum is not None:
            row[_COL_CHECKSUM] = str(checksum)
            stats["pe_checksum"] += 1

    return rows, stats


class DllsExtractor(BaseExtractor):
    name = "dlls"
    output_filename = "dlls.csv"
    source = "forensic_csv"

    HEADERS = [
        "pid", "process_name", "module_name", "module_path",
        "base_address", "size", "entry_point", "entry_point_rva",
        "is_wow64", "module_type", "pe_timedatestamp", "pe_timedatestamp_utc",
        "pe_checksum",
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

        timestamp = self._cell(
            row, "pe_timedatestamp", "timedatestamp", "TimeDateStamp"
        ).strip()
        timestamp_utc = self._cell(
            row, "pe_timedatestamp_utc", "timedatestamp_utc"
        ).strip()
        if not timestamp_utc and timestamp:
            timestamp_utc = format_pe_timedatestamp_utc(timestamp)

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
            timestamp,
            timestamp_utc,
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
                    "DLL PE enrichment failed for dump %s: %s",
                    dump_path,
                    exc,
                )
            rows, stats = merge_enrichment_rows(rows, enrichment)
            logger.info(
                "DLL enrichment: matched=%d/%d, entry_point=%d, "
                "entry_point_rva=%d, pe_timedatestamp=%d, pe_checksum=%d",
                stats["matched"],
                len(rows),
                stats["entry_point"],
                stats["entry_point_rva"],
                stats["pe_timedatestamp"],
                stats["pe_checksum"],
            )

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

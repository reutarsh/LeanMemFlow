"""Parse MemProcFS timeline_process Text field and enrich extracted CSV.

Pad is unused CSV line padding from MemProcFS m_fc_csv.c
(M_FcCSV_ReadTimeline2 writes Pad as fixed-width spaces via "%*s" with "").
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_PROCESS_FILENAME = "timeline_process.csv"

GENERIC_TO_SEMANTIC: dict[str, str] = {
    "Value32": "PPID",
    "Value64": "EprocessVirtualAddress",
    "Text": "ProcessDescription",
}

GENERIC_HEADERS: frozenset[str] = frozenset(GENERIC_TO_SEMANTIC)
DROPPED_HEADERS: frozenset[str] = frozenset({"Pad"})

TIMELINE_PROCESS_GENERIC_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "Value32",
    "Value64",
    "Text",
    "Pad",
)

TIMELINE_PROCESS_DERIVED_COLUMNS: tuple[str, ...] = (
    "ProcessName",
    "Account",
    "KernelPath",
)

TIMELINE_PROCESS_OUTPUT_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "PPID",
    "EprocessVirtualAddress",
    *TIMELINE_PROCESS_DERIVED_COLUMNS,
    "ProcessDescription",
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_PROCESS_NATIVE_HEADERS = TIMELINE_PROCESS_GENERIC_HEADERS
TIMELINE_PROCESS_SEMANTIC_HEADERS = TIMELINE_PROCESS_OUTPUT_HEADERS

_TIMELINE_PROCESS_TEXT_RE = re.compile(
    r"^(?P<process_name>.*?) \[(?P<account>[^\]]*)\](?: (?P<kernel_path>.*))?$"
)


def convert_ppid_to_decimal(value: str) -> str:
    """Convert a PPID cell to a decimal string; preserve the original on failure."""
    if not value:
        return value

    stripped = value.strip()
    if not stripped:
        return value

    try:
        if stripped.lower().startswith("0x"):
            return str(int(stripped, 16))
        return str(int(stripped, 10))
    except ValueError:
        return value


def parse_timeline_process_text(text: str) -> tuple[str, str, str]:
    """Return (ProcessName, Account, KernelPath) parsed from MemProcFS Text.

    Never raises. On empty or unrecognized input returns three empty strings.
    """
    if not text:
        return "", "", ""

    match = _TIMELINE_PROCESS_TEXT_RE.fullmatch(text)
    if match is None:
        return "", "", ""

    return (
        match.group("process_name"),
        match.group("account"),
        match.group("kernel_path") or "",
    )


def _already_enriched(headers: list[str]) -> bool:
    if list(headers) != list(TIMELINE_PROCESS_OUTPUT_HEADERS):
        return False
    return not any(header in headers for header in GENERIC_HEADERS | DROPPED_HEADERS)


def _cell(header_index: dict[str, int], row: list[str], *names: str) -> str:
    for name in names:
        idx = header_index.get(name)
        if idx is not None and idx < len(row):
            return row[idx]
    return ""


def enrich_timeline_process_csv(csv_path: Path) -> int:
    """Read case timeline_process.csv, emit semantic columns, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic and derived columns already present in %s",
            csv_path,
        )
        return table.row_count

    header_index = {header: idx for idx, header in enumerate(table.headers)}
    output_rows: list[list[str]] = []

    for row_idx, row in enumerate(table.rows):
        process_description = _cell(
            header_index, row, "ProcessDescription", "Text"
        )
        ppid = convert_ppid_to_decimal(
            _cell(header_index, row, "PPID", "Value32")
        )
        process_name, account, kernel_path = parse_timeline_process_text(
            process_description
        )
        if process_description and not process_name and not account and not kernel_path:
            logger.debug(
                "timeline_process ProcessDescription parse miss row %d: %r",
                row_idx,
                process_description,
            )
            process_name = _cell(header_index, row, "ProcessName") or process_name
            account = _cell(header_index, row, "Account") or account
            kernel_path = _cell(header_index, row, "KernelPath") or kernel_path

        output_rows.append(
            [
                _cell(header_index, row, "Time"),
                _cell(header_index, row, "Type"),
                _cell(header_index, row, "Action"),
                _cell(header_index, row, "PID"),
                ppid,
                _cell(header_index, row, "EprocessVirtualAddress", "Value64"),
                process_name,
                account,
                kernel_path,
                process_description,
            ]
        )

    enriched = RawTable(
        source_path=csv_path,
        headers=list(TIMELINE_PROCESS_OUTPUT_HEADERS),
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    write_csv_safe(enriched, csv_path)
    return enriched.row_count

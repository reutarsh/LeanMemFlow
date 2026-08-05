"""Parse MemProcFS timeline_process Text field and enrich extracted CSV."""

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

TIMELINE_PROCESS_SEMANTIC_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "PPID",
    "EprocessVirtualAddress",
    "ProcessDescription",
    "Pad",
)

TIMELINE_PROCESS_DERIVED_COLUMNS: tuple[str, ...] = (
    "ProcessName",
    "Account",
    "KernelPath",
)

TIMELINE_PROCESS_OUTPUT_HEADERS: tuple[str, ...] = (
    *TIMELINE_PROCESS_SEMANTIC_HEADERS,
    *TIMELINE_PROCESS_DERIVED_COLUMNS,
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_PROCESS_NATIVE_HEADERS = TIMELINE_PROCESS_GENERIC_HEADERS

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


def _derived_columns_present(headers: list[str]) -> bool:
    return all(col in headers for col in TIMELINE_PROCESS_DERIVED_COLUMNS)


def _semantic_headers_present(headers: list[str]) -> bool:
    return all(
        col in headers
        for col in ("PPID", "EprocessVirtualAddress", "ProcessDescription")
    )


def _already_enriched(headers: list[str]) -> bool:
    if any(header in GENERIC_HEADERS for header in headers):
        return False
    if not _semantic_headers_present(headers):
        return False
    return _derived_columns_present(headers)


def _build_output_headers(headers: list[str]) -> list[str]:
    renamed = [GENERIC_TO_SEMANTIC.get(header, header) for header in headers]

    if "ProcessDescription" not in renamed and "Text" not in headers:
        if "Pad" in renamed:
            renamed.insert(renamed.index("Pad"), "ProcessDescription")
        else:
            renamed.append("ProcessDescription")

    for column in TIMELINE_PROCESS_DERIVED_COLUMNS:
        if column not in renamed:
            renamed.append(column)

    return renamed


def enrich_timeline_process_csv(csv_path: Path) -> int:
    """Read case timeline_process.csv, rename headers, append derived columns, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic and derived columns already present in %s",
            csv_path,
        )
        return table.row_count

    output_headers = _build_output_headers(table.headers)
    ppid_idx = output_headers.index("PPID")
    process_description_idx = output_headers.index("ProcessDescription")
    output_rows: list[list[str]] = []

    for row_idx, row in enumerate(table.rows):
        output_row = [""] * len(output_headers)

        for src_idx, header in enumerate(table.headers):
            dst_name = GENERIC_TO_SEMANTIC.get(header, header)
            if dst_name in output_headers:
                dst_idx = output_headers.index(dst_name)
                output_row[dst_idx] = row[src_idx] if src_idx < len(row) else ""

        output_row[ppid_idx] = convert_ppid_to_decimal(output_row[ppid_idx])

        text = output_row[process_description_idx]
        process_name, account, kernel_path = parse_timeline_process_text(text)
        if text and not process_name and not account and not kernel_path:
            logger.debug(
                "timeline_process ProcessDescription parse miss row %d: %r",
                row_idx,
                text,
            )

        for column, value in zip(
            TIMELINE_PROCESS_DERIVED_COLUMNS,
            (process_name, account, kernel_path),
        ):
            output_row[output_headers.index(column)] = value

        output_rows.append(output_row)

    enriched = RawTable(
        source_path=csv_path,
        headers=output_headers,
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    write_csv_safe(enriched, csv_path)
    return enriched.row_count

"""Transform MemProcFS timeline_thread.csv into semantic case-output schema."""

from __future__ import annotations

import logging
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_THREAD_FILENAME = "timeline_thread.csv"

GENERIC_TO_SEMANTIC: dict[str, str] = {
    "Value32": "TID",
    "Value64": "EThreadAddress",
    "Text": "ThreadInfo",
}

GENERIC_HEADERS: frozenset[str] = frozenset(GENERIC_TO_SEMANTIC)

TIMELINE_THREAD_GENERIC_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "Value32",
    "Value64",
    "Text",
    "Pad",
)

TIMELINE_THREAD_OUTPUT_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "TID",
    "EThreadAddress",
    "ThreadInfo",
    "Pad",
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_THREAD_NATIVE_HEADERS = TIMELINE_THREAD_GENERIC_HEADERS


def convert_tid_to_decimal(value: str) -> str:
    """Convert a TID cell to a decimal string; preserve the original on failure."""
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


def _semantic_headers_present(headers: list[str]) -> bool:
    return all(
        column in headers
        for column in ("TID", "EThreadAddress", "ThreadInfo")
    )


def _already_enriched(headers: list[str]) -> bool:
    if any(header in GENERIC_HEADERS for header in headers):
        return False
    return _semantic_headers_present(headers)


def _build_output_headers(headers: list[str]) -> list[str]:
    renamed = [GENERIC_TO_SEMANTIC.get(header, header) for header in headers]

    if "ThreadInfo" not in renamed and "Text" not in headers:
        if "Pad" in renamed:
            renamed.insert(renamed.index("Pad"), "ThreadInfo")
        else:
            renamed.append("ThreadInfo")

    return renamed


def enrich_timeline_thread_csv(csv_path: Path) -> int:
    """Read case timeline_thread.csv, rename headers, convert TID, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic thread headers already present in %s",
            csv_path,
        )
        return table.row_count

    output_headers = _build_output_headers(table.headers)
    tid_idx = output_headers.index("TID")
    output_rows: list[list[str]] = []

    for row in table.rows:
        output_row = [""] * len(output_headers)

        for src_idx, header in enumerate(table.headers):
            dst_name = GENERIC_TO_SEMANTIC.get(header, header)
            if dst_name in output_headers:
                dst_idx = output_headers.index(dst_name)
                output_row[dst_idx] = row[src_idx] if src_idx < len(row) else ""

        output_row[tid_idx] = convert_tid_to_decimal(output_row[tid_idx])
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

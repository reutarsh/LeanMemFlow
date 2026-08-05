"""Append KernelObjectPath (= Text) to extracted timeline_kernelobject.csv."""

from __future__ import annotations

import logging
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_KERNELOBJECT_FILENAME = "timeline_kernelobject.csv"

TIMELINE_KERNELOBJECT_NATIVE_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "Value32",
    "Value64",
    "Text",
    "Pad",
)
TIMELINE_KERNELOBJECT_DERIVED_COLUMNS: tuple[str, ...] = (
    "KernelObjectPath",
)
TIMELINE_KERNELOBJECT_OUTPUT_HEADERS: tuple[str, ...] = (
    *TIMELINE_KERNELOBJECT_NATIVE_HEADERS,
    *TIMELINE_KERNELOBJECT_DERIVED_COLUMNS,
)


def _derived_columns_present(headers: list[str]) -> bool:
    return all(col in headers for col in TIMELINE_KERNELOBJECT_DERIVED_COLUMNS)


def enrich_timeline_kernelobject_csv(csv_path: Path) -> int:
    """Read case timeline_kernelobject.csv, append KernelObjectPath (= Text), rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _derived_columns_present(table.headers):
        logger.debug("Skipping enrichment; derived columns already present in %s", csv_path)
        return table.row_count

    text_idx = table.headers.index("Text") if "Text" in table.headers else None
    output_headers = list(table.headers) + list(TIMELINE_KERNELOBJECT_DERIVED_COLUMNS)
    output_rows: list[list[str]] = []

    for row in table.rows:
        output_row = list(row)
        text = output_row[text_idx] if text_idx is not None and text_idx < len(output_row) else ""
        output_row.append(text)
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

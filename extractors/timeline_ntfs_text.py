"""Transform MemProcFS timeline_ntfs.csv into semantic case-output schema."""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_NTFS_FILENAME = "timeline_ntfs.csv"

TIMELINE_NTFS_GENERIC_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "Value32",
    "Value64",
    "Text",
    "Pad",
)

GENERIC_TO_SEMANTIC: dict[str, str] = {
    "Value32": "FileSize",
    "Value64": "MftRecordPhysicalAddress",
    "Text": "NtfsPath",
}

GENERIC_HEADERS: frozenset[str] = frozenset(GENERIC_TO_SEMANTIC)

DROPPED_HEADERS: frozenset[str] = frozenset({"PID", "Pad"})

TIMELINE_NTFS_OUTPUT_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "FileSize",
    "MftRecordPhysicalAddress",
    "NtfsPath",
)


def _already_enriched(headers: list[str]) -> bool:
    if list(headers) != list(TIMELINE_NTFS_OUTPUT_HEADERS):
        return False
    return not any(header in headers for header in GENERIC_HEADERS | DROPPED_HEADERS)


def _get_cell(header_index: dict[str, int], row: list[str], *names: str) -> str:
    fallback = ""

    for name in names:
        idx = header_index.get(name)
        if idx is None or idx >= len(row):
            continue

        value = row[idx]

        if fallback == "":
            fallback = value

        if value != "":
            return value

    return fallback


def _write_enriched_csv(table: RawTable, csv_path: Path) -> None:
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=csv_path.parent,
        prefix=f".{csv_path.name}.",
        suffix=".tmp",
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        write_csv_safe(table, tmp_path)
        os.replace(tmp_path, csv_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def enrich_timeline_ntfs_csv(csv_path: Path) -> int:
    """Read case timeline_ntfs.csv, emit semantic columns, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic NTFS headers already present in %s",
            csv_path,
        )
        return table.row_count

    header_index = {header: idx for idx, header in enumerate(table.headers)}
    output_rows: list[list[str]] = []

    for row in table.rows:
        output_rows.append(
            [
                _get_cell(header_index, row, "Time"),
                _get_cell(header_index, row, "Type"),
                _get_cell(header_index, row, "Action"),
                _get_cell(header_index, row, "FileSize", "Value32"),
                _get_cell(header_index, row, "MftRecordPhysicalAddress", "Value64"),
                _get_cell(header_index, row, "NtfsPath", "Text"),
            ]
        )

    enriched = RawTable(
        source_path=csv_path,
        headers=list(TIMELINE_NTFS_OUTPUT_HEADERS),
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    _write_enriched_csv(enriched, csv_path)
    return enriched.row_count

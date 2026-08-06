"""Transform MemProcFS timeline_kernelobject.csv into semantic case-output schema.

MemProcFS evidence (do not drop fields without this kind of confirmation):
- Wiki FS_Forensic_Timeline: for type KObj, NUM is unused; HEX is Object address.
- Source m_sys_obj.c MSysObj_Timeline:
  pfnAddEntry(..., dwPID=0, dwData32=0, qwData64=pe->va, uszText=uszPath)
  so PID and Value32 are always zero; Value64 is the object VA; Text is the path.
"""

from __future__ import annotations

import logging
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_KERNELOBJECT_FILENAME = "timeline_kernelobject.csv"

TIMELINE_KERNELOBJECT_GENERIC_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "Value32",
    "Value64",
    "Text",
    "Pad",
)

# Always zero in MSysObj_Timeline; Pad is unused CSV padding (not in timeline format).
DROPPED_GENERIC_HEADERS: frozenset[str] = frozenset(
    {"PID", "Value32", "Value64", "Text", "Pad"}
)

TIMELINE_KERNELOBJECT_OUTPUT_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "ObjectAddress",
    "KernelObjectPath",
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_KERNELOBJECT_NATIVE_HEADERS = TIMELINE_KERNELOBJECT_GENERIC_HEADERS
TIMELINE_KERNELOBJECT_DERIVED_COLUMNS: tuple[str, ...] = (
    "ObjectAddress",
    "KernelObjectPath",
)


def _already_enriched(headers: list[str]) -> bool:
    if list(headers) != list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS):
        return False
    return not any(header in headers for header in DROPPED_GENERIC_HEADERS)


def _is_unexpected_nonzero(value: str) -> bool:
    if not value:
        return False

    stripped = value.strip()
    if not stripped:
        return False
    if stripped in {"0", "0x0"}:
        return False

    try:
        if stripped.lower().startswith("0x"):
            return int(stripped, 16) != 0
        return int(stripped, 10) != 0
    except ValueError:
        return True


def _warn_unexpected_generic_values(
    row_idx: int,
    headers: list[str],
    row: list[str],
) -> None:
    for column in ("PID", "Value32"):
        if column not in headers:
            continue
        idx = headers.index(column)
        value = row[idx] if idx < len(row) else ""
        if _is_unexpected_nonzero(value):
            logger.warning(
                "timeline_kernelobject row %d has unexpected nonzero %s=%r; "
                "dropping from case output (MemProcFS MSysObj_Timeline always passes 0)",
                row_idx,
                column,
                value,
            )


def _cell(header_index: dict[str, int], row: list[str], *names: str) -> str:
    for name in names:
        idx = header_index.get(name)
        if idx is not None and idx < len(row):
            return row[idx]
    return ""


def enrich_timeline_kernelobject_csv(csv_path: Path) -> int:
    """Read case timeline_kernelobject.csv, emit semantic columns, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic kernelobject headers already present in %s",
            csv_path,
        )
        return table.row_count

    header_index = {header: idx for idx, header in enumerate(table.headers)}
    output_rows: list[list[str]] = []

    for row_idx, row in enumerate(table.rows):
        _warn_unexpected_generic_values(row_idx, table.headers, row)
        output_rows.append(
            [
                _cell(header_index, row, "Time"),
                _cell(header_index, row, "Type"),
                _cell(header_index, row, "Action"),
                _cell(header_index, row, "ObjectAddress", "Value64"),
                _cell(header_index, row, "KernelObjectPath", "Text"),
            ]
        )

    enriched = RawTable(
        source_path=csv_path,
        headers=list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS),
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    write_csv_safe(enriched, csv_path)
    return enriched.row_count

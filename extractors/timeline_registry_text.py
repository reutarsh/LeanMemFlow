"""Transform MemProcFS timeline_registry.csv into semantic case-output schema."""

from __future__ import annotations

import logging
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_REGISTRY_FILENAME = "timeline_registry.csv"

TIMELINE_REGISTRY_GENERIC_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    "Value32",
    "Value64",
    "Text",
    "Pad",
)

DROPPED_GENERIC_HEADERS: frozenset[str] = frozenset(
    {"PID", "Value32", "Value64", "Text"}
)

TIMELINE_REGISTRY_OUTPUT_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "RegistryPath",
    "Pad",
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_REGISTRY_NATIVE_HEADERS = TIMELINE_REGISTRY_GENERIC_HEADERS
TIMELINE_REGISTRY_DERIVED_COLUMNS: tuple[str, ...] = ("RegistryPath",)


def _already_enriched(headers: list[str]) -> bool:
    if list(headers) != list(TIMELINE_REGISTRY_OUTPUT_HEADERS):
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
    for column in ("PID", "Value32", "Value64"):
        if column not in headers:
            continue
        idx = headers.index(column)
        value = row[idx] if idx < len(row) else ""
        if _is_unexpected_nonzero(value):
            logger.warning(
                "timeline_registry row %d has unexpected nonzero %s=%r; dropping from case output",
                row_idx,
                column,
                value,
            )


def enrich_timeline_registry_csv(csv_path: Path) -> int:
    """Read case timeline_registry.csv, emit semantic columns, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic registry headers already present in %s",
            csv_path,
        )
        return table.row_count

    header_index = {header: idx for idx, header in enumerate(table.headers)}
    text_idx = header_index.get("Text")
    registry_path_idx = header_index.get("RegistryPath")
    output_rows: list[list[str]] = []

    for row_idx, row in enumerate(table.rows):
        _warn_unexpected_generic_values(row_idx, table.headers, row)

        registry_path = ""
        if text_idx is not None and text_idx < len(row):
            registry_path = row[text_idx]
        elif registry_path_idx is not None and registry_path_idx < len(row):
            registry_path = row[registry_path_idx]

        output_rows.append(
            [
                row[header_index["Time"]] if "Time" in header_index and header_index["Time"] < len(row) else "",
                row[header_index["Type"]] if "Type" in header_index and header_index["Type"] < len(row) else "",
                row[header_index["Action"]] if "Action" in header_index and header_index["Action"] < len(row) else "",
                registry_path,
                row[header_index["Pad"]] if "Pad" in header_index and header_index["Pad"] < len(row) else "",
            ]
        )

    enriched = RawTable(
        source_path=csv_path,
        headers=list(TIMELINE_REGISTRY_OUTPUT_HEADERS),
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    write_csv_safe(enriched, csv_path)
    return enriched.row_count

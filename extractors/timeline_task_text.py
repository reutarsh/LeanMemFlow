"""Transform MemProcFS timeline_task.csv into semantic case-output schema."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_TASK_FILENAME = "timeline_task.csv"

TIMELINE_TASK_GENERIC_HEADERS: tuple[str, ...] = (
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

TIMELINE_TASK_OUTPUT_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "TaskDescription",
    "Pad",
    "TaskName",
    "CommandLine",
    "Parameters",
    "User",
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_TASK_NATIVE_HEADERS = TIMELINE_TASK_GENERIC_HEADERS
TIMELINE_TASK_DERIVED_COLUMNS: tuple[str, ...] = (
    "TaskName",
    "CommandLine",
    "Parameters",
    "User",
)

_TIMELINE_TASK_TEXT_RE = re.compile(
    r"^(?P<task_name>.*?) - \[(?P<command_line>.*?) :: (?P<parameters>.*)\] \((?P<user>.*)\)$"
)


def parse_timeline_task_text(text: str) -> tuple[str, str, str, str]:
    """Return (TaskName, CommandLine, Parameters, User) parsed from MemProcFS Text.

    Never raises. On empty or unrecognized input returns four empty strings.
    """
    if not text:
        return "", "", "", ""

    match = _TIMELINE_TASK_TEXT_RE.fullmatch(text)
    if match is None:
        return "", "", "", ""

    return (
        match.group("task_name"),
        match.group("command_line"),
        match.group("parameters"),
        match.group("user"),
    )


def _already_enriched(headers: list[str]) -> bool:
    return (
        not any(header in headers for header in DROPPED_GENERIC_HEADERS)
        and all(header in headers for header in TIMELINE_TASK_OUTPUT_HEADERS)
    )


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
                "timeline_task row %d has unexpected nonzero %s=%r; dropping from case output",
                row_idx,
                column,
                value,
            )


def enrich_timeline_task_csv(csv_path: Path) -> int:
    """Read case timeline_task.csv, copy Text to TaskDescription, parse, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic task headers already present in %s",
            csv_path,
        )
        return table.row_count

    header_index = {header: idx for idx, header in enumerate(table.headers)}
    text_idx = header_index.get("Text")
    task_description_idx = header_index.get("TaskDescription")
    output_rows: list[list[str]] = []
    parse_miss_count = 0

    for row_idx, row in enumerate(table.rows):
        _warn_unexpected_generic_values(row_idx, table.headers, row)

        task_description = ""
        if text_idx is not None and text_idx < len(row):
            task_description = row[text_idx]
        elif task_description_idx is not None and task_description_idx < len(row):
            task_description = row[task_description_idx]

        task_name, command_line, parameters, user = parse_timeline_task_text(task_description)
        if task_description and not any((task_name, command_line, parameters, user)):
            parse_miss_count += 1

        output_rows.append(
            [
                row[header_index["Time"]] if "Time" in header_index and header_index["Time"] < len(row) else "",
                row[header_index["Type"]] if "Type" in header_index and header_index["Type"] < len(row) else "",
                row[header_index["Action"]] if "Action" in header_index and header_index["Action"] < len(row) else "",
                task_description,
                row[header_index["Pad"]] if "Pad" in header_index and header_index["Pad"] < len(row) else "",
                task_name,
                command_line,
                parameters,
                user,
            ]
        )

    if parse_miss_count:
        logger.debug(
            "timeline_task TaskDescription parse miss: %d row(s) in %s",
            parse_miss_count,
            csv_path,
        )

    enriched = RawTable(
        source_path=csv_path,
        headers=list(TIMELINE_TASK_OUTPUT_HEADERS),
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    write_csv_safe(enriched, csv_path)
    return enriched.row_count

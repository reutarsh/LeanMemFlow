"""Transform MemProcFS timeline_web.csv into semantic case-output schema.

MemProcFS evidence (do not drop fields without this kind of confirmation):
- Source m_fc_web.c MWeb_FcTimeline:
  pfnAddEntry(..., dwPID=pe->dwPID, dwData32=0, qwData64=0, uszText)
  so Value32 and Value64 are always zero; PID is the browser process; Text is:
  browser:[%s] type:[%s] url:[%s] info:[%s]
- Pad is unused CSV padding (not in the timeline text format).
"""

from __future__ import annotations

import logging
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_WEB_FILENAME = "timeline_web.csv"

TIMELINE_WEB_GENERIC_HEADERS: tuple[str, ...] = (
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
    {"Value32", "Value64", "Text", "Pad"}
)

TIMELINE_WEB_DERIVED_COLUMNS: tuple[str, ...] = (
    "Browser",
    "WebAction",
    "Url",
    "Info",
)

TIMELINE_WEB_OUTPUT_HEADERS: tuple[str, ...] = (
    "Time",
    "Type",
    "Action",
    "PID",
    *TIMELINE_WEB_DERIVED_COLUMNS,
    "WebDescription",
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_WEB_NATIVE_HEADERS = TIMELINE_WEB_GENERIC_HEADERS

_PREFIX = "browser:["
_MID_TYPE = "] type:["
_MID_URL = "] url:["
_MID_INFO = "] info:["


def parse_timeline_web_text(text: str) -> tuple[str, str, str, str]:
    """Return (Browser, WebAction, Url, Info) parsed from MemProcFS Text.

    Never raises. On empty or unrecognized input returns four empty strings.
    """
    if not text:
        return "", "", "", ""

    if not text.startswith(_PREFIX) or not text.endswith("]"):
        return "", "", "", ""

    rest = text[len(_PREFIX) : -1]

    i_type = rest.find(_MID_TYPE)
    if i_type < 0:
        return "", "", "", ""
    browser = rest[:i_type]

    after_type = rest[i_type + len(_MID_TYPE) :]
    i_url = after_type.find(_MID_URL)
    if i_url < 0:
        return "", "", "", ""
    web_action = after_type[:i_url]

    after_url = after_type[i_url + len(_MID_URL) :]
    i_info = after_url.find(_MID_INFO)
    if i_info < 0:
        return "", "", "", ""
    url = after_url[:i_info]
    info = after_url[i_info + len(_MID_INFO) :]

    return browser, web_action, url, info


def _already_enriched(headers: list[str]) -> bool:
    if list(headers) != list(TIMELINE_WEB_OUTPUT_HEADERS):
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
    for column in ("Value32", "Value64"):
        if column not in headers:
            continue
        idx = headers.index(column)
        value = row[idx] if idx < len(row) else ""
        if _is_unexpected_nonzero(value):
            logger.warning(
                "timeline_web row %d has unexpected nonzero %s=%r; "
                "dropping from case output (MemProcFS MWeb_FcTimeline always passes 0)",
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


def enrich_timeline_web_csv(csv_path: Path) -> int:
    """Read case timeline_web.csv, emit semantic columns, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic web headers already present in %s",
            csv_path,
        )
        return table.row_count

    header_index = {header: idx for idx, header in enumerate(table.headers)}
    output_rows: list[list[str]] = []
    parse_miss_count = 0

    for row_idx, row in enumerate(table.rows):
        _warn_unexpected_generic_values(row_idx, table.headers, row)

        web_description = _cell(header_index, row, "WebDescription", "Text")
        if web_description:
            browser, web_action, url, info = parse_timeline_web_text(web_description)
            if not any((browser, web_action, url, info)):
                parse_miss_count += 1
        else:
            browser = _cell(header_index, row, "Browser")
            web_action = _cell(header_index, row, "WebAction")
            url = _cell(header_index, row, "Url")
            info = _cell(header_index, row, "Info")

        output_rows.append(
            [
                _cell(header_index, row, "Time"),
                _cell(header_index, row, "Type"),
                _cell(header_index, row, "Action"),
                _cell(header_index, row, "PID"),
                browser,
                web_action,
                url,
                info,
                web_description,
            ]
        )

    if parse_miss_count:
        logger.debug(
            "timeline_web WebDescription parse miss: %d row(s) in %s",
            parse_miss_count,
            csv_path,
        )

    enriched = RawTable(
        source_path=csv_path,
        headers=list(TIMELINE_WEB_OUTPUT_HEADERS),
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    write_csv_safe(enriched, csv_path)
    return enriched.row_count

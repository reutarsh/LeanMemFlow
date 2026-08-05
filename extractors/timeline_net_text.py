"""Transform MemProcFS timeline_net.csv into semantic case-output schema."""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

TIMELINE_NET_FILENAME = "timeline_net.csv"

TIMELINE_NET_GENERIC_HEADERS: tuple[str, ...] = (
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
    "Time": "ConnectionTime",
    "Value64": "KernelObjectAddress",
}

GENERIC_HEADERS: frozenset[str] = frozenset({"Time", "Value32", "Value64"})

DROPPED_HEADERS: frozenset[str] = frozenset({"Value32", "Pad"})

TIMELINE_NET_DERIVED_COLUMNS: tuple[str, ...] = (
    "Protocol",
    "State",
    "SourceAddress",
    "SourcePort",
    "DestinationAddress",
    "DestinationPort",
)

TIMELINE_NET_OUTPUT_HEADERS: tuple[str, ...] = (
    "ConnectionTime",
    "Type",
    "Action",
    "PID",
    "KernelObjectAddress",
    *TIMELINE_NET_DERIVED_COLUMNS,
    "Text",
)

# Backward compatibility for callers that referenced native MemProcFS headers.
TIMELINE_NET_NATIVE_HEADERS = TIMELINE_NET_GENERIC_HEADERS


def parse_network_endpoint(endpoint: str) -> tuple[str, str]:
    """Return (Address, Port) parsed from a MemProcFS network endpoint token.

    Never raises. On empty or unrecognized input returns two empty strings.
    """
    endpoint = endpoint.strip()

    if not endpoint or endpoint == "***":
        return "", ""

    if endpoint.startswith("["):
        close = endpoint.find("]")
        if close == -1:
            return "", ""
        if close + 1 >= len(endpoint) or endpoint[close + 1] != ":":
            return "", ""
        address = endpoint[1:close]
        port = endpoint[close + 2:]
        if not address or not port:
            return "", ""
        return address, port

    if endpoint.count(":") > 1:
        return "", ""

    address, sep, port = endpoint.partition(":")
    if not sep or not address or not port:
        return "", ""
    return address, port


def parse_timeline_net_text(text: str) -> tuple[str, str, str, str, str, str]:
    """Return six derived fields parsed from MemProcFS timeline_net Text.

    Never raises. On empty or unrecognized input returns six empty strings.
    """
    if not text:
        return "", "", "", "", "", ""

    parts = text.strip().split(None, 3)
    if len(parts) != 4:
        return "", "", "", "", "", ""

    protocol, state, source_ep, dest_ep = parts
    src_addr, src_port = parse_network_endpoint(source_ep)
    dst_addr, dst_port = parse_network_endpoint(dest_ep)
    return protocol, state, src_addr, src_port, dst_addr, dst_port


def _already_enriched(headers: list[str]) -> bool:
    if list(headers) != list(TIMELINE_NET_OUTPUT_HEADERS):
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


def _parsed_network_fields(
    header_index: dict[str, int],
    row: list[str],
    text: str,
) -> tuple[str, str, str, str, str, str]:
    if text:
        return parse_timeline_net_text(text)

    return (
        _get_cell(header_index, row, "Protocol"),
        _get_cell(header_index, row, "State"),
        _get_cell(header_index, row, "SourceAddress"),
        _get_cell(header_index, row, "SourcePort"),
        _get_cell(header_index, row, "DestinationAddress"),
        _get_cell(header_index, row, "DestinationPort"),
    )


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


def enrich_timeline_net_csv(csv_path: Path) -> int:
    """Read case timeline_net.csv, emit semantic columns, rewrite in place.

    Returns the number of data rows written.
    """
    table = read_csv_safe(csv_path)

    if _already_enriched(table.headers):
        logger.debug(
            "Skipping enrichment; semantic net headers already present in %s",
            csv_path,
        )
        return table.row_count

    header_index = {header: idx for idx, header in enumerate(table.headers)}
    output_rows: list[list[str]] = []
    parse_miss_count = 0

    for row in table.rows:
        text = _get_cell(header_index, row, "Text")
        protocol, state, src_addr, src_port, dst_addr, dst_port = _parsed_network_fields(
            header_index,
            row,
            text,
        )
        if text and not any((protocol, state, src_addr, src_port, dst_addr, dst_port)):
            parse_miss_count += 1

        output_rows.append(
            [
                _get_cell(header_index, row, "ConnectionTime", "Time"),
                _get_cell(header_index, row, "Type"),
                _get_cell(header_index, row, "Action"),
                _get_cell(header_index, row, "PID"),
                _get_cell(header_index, row, "KernelObjectAddress", "Value64"),
                protocol,
                state,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                text,
            ]
        )

    if parse_miss_count:
        logger.debug(
            "timeline_net Text parse miss: %d row(s) in %s",
            parse_miss_count,
            csv_path,
        )

    enriched = RawTable(
        source_path=csv_path,
        headers=list(TIMELINE_NET_OUTPUT_HEADERS),
        rows=output_rows,
        ingest_errors=list(table.ingest_errors),
        sha256=table.sha256,
        raw_row_count=table.raw_row_count,
    )
    _write_enriched_csv(enriched, csv_path)
    return enriched.row_count

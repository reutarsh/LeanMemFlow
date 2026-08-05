"""Tests for timeline_thread semantic schema enrichment and extraction integration."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_process_text import TIMELINE_PROCESS_GENERIC_HEADERS
from extractors.timeline_thread_text import (
    TIMELINE_THREAD_GENERIC_HEADERS,
    TIMELINE_THREAD_OUTPUT_HEADERS,
    convert_tid_to_decimal,
    enrich_timeline_thread_csv,
)
from memflow_common.csv_io import read_csv_safe

GENERIC_HEADERS = list(TIMELINE_THREAD_GENERIC_HEADERS)

THREAD_INFO = r"explorer.exe [user3] \Device\HarddiskVolume3\Windows\explorer.exe"
ETHREAD_ADDRESS = "0xFFFFFA8012345678"
HEX_TID = "0x81c"
DECIMAL_TID = "2076"
HEX_TID_2 = "0x96f4"
DECIMAL_TID_2 = "38644"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _sample_row(
    *,
    pid: str = "1234",
    value32: str = HEX_TID,
    value64: str = ETHREAD_ADDRESS,
    text: str = THREAD_INFO,
) -> list[str]:
    return [
        "2024-01-15 08:00:00",
        "THREAD",
        "Create",
        pid,
        value32,
        value64,
        text,
        "",
    ]


def _semantic_row(
    *,
    pid: str = "1234",
    tid: str = DECIMAL_TID,
    ethread_address: str = ETHREAD_ADDRESS,
    thread_info: str = THREAD_INFO,
) -> list[str]:
    return [
        "2024-01-15 08:00:00",
        "THREAD",
        "Create",
        pid,
        tid,
        ethread_address,
        thread_info,
        "",
    ]


def _cell(row: dict[str, str], *names: str) -> str:
    for name in names:
        if name in row and row[name] is not None:
            return row[name].strip()
    return ""


def _truncate(value: str, max_len: int) -> str:
    if value is None:
        return ""
    return value[:max_len] if len(value) > max_len else value


def _normalize_tid(value: str) -> str:
    """Mirror C# RowHashBuilder.NormalizeTid / NormalizePpid."""
    if not value:
        return value

    stripped = value.strip()
    if not stripped:
        return ""

    try:
        if stripped.lower().startswith("0x"):
            return str(int(stripped, 16))
        return str(int(stripped, 10))
    except ValueError:
        return stripped


def _parse_tid(value: str) -> int | None:
    """Mirror C# CsvRowMappers.ParseTid."""
    if not value or not value.strip():
        return None

    stripped = value.strip()
    try:
        if stripped.lower().startswith("0x"):
            return int(stripped, 16)
        return int(stripped, 10)
    except ValueError:
        return None


def _map_timeline_thread(row: dict[str, str]) -> dict[str, object]:
    """Mirror C# MapTimelineThread field resolution."""
    return {
        "Time": _truncate(_cell(row, "Time"), 100),
        "Type": _truncate(_cell(row, "Type"), 100),
        "Action": _truncate(_cell(row, "Action"), 100),
        "Pid": _truncate(_cell(row, "PID", "pid"), 50),
        "Tid": _parse_tid(_cell(row, "TID", "Value32")),
        "EThreadAddress": _truncate(_cell(row, "EThreadAddress", "Value64"), 100),
        "ThreadInfo": _cell(row, "ThreadInfo", "Text"),
        "Pad": _truncate(_cell(row, "Pad"), 100),
    }


def _get_row_value(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _build_timeline_thread_event_row(row: dict[str, str]) -> str:
    """Mirror C# RowHashBuilder.BuildTimelineThreadEventRow."""
    values = [
        _get_row_value(row, "Time", "time"),
        _get_row_value(row, "Type", "type"),
        _get_row_value(row, "Action", "action"),
        _get_row_value(row, "PID", "pid"),
        _normalize_tid(_get_row_value(row, "TID", "Value32")),
        _get_row_value(row, "EThreadAddress", "Value64"),
        _get_row_value(row, "ThreadInfo", "Text"),
        _get_row_value(row, "Pad"),
    ]
    joined = "||".join(values)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _row_dict(headers: list[str], values: list[str]) -> dict[str, str]:
    return dict(zip(headers, values))


class TestConvertTidToDecimal:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("0x81c", "2076"),
            ("0x96f4", "38644"),
            ("2076", "2076"),
            ("38644", "38644"),
            ("0", "0"),
            ("0x0", "0"),
        ],
    )
    def test_hex_and_decimal_conversion(self, value: str, expected: str) -> None:
        assert convert_tid_to_decimal(value) == expected

    @pytest.mark.parametrize("value", ["", "   "])
    def test_empty_values_preserved(self, value: str) -> None:
        assert convert_tid_to_decimal(value) == value

    def test_invalid_hex_preserved(self) -> None:
        assert convert_tid_to_decimal("0xZZZZ") == "0xZZZZ"

    def test_missing_prefix_hex_preserved(self) -> None:
        assert convert_tid_to_decimal("81c") == "81c"


class TestEnrichTimelineThreadCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(value32=HEX_TID, text=THREAD_INFO),
            _sample_row(value32=HEX_TID_2, text=""),
        ]

    def test_exact_final_header_order(self, tmp_path: Path, sample_rows: list[list[str]]) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_THREAD_OUTPUT_HEADERS)

    def test_tid_hex_converted_to_decimal(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(value32=HEX_TID)])

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][4] == DECIMAL_TID

    def test_second_tid_example(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(value32=HEX_TID_2)])

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][4] == DECIMAL_TID_2

    def test_ethread_address_preserved(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row()])

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][5] == ETHREAD_ADDRESS

    def test_thread_info_preserved(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row()])

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == THREAD_INFO

    def test_generic_columns_renamed(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row()])

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "Value32" not in table.headers
        assert "Value64" not in table.headers
        assert "Text" not in table.headers
        assert "TID" in table.headers
        assert "EThreadAddress" in table.headers
        assert "ThreadInfo" in table.headers

    def test_empty_thread_info(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(text="")])

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == ""

    def test_missing_text_header(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Pad"]
        rows = [["2024-01-15 08:00:00", "THREAD", "Create", "1234", HEX_TID, ETHREAD_ADDRESS, ""]]
        _write_csv(csv_path, headers, rows)

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_THREAD_OUTPUT_HEADERS)
        assert table.rows[0][4] == DECIMAL_TID
        assert table.rows[0][6] == ""

    def test_row_count_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        row_count = enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)
        assert table.rows[0][4] == DECIMAL_TID
        assert table.rows[1][4] == DECIMAL_TID_2

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_thread_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_thread_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows

    def test_already_semantic_not_rewritten(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_thread.csv"
        row = _semantic_row()
        _write_csv(csv_path, list(TIMELINE_THREAD_OUTPUT_HEADERS), [row])

        enrich_timeline_thread_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_THREAD_OUTPUT_HEADERS)
        assert table.rows[0] == row


class TestCSharpAliasParity:
    def test_generic_and_semantic_rows_map_equivalent_fields(self) -> None:
        generic = _row_dict(GENERIC_HEADERS, _sample_row())
        semantic = _row_dict(list(TIMELINE_THREAD_OUTPUT_HEADERS), _semantic_row())

        generic_mapped = _map_timeline_thread(generic)
        semantic_mapped = _map_timeline_thread(semantic)

        assert generic_mapped["Tid"] == semantic_mapped["Tid"] == 2076
        assert generic_mapped["EThreadAddress"] == semantic_mapped["EThreadAddress"]
        assert generic_mapped["ThreadInfo"] == semantic_mapped["ThreadInfo"]

    def test_generic_and_semantic_rows_hash_identically(self) -> None:
        generic = _row_dict(GENERIC_HEADERS, _sample_row())
        semantic = _row_dict(list(TIMELINE_THREAD_OUTPUT_HEADERS), _semantic_row())

        assert _build_timeline_thread_event_row(generic) == _build_timeline_thread_event_row(
            semantic
        )

    def test_parse_tid_edge_cases(self) -> None:
        assert _parse_tid("") is None
        assert _parse_tid("   ") is None
        assert _parse_tid("0x81c") == 2076
        assert _parse_tid("2076") == 2076
        assert _parse_tid("0xZZZZ") is None


class TestTimelinesExtractorIntegration:
    def test_extract_enriches_timeline_thread_and_leaves_source_unchanged(
        self, tmp_path: Path
    ) -> None:
        from extractors.timelines import TimelinesExtractor

        memprocfs_root = tmp_path / "memprocfs"
        forensic_csv = memprocfs_root / "forensic" / "csv"

        thread_source = forensic_csv / "timeline_thread.csv"
        process_source = forensic_csv / "timeline_process.csv"
        web_source = forensic_csv / "timeline_web.csv"

        _write_csv(thread_source, GENERIC_HEADERS, [_sample_row()])
        _write_csv(
            process_source,
            list(TIMELINE_PROCESS_GENERIC_HEADERS),
            [
                [
                    "2024-01-15 08:00:00",
                    "PROC",
                    "Create",
                    "1234",
                    "0",
                    "0",
                    THREAD_INFO,
                    "",
                ],
            ],
        )
        _write_csv(
            web_source,
            GENERIC_HEADERS,
            [_sample_row(text=r"\Software\Should\Not\Change")],
        )

        thread_bytes = thread_source.read_bytes()
        process_bytes = process_source.read_bytes()
        web_bytes = web_source.read_bytes()

        out_dir = tmp_path / "case" / "csv"
        out_dir.mkdir(parents=True)
        result = TimelinesExtractor().extract(memprocfs_root, out_dir)

        assert result.ok is True
        assert "timeline_thread.csv" in result.files_written

        thread = read_csv_safe(out_dir / "timeline_thread.csv")
        assert thread.headers == list(TIMELINE_THREAD_OUTPUT_HEADERS)
        assert thread.rows[0][4] == DECIMAL_TID
        assert thread.rows[0][5] == ETHREAD_ADDRESS
        assert thread.rows[0][6] == THREAD_INFO

        web = read_csv_safe(out_dir / "timeline_web.csv")
        assert web.headers == GENERIC_HEADERS
        assert web.rows[0][6] == r"\Software\Should\Not\Change"

        assert thread_source.read_bytes() == thread_bytes
        assert process_source.read_bytes() == process_bytes
        assert web_source.read_bytes() == web_bytes

    def test_thread_enrichment_skipped_when_result_not_ok(self, tmp_path: Path) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        thread_path = out_dir / "timeline_thread.csv"
        _write_csv(thread_path, GENERIC_HEADERS, [_sample_row()])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=False, error="copy failed")

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            returned = extractor.extract(tmp_path / "memprocfs", out_dir)

        assert returned.ok is False
        table = read_csv_safe(thread_path)
        assert table.headers == GENERIC_HEADERS
        assert "TID" not in table.headers

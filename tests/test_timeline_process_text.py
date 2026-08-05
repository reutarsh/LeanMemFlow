"""Tests for timeline_process Text parsing and extraction enrichment."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_process_text import (
    TIMELINE_PROCESS_DERIVED_COLUMNS,
    TIMELINE_PROCESS_GENERIC_HEADERS,
    TIMELINE_PROCESS_OUTPUT_HEADERS,
    convert_ppid_to_decimal,
    enrich_timeline_process_csv,
    parse_timeline_process_text,
)
from memflow_common.csv_io import read_csv_safe

GENERIC_HEADERS = list(TIMELINE_PROCESS_GENERIC_HEADERS)

POWERSHELL_TEXT = (
    r"powershell.exe [user3] \Device\HarddiskVolume3\Windows\System32"
    r"\WindowsPowerShell\v1.0\powershell.exe"
)
POWERSHELL_PATH = (
    r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
SVCHOST_TEXT = (
    r"svchost.exe [*SYSTEM] \Device\HarddiskVolume3\Windows\System32\svchost.exe"
)
SVCHOST_PATH = r"\Device\HarddiskVolume3\Windows\System32\svchost.exe"
EPROCESS_ADDRESS = "0xFFFFE501E8F9EE10"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _sample_row(
    *,
    pid: str = "1234",
    value32: str = "0",
    value64: str = "0",
    text: str = POWERSHELL_TEXT,
) -> list[str]:
    return [
        "2024-01-15 08:00:00",
        "PROC",
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
    ppid: str = "0",
    eprocess_address: str = "0",
    process_description: str = POWERSHELL_TEXT,
) -> list[str]:
    return [
        "2024-01-15 08:00:00",
        "PROC",
        "Create",
        pid,
        ppid,
        eprocess_address,
        process_description,
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


def _normalize_ppid(value: str) -> str:
    """Mirror C# CsvRowMappers.NormalizePpid."""
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


def _map_timeline_process(row: dict[str, str]) -> dict[str, str]:
    """Mirror C# MapTimelineProcess field resolution."""
    return {
        "Time": _truncate(_cell(row, "Time"), 100),
        "Type": _truncate(_cell(row, "Type"), 100),
        "Action": _truncate(_cell(row, "Action"), 100),
        "Pid": _truncate(_cell(row, "PID", "pid"), 50),
        "Value32": _truncate(_normalize_ppid(_cell(row, "PPID", "Value32")), 100),
        "Value64": _truncate(_cell(row, "EprocessVirtualAddress", "Value64"), 100),
        "Text": _cell(row, "ProcessDescription", "Text"),
        "Pad": _truncate(_cell(row, "Pad"), 100),
    }


def _get_row_value(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _build_timeline_process_event_row(row: dict[str, str]) -> str:
    """Mirror C# RowHashBuilder.BuildTimelineProcessEventRow."""
    values = [
        _get_row_value(row, "Time", "time"),
        _get_row_value(row, "Type", "type"),
        _get_row_value(row, "Action", "action"),
        _get_row_value(row, "PID", "pid"),
        _normalize_ppid(_get_row_value(row, "PPID", "Value32")),
        _get_row_value(row, "EprocessVirtualAddress", "Value64"),
        _get_row_value(row, "ProcessDescription", "Text"),
        _get_row_value(row, "Pad"),
    ]
    joined = "||".join(values)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _row_dict(headers: list[str], values: list[str]) -> dict[str, str]:
    return dict(zip(headers, values))


class TestConvertPpidToDecimal:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("0x4", "4"),
            ("0x2A8", "680"),
            ("680", "680"),
            ("0", "0"),
            ("", ""),
            ("  0x4  ", "4"),
            ("  680  ", "680"),
            ("not-a-number", "not-a-number"),
        ],
    )
    def test_conversion_cases(self, raw: str, expected: str) -> None:
        assert convert_ppid_to_decimal(raw) == expected


class TestParseTimelineProcessText:
    def test_normal_user_account(self) -> None:
        process_name, account, kernel_path = parse_timeline_process_text(POWERSHELL_TEXT)
        assert process_name == "powershell.exe"
        assert account == "user3"
        assert kernel_path == POWERSHELL_PATH

    def test_well_known_account(self) -> None:
        process_name, account, kernel_path = parse_timeline_process_text(SVCHOST_TEXT)
        assert process_name == "svchost.exe"
        assert account == "*SYSTEM"
        assert kernel_path == SVCHOST_PATH

    def test_account_with_space(self) -> None:
        text = r"process.exe [*LOCAL SERVICE] \Device\HarddiskVolume3\path\process.exe"
        process_name, account, kernel_path = parse_timeline_process_text(text)
        assert process_name == "process.exe"
        assert account == "*LOCAL SERVICE"
        assert kernel_path == r"\Device\HarddiskVolume3\path\process.exe"

    def test_path_with_spaces(self) -> None:
        text = (
            r"chrome.exe [user3] \Device\HarddiskVolume3\Program Files\Google"
            r"\Chrome\Application\chrome.exe"
        )
        process_name, account, kernel_path = parse_timeline_process_text(text)
        assert process_name == "chrome.exe"
        assert account == "user3"
        assert kernel_path == (
            r"\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\chrome.exe"
        )

    def test_empty_account(self) -> None:
        text = r"process.exe [] \Device\HarddiskVolume3\path\process.exe"
        process_name, account, kernel_path = parse_timeline_process_text(text)
        assert process_name == "process.exe"
        assert account == ""
        assert kernel_path == r"\Device\HarddiskVolume3\path\process.exe"

    def test_missing_path(self) -> None:
        process_name, account, kernel_path = parse_timeline_process_text("process.exe [user3]")
        assert process_name == "process.exe"
        assert account == "user3"
        assert kernel_path == ""

    def test_empty_text(self) -> None:
        assert parse_timeline_process_text("") == ("", "", "")

    def test_malformed_without_brackets(self) -> None:
        assert parse_timeline_process_text("malformed without brackets") == ("", "", "")


class TestEnrichTimelineProcessCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(text=POWERSHELL_TEXT),
            _sample_row(text=SVCHOST_TEXT, pid="5678"),
            _sample_row(text="malformed without brackets", pid="9999"),
        ]

    def test_exact_final_header_order(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_PROCESS_OUTPUT_HEADERS)

    def test_pid_unchanged(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(pid="4321")])

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][3] == "4321"

    def test_value32_becomes_ppid_decimal(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(value32="0x2A8")])

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers[4] == "PPID"
        assert table.rows[0][4] == "680"
        assert "Value32" not in table.headers

    def test_value64_becomes_eprocess_virtual_address(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(value64=EPROCESS_ADDRESS)])

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers[5] == "EprocessVirtualAddress"
        assert table.rows[0][5] == EPROCESS_ADDRESS

    def test_text_becomes_process_description(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(text=POWERSHELL_TEXT)])

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers[6] == "ProcessDescription"
        assert table.rows[0][6] == POWERSHELL_TEXT

    def test_parsed_fields(self, tmp_path: Path, sample_rows: list[list[str]]) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_process_csv(csv_path)

        table = read_csv_safe(csv_path)
        assert table.rows[0][8:] == ["powershell.exe", "user3", POWERSHELL_PATH]
        assert table.rows[1][8:] == ["svchost.exe", "*SYSTEM", SVCHOST_PATH]
        assert table.rows[2][8:] == ["", "", ""]

    def test_quoted_text_with_comma(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        text = r"proc.exe [user3] \Device\HarddiskVolume3\a,b,c"
        _write_csv(
            csv_path,
            GENERIC_HEADERS,
            [_sample_row(text=text, pid="1")],
        )

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == text
        assert table.rows[0][8:] == ["proc.exe", "user3", r"\Device\HarddiskVolume3\a,b,c"]

    def test_missing_text_header(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Pad"]
        rows = [["2024-01-15 08:00:00", "PROC", "Create", "1234", "0x4", "0", ""]]
        _write_csv(csv_path, headers, rows)

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_PROCESS_OUTPUT_HEADERS)
        assert table.rows[0][4] == "4"
        assert table.rows[0][6] == ""
        assert table.rows[0][8:] == ["", "", ""]

    def test_row_count_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        row_count = enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)

    def test_no_duplicate_columns(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row()])

        enrich_timeline_process_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert len(table.headers) == len(set(table.headers))

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_process.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_process_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_process_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows


class TestCSharpAliasParity:
    def test_generic_and_semantic_rows_map_identically(self) -> None:
        generic = _row_dict(
            GENERIC_HEADERS,
            _sample_row(value32="0x4", value64=EPROCESS_ADDRESS),
        )
        semantic = _row_dict(
            list(TIMELINE_PROCESS_OUTPUT_HEADERS[:8]),
            _semantic_row(ppid="4", eprocess_address=EPROCESS_ADDRESS),
        )

        assert _map_timeline_process(generic) == _map_timeline_process(semantic)

    def test_generic_and_semantic_rows_hash_identically(self) -> None:
        generic = _row_dict(
            GENERIC_HEADERS,
            _sample_row(value32="0x4", value64=EPROCESS_ADDRESS),
        )
        semantic = _row_dict(
            list(TIMELINE_PROCESS_OUTPUT_HEADERS[:8]),
            _semantic_row(ppid="4", eprocess_address=EPROCESS_ADDRESS),
        )

        assert _build_timeline_process_event_row(generic) == _build_timeline_process_event_row(
            semantic
        )


class TestTimelinesExtractorIntegration:
    def test_extract_enriches_timeline_process_only(self, tmp_path: Path) -> None:
        from extractors.timelines import TimelinesExtractor

        memprocfs_root = tmp_path / "memprocfs"
        forensic_csv = memprocfs_root / "forensic" / "csv"
        process_source = forensic_csv / "timeline_process.csv"
        all_source = forensic_csv / "timeline_all.csv"

        _write_csv(process_source, GENERIC_HEADERS, [_sample_row()])
        _write_csv(all_source, ["time"], [["2026-01-01"]])

        source_bytes = process_source.read_bytes()
        all_source_bytes = all_source.read_bytes()

        out_dir = tmp_path / "case" / "csv"
        out_dir.mkdir(parents=True)
        result = TimelinesExtractor().extract(memprocfs_root, out_dir)

        assert result.ok is True
        assert "timeline_process.csv" in result.files_written

        enriched = read_csv_safe(out_dir / "timeline_process.csv")
        assert enriched.headers == list(TIMELINE_PROCESS_OUTPUT_HEADERS)
        assert enriched.row_count == 1
        assert enriched.rows[0][6] == POWERSHELL_TEXT
        assert enriched.rows[0][8:] == ["powershell.exe", "user3", POWERSHELL_PATH]

        timeline_all = read_csv_safe(out_dir / "timeline_all.csv")
        assert timeline_all.headers == ["time"]
        assert timeline_all.rows == [["2026-01-01"]]

        assert process_source.read_bytes() == source_bytes
        assert all_source.read_bytes() == all_source_bytes

    def test_files_written_path_entry_still_enriches(self, tmp_path: Path) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor, _files_written_contains

        assert _files_written_contains(["timeline_process.csv"], "timeline_process.csv")
        assert _files_written_contains([Path("timeline_process.csv")], "timeline_process.csv")
        assert _files_written_contains(
            [Path("/tmp/case/csv/timeline_process.csv")],
            "timeline_process.csv",
        )
        assert not _files_written_contains(["timeline_all.csv"], "timeline_process.csv")

        memprocfs_root = tmp_path / "memprocfs"
        process_source = memprocfs_root / "forensic" / "csv" / "timeline_process.csv"
        _write_csv(process_source, GENERIC_HEADERS, [_sample_row(text=SVCHOST_TEXT)])

        extractor = TimelinesExtractor()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = ExtractResult(
            ok=True,
            files_written=[Path("timeline_process.csv")],
        )
        if result.ok and _files_written_contains(result.files_written, "timeline_process.csv"):
            extractor.copy_forensic_csvs_matching(memprocfs_root, "timeline_", out_dir)
            enrich_timeline_process_csv(out_dir / "timeline_process.csv")

        table = read_csv_safe(out_dir / "timeline_process.csv")
        assert list(TIMELINE_PROCESS_DERIVED_COLUMNS) == ["ProcessName", "Account", "KernelPath"]
        assert table.rows[0][8:] == ["svchost.exe", "*SYSTEM", SVCHOST_PATH]

    def test_process_enrichment_skipped_when_result_not_ok(self, tmp_path: Path) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        process_path = out_dir / "timeline_process.csv"
        _write_csv(process_path, GENERIC_HEADERS, [_sample_row()])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=False, error="copy failed")

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            returned = extractor.extract(tmp_path / "memprocfs", out_dir)

        assert returned.ok is False
        table = read_csv_safe(process_path)
        assert table.headers == GENERIC_HEADERS
        assert "ProcessName" not in table.headers

    def test_process_enrichment_skipped_when_absent_from_files_written(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        process_path = out_dir / "timeline_process.csv"
        _write_csv(process_path, GENERIC_HEADERS, [_sample_row()])

        extractor = TimelinesExtractor()
        result = ExtractResult(
            ok=True,
            rows=0,
            files_written=["timeline_all.csv"],
        )

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            extractor.extract(tmp_path / "memprocfs", out_dir)

        table = read_csv_safe(process_path)
        assert table.headers == GENERIC_HEADERS
        assert "PPID" not in table.headers

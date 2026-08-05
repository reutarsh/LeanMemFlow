"""Tests for timeline_ntfs semantic schema enrichment and extraction integration."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_ntfs_text import (
    TIMELINE_NTFS_GENERIC_HEADERS,
    TIMELINE_NTFS_OUTPUT_HEADERS,
    enrich_timeline_ntfs_csv,
)
from extractors.timeline_registry_text import (
    TIMELINE_REGISTRY_GENERIC_HEADERS,
)
from memflow_common.csv_io import read_csv_safe

GENERIC_HEADERS = list(TIMELINE_NTFS_GENERIC_HEADERS)

NORMAL_PATH = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"
PATH_WITH_SPACES = r"\Device\HarddiskVolume3\My Files\readme.txt"
PATH_WITH_COMMA = r"\Device\HarddiskVolume3\foo,bar\baz.txt"
PATH_WITH_QUOTES = r'\Device\HarddiskVolume3\foo"bar\baz.txt'
PATH_WITH_PIPE = r"\Device\HarddiskVolume3\foo|bar\baz.txt"
PATH_WITH_AT = r"\Device\HarddiskVolume3\foo@bar\baz.txt"
PATH_WITH_BRACKETS = r"\Device\HarddiskVolume3\foo[1]\bar.txt"
PATH_WITH_UNICODE = r"\Device\HarddiskVolume3\עברית\file.txt"
HEX_MFT = "0x00000000001C2A00"
FILE_SIZE = "4096"
TIME = "2024-01-15 08:00:00"
EVENT_TYPE = "NTFS"
ACTION = "Write"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _sample_row(
    *,
    ntfs_path: str = NORMAL_PATH,
    value32: str = FILE_SIZE,
    value64: str = HEX_MFT,
    pid: str = "1234",
    pad: str = "",
) -> list[str]:
    return [TIME, EVENT_TYPE, ACTION, pid, value32, value64, ntfs_path, pad]


def _semantic_row(
    *,
    ntfs_path: str = NORMAL_PATH,
    file_size: str = FILE_SIZE,
    mft_address: str = HEX_MFT,
) -> list[str]:
    return [TIME, EVENT_TYPE, ACTION, file_size, mft_address, ntfs_path]


def _expected_enriched_row(
    *,
    ntfs_path: str = NORMAL_PATH,
    file_size: str = FILE_SIZE,
    mft_address: str = HEX_MFT,
) -> list[str]:
    return _semantic_row(
        ntfs_path=ntfs_path,
        file_size=file_size,
        mft_address=mft_address,
    )


def _cell(row: dict[str, str], *names: str) -> str:
    """Mirror C# CsvRowMappers.Cell (trim on hit)."""
    for name in names:
        if name in row and row[name] is not None:
            return row[name].strip()
    return ""


def _truncate(value: str, max_len: int) -> str:
    if value is None:
        return ""
    return value[:max_len] if len(value) > max_len else value


def _map_timeline_ntfs(row: dict[str, str]) -> dict[str, str]:
    """Mirror C# MapTimelineNtfs field resolution (semantic headers first)."""
    return {
        "Time": _truncate(_cell(row, "Time"), 100),
        "Type": _truncate(_cell(row, "Type"), 100),
        "Action": _truncate(_cell(row, "Action"), 100),
        "Pid": _truncate(_cell(row, "PID", "pid"), 50),
        "Value32": _truncate(_cell(row, "FileSize", "Value32"), 100),
        "Value64": _truncate(_cell(row, "MftRecordPhysicalAddress", "Value64"), 100),
        "Text": _cell(row, "NtfsPath", "Text"),
        "Pad": _truncate(_cell(row, "Pad"), 100),
    }


def _get_row_value(row: dict[str, str], *keys: str) -> str:
    """Mirror C# RowHashBuilder.Get."""
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _build_timeline_event_row(row: dict[str, str]) -> str:
    """Mirror C# RowHashBuilder.BuildTimelineEventRow."""
    values = [
        _get_row_value(row, "Time", "time"),
        _get_row_value(row, "Type", "type"),
        _get_row_value(row, "Action", "action"),
        _get_row_value(row, "PID", "pid"),
        _get_row_value(row, "FileSize", "Value32"),
        _get_row_value(row, "MftRecordPhysicalAddress", "Value64"),
        _get_row_value(row, "NtfsPath", "Text", "description"),
        _get_row_value(row, "Pad"),
    ]
    joined = "||".join(values)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _row_dict(headers: list[str], values: list[str]) -> dict[str, str]:
    return dict(zip(headers, values))


class TestEnrichTimelineNtfsCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(ntfs_path=NORMAL_PATH),
            _sample_row(ntfs_path=PATH_WITH_SPACES),
            _sample_row(ntfs_path=""),
        ]

    def test_normal_generic_memprocfs_row(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row()])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0] == _expected_enriched_row()

    def test_exact_final_header_order(self, tmp_path: Path, sample_rows: list[list[str]]) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_NTFS_OUTPUT_HEADERS)

    def test_pid_removed(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(pid="5678")])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "PID" not in table.headers

    def test_pad_removed(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(pad="padding")])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "Pad" not in table.headers

    def test_retained_values_preserved(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        row = _sample_row(
            ntfs_path=PATH_WITH_COMMA,
            value32=FILE_SIZE,
            value64=HEX_MFT,
        )
        _write_csv(csv_path, GENERIC_HEADERS, [row])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0] == _expected_enriched_row(
            ntfs_path=PATH_WITH_COMMA,
            file_size=FILE_SIZE,
            mft_address=HEX_MFT,
        )

    def test_multiple_rows_preserve_order_and_count(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        row_count = enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)
        assert table.rows == [
            _expected_enriched_row(ntfs_path=NORMAL_PATH),
            _expected_enriched_row(ntfs_path=PATH_WITH_SPACES),
            _expected_enriched_row(ntfs_path=""),
        ]

    @pytest.mark.parametrize(
        "path",
        [
            PATH_WITH_COMMA,
            PATH_WITH_QUOTES,
        ],
    )
    def test_csv_special_characters_preserved(self, tmp_path: Path, path: str) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(ntfs_path=path)])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][5] == path

    @pytest.mark.parametrize(
        "path",
        [
            PATH_WITH_SPACES,
            PATH_WITH_PIPE,
            PATH_WITH_AT,
            PATH_WITH_BRACKETS,
            PATH_WITH_UNICODE,
        ],
    )
    def test_path_values_preserved(self, tmp_path: Path, path: str) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(ntfs_path=path)])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][5] == path

    def test_empty_ntfs_path(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(ntfs_path="")])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][5] == ""

    def test_reordered_input_columns(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        headers = ["Pad", "Text", "Value64", "Value32", "PID", "Action", "Type", "Time"]
        row = ["", NORMAL_PATH, HEX_MFT, FILE_SIZE, "0", ACTION, EVENT_TYPE, TIME]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_NTFS_OUTPUT_HEADERS)
        assert table.rows[0] == _expected_enriched_row()

    def test_missing_pid(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        headers = ["Time", "Type", "Action", "Value32", "Value64", "Text", "Pad"]
        row = [TIME, EVENT_TYPE, ACTION, FILE_SIZE, HEX_MFT, NORMAL_PATH, ""]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "PID" not in table.headers
        assert table.rows[0] == _expected_enriched_row()

    def test_missing_pad(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Text"]
        row = [TIME, EVENT_TYPE, ACTION, "0", FILE_SIZE, HEX_MFT, NORMAL_PATH]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "Pad" not in table.headers
        assert table.rows[0] == _expected_enriched_row()

    def test_missing_text_header(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Pad"]
        row = [TIME, EVENT_TYPE, ACTION, "1234", FILE_SIZE, HEX_MFT, ""]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_NTFS_OUTPUT_HEADERS)
        assert table.rows[0] == _expected_enriched_row(ntfs_path="")

    def test_partially_transformed_with_pid_and_pad_remaining(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        headers = [
            "Time",
            "Type",
            "Action",
            "PID",
            "FileSize",
            "MftRecordPhysicalAddress",
            "NtfsPath",
            "Pad",
        ]
        row = [TIME, EVENT_TYPE, ACTION, "0", FILE_SIZE, HEX_MFT, NORMAL_PATH, "pad"]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_NTFS_OUTPUT_HEADERS)
        assert "PID" not in table.headers
        assert "Pad" not in table.headers
        assert table.rows[0] == _expected_enriched_row()

    def test_partially_transformed_with_some_fields_renamed(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        headers = ["Time", "Type", "Action", "PID", "FileSize", "Value64", "Text", "Pad"]
        row = [TIME, EVENT_TYPE, ACTION, "0", FILE_SIZE, HEX_MFT, NORMAL_PATH, ""]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_NTFS_OUTPUT_HEADERS)
        assert table.rows[0] == _expected_enriched_row()

    def test_fully_transformed_file_unchanged(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        row = _semantic_row()
        _write_csv(csv_path, list(TIMELINE_NTFS_OUTPUT_HEADERS), [row])
        before = read_csv_safe(csv_path)

        enrich_timeline_ntfs_csv(csv_path)
        after = read_csv_safe(csv_path)

        assert before.headers == after.headers
        assert before.rows == after.rows

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_ntfs_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_ntfs_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows

    def test_no_generic_headers_remain(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row()])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "Value32" not in table.headers
        assert "Value64" not in table.headers
        assert "Text" not in table.headers

    def test_no_duplicate_columns(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_ntfs.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row()])

        enrich_timeline_ntfs_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert len(table.headers) == len(set(table.headers))


class TestCSharpAliasParity:
    @pytest.fixture
    def logical_values(self) -> list[str]:
        return _sample_row(ntfs_path=PATH_WITH_COMMA, value64=HEX_MFT)

    def test_generic_and_semantic_rows_map_equivalent_fields(
        self, logical_values: list[str]
    ) -> None:
        generic = _row_dict(GENERIC_HEADERS, logical_values)
        semantic = _row_dict(
            list(TIMELINE_NTFS_OUTPUT_HEADERS),
            _semantic_row(ntfs_path=PATH_WITH_COMMA, mft_address=HEX_MFT),
        )

        generic_mapped = _map_timeline_ntfs(generic)
        semantic_mapped = _map_timeline_ntfs(semantic)

        assert generic_mapped["Time"] == semantic_mapped["Time"]
        assert generic_mapped["Type"] == semantic_mapped["Type"]
        assert generic_mapped["Action"] == semantic_mapped["Action"]
        assert generic_mapped["Value32"] == semantic_mapped["Value32"] == FILE_SIZE
        assert generic_mapped["Value64"] == semantic_mapped["Value64"] == HEX_MFT
        assert generic_mapped["Text"] == semantic_mapped["Text"] == PATH_WITH_COMMA

    def test_semantic_headers_resolve_directly(self) -> None:
        semantic = _row_dict(
            list(TIMELINE_NTFS_OUTPUT_HEADERS),
            _semantic_row(),
        )
        mapped = _map_timeline_ntfs(semantic)

        assert mapped["Value32"] == FILE_SIZE
        assert mapped["Value64"] == HEX_MFT
        assert mapped["Text"] == NORMAL_PATH

    def test_generic_headers_resolve_via_fallback(self) -> None:
        generic = _row_dict(GENERIC_HEADERS, _sample_row())
        mapped = _map_timeline_ntfs(generic)

        assert mapped["Value32"] == FILE_SIZE
        assert mapped["Value64"] == HEX_MFT
        assert mapped["Text"] == NORMAL_PATH


class TestTimelinesExtractorIntegration:
    def test_extract_renames_timeline_ntfs_and_leaves_source_unchanged(
        self, tmp_path: Path
    ) -> None:
        from extractors.timelines import TimelinesExtractor

        memprocfs_root = tmp_path / "memprocfs"
        forensic_csv = memprocfs_root / "forensic" / "csv"

        ntfs_source = forensic_csv / "timeline_ntfs.csv"
        registry_source = forensic_csv / "timeline_registry.csv"
        all_source = forensic_csv / "timeline_all.csv"

        _write_csv(ntfs_source, GENERIC_HEADERS, [_sample_row()])
        _write_csv(
            registry_source,
            list(TIMELINE_REGISTRY_GENERIC_HEADERS),
            [
                "2024-01-15 08:00:00",
                "REG",
                "Write",
                "1234",
                "0",
                "0",
                NORMAL_PATH,
                "",
            ],
        )
        _write_csv(all_source, ["time"], [["2026-01-01"]])

        ntfs_bytes = ntfs_source.read_bytes()
        registry_bytes = registry_source.read_bytes()
        all_bytes = all_source.read_bytes()

        out_dir = tmp_path / "case" / "csv"
        out_dir.mkdir(parents=True)
        result = TimelinesExtractor().extract(memprocfs_root, out_dir)

        assert result.ok is True
        assert "timeline_ntfs.csv" in result.files_written

        ntfs = read_csv_safe(out_dir / "timeline_ntfs.csv")
        assert ntfs.headers == list(TIMELINE_NTFS_OUTPUT_HEADERS)
        assert ntfs.rows[0][5] == NORMAL_PATH
        assert ntfs.rows[0][4] == HEX_MFT
        assert "PID" not in ntfs.headers
        assert "Pad" not in ntfs.headers

        registry = read_csv_safe(out_dir / "timeline_registry.csv")
        assert "RegistryPath" in registry.headers
        assert "FileSize" not in registry.headers

        timeline_all = read_csv_safe(out_dir / "timeline_all.csv")
        assert timeline_all.headers == ["time"]

        assert ntfs_source.read_bytes() == ntfs_bytes
        assert registry_source.read_bytes() == registry_bytes
        assert all_source.read_bytes() == all_bytes

    def test_ntfs_enrichment_skipped_when_result_not_ok(self, tmp_path: Path) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ntfs_path = out_dir / "timeline_ntfs.csv"
        _write_csv(ntfs_path, GENERIC_HEADERS, [_sample_row()])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=False, error="copy failed")

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            returned = extractor.extract(tmp_path / "memprocfs", out_dir)

        assert returned.ok is False
        table = read_csv_safe(ntfs_path)
        assert table.headers == GENERIC_HEADERS
        assert "FileSize" not in table.headers

    def test_ntfs_enrichment_skipped_when_absent_from_files_written(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ntfs_path = out_dir / "timeline_ntfs.csv"
        _write_csv(ntfs_path, GENERIC_HEADERS, [_sample_row()])

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

        table = read_csv_safe(ntfs_path)
        assert table.headers == GENERIC_HEADERS
        assert "FileSize" not in table.headers

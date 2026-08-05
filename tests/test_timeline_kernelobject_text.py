"""Tests for timeline_kernelobject Text alias enrichment and extraction integration."""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_kernelobject_text import (
    TIMELINE_KERNELOBJECT_OUTPUT_HEADERS,
    enrich_timeline_kernelobject_csv,
)
from memflow_common.csv_io import read_csv_safe

NATIVE_HEADERS = list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS[:8])

LOW_MEMORY_PATH = r"\KernelObjects\LowMemoryCondition"
DEVICE_PATH = r"\Device\LanmanRedirector"
GLOBAL_PATH = r"\GLOBAL??\pmem"
ARCNAME_PATH = r"\ArcName\multi(0)disk(0)rdisk(0)"
PATH_WITH_SPACES = r"\KernelObjects\My Object Path"
PATH_WITH_COMMA = r"\Device\foo,bar\baz"
PATH_WITH_PIPE = r"\Device\foo|bar\baz"
PATH_WITH_AT = r"\Device\foo@bar\baz"
PATH_WITH_BRACKETS = r"\Device\foo[1]\bar"
PATH_WITH_GUID = r"\Device\{01234567-89ab-cdef-0123-456789abcdef}"
PATH_WITH_HASH = r"\Device\Harddisk#0"
PATH_WITH_UNICODE = r"\KernelObjects\עברית"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _sample_row(
    text: str,
    *,
    pid: str = "0",
    value32: str = "0x0",
    value64: str = "0xFFFFFA8012345678",
    time: str = "2024-01-15 08:00:00",
) -> list[str]:
    return [time, "KObj", "CRE", pid, value32, value64, text, ""]


class TestEnrichTimelineKernelObjectCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(LOW_MEMORY_PATH),
            _sample_row(PATH_WITH_SPACES),
            _sample_row(""),
        ]

    def test_normal_kernel_object_path(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(LOW_MEMORY_PATH)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == LOW_MEMORY_PATH
        assert table.rows[0][8] == LOW_MEMORY_PATH

    def test_device_path(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(DEVICE_PATH)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == DEVICE_PATH
        assert table.rows[0][8] == DEVICE_PATH

    def test_global_path(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(GLOBAL_PATH)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == GLOBAL_PATH
        assert table.rows[0][8] == GLOBAL_PATH

    def test_arcname_path(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(ARCNAME_PATH)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == ARCNAME_PATH
        assert table.rows[0][8] == ARCNAME_PATH

    def test_path_with_spaces(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_SPACES)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_SPACES
        assert table.rows[0][8] == PATH_WITH_SPACES

    def test_path_with_comma(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_COMMA)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_COMMA
        assert table.rows[0][8] == PATH_WITH_COMMA

    def test_path_with_pipe(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_PIPE)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_PIPE
        assert table.rows[0][8] == PATH_WITH_PIPE

    def test_path_with_at(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_AT)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_AT
        assert table.rows[0][8] == PATH_WITH_AT

    def test_path_with_brackets(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_BRACKETS)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_BRACKETS
        assert table.rows[0][8] == PATH_WITH_BRACKETS

    def test_path_with_guid(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_GUID)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_GUID
        assert table.rows[0][8] == PATH_WITH_GUID

    def test_path_with_hash(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_HASH)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_HASH
        assert table.rows[0][8] == PATH_WITH_HASH

    def test_path_with_unicode(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row(PATH_WITH_UNICODE)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == PATH_WITH_UNICODE
        assert table.rows[0][8] == PATH_WITH_UNICODE

    def test_empty_text(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, [_sample_row("")])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][6] == ""
        assert table.rows[0][8] == ""

    def test_missing_text_header(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Pad"]
        rows = [
            [
                "2024-01-15 08:00:00",
                "KObj",
                "CRE",
                "0",
                "0x0",
                "0xFFFFFA8012345678",
                "",
            ],
        ]
        _write_csv(csv_path, headers, rows)

        row_count = enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == 1
        assert table.headers == headers + ["KernelObjectPath"]
        assert table.rows[0][:-1] == rows[0]
        assert table.rows[0][-1] == ""

    def test_native_columns_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, sample_rows)

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        for src_row, out_row in zip(sample_rows, table.rows):
            assert out_row[:8] == src_row
            assert out_row[3] == "0"
            assert out_row[4] == "0x0"
            assert out_row[5] == "0xFFFFFA8012345678"

    def test_kernel_object_path_equals_text(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, sample_rows)

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        for row in table.rows:
            assert row[8] == row[6]

    def test_header_order(self, tmp_path: Path, sample_rows: list[list[str]]) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, sample_rows)

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS)

    def test_row_count_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, sample_rows)

        row_count = enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, NATIVE_HEADERS, sample_rows)
        enrich_timeline_kernelobject_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_kernelobject_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows


class TestTimelinesExtractorIntegration:
    def test_extract_enriches_timeline_kernelobject(
        self, tmp_path: Path
    ) -> None:
        from extractors.timelines import TimelinesExtractor

        memprocfs_root = tmp_path / "memprocfs"
        forensic_csv = memprocfs_root / "forensic" / "csv"

        kernelobject_source = forensic_csv / "timeline_kernelobject.csv"
        web_source = forensic_csv / "timeline_web.csv"
        all_source = forensic_csv / "timeline_all.csv"

        _write_csv(
            kernelobject_source,
            NATIVE_HEADERS,
            [_sample_row(LOW_MEMORY_PATH)],
        )
        _write_csv(
            web_source,
            NATIVE_HEADERS,
            [_sample_row(r"\KernelObjects\Should\Not\Change")],
        )
        _write_csv(all_source, ["time"], [["2026-01-01"]])

        kernelobject_bytes = kernelobject_source.read_bytes()
        web_bytes = web_source.read_bytes()
        all_bytes = all_source.read_bytes()

        out_dir = tmp_path / "case" / "csv"
        out_dir.mkdir(parents=True)
        result = TimelinesExtractor().extract(memprocfs_root, out_dir)

        assert result.ok is True
        assert "timeline_kernelobject.csv" in result.files_written

        kernelobject = read_csv_safe(out_dir / "timeline_kernelobject.csv")
        assert kernelobject.headers == list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS)
        assert kernelobject.rows[0][6] == LOW_MEMORY_PATH
        assert kernelobject.rows[0][8] == LOW_MEMORY_PATH
        assert kernelobject.rows[0][8] == kernelobject.rows[0][6]

        web = read_csv_safe(out_dir / "timeline_web.csv")
        assert web.headers == NATIVE_HEADERS
        assert web.rows[0][6] == r"\KernelObjects\Should\Not\Change"
        assert len(web.headers) == 8

        timeline_all = read_csv_safe(out_dir / "timeline_all.csv")
        assert timeline_all.headers == ["time"]
        assert timeline_all.rows == [["2026-01-01"]]

        assert kernelobject_source.read_bytes() == kernelobject_bytes
        assert web_source.read_bytes() == web_bytes
        assert all_source.read_bytes() == all_bytes

    def test_kernelobject_enrichment_skipped_when_result_not_ok(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        kernelobject_path = out_dir / "timeline_kernelobject.csv"
        _write_csv(kernelobject_path, NATIVE_HEADERS, [_sample_row(LOW_MEMORY_PATH)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=False, error="copy failed")

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            returned = extractor.extract(tmp_path / "memprocfs", out_dir)

        assert returned.ok is False
        table = read_csv_safe(kernelobject_path)
        assert table.headers == NATIVE_HEADERS
        assert "KernelObjectPath" not in table.headers

    def test_kernelobject_enrichment_skipped_when_file_not_written(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        kernelobject_path = out_dir / "timeline_kernelobject.csv"
        _write_csv(kernelobject_path, NATIVE_HEADERS, [_sample_row(LOW_MEMORY_PATH)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=True, files_written=["timeline_all.csv"])

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            extractor.extract(tmp_path / "memprocfs", out_dir)

        table = read_csv_safe(kernelobject_path)
        assert table.headers == NATIVE_HEADERS
        assert "KernelObjectPath" not in table.headers

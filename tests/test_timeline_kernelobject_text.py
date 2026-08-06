"""Tests for timeline_kernelobject semantic schema enrichment and extraction integration."""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_kernelobject_text import (
    TIMELINE_KERNELOBJECT_GENERIC_HEADERS,
    TIMELINE_KERNELOBJECT_OUTPUT_HEADERS,
    enrich_timeline_kernelobject_csv,
)
from memflow_common.csv_io import read_csv_safe

GENERIC_HEADERS = list(TIMELINE_KERNELOBJECT_GENERIC_HEADERS)

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
OBJECT_ADDRESS = "0xFFFFFA8012345678"
TIME = "2024-01-15 08:00:00"


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
    value32: str = "0",
    value64: str = OBJECT_ADDRESS,
    time: str = TIME,
) -> list[str]:
    return [time, "KObj", "CRE", pid, value32, value64, text, ""]


def _expected_row(
    path: str,
    *,
    object_address: str = OBJECT_ADDRESS,
    time: str = TIME,
) -> list[str]:
    return [time, "KObj", "CRE", object_address, path]


class TestEnrichTimelineKernelObjectCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(LOW_MEMORY_PATH),
            _sample_row(PATH_WITH_SPACES),
            _sample_row(""),
        ]

    @pytest.mark.parametrize(
        "path",
        [
            LOW_MEMORY_PATH,
            DEVICE_PATH,
            GLOBAL_PATH,
            ARCNAME_PATH,
            PATH_WITH_SPACES,
            PATH_WITH_COMMA,
            PATH_WITH_PIPE,
            PATH_WITH_AT,
            PATH_WITH_BRACKETS,
            PATH_WITH_GUID,
            PATH_WITH_HASH,
            PATH_WITH_UNICODE,
            "",
        ],
    )
    def test_path_and_address_preserved(self, tmp_path: Path, path: str) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(path)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS)
        assert table.rows[0] == _expected_row(path)

    def test_drops_pid_value32_text_pad(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(LOW_MEMORY_PATH)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "PID" not in table.headers
        assert "Value32" not in table.headers
        assert "Value64" not in table.headers
        assert "Text" not in table.headers
        assert "Pad" not in table.headers

    def test_renames_value64_and_text(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(DEVICE_PATH)])

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][3] == OBJECT_ADDRESS
        assert table.rows[0][4] == DEVICE_PATH

    def test_missing_text_header_yields_empty_path(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Pad"]
        rows = [[TIME, "KObj", "CRE", "0", "0", OBJECT_ADDRESS, ""]]
        _write_csv(csv_path, headers, rows)

        row_count = enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == 1
        assert table.headers == list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS)
        assert table.rows[0] == _expected_row("")

    def test_legacy_appended_kernel_object_path_column(self, tmp_path: Path) -> None:
        """Older enricher kept generics and appended KernelObjectPath."""
        csv_path = tmp_path / "timeline_kernelobject.csv"
        headers = GENERIC_HEADERS + ["KernelObjectPath"]
        rows = [_sample_row(LOW_MEMORY_PATH) + [LOW_MEMORY_PATH]]
        _write_csv(csv_path, headers, rows)

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS)
        assert table.rows[0] == _expected_row(LOW_MEMORY_PATH)

    def test_header_order(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_KERNELOBJECT_OUTPUT_HEADERS)

    def test_row_count_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        row_count = enrich_timeline_kernelobject_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)
        assert table.rows == [
            _expected_row(LOW_MEMORY_PATH),
            _expected_row(PATH_WITH_SPACES),
            _expected_row(""),
        ]

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_kernelobject.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_kernelobject_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_kernelobject_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows


class TestTimelinesExtractorIntegration:
    def test_extract_enriches_timeline_kernelobject(self, tmp_path: Path) -> None:
        from extractors.timelines import TimelinesExtractor

        memprocfs_root = tmp_path / "memprocfs"
        forensic_csv = memprocfs_root / "forensic" / "csv"

        kernelobject_source = forensic_csv / "timeline_kernelobject.csv"
        web_source = forensic_csv / "timeline_web.csv"
        all_source = forensic_csv / "timeline_all.csv"

        _write_csv(
            kernelobject_source,
            GENERIC_HEADERS,
            [_sample_row(LOW_MEMORY_PATH)],
        )
        _write_csv(
            web_source,
            GENERIC_HEADERS,
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
        assert kernelobject.rows[0] == _expected_row(LOW_MEMORY_PATH)

        web = read_csv_safe(out_dir / "timeline_web.csv")
        assert web.headers == GENERIC_HEADERS
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
        _write_csv(kernelobject_path, GENERIC_HEADERS, [_sample_row(LOW_MEMORY_PATH)])

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
        assert table.headers == GENERIC_HEADERS
        assert "ObjectAddress" not in table.headers

    def test_kernelobject_enrichment_skipped_when_file_not_written(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        kernelobject_path = out_dir / "timeline_kernelobject.csv"
        _write_csv(kernelobject_path, GENERIC_HEADERS, [_sample_row(LOW_MEMORY_PATH)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=True, files_written=["timeline_all.csv"])

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            extractor.extract(tmp_path / "memprocfs", out_dir)

        table = read_csv_safe(kernelobject_path)
        assert table.headers == GENERIC_HEADERS
        assert "KernelObjectPath" not in table.headers

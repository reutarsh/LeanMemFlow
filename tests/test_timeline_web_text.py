"""Tests for timeline_web Text parsing and extraction enrichment."""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_web_text import (
    TIMELINE_WEB_GENERIC_HEADERS,
    TIMELINE_WEB_OUTPUT_HEADERS,
    enrich_timeline_web_csv,
    parse_timeline_web_text,
)
from memflow_common.csv_io import read_csv_safe

GENERIC_HEADERS = list(TIMELINE_WEB_GENERIC_HEADERS)

CHROME_VISIT_TEXT = (
    "browser:[chrome] type:[visit] url:[https://example.com/path] info:[title here]"
)
EDGE_DOWNLOAD_TEXT = (
    "browser:[msedge] type:[download] url:[https://cdn.example.com/a.exe] info:[a.exe]"
)
FIREFOX_LOGIN_TEXT = (
    "browser:[firefox] type:[loginpwd] url:[https://login.example.com/] info:[user@example.com]"
)
URL_WITH_BRACKETS = (
    "browser:[chrome] type:[visit] url:[https://example.com/foo[1]/bar] info:[ok]"
)
URL_WITH_COMMA = (
    "browser:[chrome] type:[visit] url:[https://example.com/a,b] info:[comma]"
)
URL_WITH_SPACES = (
    "browser:[chrome] type:[visit] url:[https://example.com/my page] info:[spaced]"
)
EMPTY_INFO_TEXT = "browser:[brave] type:[visit] url:[https://brave.example/] info:[]"
MALFORMED_TEXT = "not a web timeline line"
TIME = "2024-01-15 08:00:00"
PID = "4321"
OBJECT_UNUSED = "0"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _sample_row(
    text: str,
    *,
    pid: str = PID,
    value32: str = OBJECT_UNUSED,
    value64: str = OBJECT_UNUSED,
    time: str = TIME,
    action: str = "CRE",
) -> list[str]:
    return [time, "WEB", action, pid, value32, value64, text, ""]


def _expected_row(
    text: str,
    *,
    browser: str,
    web_action: str,
    url: str,
    info: str,
    pid: str = PID,
    time: str = TIME,
    action: str = "CRE",
) -> list[str]:
    return [time, "WEB", action, pid, browser, web_action, url, info, text]


class TestParseTimelineWebText:
    def test_chrome_visit(self) -> None:
        assert parse_timeline_web_text(CHROME_VISIT_TEXT) == (
            "chrome",
            "visit",
            "https://example.com/path",
            "title here",
        )

    def test_edge_download(self) -> None:
        assert parse_timeline_web_text(EDGE_DOWNLOAD_TEXT) == (
            "msedge",
            "download",
            "https://cdn.example.com/a.exe",
            "a.exe",
        )

    def test_firefox_login(self) -> None:
        assert parse_timeline_web_text(FIREFOX_LOGIN_TEXT) == (
            "firefox",
            "loginpwd",
            "https://login.example.com/",
            "user@example.com",
        )

    def test_url_with_brackets(self) -> None:
        assert parse_timeline_web_text(URL_WITH_BRACKETS) == (
            "chrome",
            "visit",
            "https://example.com/foo[1]/bar",
            "ok",
        )

    def test_empty_info(self) -> None:
        assert parse_timeline_web_text(EMPTY_INFO_TEXT) == (
            "brave",
            "visit",
            "https://brave.example/",
            "",
        )

    def test_empty_and_malformed(self) -> None:
        assert parse_timeline_web_text("") == ("", "", "", "")
        assert parse_timeline_web_text(MALFORMED_TEXT) == ("", "", "", "")
        assert parse_timeline_web_text("browser:[chrome] type:[visit]") == (
            "",
            "",
            "",
            "",
        )


class TestEnrichTimelineWebCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(CHROME_VISIT_TEXT),
            _sample_row(EDGE_DOWNLOAD_TEXT, action="RD"),
            _sample_row(""),
        ]

    def test_exact_final_header_order(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(CHROME_VISIT_TEXT)])

        enrich_timeline_web_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_WEB_OUTPUT_HEADERS)

    def test_drops_value32_value64_text_pad(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(CHROME_VISIT_TEXT)])

        enrich_timeline_web_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "Value32" not in table.headers
        assert "Value64" not in table.headers
        assert "Text" not in table.headers
        assert "Pad" not in table.headers
        assert "PID" in table.headers

    def test_parsed_fields_and_description(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(CHROME_VISIT_TEXT)])

        enrich_timeline_web_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0] == _expected_row(
            CHROME_VISIT_TEXT,
            browser="chrome",
            web_action="visit",
            url="https://example.com/path",
            info="title here",
        )

    @pytest.mark.parametrize(
        "text,browser,web_action,url,info",
        [
            (
                URL_WITH_BRACKETS,
                "chrome",
                "visit",
                "https://example.com/foo[1]/bar",
                "ok",
            ),
            (URL_WITH_COMMA, "chrome", "visit", "https://example.com/a,b", "comma"),
            (
                URL_WITH_SPACES,
                "chrome",
                "visit",
                "https://example.com/my page",
                "spaced",
            ),
            (EMPTY_INFO_TEXT, "brave", "visit", "https://brave.example/", ""),
        ],
    )
    def test_special_urls_preserved(
        self,
        tmp_path: Path,
        text: str,
        browser: str,
        web_action: str,
        url: str,
        info: str,
    ) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(text)])

        enrich_timeline_web_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0] == _expected_row(
            text,
            browser=browser,
            web_action=web_action,
            url=url,
            info=info,
        )

    def test_malformed_text_keeps_description(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(MALFORMED_TEXT)])

        enrich_timeline_web_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0] == _expected_row(
            MALFORMED_TEXT,
            browser="",
            web_action="",
            url="",
            info="",
        )

    def test_empty_text(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row("")])

        enrich_timeline_web_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0] == _expected_row(
            "",
            browser="",
            web_action="",
            url="",
            info="",
        )

    def test_row_count_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        row_count = enrich_timeline_web_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)
        assert table.rows == [
            _expected_row(
                CHROME_VISIT_TEXT,
                browser="chrome",
                web_action="visit",
                url="https://example.com/path",
                info="title here",
            ),
            _expected_row(
                EDGE_DOWNLOAD_TEXT,
                browser="msedge",
                web_action="download",
                url="https://cdn.example.com/a.exe",
                info="a.exe",
                action="RD",
            ),
            _expected_row(
                "",
                browser="",
                web_action="",
                url="",
                info="",
            ),
        ]

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_web.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_web_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_web_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows


class TestTimelinesExtractorIntegration:
    def test_extract_enriches_timeline_web(self, tmp_path: Path) -> None:
        from extractors.timelines import TimelinesExtractor

        memprocfs_root = tmp_path / "memprocfs"
        forensic_csv = memprocfs_root / "forensic" / "csv"

        web_source = forensic_csv / "timeline_web.csv"
        all_source = forensic_csv / "timeline_all.csv"

        _write_csv(web_source, GENERIC_HEADERS, [_sample_row(CHROME_VISIT_TEXT)])
        _write_csv(all_source, ["time"], [["2026-01-01"]])

        web_bytes = web_source.read_bytes()
        all_bytes = all_source.read_bytes()

        out_dir = tmp_path / "case" / "csv"
        out_dir.mkdir(parents=True)
        result = TimelinesExtractor().extract(memprocfs_root, out_dir)

        assert result.ok is True
        assert "timeline_web.csv" in result.files_written

        web = read_csv_safe(out_dir / "timeline_web.csv")
        assert web.headers == list(TIMELINE_WEB_OUTPUT_HEADERS)
        assert web.rows[0] == _expected_row(
            CHROME_VISIT_TEXT,
            browser="chrome",
            web_action="visit",
            url="https://example.com/path",
            info="title here",
        )

        timeline_all = read_csv_safe(out_dir / "timeline_all.csv")
        assert timeline_all.headers == ["time"]
        assert timeline_all.rows == [["2026-01-01"]]

        assert web_source.read_bytes() == web_bytes
        assert all_source.read_bytes() == all_bytes

    def test_web_enrichment_skipped_when_result_not_ok(self, tmp_path: Path) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        web_path = out_dir / "timeline_web.csv"
        _write_csv(web_path, GENERIC_HEADERS, [_sample_row(CHROME_VISIT_TEXT)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=False, error="copy failed")

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            returned = extractor.extract(tmp_path / "memprocfs", out_dir)

        assert returned.ok is False
        table = read_csv_safe(web_path)
        assert table.headers == GENERIC_HEADERS
        assert "Browser" not in table.headers

    def test_web_enrichment_skipped_when_file_not_written(self, tmp_path: Path) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        web_path = out_dir / "timeline_web.csv"
        _write_csv(web_path, GENERIC_HEADERS, [_sample_row(CHROME_VISIT_TEXT)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=True, files_written=["timeline_all.csv"])

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            extractor.extract(tmp_path / "memprocfs", out_dir)

        table = read_csv_safe(web_path)
        assert table.headers == GENERIC_HEADERS
        assert "WebDescription" not in table.headers

"""Tests for timeline_task semantic schema enrichment and extraction integration."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_process_text import (
    TIMELINE_PROCESS_GENERIC_HEADERS,
    TIMELINE_PROCESS_OUTPUT_HEADERS,
)
from extractors.timeline_registry_text import (
    TIMELINE_REGISTRY_GENERIC_HEADERS,
    TIMELINE_REGISTRY_OUTPUT_HEADERS,
)
from extractors.timeline_task_text import (
    TIMELINE_TASK_GENERIC_HEADERS,
    TIMELINE_TASK_OUTPUT_HEADERS,
    enrich_timeline_task_csv,
    parse_timeline_task_text,
)
from extractors.timeline_web_text import TIMELINE_WEB_OUTPUT_HEADERS
from memflow_common.csv_io import read_csv_safe

GENERIC_HEADERS = list(TIMELINE_TASK_GENERIC_HEADERS)

DEFENDER_TEXT = (
    "Windows Defender Scheduled Scan - "
    "[C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26040.7-0\\MpCmdRun.exe "
    ":: Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob] (LocalSystem)"
)
DEFENDER_CMD = (
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"
)
DEFENDER_PARAMS = "Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob"

USAGE_DATA_TEXT = "UsageDataReceiver - [Custom Handler :: ---] (LocalSystem)"
ANALYZE_SYSTEM_TEXT = "AnalyzeSystem - [Custom Handler :: ---] (LocalSystemAccount)"
MALFORMED_TEXT = "malformed without delimiters"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _sample_row(
    text: str,
    *,
    action: str = "MOD",
    time: str = "2024-01-15 08:00:00",
) -> list[str]:
    return [time, "ShTask", action, "0", "0x0", "0x0", text, ""]


def _semantic_row(
    *,
    task_description: str = DEFENDER_TEXT,
    task_name: str = "Windows Defender Scheduled Scan",
    command_line: str = DEFENDER_CMD,
    parameters: str = DEFENDER_PARAMS,
    user: str = "LocalSystem",
    action: str = "MOD",
) -> list[str]:
    return [
        "2024-01-15 08:00:00",
        "ShTask",
        action,
        task_description,
        "",
        task_name,
        command_line,
        parameters,
        user,
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


def _get_task_text(row: dict[str, str]) -> str:
    """Mirror C# GetTaskText / GetTaskEventText."""
    task_description = _cell(row, "TaskDescription")
    if task_description:
        return task_description

    legacy_text = _cell(row, "Text")
    if legacy_text:
        return legacy_text

    task_name = _cell(row, "TaskName")
    command_line = _cell(row, "CommandLine")
    parameters = _cell(row, "Parameters")
    user = _cell(row, "User")
    if not any((task_name, command_line, parameters, user)):
        return ""

    return f"{task_name} - [{command_line} :: {parameters}] ({user})"


def _map_timeline_task(row: dict[str, str]) -> dict[str, str]:
    """Mirror C# MapTimelineTask field resolution."""
    return {
        "Time": _truncate(_cell(row, "Time"), 100),
        "Type": _truncate(_cell(row, "Type"), 100),
        "Action": _truncate(_cell(row, "Action"), 100),
        "Pid": _truncate(_cell(row, "PID", "pid"), 50),
        "Value32": _truncate(_cell(row, "Value32"), 100),
        "Value64": _truncate(_cell(row, "Value64"), 100),
        "Text": _get_task_text(row),
        "Pad": _truncate(_cell(row, "Pad"), 100),
    }


def _get_row_value(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _build_timeline_task_event_row(row: dict[str, str]) -> str:
    """Mirror C# RowHashBuilder.BuildTimelineTaskEventRow."""
    values = [
        _get_row_value(row, "Time", "time"),
        _get_row_value(row, "Type", "type"),
        _get_row_value(row, "Action", "action"),
        "",
        "",
        "",
        _get_task_text(row),
        _get_row_value(row, "Pad"),
    ]
    joined = "||".join(values)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _row_dict(headers: list[str], values: list[str]) -> dict[str, str]:
    return dict(zip(headers, values))


class TestParseTimelineTaskText:
    def test_normal_defender_scan(self) -> None:
        task_name, command_line, parameters, user = parse_timeline_task_text(DEFENDER_TEXT)
        assert task_name == "Windows Defender Scheduled Scan"
        assert command_line == DEFENDER_CMD
        assert parameters == DEFENDER_PARAMS
        assert user == "LocalSystem"

    def test_custom_handler(self) -> None:
        task_name, command_line, parameters, user = parse_timeline_task_text(USAGE_DATA_TEXT)
        assert task_name == "UsageDataReceiver"
        assert command_line == "Custom Handler"
        assert parameters == "---"
        assert user == "LocalSystem"

    def test_local_system_account(self) -> None:
        task_name, command_line, parameters, user = parse_timeline_task_text(ANALYZE_SYSTEM_TEXT)
        assert task_name == "AnalyzeSystem"
        assert command_line == "Custom Handler"
        assert parameters == "---"
        assert user == "LocalSystemAccount"

    def test_task_name_with_spaces(self) -> None:
        text = "AD RMS Rights Policy Template Management (Automated) - [Custom Handler :: ---] (LocalSystem)"
        task_name, _, _, _ = parse_timeline_task_text(text)
        assert task_name == "AD RMS Rights Policy Template Management (Automated)"

    def test_command_line_with_spaces(self) -> None:
        text = "My Task - [C:\\Program Files\\App\\tool.exe :: arg] (LocalSystem)"
        _, command_line, _, _ = parse_timeline_task_text(text)
        assert command_line == r"C:\Program Files\App\tool.exe"

    def test_parameters_with_multiple_switches(self) -> None:
        _, _, parameters, _ = parse_timeline_task_text(DEFENDER_TEXT)
        assert parameters == DEFENDER_PARAMS

    def test_parameters_literal_dashes(self) -> None:
        _, _, parameters, _ = parse_timeline_task_text(USAGE_DATA_TEXT)
        assert parameters == "---"

    def test_empty_command_line(self) -> None:
        text = "SomeTask - [ :: ---] (LocalSystem)"
        _, command_line, parameters, user = parse_timeline_task_text(text)
        assert command_line == ""
        assert parameters == "---"
        assert user == "LocalSystem"

    def test_empty_parameters(self) -> None:
        text = "SomeTask - [Custom Handler :: ] (LocalSystem)"
        _, command_line, parameters, user = parse_timeline_task_text(text)
        assert command_line == "Custom Handler"
        assert parameters == ""
        assert user == "LocalSystem"

    def test_empty_text(self) -> None:
        assert parse_timeline_task_text("") == ("", "", "", "")

    def test_malformed_without_delimiters(self) -> None:
        assert parse_timeline_task_text(MALFORMED_TEXT) == ("", "", "", "")


class TestEnrichTimelineTaskCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(DEFENDER_TEXT),
            _sample_row(USAGE_DATA_TEXT),
            _sample_row(MALFORMED_TEXT),
        ]

    def test_exact_final_header_order(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_TASK_OUTPUT_HEADERS)

    def test_task_description_equals_original_text(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(DEFENDER_TEXT)])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][3] == DEFENDER_TEXT

    def test_dropped_generic_columns_absent(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(DEFENDER_TEXT)])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "PID" not in table.headers
        assert "Value32" not in table.headers
        assert "Value64" not in table.headers
        assert "Text" not in table.headers
        assert "TaskDescription" in table.headers

    def test_parsed_fields(self, tmp_path: Path, sample_rows: list[list[str]]) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_task_csv(csv_path)

        table = read_csv_safe(csv_path)
        assert table.rows[0][5:9] == [
            "Windows Defender Scheduled Scan",
            DEFENDER_CMD,
            DEFENDER_PARAMS,
            "LocalSystem",
        ]
        assert table.rows[1][5:9] == [
            "UsageDataReceiver",
            "Custom Handler",
            "---",
            "LocalSystem",
        ]
        assert table.rows[2][5:9] == ["", "", "", ""]

    def test_malformed_description_preserved_with_empty_parsed_fields(
        self, tmp_path: Path
    ) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(MALFORMED_TEXT)])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][3] == MALFORMED_TEXT
        assert table.rows[0][5:9] == ["", "", "", ""]

    def test_quoted_text_with_comma(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        text = "My Task - [C:\\path\\a,b,c.exe :: run] (LocalSystem)"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(text)])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][3] == text
        assert table.rows[0][5:9] == ["My Task", r"C:\path\a,b,c.exe", "run", "LocalSystem"]

    def test_unicode_in_text(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        text = "משימה - [C:\\עברית\\tool.exe :: arg] (LocalSystem)"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(text)])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][3] == text
        assert table.rows[0][5:9] == ["משימה", r"C:\עברית\tool.exe", "arg", "LocalSystem"]

    def test_empty_text(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row("")])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][3] == ""
        assert table.rows[0][5:9] == ["", "", "", ""]

    def test_missing_text_header(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Pad"]
        rows = [["2024-01-15 08:00:00", "ShTask", "MOD", "0", "0x0", "0x0", ""]]
        _write_csv(csv_path, headers, rows)

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_TASK_OUTPUT_HEADERS)
        assert table.rows[0][3] == ""
        assert table.rows[0][5:9] == ["", "", "", ""]

    def test_row_count_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        row_count = enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)

    def test_no_duplicate_columns(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(DEFENDER_TEXT)])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert len(table.headers) == len(set(table.headers))

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_task_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_task_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows

    def test_already_semantic_with_extra_columns_not_rewritten(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        headers = list(TIMELINE_TASK_OUTPUT_HEADERS) + ["ExtraColumn"]
        row = _semantic_row() + ["keep-me"]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == headers
        assert table.rows[0] == row

    def test_already_semantic_with_different_header_order_not_rewritten(
        self, tmp_path: Path
    ) -> None:
        csv_path = tmp_path / "timeline_task.csv"
        headers = [
            "TaskName",
            "Time",
            "Type",
            "Action",
            "TaskDescription",
            "Pad",
            "CommandLine",
            "Parameters",
            "User",
        ]
        values = [
            "CustomName",
            "2024-01-15 08:00:00",
            "ShTask",
            "MOD",
            "stored description",
            "",
            "stored cmd",
            "stored params",
            "stored user",
        ]
        _write_csv(csv_path, headers, [values])

        enrich_timeline_task_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == headers
        assert table.rows[0] == values


class TestCSharpAliasParity:
    def test_legacy_and_semantic_rows_map_equivalent_text(self) -> None:
        generic = _row_dict(GENERIC_HEADERS, _sample_row(DEFENDER_TEXT))
        semantic = _row_dict(
            list(TIMELINE_TASK_OUTPUT_HEADERS),
            _semantic_row(),
        )

        generic_mapped = _map_timeline_task(generic)
        semantic_mapped = _map_timeline_task(semantic)

        assert generic_mapped["Text"] == semantic_mapped["Text"]
        assert generic_mapped["Time"] == semantic_mapped["Time"]
        assert generic_mapped["Type"] == semantic_mapped["Type"]
        assert generic_mapped["Action"] == semantic_mapped["Action"]
        assert generic_mapped["Pad"] == semantic_mapped["Pad"]

    def test_legacy_and_semantic_rows_hash_identically(self) -> None:
        generic = _row_dict(GENERIC_HEADERS, _sample_row(DEFENDER_TEXT))
        semantic = _row_dict(
            list(TIMELINE_TASK_OUTPUT_HEADERS),
            _semantic_row(),
        )

        assert _build_timeline_task_event_row(generic) == _build_timeline_task_event_row(
            semantic
        )


class TestTimelinesExtractorIntegration:
    def test_extract_enriches_task_process_and_registry(
        self, tmp_path: Path
    ) -> None:
        from extractors.timelines import TimelinesExtractor

        memprocfs_root = tmp_path / "memprocfs"
        forensic_csv = memprocfs_root / "forensic" / "csv"

        process_text = (
            r"powershell.exe [user3] \Device\HarddiskVolume3\Windows\System32"
            r"\WindowsPowerShell\v1.0\powershell.exe"
        )
        registry_path = r"\Software\Microsoft\Windows\CurrentVersion\Run"

        task_source = forensic_csv / "timeline_task.csv"
        process_source = forensic_csv / "timeline_process.csv"
        registry_source = forensic_csv / "timeline_registry.csv"
        web_source = forensic_csv / "timeline_web.csv"
        all_source = forensic_csv / "timeline_all.csv"

        _write_csv(task_source, GENERIC_HEADERS, [_sample_row(DEFENDER_TEXT, action="CRE")])
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
                    process_text,
                    "",
                ],
            ],
        )
        _write_csv(
            registry_source,
            list(TIMELINE_REGISTRY_GENERIC_HEADERS),
            [
                [
                    "2024-01-15 08:00:00",
                    "REG",
                    "Write",
                    "1234",
                    "0",
                    "0",
                    registry_path,
                    "",
                ],
            ],
        )
        _write_csv(
            web_source,
            GENERIC_HEADERS,
            [_sample_row("should not change", action="MOD")],
        )
        _write_csv(all_source, ["time"], [["2026-01-01"]])

        task_bytes = task_source.read_bytes()
        process_bytes = process_source.read_bytes()
        registry_bytes = registry_source.read_bytes()
        web_bytes = web_source.read_bytes()
        all_bytes = all_source.read_bytes()

        out_dir = tmp_path / "case" / "csv"
        out_dir.mkdir(parents=True)
        result = TimelinesExtractor().extract(memprocfs_root, out_dir)

        assert result.ok is True
        assert "timeline_task.csv" in result.files_written

        task = read_csv_safe(out_dir / "timeline_task.csv")
        assert task.headers == list(TIMELINE_TASK_OUTPUT_HEADERS)
        assert task.rows[0][3] == DEFENDER_TEXT
        assert task.rows[0][5:9] == [
            "Windows Defender Scheduled Scan",
            DEFENDER_CMD,
            DEFENDER_PARAMS,
            "LocalSystem",
        ]

        process = read_csv_safe(out_dir / "timeline_process.csv")
        assert process.headers == list(TIMELINE_PROCESS_OUTPUT_HEADERS)

        registry = read_csv_safe(out_dir / "timeline_registry.csv")
        assert registry.headers == list(TIMELINE_REGISTRY_OUTPUT_HEADERS)
        assert registry.rows[0][3] == registry_path

        web = read_csv_safe(out_dir / "timeline_web.csv")
        assert web.headers == list(TIMELINE_WEB_OUTPUT_HEADERS)

        timeline_all = read_csv_safe(out_dir / "timeline_all.csv")
        assert timeline_all.headers == ["time"]
        assert timeline_all.rows == [["2026-01-01"]]

        assert task_source.read_bytes() == task_bytes
        assert process_source.read_bytes() == process_bytes
        assert registry_source.read_bytes() == registry_bytes
        assert web_source.read_bytes() == web_bytes
        assert all_source.read_bytes() == all_bytes

    def test_task_enrichment_skipped_when_result_not_ok(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        task_path = out_dir / "timeline_task.csv"
        _write_csv(task_path, GENERIC_HEADERS, [_sample_row(DEFENDER_TEXT)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=False, error="copy failed")

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            returned = extractor.extract(tmp_path / "memprocfs", out_dir)

        assert returned.ok is False
        table = read_csv_safe(task_path)
        assert table.headers == GENERIC_HEADERS
        assert "TaskName" not in table.headers

    def test_task_enrichment_skipped_when_file_not_written(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        task_path = out_dir / "timeline_task.csv"
        _write_csv(task_path, GENERIC_HEADERS, [_sample_row(DEFENDER_TEXT)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=True, files_written=["timeline_all.csv"])

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            extractor.extract(tmp_path / "memprocfs", out_dir)

        table = read_csv_safe(task_path)
        assert table.headers == GENERIC_HEADERS
        assert "TaskName" not in table.headers

"""Tests for timeline_net Text parsing and extraction enrichment."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from extractors.timeline_net_text import (
    TIMELINE_NET_GENERIC_HEADERS,
    TIMELINE_NET_OUTPUT_HEADERS,
    enrich_timeline_net_csv,
    parse_network_endpoint,
    parse_timeline_net_text,
)
from extractors.timeline_process_text import TIMELINE_PROCESS_GENERIC_HEADERS, TIMELINE_PROCESS_OUTPUT_HEADERS
from extractors.timeline_registry_text import (
    TIMELINE_REGISTRY_GENERIC_HEADERS,
    TIMELINE_REGISTRY_OUTPUT_HEADERS,
)
from extractors.timeline_task_text import (
    TIMELINE_TASK_GENERIC_HEADERS,
    TIMELINE_TASK_OUTPUT_HEADERS,
)
from extractors.timeline_web_text import TIMELINE_WEB_OUTPUT_HEADERS
from memflow_common.csv_io import read_csv_safe

GENERIC_HEADERS = list(TIMELINE_NET_GENERIC_HEADERS)

TCPV4_ESTABLISHED_TEXT = (
    "TCPv4  ESTABLISHED  192.168.8.100:55615  142.250.75.142:443"
)
TCPV6_LISTENING_TEXT = "TCPv6  LISTENING  [::]:135  ***"
UDPV4_TEXT = "UDPv4  ***  0.0.0.0:5353  ***"
UDPV6_TEXT = "UDPv6  ***  [::]:54920  ***"
KERNEL_OBJECT_ADDRESS = "0xFFFFFA8012345678"
CONNECTION_TIME = "2024-01-15 08:00:00"

DEFENDER_TEXT = (
    "Windows Defender Scheduled Scan - "
    "[C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26040.7-0\\MpCmdRun.exe "
    ":: Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob] (LocalSystem)"
)


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _sample_row(
    text: str,
    *,
    action: str = "CRE",
    pid: str = "4528",
    value32: str = "0x0",
    value64: str = KERNEL_OBJECT_ADDRESS,
    time: str = CONNECTION_TIME,
) -> list[str]:
    return [time, "Net", action, pid, value32, value64, text, ""]


def _semantic_row(
    *,
    connection_time: str = CONNECTION_TIME,
    pid: str = "4528",
    kernel_object_address: str = KERNEL_OBJECT_ADDRESS,
    text: str = TCPV4_ESTABLISHED_TEXT,
) -> list[str]:
    protocol, state, src_addr, src_port, dst_addr, dst_port = parse_timeline_net_text(text)
    return [
        connection_time,
        "Net",
        "CRE",
        pid,
        kernel_object_address,
        protocol,
        state,
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        text,
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


def _map_timeline_net(row: dict[str, str]) -> dict[str, str]:
    """Mirror C# MapTimelineNet field resolution."""
    text = _cell(row, "ConnectionDescription", "Text")
    protocol = _cell(row, "Protocol")
    state = _cell(row, "State")
    source_address = _cell(row, "SourceAddress")
    source_port = _cell(row, "SourcePort")
    destination_address = _cell(row, "DestinationAddress")
    destination_port = _cell(row, "DestinationPort")

    if text and not any(
        (protocol, state, source_address, source_port, destination_address, destination_port)
    ):
        protocol, state, source_address, source_port, destination_address, destination_port = (
            parse_timeline_net_text(text)
        )

    return {
        "ConnectionTime": _truncate(_cell(row, "ConnectionTime", "Time"), 100),
        "Type": _truncate(_cell(row, "Type"), 100),
        "Action": _truncate(_cell(row, "Action"), 100),
        "Pid": _truncate(_cell(row, "PID", "pid"), 50),
        "KernelObjectAddress": _truncate(_cell(row, "KernelObjectAddress", "Value64"), 100),
        "Protocol": _truncate(protocol, 100),
        "State": _truncate(state, 100),
        "SourceAddress": _truncate(source_address, 100),
        "SourcePort": _truncate(source_port, 100),
        "DestinationAddress": _truncate(destination_address, 100),
        "DestinationPort": _truncate(destination_port, 100),
        "ConnectionDescription": text,
    }


def _get_row_value(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _build_timeline_net_event_row(row: dict[str, str]) -> str:
    """Mirror C# RowHashBuilder.BuildTimelineNetEventRow."""
    text = _get_row_value(row, "ConnectionDescription", "Text")
    protocol = _get_row_value(row, "Protocol")
    state = _get_row_value(row, "State")
    source_address = _get_row_value(row, "SourceAddress")
    source_port = _get_row_value(row, "SourcePort")
    destination_address = _get_row_value(row, "DestinationAddress")
    destination_port = _get_row_value(row, "DestinationPort")

    if text and not any(
        (
            protocol,
            state,
            source_address,
            source_port,
            destination_address,
            destination_port,
        )
    ):
        protocol, state, source_address, source_port, destination_address, destination_port = (
            parse_timeline_net_text(text)
        )

    values = [
        _get_row_value(row, "ConnectionTime", "Time"),
        _get_row_value(row, "Type", "type"),
        _get_row_value(row, "Action", "action"),
        _get_row_value(row, "PID", "pid"),
        _get_row_value(row, "KernelObjectAddress", "Value64"),
        protocol,
        state,
        source_address,
        source_port,
        destination_address,
        destination_port,
        text,
    ]
    joined = "||".join(values)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _row_dict(headers: list[str], values: list[str]) -> dict[str, str]:
    return dict(zip(headers, values))


class TestParseNetworkEndpoint:
    def test_ipv4(self) -> None:
        assert parse_network_endpoint("192.168.8.100:55615") == (
            "192.168.8.100",
            "55615",
        )

    def test_bracketed_ipv6_empty_address(self) -> None:
        assert parse_network_endpoint("[::]:135") == ("::", "135")

    def test_bracketed_ipv6_nonempty_address(self) -> None:
        assert parse_network_endpoint("[fe80::1]:443") == ("fe80::1", "443")

    def test_missing_endpoint_marker(self) -> None:
        assert parse_network_endpoint("***") == ("", "")

    def test_padded_missing_endpoint_marker(self) -> None:
        assert parse_network_endpoint("***                         ") == ("", "")

    def test_empty_string(self) -> None:
        assert parse_network_endpoint("") == ("", "")

    def test_malformed_empty_ipv6_address(self) -> None:
        assert parse_network_endpoint("[]:443") == ("", "")

    def test_malformed_empty_ipv6_port(self) -> None:
        assert parse_network_endpoint("[::]:") == ("", "")

    def test_malformed_no_port(self) -> None:
        assert parse_network_endpoint("192.168.1.1") == ("", "")

    def test_malformed_brackets_only(self) -> None:
        assert parse_network_endpoint("[::]") == ("", "")

    def test_malformed_unclosed_bracket(self) -> None:
        assert parse_network_endpoint("[fe80::1") == ("", "")

    def test_malformed_unbracketed_ipv6(self) -> None:
        assert parse_network_endpoint("fe80::1:443") == ("", "")


class TestParseTimelineNetText:
    def test_tcpv4_established(self) -> None:
        assert parse_timeline_net_text(TCPV4_ESTABLISHED_TEXT) == (
            "TCPv4",
            "ESTABLISHED",
            "192.168.8.100",
            "55615",
            "142.250.75.142",
            "443",
        )

    def test_tcpv6_listening(self) -> None:
        assert parse_timeline_net_text(TCPV6_LISTENING_TEXT) == (
            "TCPv6",
            "LISTENING",
            "::",
            "135",
            "",
            "",
        )

    def test_udpv4(self) -> None:
        assert parse_timeline_net_text(UDPV4_TEXT) == (
            "UDPv4",
            "***",
            "0.0.0.0",
            "5353",
            "",
            "",
        )

    def test_udpv6(self) -> None:
        assert parse_timeline_net_text(UDPV6_TEXT) == (
            "UDPv6",
            "***",
            "::",
            "54920",
            "",
            "",
        )

    def test_padded_udp_destination_marker(self) -> None:
        text = (
            "UDPv6  ***          [::]:61578                    "
            "***                         "
        )

        assert parse_timeline_net_text(text) == (
            "UDPv6",
            "***",
            "::",
            "61578",
            "",
            "",
        )

    def test_multiple_spaces(self) -> None:
        text = "TCPv4    ESTABLISHED    192.168.8.100:55615    142.250.75.142:443"
        assert parse_timeline_net_text(text) == (
            "TCPv4",
            "ESTABLISHED",
            "192.168.8.100",
            "55615",
            "142.250.75.142",
            "443",
        )

    def test_tabs(self) -> None:
        text = "TCPv4\tESTABLISHED\t192.168.8.100:55615\t142.250.75.142:443"
        assert parse_timeline_net_text(text) == (
            "TCPv4",
            "ESTABLISHED",
            "192.168.8.100",
            "55615",
            "142.250.75.142",
            "443",
        )

    def test_empty_text(self) -> None:
        assert parse_timeline_net_text("") == ("", "", "", "", "", "")

    def test_malformed_top_level(self) -> None:
        assert parse_timeline_net_text("TCPv4 ESTABLISHED") == (
            "",
            "",
            "",
            "",
            "",
            "",
        )


class TestEnrichTimelineNetCsv:
    @pytest.fixture
    def sample_rows(self) -> list[list[str]]:
        return [
            _sample_row(TCPV4_ESTABLISHED_TEXT),
            _sample_row(TCPV6_LISTENING_TEXT),
            _sample_row("malformed without delimiters"),
        ]

    def test_exact_final_header_order(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_NET_OUTPUT_HEADERS)
        assert table.headers[-1] == "ConnectionDescription"

    def test_value32_and_pad_removed(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(TCPV4_ESTABLISHED_TEXT)])

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "Value32" not in table.headers
        assert "Pad" not in table.headers

    def test_connection_time_and_kernel_object_address_renamed(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(TCPV4_ESTABLISHED_TEXT)])

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert "Time" not in table.headers
        assert "Value64" not in table.headers
        assert table.rows[0][0] == CONNECTION_TIME
        assert table.rows[0][4] == KERNEL_OBJECT_ADDRESS
        assert table.rows[0][3] == "4528"

    def test_parsed_fields(self, tmp_path: Path, sample_rows: list[list[str]]) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][5:11] == [
            "TCPv4",
            "ESTABLISHED",
            "192.168.8.100",
            "55615",
            "142.250.75.142",
            "443",
        ]
        assert table.rows[0][11] == TCPV4_ESTABLISHED_TEXT
        assert table.rows[1][5:11] == [
            "TCPv6",
            "LISTENING",
            "::",
            "135",
            "",
            "",
        ]
        assert table.rows[2][5:11] == ["", "", "", "", "", ""]

    def test_row_count_preserved(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)

        row_count = enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == len(sample_rows)
        assert table.row_count == len(sample_rows)

    def test_empty_text(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row("")])

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][11] == ""
        assert table.rows[0][5:11] == ["", "", "", "", "", ""]

    def test_missing_text_header(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        headers = ["Time", "Type", "Action", "PID", "Value32", "Value64", "Pad"]
        rows = [
            [
                CONNECTION_TIME,
                "Net",
                "CRE",
                "4528",
                "0x0",
                KERNEL_OBJECT_ADDRESS,
                "",
            ],
        ]
        _write_csv(csv_path, headers, rows)

        row_count = enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert row_count == 1
        assert table.headers == list(TIMELINE_NET_OUTPUT_HEADERS)
        assert table.rows[0][11] == ""
        assert table.rows[0][5:11] == ["", "", "", "", "", ""]

    def test_quoted_text_round_trip(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        text = "TCPv4  ESTABLISHED  192.168.8.100:55615  142.250.75.142:443"
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(text)])

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][11] == text
        assert table.rows[0][5:11] == [
            "TCPv4",
            "ESTABLISHED",
            "192.168.8.100",
            "55615",
            "142.250.75.142",
            "443",
        ]

    def test_padded_text_preserved_after_enrichment(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        text = (
            "UDPv6  ***          [::]:61578                    "
            "***                         "
        )
        _write_csv(csv_path, GENERIC_HEADERS, [_sample_row(text)])

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.rows[0][11] == text
        assert table.rows[0][5:11] == [
            "UDPv6",
            "***",
            "::",
            "61578",
            "",
            "",
        ]

    def test_partially_transformed_legacy_derived_layout(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        headers = list(GENERIC_HEADERS) + list(TIMELINE_NET_OUTPUT_HEADERS[5:11])
        row = _sample_row(TCPV4_ESTABLISHED_TEXT) + [
            "TCPv4",
            "ESTABLISHED",
            "192.168.8.100",
            "55615",
            "142.250.75.142",
            "443",
        ]
        _write_csv(csv_path, headers, [row])

        enrich_timeline_net_csv(csv_path)
        table = read_csv_safe(csv_path)

        assert table.headers == list(TIMELINE_NET_OUTPUT_HEADERS)
        assert table.rows[0] == _semantic_row()

    def test_idempotent_when_already_enriched(
        self, tmp_path: Path, sample_rows: list[list[str]]
    ) -> None:
        csv_path = tmp_path / "timeline_net.csv"
        _write_csv(csv_path, GENERIC_HEADERS, sample_rows)
        enrich_timeline_net_csv(csv_path)
        first = read_csv_safe(csv_path)

        enrich_timeline_net_csv(csv_path)
        second = read_csv_safe(csv_path)

        assert first.headers == second.headers
        assert first.rows == second.rows


class TestCSharpAliasParity:
    def test_generic_and_semantic_rows_map_equivalent_fields(self) -> None:
        generic = _row_dict(GENERIC_HEADERS, _sample_row(TCPV4_ESTABLISHED_TEXT))
        semantic = _row_dict(
            list(TIMELINE_NET_OUTPUT_HEADERS),
            _semantic_row(),
        )

        generic_mapped = _map_timeline_net(generic)
        semantic_mapped = _map_timeline_net(semantic)

        assert generic_mapped["ConnectionTime"] == semantic_mapped["ConnectionTime"]
        assert generic_mapped["KernelObjectAddress"] == semantic_mapped["KernelObjectAddress"]
        assert generic_mapped["Protocol"] == semantic_mapped["Protocol"] == "TCPv4"
        assert (
            generic_mapped["ConnectionDescription"]
            == semantic_mapped["ConnectionDescription"]
            == TCPV4_ESTABLISHED_TEXT
        )

    def test_generic_and_semantic_rows_hash_identically(self) -> None:
        generic = _row_dict(GENERIC_HEADERS, _sample_row(TCPV4_ESTABLISHED_TEXT))
        semantic = _row_dict(list(TIMELINE_NET_OUTPUT_HEADERS), _semantic_row())

        assert _build_timeline_net_event_row(generic) == _build_timeline_net_event_row(semantic)


class TestTimelinesExtractorIntegration:
    def test_extract_enriches_net_process_registry_and_task(
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

        net_source = forensic_csv / "timeline_net.csv"
        task_source = forensic_csv / "timeline_task.csv"
        process_source = forensic_csv / "timeline_process.csv"
        registry_source = forensic_csv / "timeline_registry.csv"
        web_source = forensic_csv / "timeline_web.csv"
        all_source = forensic_csv / "timeline_all.csv"

        _write_csv(
            net_source,
            GENERIC_HEADERS,
            [_sample_row(TCPV4_ESTABLISHED_TEXT)],
        )
        _write_csv(
            task_source,
            list(TIMELINE_TASK_GENERIC_HEADERS),
            [
                [
                    "2024-01-15 08:00:00",
                    "ShTask",
                    "MOD",
                    "0",
                    "0x0",
                    "0x0",
                    DEFENDER_TEXT,
                    "",
                ],
            ],
        )
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

        net_bytes = net_source.read_bytes()
        task_bytes = task_source.read_bytes()
        process_bytes = process_source.read_bytes()
        registry_bytes = registry_source.read_bytes()
        web_bytes = web_source.read_bytes()
        all_bytes = all_source.read_bytes()

        out_dir = tmp_path / "case" / "csv"
        out_dir.mkdir(parents=True)
        result = TimelinesExtractor().extract(memprocfs_root, out_dir)

        assert result.ok is True
        assert "timeline_net.csv" in result.files_written

        net = read_csv_safe(out_dir / "timeline_net.csv")
        assert net.headers == list(TIMELINE_NET_OUTPUT_HEADERS)
        assert net.headers[-1] == "ConnectionDescription"
        assert net.rows[0][11] == TCPV4_ESTABLISHED_TEXT
        assert net.rows[0][5:11] == [
            "TCPv4",
            "ESTABLISHED",
            "192.168.8.100",
            "55615",
            "142.250.75.142",
            "443",
        ]
        assert "Value32" not in net.headers
        assert "Pad" not in net.headers

        task = read_csv_safe(out_dir / "timeline_task.csv")
        assert task.headers == list(TIMELINE_TASK_OUTPUT_HEADERS)
        assert "TaskName" in task.headers

        process = read_csv_safe(out_dir / "timeline_process.csv")
        assert process.headers == list(TIMELINE_PROCESS_OUTPUT_HEADERS)
        assert "ProcessName" in process.headers

        registry = read_csv_safe(out_dir / "timeline_registry.csv")
        assert registry.headers == list(TIMELINE_REGISTRY_OUTPUT_HEADERS)
        assert "RegistryPath" in registry.headers

        web = read_csv_safe(out_dir / "timeline_web.csv")
        assert web.headers == list(TIMELINE_WEB_OUTPUT_HEADERS)

        timeline_all = read_csv_safe(out_dir / "timeline_all.csv")
        assert timeline_all.headers == ["time"]
        assert timeline_all.rows == [["2026-01-01"]]

        assert net_source.read_bytes() == net_bytes
        assert task_source.read_bytes() == task_bytes
        assert process_source.read_bytes() == process_bytes
        assert registry_source.read_bytes() == registry_bytes
        assert web_source.read_bytes() == web_bytes
        assert all_source.read_bytes() == all_bytes

    def test_net_enrichment_skipped_when_result_not_ok(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        net_path = out_dir / "timeline_net.csv"
        _write_csv(net_path, GENERIC_HEADERS, [_sample_row(TCPV4_ESTABLISHED_TEXT)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=False, error="copy failed")

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            returned = extractor.extract(tmp_path / "memprocfs", out_dir)

        assert returned.ok is False
        table = read_csv_safe(net_path)
        assert table.headers == GENERIC_HEADERS
        assert "ConnectionTime" not in table.headers

    def test_net_enrichment_skipped_when_file_not_written(
        self, tmp_path: Path
    ) -> None:
        from extractors.base import ExtractResult
        from extractors.timelines import TimelinesExtractor

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        net_path = out_dir / "timeline_net.csv"
        _write_csv(net_path, GENERIC_HEADERS, [_sample_row(TCPV4_ESTABLISHED_TEXT)])

        extractor = TimelinesExtractor()
        result = ExtractResult(ok=True, files_written=["timeline_all.csv"])

        with patch.object(
            extractor,
            "copy_forensic_csvs_matching",
            return_value=result,
        ):
            extractor.extract(tmp_path / "memprocfs", out_dir)

        table = read_csv_safe(net_path)
        assert table.headers == GENERIC_HEADERS
        assert "ConnectionTime" not in table.headers

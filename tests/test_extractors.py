"""Tests for file-based extractor architecture."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from extractors import discover_extractors
from extractors.base import BaseExtractor


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


@pytest.fixture
def memprocfs_root(tmp_path: Path) -> Path:
    root = tmp_path / "memprocfs"
    _write_csv(
        root / "forensic" / "csv" / "process.csv",
        ["pid", "ppid", "pppid", "name", "parent_name", "grandparent_name", "path", "user", "username", "cmdline", "state", "create_time", "exit_time", "wow64"],
        [["10", "4", "0", "child.exe", "System", "", "C:\\child.exe", "S-1", "SYSTEM", "child.exe", "0", "", "", "False"]],
    )
    # DllsExtractor prefers modules.csv (MemProcFS forensic); dlls.csv is fallback only.
    _write_csv(
        root / "forensic" / "csv" / "modules.csv",
        [
            "PID", "Process", "Name", "Wow64", "Size", "Start", "Path", "KernelPath",
        ],
        [
            [
                "10",
                "child.exe",
                "ntdll.dll",
                "0",
                "0x1000",
                "0x1000",
                r"C:\Windows\System32\ntdll.dll",
                "",
            ],
        ],
    )
    _write_csv(root / "forensic" / "csv" / "handles.csv", ["pid"], [["10"]])
    _write_csv(root / "forensic" / "csv" / "timeline_all.csv", ["time"], [["2026-01-01"]])
    _write_csv(
        root / "forensic" / "csv" / "timeline_process.csv",
        ["Time", "Type", "Action", "PID", "Value32", "Value64", "Text", "Pad"],
        [[
            "2024-01-15 08:00:00",
            "PROC",
            "Create",
            "1234",
            "0",
            "0",
            (
                r"powershell.exe [user3] \Device\HarddiskVolume3\Windows\System32"
                r"\WindowsPowerShell\v1.0\powershell.exe"
            ),
            "",
        ]],
    )
    # Primary network source: forensic net.csv (MemProcFS); netstat.txt is fallback only.
    _write_csv(
        root / "forensic" / "csv" / "net.csv",
        ["Proto", "SrcAddr", "SrcPort", "DstAddr", "DstPort", "State", "PID", "Process"],
        [["TCP", "0.0.0.0", "80", "0.0.0.0", "0", "LISTENING", "10", "child.exe"]],
    )
    _write_csv(
        root / "forensic" / "csv" / "services.csv",
        ["PID", "Ordinal", "ServiceName", "DisplayName", "User", "StartType", "State", "ImagePath", "DriverpathOrCmdline"],
        [["456", "0", "LanmanServer", "Server", "NT AUTHORITY\\NETWORK SERVICE", "3", "4", r"C:\Windows\system32\svchost.exe", ""]],
    )
    _write_csv(
        root / "forensic" / "csv" / "tasks.csv",
        ["GUID", "TaskName", "TaskPath", "User", "TimeMostRecent", "CommandLine", "Parameters", "TimeReg", "TimeCreate", "TimeLastRun", "TimeCompleted"],
        [["{00000000-0000-0000-0000-000000000001}", "TestTask", "\\Test", "SYSTEM", "2026-01-01", "cmd.exe", "/c echo", "2026-01-01", "2026-01-01", "", ""]],
    )
    _write_csv(
        root / "forensic" / "csv" / "drivers.csv",
        ["Name", "ObjectAddress", "Size", "Start", "End", "ServiceKey", "DriverName", "DriverPath"],
        [["CLFS", "0xffffe501e8f9ee10", "0x8a000", "0xfffff804679d0000", "0xfffff80467a59fff", "CLFS", "CLFS", r"\SystemRoot\System32\drivers\CLFS.SYS"]],
    )
    return root


def test_discover_extractors() -> None:
    registry = discover_extractors()
    assert "processes" in registry
    assert "dlls" in registry
    assert "netstat" in registry
    assert "timelines" in registry


def test_copy_forensic_csv_file_based(memprocfs_root: Path, tmp_path: Path) -> None:
    result = BaseExtractor.copy_forensic_csv(memprocfs_root, "process.csv", tmp_path)
    assert result.ok is True
    assert (tmp_path / "process.csv").exists()
    assert result.rows == 1


def test_processes_extractor_file_based(memprocfs_root: Path, tmp_path: Path) -> None:
    from extractors.processes import ProcessesExtractor

    result = ProcessesExtractor().extract(memprocfs_root, tmp_path)
    assert result.ok is True
    with (tmp_path / "process.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0][0] == "pid"
    assert rows[1][0] == "10"


def test_processes_path_userpath_kernelpath(tmp_path: Path) -> None:
    from extractors.processes import ProcessesExtractor

    root = tmp_path / "memprocfs"
    _write_csv(
        root / "forensic" / "csv" / "process.csv",
        ["PID", "PPID", "Name", "UserPath", "KernelPath", "User", "CommandLine", "State", "CreateTime", "ExitTime", "Wow64"],
        [["100", "4", "smss.exe", "", r"\SystemRoot\System32\smss.exe", "S-1-5-18", r"\SystemRoot\System32\smss.exe", "0", "", "", "0"]],
    )
    result = ProcessesExtractor().extract(root, tmp_path)
    assert result.ok is True
    with (tmp_path / "process.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["path"].lower().startswith("\\systemroot")


def test_dlls_extractor_file_based(memprocfs_root: Path, tmp_path: Path) -> None:
    from extractors.dlls import DllsExtractor

    result = DllsExtractor().extract(memprocfs_root, tmp_path)
    assert result.ok is True
    with (tmp_path / "dlls.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0][2] == "module_name"
    assert rows[1][2] == "ntdll.dll"


def test_netstat_extractor_forensic_csv(memprocfs_root: Path, tmp_path: Path) -> None:
    from extractors.netstat import NetstatExtractor

    result = NetstatExtractor().extract(memprocfs_root, tmp_path)
    assert result.ok is True
    with (tmp_path / "net.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0][1] == "process_name"
    assert rows[1][1] == "child.exe"
    assert rows[1][3] == "LISTENING"


def test_services_extractor_canonical(tmp_path: Path, memprocfs_root: Path) -> None:
    from extractors.services import ServicesExtractor

    out = tmp_path / "out"
    out.mkdir()
    result = ServicesExtractor().extract(memprocfs_root, out)
    assert result.ok is True
    with (out / "services.csv").open("r", encoding="utf-8", newline="") as fh:
        r = list(csv.DictReader(fh))
    assert r[0]["service_name"] == "LanmanServer"
    assert "svchost" in r[0]["binary_path"].lower()


def test_tasks_extractor_canonical(tmp_path: Path, memprocfs_root: Path) -> None:
    from extractors.tasks import TasksExtractor

    out = tmp_path / "out2"
    out.mkdir()
    result = TasksExtractor().extract(memprocfs_root, out)
    assert result.ok is True
    with (out / "tasks.csv").open("r", encoding="utf-8", newline="") as fh:
        r = list(csv.DictReader(fh))
    assert r[0]["name"] == "TestTask"
    assert "TimeMostRecent" in r[0]["trigger"]


def test_drivers_extractor_canonical(tmp_path: Path, memprocfs_root: Path) -> None:
    from extractors.drivers import DriversExtractor

    out = tmp_path / "out3"
    out.mkdir()
    result = DriversExtractor().extract(memprocfs_root, out)
    assert result.ok is True
    with (out / "drivers.csv").open("r", encoding="utf-8", newline="") as fh:
        r = list(csv.DictReader(fh))
    assert r[0]["service_name"] == "CLFS"
    assert r[0]["name"] == "CLFS"


def test_timelines_prefix_copy(memprocfs_root: Path, tmp_path: Path) -> None:
    from extractors.timelines import TimelinesExtractor

    result = TimelinesExtractor().extract(memprocfs_root, tmp_path)
    assert result.ok is True
    assert "timeline_all.csv" in result.files_written


def test_timeline_process_enriched_on_extract(memprocfs_root: Path, tmp_path: Path) -> None:
    from extractors.timeline_process_text import TIMELINE_PROCESS_OUTPUT_HEADERS
    from extractors.timelines import TimelinesExtractor
    from memflow_common.csv_io import read_csv_safe

    source_path = memprocfs_root / "forensic" / "csv" / "timeline_process.csv"
    source_bytes = source_path.read_bytes()

    result = TimelinesExtractor().extract(memprocfs_root, tmp_path)
    assert result.ok is True
    assert "timeline_process.csv" in result.files_written

    table = read_csv_safe(tmp_path / "timeline_process.csv")
    assert table.headers == list(TIMELINE_PROCESS_OUTPUT_HEADERS)
    assert table.rows[0][6].startswith("powershell.exe [user3]")
    assert table.rows[0][8:] == [
        "powershell.exe",
        "user3",
        (
            r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0"
            r"\powershell.exe"
        ),
    ]

    timeline_all = read_csv_safe(tmp_path / "timeline_all.csv")
    assert timeline_all.headers == ["time"]
    assert timeline_all.rows == [["2026-01-01"]]
    assert source_path.read_bytes() == source_bytes


def test_netstat_fallback_vfs_txt(tmp_path: Path) -> None:
    """When forensic net.csv is absent, parse netstat.txt."""
    root = tmp_path / "mfs"
    fc = root / "forensic" / "csv"
    fc.mkdir(parents=True)
    _write_csv(
        fc / "process.csv",
        ["pid", "name"],
        [["44", "svc.exe"]],
    )
    netdir = root / "sys" / "net"
    netdir.mkdir(parents=True)
    (netdir / "netstat.txt").write_text(
        "Proto  Local Address  Foreign Address  State  PID\n"
        "TCP    127.0.0.1:443  0.0.0.0:0        LISTENING  44\n",
        encoding="utf-8",
    )
    from extractors.netstat import NetstatExtractor

    out = tmp_path / "nout"
    out.mkdir()
    result = NetstatExtractor().extract(root, out)
    assert result.ok is True
    with (out / "net.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["pid"] == "44"
    assert rows[0]["process_name"] == "svc.exe"


def test_orchestrator_list_flag() -> None:
    from run_extract import main

    assert main(["--list"]) == 0


def test_orchestrator_missing_args() -> None:
    from run_extract import main

    with pytest.raises(SystemExit):
        main(["--dump-path", "x"])

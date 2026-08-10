"""Tests for HandlesExtractor ProcessName enrichment with VFS gate."""

from __future__ import annotations

import csv
from pathlib import Path

from extractors.handles import (
    PROCESS_NAME_HEADERS,
    HandlesExtractor,
    verify_handle_vfs,
)
from extractors.pid_ownership import (
    VfsContext,
    build_process_name_map,
    normalize_hex_address,
    parse_handles_txt,
)
from memflow_common.csv_io import read_csv_safe

HANDLE_HEADERS = [
    "PID",
    "Handle",
    "Object",
    "Access",
    "Type",
    "Tag",
    "HandleCount",
    "Device",
    "Description",
]

DEFAULT_OBJECT = "ffff83073ed52c00"
DEFAULT_HANDLE = "34"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _handle_row(
    *,
    pid: str = "1000",
    handle: str = DEFAULT_HANDLE,
    obj: str = DEFAULT_OBJECT,
    access: str = "3",
    htype: str = "Directory",
    description: str = "KnownDlls",
) -> list[str]:
    return [pid, handle, obj, access, htype, "", "0x1", "", description]


def _write_handles_txt(
    path: Path,
    *,
    pid: str = "1000",
    handle: str = DEFAULT_HANDLE,
    obj: str = DEFAULT_OBJECT,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#       PID  Handle Object Address   Access Type             Description\n"
        "========================================================================\n"
        f"000c   {pid}      {handle} {obj}      3 Directory        KnownDlls\n",
        encoding="utf-8",
    )


def _write_name_txt(path: Path, name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(name + "\n", encoding="utf-8")


def _write_process_csv(root: Path, rows: list[list[str]]) -> None:
    _write_csv(
        root / "forensic" / "csv" / "process.csv",
        ["pid", "ppid", "name"],
        rows,
    )


def _setup_handles(
    root: Path,
    handle_rows: list[list[str]],
) -> None:
    _write_csv(root / "forensic" / "csv" / "handles.csv", HANDLE_HEADERS, handle_rows)


class TestParseHelpers:
    def test_parse_handles_txt(self, tmp_path: Path) -> None:
        path = tmp_path / "handles.txt"
        _write_handles_txt(path)
        index = parse_handles_txt(path)
        assert index is not None
        assert index[normalize_hex_address(DEFAULT_HANDLE)] == normalize_hex_address(
            DEFAULT_OBJECT
        )

    def test_build_process_name_map(self, tmp_path: Path) -> None:
        _write_process_csv(tmp_path, [["1000", "4", "chrome.exe"]])
        mapping = build_process_name_map(tmp_path)
        assert mapping["1000"] == "chrome.exe"

    def test_verify_handle_vfs(self, tmp_path: Path) -> None:
        _write_handles_txt(tmp_path / "pid" / "1000" / "handles" / "handles.txt")
        ctx = VfsContext(tmp_path)
        assert (
            verify_handle_vfs("1000", DEFAULT_HANDLE, DEFAULT_OBJECT, ctx) == "ok"
        )
        assert (
            verify_handle_vfs("1000", "0x" + DEFAULT_HANDLE, "0x" + DEFAULT_OBJECT, ctx)
            == "ok"
        )
        assert (
            verify_handle_vfs("1000", DEFAULT_HANDLE, "ffff83073ed52c01", ctx)
            == "object_mismatch"
        )
        assert verify_handle_vfs("1000", "99", DEFAULT_OBJECT, ctx) == "no_vfs_handle"
        assert verify_handle_vfs("9999", DEFAULT_HANDLE, DEFAULT_OBJECT, ctx) == (
            "no_vfs_handle"
        )


class TestHandlesExtractor:
    def test_vfs_match_fills_name_from_name_txt(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(root, [_handle_row()])
        _write_handles_txt(root / "pid" / "1000" / "handles" / "handles.txt")
        _write_name_txt(root / "pid" / "1000" / "name.txt", "chrome.exe")

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = HandlesExtractor().extract(root, out_dir)

        assert result.ok
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.headers[-2:] == list(PROCESS_NAME_HEADERS)
        assert table.rows[0][-2:] == ["chrome.exe", "ok"]

    def test_missing_handles_txt(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(root, [_handle_row()])
        _write_name_txt(root / "pid" / "1000" / "name.txt", "chrome.exe")

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        HandlesExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.rows[0][-2:] == ["", "no_vfs_handle"]

    def test_object_mismatch(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(root, [_handle_row(obj="ffff83073ed52c01")])
        _write_handles_txt(root / "pid" / "1000" / "handles" / "handles.txt")
        _write_name_txt(root / "pid" / "1000" / "name.txt", "chrome.exe")

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        HandlesExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.rows[0][-2:] == ["", "object_mismatch"]

    def test_vfs_ok_falls_back_to_process_csv(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(root, [_handle_row()])
        _write_handles_txt(root / "pid" / "1000" / "handles" / "handles.txt")
        _write_process_csv(root, [["1000", "4", "chrome.exe"]])

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        HandlesExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.rows[0][-2:] == ["chrome.exe", "ok"]

    def test_csv_only_without_vfs_joins_process_csv(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(root, [_handle_row()])
        _write_process_csv(root, [["1000", "4", "notepad.exe"]])

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = HandlesExtractor(allow_csv_only=True).extract(root, out_dir)
        assert result.ok
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.rows[0][-2:] == ["notepad.exe", "ok"]

    def test_unknown_pid_no_process(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(root, [_handle_row(pid="9999")])
        _write_handles_txt(
            root / "pid" / "9999" / "handles" / "handles.txt",
            pid="9999",
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        HandlesExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.rows[0][-2:] == ["", "no_process"]

    def test_preserves_original_columns(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(root, [_handle_row(description="Special")])
        _write_handles_txt(root / "pid" / "1000" / "handles" / "handles.txt")
        _write_name_txt(root / "pid" / "1000" / "name.txt", "chrome.exe")

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        HandlesExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.headers[: len(HANDLE_HEADERS)] == HANDLE_HEADERS
        assert table.rows[0][8] == "Special"

    def test_cache_reads_handles_and_name_once_per_pid(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_handles(
            root,
            [
                _handle_row(handle="34"),
                _handle_row(handle="a4", obj="ffff978117262ca0"),
            ],
        )
        handles_path = root / "pid" / "1000" / "handles" / "handles.txt"
        handles_path.parent.mkdir(parents=True, exist_ok=True)
        handles_path.write_text(
            "#       PID  Handle Object Address   Access Type             Description\n"
            "========================================================================\n"
            f"000c   1000      34 {DEFAULT_OBJECT}      3 Directory        KnownDlls\n"
            "0028   1000      a4 ffff978117262ca0  f037f WindowStation    WinSta0\n",
            encoding="utf-8",
        )
        _write_name_txt(root / "pid" / "1000" / "name.txt", "chrome.exe")

        ctx = VfsContext(root)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        HandlesExtractor(ctx=ctx).extract(root, out_dir)

        assert ctx.handles_txt_reads == 1
        assert ctx.name_txt_reads == 1
        table = read_csv_safe(out_dir / "handles.csv")
        assert table.rows[0][-2:] == ["chrome.exe", "ok"]
        assert table.rows[1][-2:] == ["chrome.exe", "ok"]

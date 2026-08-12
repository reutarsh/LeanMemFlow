"""Tests for ThreadsExtractor module-start enrichment with VFS gate."""

from __future__ import annotations

import csv
from pathlib import Path

from extractors.pid_ownership import (
    VfsContext,
    normalize_hex_address,
    parse_address,
    parse_info_txt_ethread,
)
from extractors.threads import (
    START_MODULE_HEADERS,
    ThreadsExtractor,
    find_containing_module,
    resolve_thread_start_address,
    verify_thread_vfs,
)
from memflow_common.csv_io import read_csv_safe

THREAD_HEADERS = [
    "PID",
    "TID",
    "ETHREAD",
    "State",
    "WaitReason",
    "CreateTime",
    "ExitTime",
    "Running",
    "BasePriority",
    "Priority",
    "ExitStatus",
    "StartAddress",
    "Win32StartAddress",
    "IP",
    "SP",
    "TEB",
    "StackBaseUser",
    "StackLimitUser",
    "StackBaseKernel",
    "StackLimitKernel",
    "TrapFrame",
    "ImpersonationToken",
]

MODULE_HEADERS = [
    "PID",
    "Process",
    "Name",
    "Wow64",
    "Size",
    "Start",
    "End",
    "Path",
    "KernelPath",
]

DEFAULT_ETHREAD = "ffff800000000001"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def _write_info_txt(path: Path, ethread: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"PID:                      1000\n"
        f"TID:                      2000\n"
        f"ETHREAD:            {ethread}\n"
        f"TEB:                         0\n",
        encoding="utf-8",
    )


def _thread_row(
    *,
    pid: str = "1000",
    tid: str = "2000",
    ethread: str = DEFAULT_ETHREAD,
    create_time: str = "2024-01-15 08:00:00",
    start_address: str = "0x7ff000001000",
    win32_start_address: str = "0x7ff000001234",
) -> list[str]:
    return [
        pid,
        tid,
        ethread,
        "Waiting",
        "UserRequest",
        create_time,
        "",
        "0",
        "8",
        "8",
        "0",
        start_address,
        win32_start_address,
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "",
    ]


def _module_row(
    *,
    pid: str,
    name: str,
    start: str,
    end: str,
    path: str,
    process: str = "app.exe",
    size: str = "0x1000",
) -> list[str]:
    return [pid, process, name, "0", size, start, end, path, ""]


def _setup_forensic(
    root: Path,
    *,
    thread_rows: list[list[str]],
    module_rows: list[list[str]],
) -> Path:
    forensic = root / "forensic" / "csv"
    _write_csv(forensic / "threads.csv", THREAD_HEADERS, thread_rows)
    _write_csv(forensic / "modules.csv", MODULE_HEADERS, module_rows)
    return forensic


class TestParseHelpers:
    def test_parse_address_hex_and_dec(self) -> None:
        assert parse_address("0x10") == 16
        assert parse_address("16") == 16
        assert parse_address("") is None
        assert parse_address("nope") is None

    def test_parse_address_bare_hex_without_prefix(self) -> None:
        assert parse_address("7ff791d2bfd0") == 0x7FF791D2BFD0
        assert parse_address("fffff804d65d3080") == 0xFFFFF804D65D3080

    def test_normalize_hex_address(self) -> None:
        assert normalize_hex_address("0xFFFF800000000001") == normalize_hex_address(
            "ffff800000000001"
        )
        assert normalize_hex_address("0x0") == "0"

    def test_format_module_rva(self) -> None:
        from extractors.threads import format_module_rva

        assert format_module_rva(0) == "0x0"
        assert format_module_rva(0x7BFD0) == "0x7bfd0"

    def test_find_containing_module_tightest(self) -> None:
        from extractors.threads import _ModuleRange

        exe = _ModuleRange(0x1000, 0x3000, "app.exe", r"C:\app.exe", "0x1000")
        dll = _ModuleRange(0x1800, 0x1FFF, "lib.dll", r"C:\lib.dll", "0x1800")
        match = find_containing_module([exe, dll], 0x1900)
        assert match is not None
        assert match.name == "lib.dll"

    def test_parse_info_txt_ethread(self, tmp_path: Path) -> None:
        path = tmp_path / "info.txt"
        _write_info_txt(path, "ffffce818c617040")
        assert parse_info_txt_ethread(path) == "ffffce818c617040"

    def test_verify_thread_vfs(self, tmp_path: Path) -> None:
        info = tmp_path / "pid" / "1000" / "threads" / "2000" / "info.txt"
        _write_info_txt(info, DEFAULT_ETHREAD)
        assert verify_thread_vfs(tmp_path, "1000", "2000", DEFAULT_ETHREAD) == "ok"
        assert verify_thread_vfs(tmp_path, "1000", "2000", "0x" + DEFAULT_ETHREAD) == "ok"
        assert (
            verify_thread_vfs(tmp_path, "1000", "2000", "ffffce818c617040")
            == "ethread_mismatch"
        )
        assert verify_thread_vfs(tmp_path, "1000", "9999", DEFAULT_ETHREAD) == "no_vfs_thread"


class TestThreadsExtractor:
    def test_vfs_match_fills_module(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[
                _thread_row(
                    start_address="fffff804d65d3080",
                    win32_start_address="7ff791d2bfd0",
                )
            ],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff791cb0000",
                    end="0x7ff79213afff",
                    path=r"C:\app.exe",
                )
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "2000" / "info.txt",
            DEFAULT_ETHREAD,
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = ThreadsExtractor().extract(root, out_dir)

        assert result.ok
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.headers[-5:] == list(START_MODULE_HEADERS)
        assert table.rows[0][-5:] == [
            "app.exe",
            r"C:\app.exe",
            "0x7ff791cb0000",
            "0x7bfd0",
            "ok",
        ]

    def test_missing_vfs_leaves_empty(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[_thread_row()],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                )
            ],
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == ["", "", "", "", "no_vfs_thread"]

    def test_ethread_mismatch(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[_thread_row()],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                )
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "2000" / "info.txt",
            "ffffce818c617040",
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == ["", "", "", "", "ethread_mismatch"]

    def test_vfs_ok_va_outside_modules(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[_thread_row(win32_start_address="0xAAAAAAAA")],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                )
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "2000" / "info.txt",
            DEFAULT_ETHREAD,
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == ["", "", "", "", "no_module"]

    def test_hit_inside_dll_prefers_tightest(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[
                _thread_row(
                    start_address="0x0",
                    win32_start_address="0x7ff000001900",
                )
            ],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                ),
                _module_row(
                    pid="1000",
                    name="lib.dll",
                    start="0x7ff000001800",
                    end="0x7ff000001fff",
                    path=r"C:\lib.dll",
                    size="0x800",
                ),
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "2000" / "info.txt",
            DEFAULT_ETHREAD,
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == [
            "lib.dll",
            r"C:\lib.dll",
            "0x7ff000001800",
            "0x100",
            "ok",
        ]

    def test_pid4_early_createtime_still_fills_with_vfs(self, tmp_path: Path) -> None:
        """CreateTime earlier than process create no longer blocks the join."""
        root = tmp_path / "memprocfs"
        ethread = "ffffce818c781280"
        _setup_forensic(
            root,
            thread_rows=[
                _thread_row(
                    pid="4",
                    tid="208",
                    ethread=ethread,
                    create_time="2026-05-26 05:07:42",
                    start_address="fffff8079e6171c0",
                    win32_start_address="fffff8079e6171c0",
                )
            ],
            module_rows=[
                _module_row(
                    pid="4",
                    name="ntoskrnl.exe",
                    start="0xfffff8079dc00000",
                    end="0xfffff8079f04ffff",
                    path=r"\SystemRoot\system32\ntoskrnl.exe",
                    process="System",
                )
            ],
        )
        _write_info_txt(
            root / "pid" / "4" / "threads" / "208" / "info.txt",
            ethread,
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == [
            "ntoskrnl.exe",
            r"\SystemRoot\system32\ntoskrnl.exe",
            "0xfffff8079dc00000",
            "0xa171c0",
            "ok",
        ]

    def test_csv_only_without_vfs_fills_on_range_hit(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[_thread_row(win32_start_address="0x7ff000001234")],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                )
            ],
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = ThreadsExtractor(allow_csv_only=True).extract(root, out_dir)
        assert result.ok
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == [
            "app.exe",
            r"C:\app.exe",
            "0x7ff000000000",
            "0x1234",
            "ok",
        ]

    def test_cross_pid_modules_ignored(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[_thread_row(pid="1000", win32_start_address="0x7ff000001234")],
            module_rows=[
                _module_row(
                    pid="9999",
                    name="other.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\other.exe",
                )
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "2000" / "info.txt",
            DEFAULT_ETHREAD,
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == ["", "", "", "", "no_modules_for_pid"]

    def test_end_reconstructed_from_size_when_missing(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        forensic = root / "forensic" / "csv"
        _write_csv(
            forensic / "threads.csv",
            THREAD_HEADERS,
            [_thread_row(win32_start_address="0x1005")],
        )
        _write_csv(
            forensic / "modules.csv",
            ["PID", "Process", "Name", "Wow64", "Size", "Start", "Path", "KernelPath"],
            [
                [
                    "1000",
                    "app.exe",
                    "app.exe",
                    "0",
                    "0x1000",
                    "0x1000",
                    r"C:\app.exe",
                    "",
                ]
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "2000" / "info.txt",
            DEFAULT_ETHREAD,
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-5:] == [
            "app.exe",
            r"C:\app.exe",
            "0x1000",
            "0x5",
            "ok",
        ]

    def test_preserves_original_thread_columns(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[_thread_row(tid="4242")],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                )
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "4242" / "info.txt",
            DEFAULT_ETHREAD,
        )

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor().extract(root, out_dir)
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.headers[: len(THREAD_HEADERS)] == THREAD_HEADERS
        assert table.rows[0][1] == "4242"

    def test_ethread_cache_reads_info_txt_once_per_tid(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[
                _thread_row(tid="2000", win32_start_address="0x7ff000001234"),
                _thread_row(tid="2000", win32_start_address="0x7ff000001234"),
            ],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                )
            ],
        )
        _write_info_txt(
            root / "pid" / "1000" / "threads" / "2000" / "info.txt",
            DEFAULT_ETHREAD,
        )

        ctx = VfsContext(root)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor(ctx=ctx).extract(root, out_dir)

        # Preload + gate share one read per unique TID.
        assert ctx.info_txt_reads == 1
        assert ("1000", "2000") in ctx.ethreads
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-1] == "ok"
        assert table.rows[1][-1] == "ok"

    def test_seeded_ethreads_skip_disk_reads(self, tmp_path: Path) -> None:
        root = tmp_path / "memprocfs"
        _setup_forensic(
            root,
            thread_rows=[_thread_row(win32_start_address="0x7ff000001234")],
            module_rows=[
                _module_row(
                    pid="1000",
                    name="app.exe",
                    start="0x7ff000000000",
                    end="0x7ff00000ffff",
                    path=r"C:\app.exe",
                )
            ],
        )
        ctx = VfsContext(root)
        ctx.seed_ethreads({("1000", "2000"): DEFAULT_ETHREAD})
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ThreadsExtractor(ctx=ctx).extract(root, out_dir)
        assert ctx.info_txt_reads == 0
        table = read_csv_safe(out_dir / "threads.csv")
        assert table.rows[0][-1] == "ok"

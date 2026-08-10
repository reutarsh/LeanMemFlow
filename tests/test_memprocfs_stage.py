"""Tests for MemProcFS local staging and cleanup."""

from __future__ import annotations

import csv
from pathlib import Path

from memflow_common.memprocfs_stage import (
    STAGE_DIRNAME,
    default_stage_root,
    remove_memprocfs_stage,
    stage_memprocfs_tree,
)


def _write(path: Path, text: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def test_default_stage_root(tmp_path: Path) -> None:
    assert default_stage_root(tmp_path) == tmp_path / STAGE_DIRNAME


def test_stage_copies_csvs_and_selective_vfs(tmp_path: Path) -> None:
    source = tmp_path / "mount"
    stage = tmp_path / "stage"

    _write_csv(
        source / "forensic" / "csv" / "threads.csv",
        ["PID", "TID", "ETHREAD"],
        [["1000", "2000", "aaaa"], ["1000", "2001", "bbbb"]],
    )
    _write_csv(
        source / "forensic" / "csv" / "handles.csv",
        ["PID", "Handle", "Object"],
        [["1000", "34", "ffff83073ed52c00"]],
    )
    _write_csv(
        source / "forensic" / "csv" / "process.csv",
        ["pid", "name"],
        [["1000", "chrome.exe"]],
    )
    _write(
        source / "pid" / "1000" / "threads" / "2000" / "info.txt",
        "ETHREAD: aaaa\n",
    )
    _write(
        source / "pid" / "1000" / "threads" / "2001" / "info.txt",
        "ETHREAD: bbbb\n",
    )
    # Extra TID not referenced by CSV — must not be required; may be skipped.
    _write(
        source / "pid" / "1000" / "threads" / "9999" / "info.txt",
        "ETHREAD: cccc\n",
    )
    _write(source / "pid" / "1000" / "handles" / "handles.txt", "handles\n")
    _write(source / "pid" / "1000" / "name.txt", "chrome.exe\n")
    # Huge file must never be staged.
    _write(source / "pid" / "1000" / "memory.vmem", "HUGE")

    result = stage_memprocfs_tree(
        source,
        stage,
        need_thread_vfs=True,
        need_handle_vfs=True,
    )
    assert result.root == stage
    assert result.ethreads[("1000", "2000")] == "aaaa"
    assert result.ethreads[("1000", "2001")] == "bbbb"
    assert result.vfs_names["1000"] == "chrome.exe"
    assert result.handle_indexes["1000"] is not None
    assert (stage / "forensic" / "csv" / "threads.csv").is_file()
    assert (stage / "forensic" / "csv" / "handles.csv").is_file()
    assert (stage / "pid" / "1000" / "threads" / "2000" / "info.txt").is_file()
    assert (stage / "pid" / "1000" / "threads" / "2001" / "info.txt").is_file()
    assert not (stage / "pid" / "1000" / "threads" / "9999" / "info.txt").exists()
    assert (stage / "pid" / "1000" / "handles" / "handles.txt").is_file()
    assert (stage / "pid" / "1000" / "name.txt").is_file()
    assert not (stage / "pid" / "1000" / "memory.vmem").exists()


def test_stage_skips_vfs_when_not_needed(tmp_path: Path) -> None:
    source = tmp_path / "mount"
    stage = tmp_path / "stage"
    _write_csv(
        source / "forensic" / "csv" / "process.csv",
        ["pid", "name"],
        [["4", "System"]],
    )
    _write(source / "pid" / "4" / "threads" / "8" / "info.txt", "ETHREAD: x\n")

    stage_memprocfs_tree(
        source,
        stage,
        need_thread_vfs=False,
        need_handle_vfs=False,
    )
    assert (stage / "forensic" / "csv" / "process.csv").is_file()
    assert not (stage / "pid").exists()


def test_remove_memprocfs_stage(tmp_path: Path) -> None:
    stage = tmp_path / STAGE_DIRNAME
    _write(stage / "forensic" / "csv" / "x.csv", "a\n")
    assert stage.exists()
    remove_memprocfs_stage(stage)
    assert not stage.exists()
    # Idempotent
    remove_memprocfs_stage(stage)


def test_stage_replaces_existing_directory(tmp_path: Path) -> None:
    source = tmp_path / "mount"
    stage = tmp_path / "stage"
    _write(stage / "stale.txt", "old")
    _write_csv(
        source / "forensic" / "csv" / "process.csv",
        ["pid", "name"],
        [["1", "a"]],
    )
    stage_memprocfs_tree(
        source,
        stage,
        need_thread_vfs=False,
        need_handle_vfs=False,
    )
    assert not (stage / "stale.txt").exists()
    assert (stage / "forensic" / "csv" / "process.csv").is_file()


def test_run_extract_removes_stage_after_run(tmp_path: Path) -> None:
    from run_extract import main

    dump = tmp_path / "memory.dmp"
    dump.write_bytes(b"x")
    mount = tmp_path / "mount"
    case = tmp_path / "case"
    _write_csv(
        mount / "forensic" / "csv" / "process.csv",
        ["pid", "ppid", "name"],
        [["10", "4", "child.exe"]],
    )
    stage = case / STAGE_DIRNAME
    code = main(
        [
            "--dump-path",
            str(dump),
            "--memprocfs-path",
            str(mount),
            "--case",
            str(case),
            "--only",
            "processes",
        ]
    )
    assert code == 0
    assert (case / "csv" / "process.csv").is_file()
    assert not stage.exists()

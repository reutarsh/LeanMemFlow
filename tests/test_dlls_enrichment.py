"""Tests for DllsExtractor dump PE enrichment (entry / stamp / checksum)."""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from extractors.dlls import (
    DllsExtractor,
    format_address,
    format_rva,
    merge_enrichment_rows,
    parse_address,
)
from extractors.module_pe_enrichment import ModulePeEnrichment
from tests.test_extractors import _write_csv


def _modules_root(tmp_path: Path, rows: list[list[str]], headers: list[str] | None = None) -> Path:
    root = tmp_path / "memprocfs"
    _write_csv(
        root / "forensic" / "csv" / "modules.csv",
        headers
        or ["PID", "Process", "Name", "Wow64", "Size", "Start", "Path"],
        rows,
    )
    return root


def _read_dlls(out_dir: Path) -> list[dict[str, str]]:
    with (out_dir / "dlls.csv").open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _canonical_row(
    *,
    pid: str = "10",
    process: str = "app",
    module: str = "a.dll",
    path: str = "",
    base: str = "",
    size: str = "0x1000",
    entry: str = "",
    entry_rva: str = "",
    wow64: str = "",
    module_type: str = "NORMAL",
    timestamp: str = "",
    checksum: str = "",
) -> list[str]:
    return [
        pid, process, module, path, base, size, entry, entry_rva,
        wow64, module_type, timestamp, checksum,
    ]


def _enrichment(
    pid: int,
    base: int,
    *,
    entry_point: int | None = None,
    entry_point_rva: int | None = None,
    pe_checksum: int | None = None,
    pe_timedatestamp: int | None = None,
) -> dict[tuple[int, int], ModulePeEnrichment]:
    return {
        (pid, base): ModulePeEnrichment(
            entry_point=entry_point,
            entry_point_rva=entry_point_rva,
            pe_checksum=pe_checksum,
            pe_timedatestamp=pe_timedatestamp,
        )
    }


@patch("extractors.dlls.DllsExtractor._load_enrichment")
def test_no_dump_path_preserves_csv_only_behavior(mock_load: MagicMock, tmp_path: Path) -> None:
    root = _modules_root(tmp_path, [["10", "app.exe", "ntdll.dll", "0", "0x1000", "0x77000000", "ntdll.dll"]])
    out = tmp_path / "out"
    out.mkdir()
    result = DllsExtractor().extract(root, out)
    assert result.ok is True
    mock_load.assert_not_called()
    rows = _read_dlls(out)
    assert rows[0]["entry_point"] == ""
    assert rows[0]["entry_point_rva"] == ""


@patch("extractors.dlls.DllsExtractor._load_enrichment")
def test_entry_point_rva_fills_empty_field(mock_load: MagicMock, tmp_path: Path) -> None:
    base = 0x77000000
    mock_load.return_value = _enrichment(10, base, entry_point_rva=0x1234, entry_point=base + 0x1234)
    root = _modules_root(tmp_path, [["10", "app.exe", "ntdll.dll", "0", "0x1000", format_address(base), "ntdll.dll"]])
    out = tmp_path / "out"
    out.mkdir()
    DllsExtractor().extract(root, out, dump_path=tmp_path / "mem.dmp")
    rows = _read_dlls(out)
    assert rows[0]["entry_point_rva"] == format_rva(0x1234)
    assert rows[0]["entry_point"] == format_address(base + 0x1234)


@patch("extractors.dlls.DllsExtractor._load_enrichment")
def test_absolute_entry_from_rva_when_mod_entry_missing(mock_load: MagicMock, tmp_path: Path) -> None:
    base = 0x77000000
    mock_load.return_value = _enrichment(10, base, entry_point_rva=0xABCD, entry_point=None)
    root = _modules_root(tmp_path, [["10", "app.exe", "ntdll.dll", "0", "0x1000", format_address(base), "ntdll.dll"]])
    out = tmp_path / "out"
    out.mkdir()
    DllsExtractor().extract(root, out, dump_path=tmp_path / "mem.dmp")
    rows = _read_dlls(out)
    assert rows[0]["entry_point_rva"] == format_rva(0xABCD)
    assert rows[0]["entry_point"] == format_address(base + 0xABCD)


@patch("extractors.dlls.DllsExtractor._load_enrichment")
def test_existing_non_empty_entry_point_is_preserved(mock_load: MagicMock, tmp_path: Path) -> None:
    base = 0x77000000
    mock_load.return_value = _enrichment(10, base, entry_point=0x99999999, entry_point_rva=0x1111)
    root = tmp_path / "memprocfs"
    _write_csv(
        root / "forensic" / "csv" / "modules.csv",
        ["PID", "Process", "Name", "Wow64", "Size", "Start", "Path", "Entry"],
        [["10", "app.exe", "ntdll.dll", "0", "0x1000", format_address(base), "ntdll.dll", "0x1111111111111111"]],
    )
    out = tmp_path / "out"
    out.mkdir()
    DllsExtractor().extract(root, out, dump_path=tmp_path / "mem.dmp")
    rows = _read_dlls(out)
    assert rows[0]["entry_point"] == "0x1111111111111111"
    assert rows[0]["entry_point_rva"] == format_rva(0x1111)


@patch("extractors.dlls.DllsExtractor._load_enrichment")
def test_existing_rva_is_preserved(mock_load: MagicMock, tmp_path: Path) -> None:
    base = 0x77000000
    mock_load.return_value = _enrichment(10, base, entry_point_rva=0x9999)
    root = tmp_path / "memprocfs"
    _write_csv(
        root / "forensic" / "csv" / "modules.csv",
        ["PID", "Process", "Name", "Wow64", "Size", "Start", "Path", "AddressOfEntryPoint"],
        [["10", "app.exe", "ntdll.dll", "0", "0x1000", format_address(base), "ntdll.dll", "0x42"]],
    )
    out = tmp_path / "out"
    out.mkdir()
    DllsExtractor().extract(root, out, dump_path=tmp_path / "mem.dmp")
    rows = _read_dlls(out)
    assert rows[0]["entry_point_rva"] == "0x42"


@patch("extractors.dlls.DllsExtractor._load_enrichment", side_effect=RuntimeError("boom"))
def test_provider_raising_is_handled_gracefully(mock_load: MagicMock, tmp_path: Path) -> None:
    root = _modules_root(tmp_path, [["10", "app.exe", "ntdll.dll", "0", "0x1000", "0x77000000", "ntdll.dll"]])
    out = tmp_path / "out"
    out.mkdir()
    result = DllsExtractor().extract(root, out, dump_path=tmp_path / "mem.dmp")
    assert result.ok is True
    assert _read_dlls(out)[0]["entry_point"] == ""
    assert _read_dlls(out)[0]["entry_point_rva"] == ""


def test_hexadecimal_base_case_and_prefix_parsing() -> None:
    assert parse_address("0x77000000") == 0x77000000
    assert parse_address("77000000") == 0x77000000
    rows = [_canonical_row(base="77000000")]
    enrichment = _enrichment(10, 0x77000000, entry_point_rva=0x10)
    merged, stats = merge_enrichment_rows([row[:] for row in rows], enrichment)
    assert stats["matched"] == 1
    assert merged[0][7] == format_rva(0x10)


def test_pe_fields_fill_empty_cells() -> None:
    rows = [_canonical_row(base=format_address(0x1000))]
    item = ModulePeEnrichment(
        entry_point=0x1100,
        entry_point_rva=0x100,
        pe_timedatestamp=99,
        pe_checksum=0xCAFEBABE,
    )
    merged, stats = merge_enrichment_rows([row[:] for row in rows], {(10, 0x1000): item})
    assert merged[0][6] == format_address(0x1100)
    assert merged[0][7] == format_rva(0x100)
    assert merged[0][10] == "99"
    assert merged[0][11] == "3405691582"
    assert stats["pe_timedatestamp"] == 1
    assert stats["pe_checksum"] == 1


def test_pe_checksum_zero_is_written() -> None:
    rows = [_canonical_row(base=format_address(0x1000))]
    enrichment = _enrichment(10, 0x1000, pe_checksum=0)
    merged, stats = merge_enrichment_rows([row[:] for row in rows], enrichment)
    assert merged[0][11] == "0"
    assert stats["pe_checksum"] == 1


def test_pe_timedatestamp_zero_is_written() -> None:
    rows = [_canonical_row(base=format_address(0x1000))]
    enrichment = _enrichment(10, 0x1000, pe_timedatestamp=0)
    merged, stats = merge_enrichment_rows([row[:] for row in rows], enrichment)
    assert merged[0][10] == "0"
    assert stats["pe_timedatestamp"] == 1


def test_existing_pe_checksum_is_preserved() -> None:
    rows = [_canonical_row(base=format_address(0x1000), checksum="54321")]
    enrichment = _enrichment(10, 0x1000, pe_checksum=999)
    merged, stats = merge_enrichment_rows([row[:] for row in rows], enrichment)
    assert merged[0][11] == "54321"
    assert stats["pe_checksum"] == 0


def test_existing_pe_timedatestamp_is_preserved() -> None:
    rows = [_canonical_row(base=format_address(0x1000), timestamp="12345")]
    enrichment = _enrichment(10, 0x1000, pe_timedatestamp=999)
    merged, stats = merge_enrichment_rows([row[:] for row in rows], enrichment)
    assert merged[0][10] == "12345"
    assert stats["pe_timedatestamp"] == 0


@patch("extractors.dlls.DllsExtractor._load_enrichment")
def test_pe_fields_via_extract(mock_load: MagicMock, tmp_path: Path) -> None:
    base = 0x77000000
    mock_load.return_value = _enrichment(
        10, base, pe_checksum=0xCAFEBABE, pe_timedatestamp=0x12345678
    )
    root = _modules_root(
        tmp_path,
        [["10", "app.exe", "ntdll.dll", "0", "0x1000", format_address(base), "ntdll.dll"]],
    )
    out = tmp_path / "out"
    out.mkdir()
    DllsExtractor().extract(root, out, dump_path=tmp_path / "mem.dmp")
    rows = _read_dlls(out)
    assert rows[0]["pe_checksum"] == "3405691582"
    assert rows[0]["pe_timedatestamp"] == "305419896"


@patch("extractors.dlls.DllsExtractor._load_enrichment", return_value={})
def test_output_csv_column_order(mock_load: MagicMock, tmp_path: Path) -> None:
    root = _modules_root(tmp_path, [["10", "app.exe", "ntdll.dll", "0", "0x1000", "0x77000000", "ntdll.dll"]])
    out = tmp_path / "out"
    out.mkdir()
    DllsExtractor().extract(root, out, dump_path=tmp_path / "mem.dmp")
    assert DllsExtractor.HEADERS == [
        "pid", "process_name", "module_name", "module_path",
        "base_address", "size", "entry_point", "entry_point_rva",
        "is_wow64", "module_type", "pe_timedatestamp", "pe_checksum",
    ]
    with (out / "dlls.csv").open("r", encoding="utf-8", newline="") as fh:
        header = next(csv.reader(fh))
    assert header == list(DllsExtractor.HEADERS)


def test_run_extract_passes_dump_path_only_to_dlls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from extractors.base import ExtractResult

    calls: list[tuple[str, tuple, dict]] = []

    class FakeDlls:
        source = "forensic_csv"

        def extract(self, memprocfs_root, out_dir, dump_path=None):
            calls.append(("dlls", (memprocfs_root, out_dir), {"dump_path": dump_path}))
            return ExtractResult(ok=True, rows=1, files_written=["dlls.csv"])

    class FakeProcesses:
        source = "forensic_csv"

        def extract(self, memprocfs_root, out_dir):
            calls.append(("processes", (memprocfs_root, out_dir), {}))
            return ExtractResult(ok=True, rows=1, files_written=["process.csv"])

    registry = {"dlls": FakeDlls, "processes": FakeProcesses}
    monkeypatch.setattr("run_extract.discover_extractors", lambda: registry)

    dump = tmp_path / "mem.dmp"
    dump.write_bytes(b"dump")
    memprocfs_root = tmp_path / "memprocfs"
    memprocfs_root.mkdir()
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    out_dir = case_dir / "csv"
    out_dir.mkdir()

    import run_extract

    argv = [
        "--dump-path", str(dump),
        "--memprocfs-path", str(memprocfs_root),
        "--case", str(case_dir),
        "--no-stage-memprocfs",
        "--only", "dlls,processes",
    ]
    code = run_extract.main(argv)
    assert code == 0
    assert ("dlls", (memprocfs_root, out_dir), {"dump_path": dump.resolve()}) in [
        (name, args, kwargs) for name, args, kwargs in calls
    ]
    assert ("processes", (memprocfs_root, out_dir), {}) in [
        (name, args, kwargs) for name, args, kwargs in calls
    ]

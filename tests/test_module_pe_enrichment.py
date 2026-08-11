"""Tests for extractors.module_pe_enrichment."""

from __future__ import annotations

import builtins
import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from extractors.module_pe_enrichment import (
    MAX_PE_HEADER_READ,
    ModulePeEnrichment,
    build_enrichment_index,
    load_enrichment_from_dump,
    read_module_pe_header,
)
from extractors.pe_enrichment import PeHeaderInfo
from tests.test_pe_enrichment import build_synthetic_pe


class TrackingMemory:
    def __init__(self, image: bytes, base: int, *, fail_reads: bool = False) -> None:
        self.image = image
        self.base = base
        self.read_calls: list[tuple[int, int]] = []
        self.fail_reads = fail_reads

    def read(self, address: int, length: int) -> bytes:
        if self.fail_reads:
            raise OSError("memory read failed")
        self.read_calls.append((address, length))
        offset = address - self.base
        if offset < 0:
            raise OSError("memory read out of range")
        chunk = self.image[offset : offset + length]
        if len(chunk) < length:
            chunk = chunk + (b"\x00" * (length - len(chunk)))
        return chunk


class GuardedModule:
    """Module mock that fails if forbidden MemProcFS attributes are accessed."""

    FORBIDDEN = frozenset({"tp", "module_type"})

    def __init__(
        self,
        *,
        base: int,
        entry: int = 0,
        name: str = "test.dll",
        fullname: str = r"C:\test.dll",
    ) -> None:
        self.base = base
        self.entry = entry
        self.name = name
        self.fullname = fullname

    def __getattr__(self, name: str) -> Any:
        if name in self.FORBIDDEN:
            raise AssertionError(f"forbidden attribute accessed: {name}")
        raise AttributeError(name)


class FakeProcess:
    def __init__(self, pid: int, modules: list[Any], memory: TrackingMemory) -> None:
        self.pid = pid
        self._modules = modules
        self.memory = memory

    def module_list(self) -> list[Any]:
        return self._modules


class FakeVmm:
    def __init__(self, processes: list[FakeProcess]) -> None:
        self._processes = {proc.pid: proc for proc in processes}
        self.closed = False

    def process(self, pid: int) -> FakeProcess:
        return self._processes[pid]

    def process_list(self) -> list[FakeProcess]:
        return list(self._processes.values())

    def close(self) -> None:
        self.closed = True


def _make_vmm(
    *,
    pid: int = 100,
    base: int = 0x10000000,
    entry: int = 0,
    image: bytes | None = None,
    memory: TrackingMemory | None = None,
) -> tuple[FakeVmm, FakeProcess, int]:
    if image is None:
        image = build_synthetic_pe(
            timedatestamp=0xAABBCCDD,
            checksum=0x01020304,
            address_of_entry_point=0x2000,
        )
    if memory is None:
        memory = TrackingMemory(image, base)
    module = GuardedModule(base=base, entry=entry)
    proc = FakeProcess(pid, [module], memory)
    vmm = FakeVmm([proc])
    return vmm, proc, base


def test_nonzero_mod_entry_is_used() -> None:
    vmm, _, base = _make_vmm(entry=0x10005000)
    index = build_enrichment_index(vmm, {100})
    enrichment = index[(100, base)]
    assert enrichment.entry_point == 0x10005000
    assert enrichment.entry_point_rva == 0x2000
    assert enrichment.pe_timedatestamp == 0xAABBCCDD
    assert enrichment.pe_checksum == 0x01020304


def test_zero_mod_entry_falls_back_to_base_plus_pe_rva() -> None:
    vmm, _, base = _make_vmm(entry=0)
    index = build_enrichment_index(vmm, {100})
    enrichment = index[(100, base)]
    assert enrichment.entry_point == base + 0x2000
    assert enrichment.entry_point_rva == 0x2000


def test_zero_mod_entry_and_zero_rva_produce_none() -> None:
    image = build_synthetic_pe(address_of_entry_point=0)
    vmm, _, base = _make_vmm(entry=0, image=image)
    index = build_enrichment_index(vmm, {100})
    enrichment = index[(100, base)]
    assert enrichment.entry_point is None


def test_timestamp_and_checksum_remain_raw_integers() -> None:
    image = build_synthetic_pe(timedatestamp=0x12345678, checksum=0x9ABCDEF0)
    vmm, _, base = _make_vmm(image=image)
    index = build_enrichment_index(vmm, {100})
    enrichment = index[(100, base)]
    assert enrichment.pe_timedatestamp == 0x12345678
    assert enrichment.pe_checksum == 0x9ABCDEF0
    assert isinstance(enrichment.pe_timedatestamp, int)
    assert isinstance(enrichment.pe_checksum, int)


def test_header_entirely_inside_first_0x1000_bytes() -> None:
    image = build_synthetic_pe()
    memory = TrackingMemory(image, 0x10000000)
    vmm, _, base = _make_vmm(image=image, memory=memory)
    build_enrichment_index(vmm, {100})
    assert memory.read_calls == [(base, 0x1000)]


def test_header_beyond_0x1000_causes_additional_read() -> None:
    e_lfanew = 0x1100
    image = build_synthetic_pe(e_lfanew=e_lfanew, buffer_size=e_lfanew + 0x200)
    base = 0x20000000
    memory = TrackingMemory(image, base)
    module = GuardedModule(base=base, entry=0)
    proc = FakeProcess(100, [module], memory)
    vmm = FakeVmm([proc])

    build_enrichment_index(vmm, {100})

    assert len(memory.read_calls) >= 2
    assert memory.read_calls[0] == (base, 0x1000)
    assert memory.read_calls[1][0] == base
    assert memory.read_calls[1][1] > 0x1000


def test_e_lfanew_requiring_more_than_1_mib_is_rejected() -> None:
    image = bytearray(0x1000)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, MAX_PE_HEADER_READ + 1)
    base = 0x30000000
    memory = TrackingMemory(bytes(image), base)
    info = read_module_pe_header(FakeProcess(1, [], memory), base)
    assert info == PeHeaderInfo()
    assert memory.read_calls == [(base, 0x1000)]


def test_invalid_mz_preserves_mod_entry_but_no_pe_values() -> None:
    image = build_synthetic_pe(invalid_mz=True)
    vmm, _, base = _make_vmm(entry=0x40001000, image=image)
    index = build_enrichment_index(vmm, {100})
    enrichment = index[(100, base)]
    assert enrichment.entry_point == 0x40001000
    assert enrichment.pe_timedatestamp is None
    assert enrichment.pe_checksum is None


def test_memory_read_failure_preserves_mod_entry() -> None:
    memory = TrackingMemory(b"", 0x10000000, fail_reads=True)
    vmm, _, base = _make_vmm(entry=0x50002000, memory=memory)
    index = build_enrichment_index(vmm, {100})
    enrichment = index[(100, base)]
    assert enrichment.entry_point == 0x50002000
    assert enrichment.pe_timedatestamp is None
    assert enrichment.pe_checksum is None


def test_timestamp_available_when_checksum_unavailable() -> None:
    image = build_synthetic_pe(
        timedatestamp=0xAABBCCDD,
        size_of_optional_header=67,
        checksum=0xDEADBEEF,
    )
    vmm, _, base = _make_vmm(image=image)
    index = build_enrichment_index(vmm, {100})
    enrichment = index[(100, base)]
    assert enrichment.pe_timedatestamp == 0xAABBCCDD
    assert enrichment.pe_checksum is None


class BrokenBaseModule:
    FORBIDDEN = GuardedModule.FORBIDDEN

    def __init__(self) -> None:
        self.entry = 0
        self.name = "bad.dll"
        self.fullname = r"C:\bad.dll"

    @property
    def base(self) -> int:
        raise RuntimeError("bad base")

    def __getattr__(self, name: str) -> Any:
        if name in self.FORBIDDEN:
            raise AssertionError(f"forbidden attribute accessed: {name}")
        raise AttributeError(name)


def test_one_failed_module_does_not_prevent_later_module() -> None:
    good_image = build_synthetic_pe(timedatestamp=0x11111111)
    base_good = 0x10000000
    base_bad = 0x20000000
    memory = TrackingMemory(good_image, base_good)
    bad_module = BrokenBaseModule()
    good_module = GuardedModule(base=base_good, entry=0x10001000)
    proc = FakeProcess(100, [bad_module, good_module], memory)
    vmm = FakeVmm([proc])

    index = build_enrichment_index(vmm, {100})

    assert index[(100, base_good)].entry_point == 0x10001000
    assert (100, base_bad) not in index


def test_one_invalid_pid_does_not_prevent_later_pid() -> None:
    vmm_good, _, base = _make_vmm(entry=0x60003000)
    processes = dict(vmm_good._processes)

    def process(pid: int) -> FakeProcess:
        if pid == 999:
            raise KeyError("missing pid")
        return processes[pid]

    vmm_good.process = process  # type: ignore[method-assign]
    index = build_enrichment_index(vmm_good, {999, 100})
    assert index[(100, base)].entry_point == 0x60003000


def test_duplicate_names_with_different_bases_create_separate_records() -> None:
    image = build_synthetic_pe()
    base_a = 0x10000000
    base_b = 0x20000000
    memory_a = TrackingMemory(image, base_a)
    memory_b = TrackingMemory(image, base_b)
    module_a = GuardedModule(base=base_a, entry=0x10000001, name="kernel32.dll")
    module_b = GuardedModule(base=base_b, entry=0x20000001, name="kernel32.dll")
    proc = FakeProcess(100, [module_a, module_b], memory_a)

    def read_for_both(address: int, length: int) -> bytes:
        if address == base_a:
            return memory_a.read(address, length)
        if address == base_b:
            return memory_b.read(address, length)
        raise OSError("bad address")

    proc.memory = MagicMock()
    proc.memory.read.side_effect = read_for_both
    vmm = FakeVmm([proc])

    index = build_enrichment_index(vmm, {100})

    assert index[(100, base_a)].entry_point == 0x10000001
    assert index[(100, base_b)].entry_point == 0x20000001


def test_keys_are_integer_pid_base_tuples() -> None:
    vmm, _, base = _make_vmm(entry=0x70004000)
    index = build_enrichment_index(vmm, {100})
    assert list(index.keys()) == [(100, base)]
    pid, module_base = next(iter(index))
    assert isinstance(pid, int)
    assert isinstance(module_base, int)


def test_only_requested_pids_are_processed() -> None:
    image = build_synthetic_pe()
    proc100 = FakeProcess(
        100,
        [GuardedModule(base=0x10000000, entry=1)],
        TrackingMemory(image, 0x10000000),
    )
    proc200 = FakeProcess(
        200,
        [GuardedModule(base=0x20000000, entry=2)],
        TrackingMemory(image, 0x20000000),
    )
    vmm = FakeVmm([proc100, proc200])

    index = build_enrichment_index(vmm, {100})

    assert (100, 0x10000000) in index
    assert (200, 0x20000000) not in index


def test_vmm_closes_after_success(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_vmm = MagicMock()
    fake_vmm.process_list.return_value = []

    fake_memprocfs = MagicMock()
    fake_memprocfs.Vmm.return_value = fake_vmm

    monkeypatch.setitem(__import__("sys").modules, "memprocfs", fake_memprocfs)

    result = load_enrichment_from_dump(Path("test.dmp"))
    assert result == {}
    fake_vmm.close.assert_called_once()


def test_vmm_closes_if_enumeration_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_vmm = MagicMock()
    fake_vmm.process_list.side_effect = RuntimeError("enum failed")

    fake_memprocfs = MagicMock()
    fake_memprocfs.Vmm.return_value = fake_vmm

    monkeypatch.setitem(__import__("sys").modules, "memprocfs", fake_memprocfs)

    result = load_enrichment_from_dump(Path("test.dmp"))
    assert result == {}
    fake_vmm.close.assert_called_once()


def test_memprocfs_import_failure_returns_empty_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, /, *args: Any, **kwargs: Any) -> Any:
        if name == "memprocfs":
            raise ImportError("memprocfs unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert load_enrichment_from_dump(Path("test.dmp")) == {}


def test_vmm_initialization_failure_returns_empty_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_memprocfs = MagicMock()
    fake_memprocfs.Vmm.side_effect = RuntimeError("init failed")
    monkeypatch.setitem(__import__("sys").modules, "memprocfs", fake_memprocfs)

    assert load_enrichment_from_dump(Path("test.dmp")) == {}


def test_no_access_to_mod_tp_or_module_type() -> None:
    vmm, _, _ = _make_vmm(entry=0x80005000)
    build_enrichment_index(vmm, {100})

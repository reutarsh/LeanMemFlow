"""MemProcFS-backed module PE enrichment for offline memory analysis."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from extractors.pe_enrichment import PeHeaderInfo, parse_pe_header

logger = logging.getLogger(__name__)

INITIAL_PE_READ = 0x1000
MAX_PE_HEADER_READ = 1024 * 1024

_DOS_HEADER_MIN_SIZE = 0x40
_MZ_SIGNATURE = b"MZ"
_PE_SIGNATURE_SIZE = 4
_IMAGE_FILE_HEADER_SIZE = 20
_FILE_HEADER_SIZE_OF_OPTIONAL_HEADER = 16


@dataclass
class ModulePeEnrichment:
    entry_point: int | None = None
    entry_point_rva: int | None = None
    pe_timedatestamp: int | None = None
    pe_checksum: int | None = None


def _read_u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _read_u16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def _required_pe_header_bytes(data: bytes) -> int | None:
    """Return total bytes needed from module base, or None if unavailable or excessive."""
    if len(data) < _DOS_HEADER_MIN_SIZE:
        return _DOS_HEADER_MIN_SIZE

    if data[0:2] != _MZ_SIGNATURE:
        return None

    e_lfanew = _read_u32(data, 0x3C)
    if e_lfanew is None or e_lfanew < 0:
        return None

    if e_lfanew > MAX_PE_HEADER_READ:
        return None

    file_header_offset = e_lfanew + _PE_SIGNATURE_SIZE
    file_header_end = file_header_offset + _IMAGE_FILE_HEADER_SIZE
    if len(data) < file_header_end:
        required = file_header_end
        return required if required <= MAX_PE_HEADER_READ else None

    size_of_optional_header = _read_u16(
        data, file_header_offset + _FILE_HEADER_SIZE_OF_OPTIONAL_HEADER
    )
    if size_of_optional_header is None:
        return None

    required = file_header_end + size_of_optional_header
    if required > MAX_PE_HEADER_READ:
        return None
    return required


def read_module_pe_header(proc: Any, base: int) -> PeHeaderInfo:
    """Read and parse PE headers from process memory at *base* using staged reads."""
    try:
        initial = proc.memory.read(base, INITIAL_PE_READ)
    except Exception as exc:
        logger.debug("Initial PE header read failed at base 0x%X: %s", base, exc)
        return PeHeaderInfo()

    required = _required_pe_header_bytes(initial)
    if required is None:
        return parse_pe_header(initial)

    if required > MAX_PE_HEADER_READ:
        logger.debug(
            "Required PE header size exceeds max (%d) at base 0x%X",
            MAX_PE_HEADER_READ,
            base,
        )
        return parse_pe_header(initial)

    buffer = initial
    if required > len(initial):
        try:
            buffer = proc.memory.read(base, required)
        except Exception as exc:
            logger.debug(
                "Extended PE header read failed at base 0x%X (%d bytes): %s",
                base,
                required,
                exc,
            )
            return parse_pe_header(initial)

    return parse_pe_header(buffer[:required])


def _resolve_entry_point(
    mod_entry: Any,
    base: int,
    pe_info: PeHeaderInfo,
) -> int | None:
    try:
        entry = int(mod_entry) if mod_entry is not None else 0
    except (TypeError, ValueError):
        entry = 0

    if entry != 0:
        return entry

    rva = pe_info.address_of_entry_point_rva
    if rva is not None and rva != 0:
        return base + rva
    return None


def _extract_pid(item: Any) -> int | None:
    if isinstance(item, bool):
        return None
    if isinstance(item, int):
        return item
    pid = getattr(item, "pid", None)
    if pid is not None:
        try:
            return int(pid)
        except (TypeError, ValueError):
            return None
    if isinstance(item, (tuple, list)) and item:
        try:
            return int(item[0])
        except (TypeError, ValueError, IndexError):
            return None
    return None


def _resolve_target_pids(vmm: Any, pids: set[int] | None) -> list[int]:
    if pids is not None:
        return sorted(pids)

    try:
        process_list = vmm.process_list()
    except Exception as exc:
        logger.debug("Failed to enumerate processes: %s", exc)
        return []

    target: list[int] = []
    for item in process_list:
        try:
            pid = _extract_pid(item)
            if pid is not None:
                target.append(pid)
        except Exception as exc:
            logger.debug("Failed to derive PID from process_list item: %s", exc)
    return target


def _enrich_module(proc: Any, mod: Any, pid: int) -> tuple[tuple[int, int], ModulePeEnrichment] | None:
    try:
        base = int(mod.base)
    except Exception as exc:
        logger.debug("Failed to read module base for pid %s: %s", pid, exc)
        return None

    try:
        mod_entry = mod.entry
    except Exception as exc:
        logger.debug("Failed to read module entry for pid %s base 0x%X: %s", pid, base, exc)
        mod_entry = None

    pe_info = read_module_pe_header(proc, base)
    entry_point = _resolve_entry_point(mod_entry, base, pe_info)
    rva = pe_info.address_of_entry_point_rva

    enrichment = ModulePeEnrichment(
        entry_point=entry_point,
        entry_point_rva=rva,
        pe_timedatestamp=pe_info.timedatestamp,
        pe_checksum=pe_info.checksum,
    )
    return (pid, base), enrichment


def _enrich_process(vmm: Any, pid: int) -> dict[tuple[int, int], ModulePeEnrichment]:
    result: dict[tuple[int, int], ModulePeEnrichment] = {}
    try:
        proc = vmm.process(pid)
    except Exception as exc:
        logger.debug("Failed to open process %s: %s", pid, exc)
        return result

    try:
        modules = proc.module_list()
    except Exception as exc:
        logger.debug("Failed to list modules for pid %s: %s", pid, exc)
        return result

    for mod in modules:
        try:
            item = _enrich_module(proc, mod, pid)
            if item is not None:
                key, enrichment = item
                result[key] = enrichment
        except Exception as exc:
            logger.debug("Failed to enrich module for pid %s: %s", pid, exc)
    return result


def build_enrichment_index(
    vmm: Any,
    pids: set[int] | None = None,
) -> dict[tuple[int, int], ModulePeEnrichment]:
    """Build ``{(pid, module_base): ModulePeEnrichment}`` from an open VMM handle."""
    index: dict[tuple[int, int], ModulePeEnrichment] = {}
    for pid in _resolve_target_pids(vmm, pids):
        index.update(_enrich_process(vmm, pid))
    return index


def load_enrichment_from_dump(
    dump_path: Path,
    pids: set[int] | None = None,
) -> dict[tuple[int, int], ModulePeEnrichment]:
    """Open a memory dump via MemProcFS and return module PE enrichment."""
    try:
        import memprocfs
    except Exception as exc:
        logger.warning("memprocfs import failed: %s", exc)
        return {}

    vmm = None
    try:
        vmm = memprocfs.Vmm(
            [
                "-device",
                str(dump_path),
                "-waitinitialize",
                "-disable-symbolserver",
            ]
        )
        return build_enrichment_index(vmm, pids)
    except Exception as exc:
        logger.warning("VMM initialization or enrichment failed for %s: %s", dump_path, exc)
        return {}
    finally:
        if vmm is not None:
            try:
                vmm.close()
            except Exception as exc:
                logger.debug("VMM close failed: %s", exc)

"""Pure-Python PE header parsing for offline module enrichment."""

from __future__ import annotations

import struct
from dataclasses import dataclass

_DOS_HEADER_MIN_SIZE = 0x40
_MZ_SIGNATURE = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"
_IMAGE_FILE_HEADER_SIZE = 20

_FILE_HEADER_TIME_DATE_STAMP = 4
_FILE_HEADER_SIZE_OF_OPTIONAL_HEADER = 16
_FILE_HEADER_CHARACTERISTICS = 18

_OPTIONAL_HEADER_MAGIC = 0
_OPTIONAL_HEADER_ADDRESS_OF_ENTRY_POINT = 16
_OPTIONAL_HEADER_CHECKSUM = 64

_PE32_MAGIC = 0x10B
_PE32_PLUS_MAGIC = 0x20B
_VALID_OPTIONAL_MAGICS = (_PE32_MAGIC, _PE32_PLUS_MAGIC)


@dataclass
class PeHeaderInfo:
    address_of_entry_point_rva: int | None = None
    timedatestamp: int | None = None
    checksum: int | None = None
    characteristics: int | None = None
    optional_header_magic: int | None = None


def _read_u16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _field_readable(
    optional_header_offset: int,
    field_offset: int,
    field_size: int,
    optional_header_end: int,
    buffer_len: int,
) -> bool:
    field_start = optional_header_offset + field_offset
    field_end = field_start + field_size
    return field_end <= optional_header_end and field_end <= buffer_len


def parse_pe_header(data: bytes) -> PeHeaderInfo:
    """Parse PE header fields from a byte buffer without a module base address."""
    result = PeHeaderInfo()
    try:
        if data is None or len(data) < _DOS_HEADER_MIN_SIZE:
            return result

        if data[0:2] != _MZ_SIGNATURE:
            return result

        e_lfanew = _read_u32(data, 0x3C)
        if e_lfanew is None:
            return result

        if e_lfanew < 0 or e_lfanew + len(_PE_SIGNATURE) > len(data):
            return result

        if data[e_lfanew : e_lfanew + len(_PE_SIGNATURE)] != _PE_SIGNATURE:
            return result

        file_header_offset = e_lfanew + len(_PE_SIGNATURE)
        file_header_end = file_header_offset + _IMAGE_FILE_HEADER_SIZE
        if file_header_end > len(data):
            return result

        timedatestamp = _read_u32(data, file_header_offset + _FILE_HEADER_TIME_DATE_STAMP)
        if timedatestamp is not None:
            result.timedatestamp = timedatestamp

        size_of_optional_header = _read_u16(
            data, file_header_offset + _FILE_HEADER_SIZE_OF_OPTIONAL_HEADER
        )
        characteristics = _read_u16(data, file_header_offset + _FILE_HEADER_CHARACTERISTICS)
        if characteristics is not None:
            result.characteristics = characteristics

        if size_of_optional_header is None or size_of_optional_header == 0:
            return result

        optional_header_offset = file_header_offset + _IMAGE_FILE_HEADER_SIZE
        optional_header_end = optional_header_offset + size_of_optional_header

        if not _field_readable(
            optional_header_offset,
            _OPTIONAL_HEADER_MAGIC,
            2,
            optional_header_end,
            len(data),
        ):
            return result

        magic = _read_u16(data, optional_header_offset + _OPTIONAL_HEADER_MAGIC)
        if magic is None or magic not in _VALID_OPTIONAL_MAGICS:
            return result

        result.optional_header_magic = magic

        if _field_readable(
            optional_header_offset,
            _OPTIONAL_HEADER_ADDRESS_OF_ENTRY_POINT,
            4,
            optional_header_end,
            len(data),
        ):
            entry_point_rva = _read_u32(
                data, optional_header_offset + _OPTIONAL_HEADER_ADDRESS_OF_ENTRY_POINT
            )
            if entry_point_rva is not None:
                result.address_of_entry_point_rva = entry_point_rva

        if _field_readable(
            optional_header_offset,
            _OPTIONAL_HEADER_CHECKSUM,
            4,
            optional_header_end,
            len(data),
        ):
            checksum = _read_u32(data, optional_header_offset + _OPTIONAL_HEADER_CHECKSUM)
            if checksum is not None:
                result.checksum = checksum

        return result
    except (IndexError, struct.error, TypeError, ValueError):
        return result

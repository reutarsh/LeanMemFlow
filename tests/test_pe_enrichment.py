"""Tests for extractors.pe_enrichment.parse_pe_header."""

from __future__ import annotations

import struct

import pytest

from extractors.pe_enrichment import PeHeaderInfo, parse_pe_header

_IMAGE_FILE_HEADER_SIZE = 20
_PE_SIGNATURE_SIZE = 4


def build_synthetic_pe(
    *,
    e_lfanew: int = 0x80,
    magic: int = 0x10B,
    timedatestamp: int = 0x5F3759DF,
    characteristics: int = 0x210E,
    address_of_entry_point: int = 0x1234,
    checksum: int = 0xCAFEBABE,
    size_of_optional_header: int = 0xE0,
    buffer_size: int | None = None,
    invalid_mz: bool = False,
    invalid_pe: bool = False,
    truncate_file_header_at: int | None = None,
    truncate_buffer_after_optional: int | None = None,
    write_pe_structure: bool = True,
) -> bytes:
    """Build a minimal synthetic PE byte buffer for parser tests."""
    optional_start = e_lfanew + _PE_SIGNATURE_SIZE + _IMAGE_FILE_HEADER_SIZE
    if buffer_size is None:
        if truncate_buffer_after_optional is not None:
            buffer_size = truncate_buffer_after_optional
        elif size_of_optional_header == 0:
            buffer_size = optional_start
        else:
            buffer_size = optional_start + size_of_optional_header

    buf = bytearray(buffer_size)

    if not invalid_mz:
        buf[0:2] = b"MZ"
    else:
        buf[0:2] = b"XX"

    if 0x3C + 4 <= len(buf):
        struct.pack_into("<I", buf, 0x3C, e_lfanew)

    if not write_pe_structure:
        return bytes(buf)

    pe_offset = e_lfanew
    if pe_offset + 4 > len(buf):
        return bytes(buf)

    if invalid_pe:
        buf[pe_offset : pe_offset + 4] = b"XX\x00\x00"
    else:
        buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    file_header_offset = pe_offset + _PE_SIGNATURE_SIZE
    if file_header_offset + _IMAGE_FILE_HEADER_SIZE > len(buf):
        return bytes(buf)

    struct.pack_into("<H", buf, file_header_offset + 0, 0x8664 if magic == 0x20B else 0x014C)
    struct.pack_into("<H", buf, file_header_offset + 2, 1)
    struct.pack_into("<I", buf, file_header_offset + 4, timedatestamp)
    struct.pack_into("<I", buf, file_header_offset + 8, 0)
    struct.pack_into("<I", buf, file_header_offset + 12, 0)
    struct.pack_into("<H", buf, file_header_offset + 16, size_of_optional_header)
    struct.pack_into("<H", buf, file_header_offset + 18, characteristics)

    if truncate_file_header_at is not None:
        return bytes(buf[: file_header_offset + truncate_file_header_at])

    if size_of_optional_header == 0:
        return bytes(buf)

    optional_header_offset = file_header_offset + _IMAGE_FILE_HEADER_SIZE
    if optional_header_offset + 2 <= len(buf):
        struct.pack_into("<H", buf, optional_header_offset + 0, magic)
    if optional_header_offset + 20 <= len(buf):
        struct.pack_into("<I", buf, optional_header_offset + 16, address_of_entry_point)
    if optional_header_offset + 68 <= len(buf):
        struct.pack_into("<I", buf, optional_header_offset + 64, checksum)

    return bytes(buf)


def test_valid_pe32() -> None:
    data = build_synthetic_pe(magic=0x10B)
    info = parse_pe_header(data)
    assert info.optional_header_magic == 0x10B
    assert info.timedatestamp == 0x5F3759DF
    assert info.characteristics == 0x210E
    assert info.address_of_entry_point_rva == 0x1234
    assert info.checksum == 0xCAFEBABE


def test_valid_pe32_plus() -> None:
    data = build_synthetic_pe(magic=0x20B, size_of_optional_header=0xF0)
    info = parse_pe_header(data)
    assert info.optional_header_magic == 0x20B
    assert info.address_of_entry_point_rva == 0x1234
    assert info.checksum == 0xCAFEBABE


def test_timedatestamp_extraction() -> None:
    data = build_synthetic_pe(timedatestamp=0xABCDEF01)
    info = parse_pe_header(data)
    assert info.timedatestamp == 0xABCDEF01


def test_checksum_extraction() -> None:
    data = build_synthetic_pe(checksum=0x01020304)
    info = parse_pe_header(data)
    assert info.checksum == 0x01020304


def test_address_of_entry_point_rva_extraction() -> None:
    data = build_synthetic_pe(address_of_entry_point=0xDEADBEEF)
    info = parse_pe_header(data)
    assert info.address_of_entry_point_rva == 0xDEADBEEF


def test_characteristics_extraction() -> None:
    data = build_synthetic_pe(characteristics=0x0022)
    info = parse_pe_header(data)
    assert info.characteristics == 0x0022


def test_zero_address_of_entry_point_is_zero() -> None:
    data = build_synthetic_pe(address_of_entry_point=0)
    info = parse_pe_header(data)
    assert info.address_of_entry_point_rva == 0


def test_zero_timedatestamp_is_zero() -> None:
    data = build_synthetic_pe(timedatestamp=0)
    info = parse_pe_header(data)
    assert info.timedatestamp == 0


def test_zero_checksum_is_zero() -> None:
    data = build_synthetic_pe(checksum=0)
    info = parse_pe_header(data)
    assert info.checksum == 0


def test_invalid_mz_signature() -> None:
    data = build_synthetic_pe(invalid_mz=True)
    info = parse_pe_header(data)
    assert info == PeHeaderInfo()


def test_buffer_shorter_than_dos_header() -> None:
    info = parse_pe_header(b"MZ" + b"\x00" * 10)
    assert info == PeHeaderInfo()


def test_invalid_pe_signature() -> None:
    data = build_synthetic_pe(invalid_pe=True)
    info = parse_pe_header(data)
    assert info == PeHeaderInfo()


def test_e_lfanew_beyond_buffer() -> None:
    data = build_synthetic_pe(e_lfanew=0x1000, buffer_size=0x100, write_pe_structure=False)
    info = parse_pe_header(data)
    assert info == PeHeaderInfo()


def test_truncated_image_file_header() -> None:
    data = build_synthetic_pe(truncate_file_header_at=10)
    info = parse_pe_header(data)
    assert info == PeHeaderInfo()


def test_size_of_optional_header_zero() -> None:
    data = build_synthetic_pe(size_of_optional_header=0)
    info = parse_pe_header(data)
    assert info.timedatestamp == 0x5F3759DF
    assert info.characteristics == 0x210E
    assert info.optional_header_magic is None
    assert info.address_of_entry_point_rva is None
    assert info.checksum is None


def test_truncated_optional_header() -> None:
    optional_start = 0x80 + _PE_SIGNATURE_SIZE + _IMAGE_FILE_HEADER_SIZE
    data = build_synthetic_pe(truncate_buffer_after_optional=optional_start + 1)
    info = parse_pe_header(data)
    assert info.timedatestamp == 0x5F3759DF
    assert info.characteristics == 0x210E
    assert info.optional_header_magic is None
    assert info.address_of_entry_point_rva is None
    assert info.checksum is None


def test_invalid_optional_header_magic() -> None:
    data = build_synthetic_pe(magic=0x9999)
    info = parse_pe_header(data)
    assert info.timedatestamp == 0x5F3759DF
    assert info.characteristics == 0x210E
    assert info.optional_header_magic is None
    assert info.address_of_entry_point_rva is None
    assert info.checksum is None


def test_optional_header_smaller_than_address_of_entry_point() -> None:
    data = build_synthetic_pe(size_of_optional_header=15)
    info = parse_pe_header(data)
    assert info.optional_header_magic == 0x10B
    assert info.address_of_entry_point_rva is None
    assert info.checksum is None


def test_optional_header_has_entry_point_but_not_checksum() -> None:
    data = build_synthetic_pe(size_of_optional_header=67)
    info = parse_pe_header(data)
    assert info.address_of_entry_point_rva == 0x1234
    assert info.checksum is None


def test_partial_result_preserves_timedatestamp_and_characteristics() -> None:
    optional_start = 0x80 + _PE_SIGNATURE_SIZE + _IMAGE_FILE_HEADER_SIZE
    data = build_synthetic_pe(
        timedatestamp=0x11223344,
        characteristics=0xABCD,
        truncate_buffer_after_optional=optional_start + 10,
    )
    info = parse_pe_header(data)
    assert info.timedatestamp == 0x11223344
    assert info.characteristics == 0xABCD
    assert info.address_of_entry_point_rva is None
    assert info.checksum is None


def test_nt_headers_after_offset_0x1000() -> None:
    e_lfanew = 0x1100
    data = build_synthetic_pe(e_lfanew=e_lfanew, buffer_size=e_lfanew + 0x200)
    info = parse_pe_header(data)
    assert info.timedatestamp == 0x5F3759DF
    assert info.address_of_entry_point_rva == 0x1234
    assert info.checksum == 0xCAFEBABE


def test_bytes_beyond_size_of_optional_header_not_used() -> None:
    optional_start = 0x80 + _PE_SIGNATURE_SIZE + _IMAGE_FILE_HEADER_SIZE
    buf = bytearray(
        build_synthetic_pe(
            size_of_optional_header=67,
            buffer_size=optional_start + 0xE0,
        )
    )
    struct.pack_into("<I", buf, optional_start + 64, 0x11111111)
    info = parse_pe_header(bytes(buf))
    assert info.address_of_entry_point_rva == 0x1234
    assert info.checksum is None


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"M",
        b"MZ",
        b"\x00" * 100,
        None,
    ],
)
def test_malformed_input_never_raises(payload: bytes | None) -> None:
    info = parse_pe_header(payload)  # type: ignore[arg-type]
    assert isinstance(info, PeHeaderInfo)

"""
tests.test_csv_io
=================
Unit tests for :mod:`memflow_common.csv_io`.

Covers:
- Well-formed CSV round-trip (read → write → read).
- Malformed rows (short, long, blank).
- Broken newlines embedded inside quoted fields.
- Mixed encoding (utf-8-sig BOM, latin-1 characters).
- SHA-256 and row-count tracking.
- Ingest-error logging to ``_ingest_errors.csv``.
- Line-wise fallback reader.
"""

from __future__ import annotations

import hashlib
import textwrap
from pathlib import Path

import pytest

from memflow_common.csv_io import (
    IngestError,
    RawTable,
    read_csv_safe,
    read_csv_safe_linewise,
    write_csv_safe,
    write_ingest_errors,
)


# ── Fixtures ──────────────────────────────────────────────────────────── #


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Shorthand for the pytest-provided temporary directory."""
    return tmp_path


def _write(tmp: Path, name: str, content: bytes) -> Path:
    """Helper: write raw bytes to a file under *tmp*."""
    p = tmp / name
    p.write_bytes(content)
    return p


# ── 1. Well-formed CSV ────────────────────────────────────────────────── #


class TestWellFormedCSV:
    """Happy-path: a perfectly valid CSV should round-trip without errors."""

    CSV_TEXT = textwrap.dedent("""\
        Name,Age,City
        Alice,30,Zürich
        Bob,25,Paris
        Charlie,40,London
    """)

    def test_read_basic(self, tmp: Path):
        p = _write(tmp, "good.csv", self.CSV_TEXT.encode("utf-8"))
        table = read_csv_safe(p)

        assert table.headers == ["Name", "Age", "City"]
        assert table.row_count == 3
        assert table.ingest_errors == []
        assert table.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()

    def test_round_trip(self, tmp: Path):
        p = _write(tmp, "good.csv", self.CSV_TEXT.encode("utf-8"))
        table = read_csv_safe(p)

        out = tmp / "out.csv"
        write_csv_safe(table, out)
        table2 = read_csv_safe(out)

        assert table2.headers == table.headers
        assert table2.row_count == table.row_count
        # Values survive the trip.
        assert table2.rows[0] == table.rows[0]

    def test_all_values_are_strings(self, tmp: Path):
        p = _write(tmp, "types.csv", b"a,b\n1,2.5\n")
        table = read_csv_safe(p)
        for row in table.rows:
            for cell in row:
                assert isinstance(cell, str), f"Expected str, got {type(cell)}"


# ── 2. Malformed rows ─────────────────────────────────────────────────── #


class TestMalformedRows:
    """CSV with short rows, extra columns, and blank lines."""

    def test_short_row_is_padded(self, tmp: Path):
        raw = b"A,B,C\n1,2\n4,5,6\n"
        p = _write(tmp, "short.csv", raw)
        table = read_csv_safe(p)

        assert table.row_count == 2
        # Short row padded with empty string.
        assert table.rows[0] == ["1", "2", ""]
        assert table.rows[1] == ["4", "5", "6"]

    def test_extra_columns_logged(self, tmp: Path):
        raw = b"A,B\n1,2,EXTRA\n3,4\n"
        p = _write(tmp, "extra.csv", raw)
        table = read_csv_safe(p)

        assert table.row_count == 2
        # Extra column truncated in data but row is kept.
        assert table.rows[0] == ["1", "2"]
        assert len(table.ingest_errors) == 1
        assert "Extra columns" in table.ingest_errors[0].error

    def test_blank_lines_skipped(self, tmp: Path):
        raw = b"X\n1\n\n2\n\n\n3\n"
        p = _write(tmp, "blanks.csv", raw)
        table = read_csv_safe(p)

        assert table.row_count == 3

    def test_empty_file(self, tmp: Path):
        p = _write(tmp, "empty.csv", b"")
        table = read_csv_safe(p)

        assert table.headers == []
        assert table.row_count == 0

    def test_header_only(self, tmp: Path):
        p = _write(tmp, "header_only.csv", b"A,B,C\n")
        table = read_csv_safe(p)

        assert table.headers == ["A", "B", "C"]
        assert table.row_count == 0
        assert table.ingest_errors == []


# ── 3. Embedded newlines inside quoted fields ─────────────────────────── #


class TestEmbeddedNewlines:
    """Quoted fields may contain \\n — the CSV reader must handle them."""

    def test_quoted_newline_in_field(self, tmp: Path):
        # The second field contains a literal newline inside quotes.
        raw = b'Name,Bio\nAlice,"Line1\nLine2"\nBob,Simple\n'
        p = _write(tmp, "newline.csv", raw)
        table = read_csv_safe(p)

        assert table.row_count == 2
        assert table.rows[0][1] == "Line1\nLine2"
        assert table.ingest_errors == []


# ── 4. Encoding resilience ────────────────────────────────────────────── #


class TestEncoding:
    """Files may be UTF-8 with BOM or latin-1."""

    def test_utf8_bom(self, tmp: Path):
        bom = b"\xef\xbb\xbf"
        raw = bom + "Name\nCafé\n".encode("utf-8")
        p = _write(tmp, "bom.csv", raw)
        table = read_csv_safe(p)

        # BOM must be stripped from the header.
        assert table.headers == ["Name"]
        assert table.rows[0][0] == "Café"

    def test_latin1_fallback(self, tmp: Path):
        # ü in latin-1 is 0xFC — invalid in UTF-8.
        raw = b"Name\nM\xfcnchen\n"
        p = _write(tmp, "latin.csv", raw)
        table = read_csv_safe(p)

        assert table.row_count == 1
        # latin-1 decoding should produce the correct character.
        assert "nchen" in table.rows[0][0]


# ── 5. SHA-256 & row count tracking ───────────────────────────────────── #


class TestIntegrity:
    """SHA-256 and raw_row_count must be populated accurately."""

    def test_sha256_matches(self, tmp: Path):
        raw = b"H1,H2\na,b\nc,d\n"
        p = _write(tmp, "hash.csv", raw)
        table = read_csv_safe(p)

        expected = hashlib.sha256(raw).hexdigest()
        assert table.sha256 == expected

    def test_raw_row_count(self, tmp: Path):
        # 3 data rows + 2 blank lines = 5 physical lines after header
        raw = b"X\n1\n\n2\n\n3\n"
        p = _write(tmp, "count.csv", raw)
        table = read_csv_safe(p)

        # raw_row_count counts every line the reader yields (incl. blanks).
        assert table.raw_row_count == 5
        # Only non-blank rows are stored.
        assert table.row_count == 3


# ── 6. write_ingest_errors ─────────────────────────────────────────────── #


class TestWriteIngestErrors:
    """Errors should be persisted to a CSV file."""

    def test_errors_written(self, tmp: Path):
        table = RawTable(
            headers=["A"],
            rows=[["ok"]],
            ingest_errors=[
                IngestError(line_number=3, raw_line="bad,stuff,here", error="Extra columns: expected 1, got 3"),
            ],
        )
        out = tmp / "_ingest_errors.csv"
        result = write_ingest_errors(table, out)

        assert result is not None
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "bad,stuff,here" in content

    def test_no_errors_returns_none(self, tmp: Path):
        table = RawTable(headers=["A"], rows=[["ok"]])
        result = write_ingest_errors(table, tmp / "nope.csv")
        assert result is None


# ── 7. Line-wise fallback reader ──────────────────────────────────────── #


class TestLinewiseFallback:
    """The line-wise reader should handle the same cases."""

    def test_basic_read(self, tmp: Path):
        raw = b"A,B\n1,2\n3,4\n"
        p = _write(tmp, "basic.csv", raw)
        table = read_csv_safe_linewise(p)

        assert table.headers == ["A", "B"]
        assert table.row_count == 2
        assert table.sha256 == hashlib.sha256(raw).hexdigest()

    def test_short_rows_padded(self, tmp: Path):
        raw = b"A,B,C\n1\n4,5,6\n"
        p = _write(tmp, "short_lw.csv", raw)
        table = read_csv_safe_linewise(p)

        assert table.rows[0] == ["1", "", ""]
        assert table.rows[1] == ["4", "5", "6"]


# ── 8. write_csv_safe creates parent dirs ─────────────────────────────── #


class TestWriteCSV:
    """write_csv_safe must create missing parent directories."""

    def test_creates_parents(self, tmp: Path):
        table = RawTable(headers=["X"], rows=[["1"], ["2"]])
        out = tmp / "deep" / "nested" / "output.csv"
        result = write_csv_safe(table, out)

        assert result == out
        assert out.exists()
        # Verify content via re-read.
        t2 = read_csv_safe(out)
        assert t2.row_count == 2

    def test_all_fields_quoted(self, tmp: Path):
        table = RawTable(headers=["Num", "Text"], rows=[["42", "hello"]])
        out = tmp / "quoted.csv"
        write_csv_safe(table, out)

        raw = out.read_text(encoding="utf-8")
        # csv.QUOTE_ALL wraps every field in double quotes.
        assert '"Num"' in raw
        assert '"42"' in raw
        assert '"hello"' in raw

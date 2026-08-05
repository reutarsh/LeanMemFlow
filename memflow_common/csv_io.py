"""
memflow_common.csv_io
=====================
Lossless CSV reader / writer for MemFlow.

Design constraints
------------------
- **Never** drop a row.  Malformed lines are captured verbatim and stored in
  ``RawTable.ingest_errors`` so they can be written to ``_ingest_errors.csv``.
- **All** values are read as ``str`` — no type inference at this layer.
- Encoding: try ``utf-8-sig`` first, fall back to ``latin-1``.
- On load, compute the SHA-256 digest and row count of the *original* file
  for integrity tracking.
"""

from __future__ import annotations

import csv
import hashlib
import io
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RawTable – the in-memory representation of an ingested CSV
# ---------------------------------------------------------------------------

@dataclass
class IngestError:
    """A single malformed line captured during ingestion."""

    line_number: int
    raw_line: str
    error: str


@dataclass
class RawTable:
    """Lossless in-memory representation of a CSV file.

    Every cell value is a plain ``str``.  No type coercion is performed.

    Attributes
    ----------
    source_path : Path | None
        The file this table was read from (``None`` when built in memory).
    headers : list[str]
        Column names taken from the first CSV row.
    rows : list[list[str]]
        Data rows.  Each inner list has the same length as *headers*
        (padded or truncated with logging on mismatch).
    ingest_errors : list[IngestError]
        Lines that could not be parsed by the CSV reader.
    sha256 : str
        Hex digest of the original file bytes (empty string for in-memory tables).
    raw_row_count : int
        Number of data lines in the original file (excluding the header).
    """

    source_path: Optional[Path] = None
    headers: List[str] = field(default_factory=list)
    rows: List[List[str]] = field(default_factory=list)
    ingest_errors: List[IngestError] = field(default_factory=list)
    sha256: str = ""
    raw_row_count: int = 0

    # Convenience ---------------------------------------------------------- #

    @property
    def column_count(self) -> int:
        return len(self.headers)

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def __repr__(self) -> str:
        return (
            f"RawTable(source={self.source_path}, "
            f"cols={self.column_count}, rows={self.row_count}, "
            f"errors={len(self.ingest_errors)})"
        )


# ---------------------------------------------------------------------------
# read_csv_safe  –  the "never crash" reader
# ---------------------------------------------------------------------------

_ENCODINGS = ("utf-8-sig", "latin-1")


def _read_bytes(path: Path) -> bytes:
    """Read the entire file as raw bytes."""
    return path.read_bytes()


def _decode(raw: bytes) -> str:
    """Decode bytes trying utf-8-sig then latin-1."""
    for enc in _ENCODINGS:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, ValueError):
            logger.debug("Encoding %s failed, trying next fallback.", enc)
    # latin-1 never raises UnicodeDecodeError, so we should never reach here,
    # but safety first.
    return raw.decode("latin-1", errors="replace")


def _compute_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_csv_safe(path: Path | str) -> RawTable:
    """Read *any* CSV into a :class:`RawTable` without crashing.

    Parameters
    ----------
    path : Path or str
        File to read.

    Returns
    -------
    RawTable
        Populated table.  Check ``table.ingest_errors`` for lines that could
        not be parsed.
    """
    path = Path(path)
    logger.info("Reading CSV: %s", path)

    raw_bytes = _read_bytes(path)
    sha = _compute_sha256(raw_bytes)
    text = _decode(raw_bytes)

    table = RawTable(source_path=path, sha256=sha)

    # --- Split into physical lines (preserve \r\n inside quoted fields) ----
    # We rely on Python's csv.reader to handle quoting/newlines correctly.
    # To catch truly broken lines we wrap the reader in a try/except per row.

    reader = csv.reader(io.StringIO(text))

    # -- Header row ---------------------------------------------------------
    try:
        table.headers = next(reader)
        logger.debug("Headers (%d cols): %s", len(table.headers), table.headers)
    except StopIteration:
        logger.warning("CSV file is empty: %s", path)
        return table

    expected_cols = len(table.headers)

    # -- Data rows ----------------------------------------------------------
    line_num = 1  # header was line 1
    for row in reader:
        line_num += 1
        table.raw_row_count += 1

        if len(row) == expected_cols:
            table.rows.append(row)
        elif len(row) == 0:
            # Completely blank line — skip silently.
            logger.debug("Skipping blank line %d", line_num)
        elif len(row) < expected_cols:
            # Pad short row with empty strings.
            padded = row + [""] * (expected_cols - len(row))
            table.rows.append(padded)
            logger.debug(
                "Line %d: padded %d→%d columns.", line_num, len(row), expected_cols
            )
        else:
            # More columns than expected — still keep it, truncate extras,
            # and log the full line as an ingest error for audit.
            truncated = row[:expected_cols]
            table.rows.append(truncated)
            raw_line = ",".join(row)
            table.ingest_errors.append(
                IngestError(
                    line_number=line_num,
                    raw_line=raw_line,
                    error=f"Extra columns: expected {expected_cols}, got {len(row)}",
                )
            )
            logger.warning(
                "Line %d: truncated %d→%d columns (extra cols logged).",
                line_num,
                len(row),
                expected_cols,
            )

    logger.info(
        "Loaded %s — %d rows, %d errors, SHA-256=%s",
        path.name,
        table.row_count,
        len(table.ingest_errors),
        sha[:16] + "…",
    )
    return table


# ---------------------------------------------------------------------------
# Line-level fallback reader (for truly broken files)
# ---------------------------------------------------------------------------

def read_csv_safe_linewise(path: Path | str) -> RawTable:
    """Fallback reader that processes the file one *physical* line at a time.

    Use this when :func:`read_csv_safe` itself throws an unrecoverable error
    (e.g. a NUL byte in the middle of the file).  Each physical line is
    attempted through ``csv.reader``; failures are logged verbatim.

    Parameters
    ----------
    path : Path or str
        File to read.

    Returns
    -------
    RawTable
    """
    path = Path(path)
    logger.info("Reading CSV (line-wise fallback): %s", path)

    raw_bytes = _read_bytes(path)
    sha = _compute_sha256(raw_bytes)
    text = _decode(raw_bytes)

    lines = text.splitlines()
    table = RawTable(source_path=path, sha256=sha)

    if not lines:
        logger.warning("CSV file is empty: %s", path)
        return table

    # -- Header -------------------------------------------------------------
    try:
        header_parsed = next(csv.reader([lines[0]]))
        table.headers = header_parsed
    except Exception as exc:
        logger.error("Cannot parse header line: %s", exc)
        table.headers = [lines[0]]
        table.ingest_errors.append(
            IngestError(line_number=1, raw_line=lines[0], error=str(exc))
        )

    expected_cols = len(table.headers)

    # -- Data ---------------------------------------------------------------
    for idx, line in enumerate(lines[1:], start=2):
        table.raw_row_count += 1
        if not line.strip():
            continue
        try:
            parsed = next(csv.reader([line]))
        except Exception as exc:
            table.ingest_errors.append(
                IngestError(line_number=idx, raw_line=line, error=str(exc))
            )
            logger.warning("Line %d: parse error — %s", idx, exc)
            continue

        # Normalise column count.
        if len(parsed) < expected_cols:
            parsed += [""] * (expected_cols - len(parsed))
        elif len(parsed) > expected_cols:
            raw_line = line
            table.ingest_errors.append(
                IngestError(
                    line_number=idx,
                    raw_line=raw_line,
                    error=f"Extra columns: expected {expected_cols}, got {len(parsed)}",
                )
            )
            parsed = parsed[:expected_cols]

        table.rows.append(parsed)

    logger.info(
        "Loaded (line-wise) %s — %d rows, %d errors, SHA-256=%s",
        path.name,
        table.row_count,
        len(table.ingest_errors),
        sha[:16] + "…",
    )
    return table


# ---------------------------------------------------------------------------
# write_csv_safe  –  strict, quoted output
# ---------------------------------------------------------------------------

def write_csv_safe(table: RawTable, path: Path | str) -> Path:
    """Write a :class:`RawTable` to disk as a strictly quoted CSV.

    Parameters
    ----------
    table : RawTable
        Table to serialise.
    path : Path or str
        Destination file.  Parent directories are created if needed.

    Returns
    -------
    Path
        The resolved output path.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Writing CSV: %s (%d rows)", path, table.row_count)

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(table.headers)
        writer.writerows(table.rows)

    logger.info("Wrote %s — %d rows.", path.name, table.row_count)
    return path


def write_ingest_errors(table: RawTable, path: Path | str) -> Optional[Path]:
    """Write ``table.ingest_errors`` to an ``_ingest_errors.csv`` file.

    Parameters
    ----------
    table : RawTable
        Source table whose errors should be persisted.
    path : Path or str
        Destination file.

    Returns
    -------
    Path or None
        The written path, or ``None`` if there were no errors to write.
    """
    if not table.ingest_errors:
        logger.debug("No ingest errors to write.")
        return None

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Writing ingest-errors: %s (%d errors)", path, len(table.ingest_errors))

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(["line_number", "raw_line", "error"])
        for err in table.ingest_errors:
            writer.writerow([str(err.line_number), err.raw_line, err.error])

    return path

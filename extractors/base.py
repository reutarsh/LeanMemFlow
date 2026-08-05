"""Base class and shared helpers for file-based MemFlow extractors."""

from __future__ import annotations

import csv
import shutil
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Sequence

logger = logging.getLogger(__name__)

FORENSIC_CSV_CANDIDATES = (
    ("forensic", "csv"),
    ("csv",),
    tuple(),
)


@dataclass
class ExtractResult:
    """Outcome returned by every extractor run."""

    ok: bool = True
    rows: int = 0
    files_written: List[str] = field(default_factory=list)
    error: Optional[str] = None


class BaseExtractor(ABC):
    """Abstract base for a single extraction capability."""

    # -- Subclass must override ------------------------------------------------
    name: str = ""
    """Short, unique identifier used for ``--only`` / ``--exclude`` filtering."""

    output_filename: str = ""
    """Default CSV filename written into ``out_dir``."""

    source: str = ""
    """One of ``"api"``, ``"vfs"``, or ``"forensic_csv"``."""

    # -- Shared helpers --------------------------------------------------------

    @abstractmethod
    def extract(self, memprocfs_root: Path, out_dir: Path) -> ExtractResult:
        """Pull data from *memprocfs_root*, write CSV(s) to *out_dir*."""
        ...

    # -- CSV writing -----------------------------------------------------------

    @staticmethod
    def write_csv(
        out_dir: Path,
        filename: str,
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
    ) -> Path:
        """Write *rows* as a strictly-quoted UTF-8 CSV and return the path."""
        filepath = out_dir / filename
        with filepath.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(row)
        logger.info("  [+] Wrote %s (%d rows)", filepath.name, len(rows))
        return filepath

    # -- File-based helpers ----------------------------------------------------

    @staticmethod
    def _resolve_forensic_csv(memprocfs_root: Path, csv_name: str) -> Optional[Path]:
        """Resolve a forensic CSV path from common output layouts."""
        for parts in FORENSIC_CSV_CANDIDATES:
            candidate = memprocfs_root.joinpath(*parts, csv_name)
            if candidate.is_file():
                return candidate
        return None

    @staticmethod
    def _resolve_first_forensic_csv(memprocfs_root: Path, *csv_names: str) -> Optional[Path]:
        """Return the first existing forensic CSV among *csv_names* (in order)."""
        for name in csv_names:
            found = BaseExtractor._resolve_forensic_csv(memprocfs_root, name)
            if found is not None:
                return found
        return None

    @staticmethod
    def _count_rows(csv_path: Path) -> int:
        """Count CSV rows excluding header."""
        return max(0, csv_path.read_text(encoding="utf-8", errors="replace").count("\n") - 1)

    @staticmethod
    def copy_forensic_csv(
        memprocfs_root: Path,
        csv_name: str,
        out_dir: Path,
    ) -> ExtractResult:
        """Copy one source CSV into *out_dir*."""
        source = BaseExtractor._resolve_forensic_csv(memprocfs_root, csv_name)
        if source is None:
            msg = f"{csv_name} not found under {memprocfs_root}"
            logger.warning("  [!] %s", msg)
            return ExtractResult(ok=False, error=msg)

        local_path = out_dir / csv_name
        shutil.copy2(source, local_path)
        row_count = BaseExtractor._count_rows(local_path)
        logger.info("  [+] Copied %s (%d bytes, ~%d rows)", csv_name, local_path.stat().st_size, row_count)
        return ExtractResult(ok=True, rows=row_count, files_written=[csv_name])

    @staticmethod
    def copy_forensic_csvs_matching(
        memprocfs_root: Path,
        prefix: str,
        out_dir: Path,
    ) -> ExtractResult:
        """Copy all source CSVs whose filename starts with *prefix*."""
        matches: list[Path] = []
        for parts in FORENSIC_CSV_CANDIDATES:
            base_dir = memprocfs_root.joinpath(*parts)
            if not base_dir.is_dir():
                continue
            matches.extend(sorted(p for p in base_dir.glob(f"{prefix}*.csv") if p.is_file()))
            if matches:
                break
        if not matches:
            msg = f"No source CSVs matching prefix '{prefix}' under {memprocfs_root}"
            logger.warning("  [!] %s", msg)
            return ExtractResult(ok=False, error=msg)

        total_rows = 0
        files: list[str] = []
        for source in matches:
            csv_name = source.name
            local_path = out_dir / csv_name
            shutil.copy2(source, local_path)
            rows = BaseExtractor._count_rows(local_path)
            total_rows += rows
            files.append(csv_name)
            logger.info("  [+] Copied %s (%d bytes, ~%d rows)", csv_name, local_path.stat().st_size, rows)

        return ExtractResult(ok=True, rows=total_rows, files_written=files)

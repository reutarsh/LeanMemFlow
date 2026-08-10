"""Shared PID / address helpers and a run-scoped lazy VFS cache.

Used by handles, threads, and netstat for process-name lookups and
normalized hex comparisons. Artifact-specific ownership gates stay in
their extractors; this module only caches and resolves shared inputs.
"""

from __future__ import annotations

import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from extractors.base import BaseExtractor

_PRELOAD_WORKERS = 8

_ETHREAD_INFO_RE = re.compile(
    r"^\s*ETHREAD\s*:\s*(?P<addr>\S+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def parse_address(value: str) -> int | None:
    """Parse a MemProcFS hex/dec address; return None if blank or invalid.

    MemProcFS thread CSV often emits bare hex (``7ff791d2bfd0``) without ``0x``;
    module CSV usually includes the prefix. Treat strings containing a-f as hex.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        lowered = stripped.lower()
        if lowered.startswith("0x"):
            return int(stripped, 16)
        if any(ch in lowered for ch in "abcdef"):
            return int(stripped, 16)
        return int(stripped, 10)
    except ValueError:
        return None


def normalize_hex_address(value: str) -> str:
    """Normalize a hex address for equality checks (no 0x, lower, no leading zeros)."""
    if value is None:
        return ""
    stripped = value.strip().lower()
    if stripped.startswith("0x"):
        stripped = stripped[2:]
    stripped = stripped.lstrip("0")
    return stripped or "0"


def build_process_name_map(memprocfs_root: Path) -> dict[str, str]:
    """Build ``{pid: name}`` from forensic ``process.csv``."""
    process_csv = BaseExtractor._resolve_forensic_csv(Path(memprocfs_root), "process.csv")
    if process_csv is None:
        return {}
    with process_csv.open("r", newline="", encoding="utf-8", errors="replace") as fh:
        mapping: dict[str, str] = {}
        for row in csv.DictReader(fh):
            pid = (row.get("pid") or row.get("PID") or "").strip()
            name = (row.get("name") or row.get("Name") or "").strip()
            if pid and name:
                mapping[pid] = name
        return mapping


def read_vfs_process_name(memprocfs_root: Path, pid: str) -> str | None:
    """Return stripped contents of ``pid/<PID>/name.txt``, or None if missing/empty."""
    if not pid:
        return None
    path = Path(memprocfs_root) / "pid" / pid / "name.txt"
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return text or None


def parse_ethread_from_text(text: str) -> str | None:
    """Return the ETHREAD address from info.txt contents, or None."""
    match = _ETHREAD_INFO_RE.search(text)
    if match is None:
        return None
    return match.group("addr").strip()


def parse_info_txt_ethread(info_path: Path) -> str | None:
    """Return the ETHREAD address from MemProcFS thread info.txt, or None."""
    try:
        text = info_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return parse_ethread_from_text(text)


def parse_handles_txt(handles_path: Path) -> dict[str, str] | None:
    """Parse ``handles.txt`` into ``{handle_norm: object_norm}``.

    Returns None if the file cannot be read. Empty dict if readable but no rows.
    MemProcFS format (whitespace-separated)::

        #       PID  Handle Object Address   Access Type  Description
        000c   5512      34 ffff83073ed52c00      3 Directory  KnownDlls
    """
    try:
        text = handles_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    index: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("="):
            continue
        upper = stripped.upper()
        if "HANDLE" in upper and "OBJECT" in upper:
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        # parts: [index, PID, Handle, Object, ...]
        handle_norm = normalize_hex_address(parts[2])
        object_norm = normalize_hex_address(parts[3])
        if handle_norm and object_norm:
            index[handle_norm] = object_norm
    return index


@dataclass
class VfsContext:
    """Run-scoped lazy cache for VFS / process.csv lookups."""

    memprocfs_root: Path
    process_names_csv: dict[str, str] | None = None
    vfs_names: dict[str, str | None] = field(default_factory=dict)
    handle_indexes: dict[str, dict[str, str] | None] = field(default_factory=dict)
    ethreads: dict[tuple[str, str], str | None] = field(default_factory=dict)

    # Optional counters for tests / diagnostics
    handles_txt_reads: int = 0
    name_txt_reads: int = 0
    info_txt_reads: int = 0
    process_csv_reads: int = 0

    def __post_init__(self) -> None:
        self.memprocfs_root = Path(self.memprocfs_root)

    def get_process_name_map(self) -> dict[str, str]:
        if self.process_names_csv is None:
            self.process_csv_reads += 1
            self.process_names_csv = build_process_name_map(self.memprocfs_root)
        return self.process_names_csv

    def resolve_process_name(self, pid: str) -> str:
        """Prefer ``name.txt``, then forensic ``process.csv``. Empty if neither."""
        if not pid:
            return ""
        if pid not in self.vfs_names:
            self.name_txt_reads += 1
            self.vfs_names[pid] = read_vfs_process_name(self.memprocfs_root, pid)
        vfs_name = self.vfs_names[pid]
        if vfs_name:
            return vfs_name
        return self.get_process_name_map().get(pid, "")

    def get_handle_index(self, pid: str) -> dict[str, str] | None:
        """Return parsed ``handles.txt`` for *pid*, or None if missing/unreadable."""
        if not pid:
            return None
        if pid not in self.handle_indexes:
            path = self.memprocfs_root / "pid" / pid / "handles" / "handles.txt"
            if not path.is_file():
                self.handle_indexes[pid] = None
            else:
                self.handles_txt_reads += 1
                self.handle_indexes[pid] = parse_handles_txt(path)
        return self.handle_indexes[pid]

    def seed_ethreads(self, mapping: dict[tuple[str, str], str | None]) -> None:
        """Merge a pre-parsed ``{(pid, tid): ethread|None}`` map into the cache."""
        if mapping:
            self.ethreads.update(mapping)

    def seed_handle_indexes(
        self, mapping: dict[str, dict[str, str] | None]
    ) -> None:
        """Merge pre-parsed handle indexes into the cache."""
        if mapping:
            self.handle_indexes.update(mapping)

    def seed_vfs_names(self, mapping: dict[str, str | None]) -> None:
        """Merge pre-read ``name.txt`` values into the cache."""
        if mapping:
            self.vfs_names.update(mapping)

    def get_ethread_vfs(self, pid: str, tid: str) -> str | None:
        """Return ETHREAD from ``pid/<PID>/threads/<TID>/info.txt``, cached."""
        if not pid or not tid:
            return None
        key = (pid, tid)
        if key not in self.ethreads:
            path = self.memprocfs_root / "pid" / pid / "threads" / tid / "info.txt"
            if not path.is_file():
                self.ethreads[key] = None
            else:
                self.info_txt_reads += 1
                self.ethreads[key] = parse_info_txt_ethread(path)
        return self.ethreads[key]

    def preload_ethreads(
        self,
        pairs: Iterable[tuple[str, str]],
        *,
        workers: int = _PRELOAD_WORKERS,
    ) -> int:
        """Load missing ``(pid, tid)`` ETHREAD values in parallel. Return reads performed."""
        pending: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for pid, tid in pairs:
            key = (pid, tid)
            if not pid or not tid or key in self.ethreads or key in seen:
                continue
            seen.add(key)
            pending.append(key)
        if not pending:
            return 0

        def _load(pid: str, tid: str) -> tuple[tuple[str, str], str | None]:
            path = self.memprocfs_root / "pid" / pid / "threads" / tid / "info.txt"
            if not path.is_file():
                return (pid, tid), None
            return (pid, tid), parse_info_txt_ethread(path)

        reads = 0
        max_workers = min(workers, max(1, len(pending)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_load, pid, tid) for pid, tid in pending]
            for fut in as_completed(futures):
                key, ethread = fut.result()
                self.ethreads[key] = ethread
                if ethread is not None:
                    reads += 1
        self.info_txt_reads += reads
        return reads

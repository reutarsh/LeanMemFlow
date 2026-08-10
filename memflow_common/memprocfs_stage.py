"""Stage a local MemProcFS tree for extractors, then remove it.

Live MemProcFS mounts are slow for thousands of small VFS file reads.
This module copies the forensic CSVs and only the VFS files needed for
ownership gates onto local disk, then deletes the staging folder after use.

While copying thread/handle VFS files, values are parsed into maps so
extractors can skip a second disk pass.

Huge process memory files (e.g. memory.vmem) are never copied.
"""

from __future__ import annotations

import csv
import logging
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from extractors.pid_ownership import parse_ethread_from_text, parse_handles_txt

logger = logging.getLogger(__name__)

STAGE_DIRNAME = ".leanmemflow_memprocfs_stage"

# Never copy these (process virtual memory / huge binaries on MemProcFS mounts).
_EXCLUDED_NAME_SUFFIXES = (
    ".vmem",
    ".dump",
    ".dmp",
    ".bin",
    ".raw",
)
_EXCLUDED_NAMES = frozenset(
    {
        "memory.vmem",
        "memory-process.vmem",
        "pagefile.sys",
    }
)

_COPY_WORKERS = 8


@dataclass
class StageResult:
    """Local stage root plus VFS values parsed during the copy."""

    root: Path
    ethreads: dict[tuple[str, str], str | None] = field(default_factory=dict)
    handle_indexes: dict[str, dict[str, str] | None] = field(default_factory=dict)
    vfs_names: dict[str, str | None] = field(default_factory=dict)


def default_stage_root(case_dir: Path) -> Path:
    """Return ``<case>/.leanmemflow_memprocfs_stage``."""
    return Path(case_dir) / STAGE_DIRNAME


def remove_memprocfs_stage(stage_root: Path) -> None:
    """Delete the staging directory tree if it exists."""
    path = Path(stage_root)
    if not path.exists():
        return
    logger.info("Removing MemProcFS stage: %s", path)
    shutil.rmtree(path, ignore_errors=False)


def _should_skip_file(path: Path) -> bool:
    name = path.name.lower()
    if name in _EXCLUDED_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in _EXCLUDED_NAME_SUFFIXES)


def _copy_file(src: Path, dst: Path) -> bool:
    """Copy one file; return True on success."""
    try:
        if not src.is_file() or _should_skip_file(src):
            return False
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return True
    except OSError as exc:
        logger.debug("Skip copy %s -> %s: %s", src, dst, exc)
        return False


def _copy_tree_filtered(src_dir: Path, dst_dir: Path) -> int:
    """Copy files under *src_dir* excluding huge binaries. Return files copied."""
    if not src_dir.is_dir():
        return 0
    copied = 0
    for src in src_dir.rglob("*"):
        if not src.is_file() or _should_skip_file(src):
            continue
        rel = src.relative_to(src_dir)
        if _copy_file(src, dst_dir / rel):
            copied += 1
    return copied


def _copy_forensic_csvs(source_root: Path, stage_root: Path) -> int:
    """Copy forensic CSV layouts into the stage. Return files copied."""
    copied = 0
    for rel in (("forensic", "csv"), ("csv",)):
        src = source_root.joinpath(*rel)
        if src.is_dir():
            copied += _copy_tree_filtered(src, stage_root.joinpath(*rel))

    # Root-level CSVs / netstat fallbacks used by extractors.
    for pattern in ("*.csv", "netstat.txt"):
        for src in source_root.glob(pattern):
            if src.is_file() and _copy_file(src, stage_root / src.name):
                copied += 1

    netstat = source_root / "sys" / "net" / "netstat.txt"
    if netstat.is_file() and _copy_file(netstat, stage_root / "sys" / "net" / "netstat.txt"):
        copied += 1
    return copied


def _unique_csv_pairs(
    csv_path: Path,
    *column_pairs: tuple[str, ...],
) -> list[tuple[str, ...]]:
    """Return unique tuples of column values from a forensic CSV."""
    if not csv_path.is_file():
        return []
    seen: set[tuple[str, ...]] = set()
    out: list[tuple[str, ...]] = []
    with csv_path.open("r", newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            values: list[str] = []
            for names in column_pairs:
                val = ""
                for name in names:
                    cell = row.get(name)
                    if cell is not None and str(cell).strip():
                        val = str(cell).strip()
                        break
                values.append(val)
            key = tuple(values)
            if any(values) and key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _resolve_source_csv(source_root: Path, name: str) -> Path | None:
    for parts in (("forensic", "csv"), ("csv",), tuple()):
        candidate = source_root.joinpath(*parts, name)
        if candidate.is_file():
            return candidate
    return None


def _write_text(dst: Path, text: str) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8", errors="replace")


def _stage_one_info(
    src: Path, dst: Path, pid: str, tid: str
) -> tuple[tuple[str, str], str | None, bool]:
    """Read source info.txt once, write stage copy, parse ETHREAD."""
    key = (pid, tid)
    try:
        if not src.is_file():
            return key, None, False
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return key, None, False
    try:
        _write_text(dst, text)
    except OSError:
        return key, None, False
    return key, parse_ethread_from_text(text), True


def _stage_thread_vfs(
    source_root: Path, stage_root: Path
) -> tuple[int, dict[tuple[str, str], str | None]]:
    """Copy info.txt files and return ``{(pid, tid): ethread|None}``."""
    threads_csv = _resolve_source_csv(source_root, "threads.csv")
    if threads_csv is None:
        return 0, {}
    pairs = _unique_csv_pairs(threads_csv, ("PID", "pid"), ("TID", "tid"))
    jobs = [
        (
            source_root / "pid" / pid / "threads" / tid / "info.txt",
            stage_root / "pid" / pid / "threads" / tid / "info.txt",
            pid,
            tid,
        )
        for pid, tid in pairs
        if pid and tid
    ]
    if not jobs:
        return 0, {}

    ethreads: dict[tuple[str, str], str | None] = {}
    copied = 0
    workers = min(_COPY_WORKERS, max(1, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_stage_one_info, src, dst, pid, tid)
            for src, dst, pid, tid in jobs
        ]
        for fut in as_completed(futures):
            key, ethread, ok = fut.result()
            ethreads[key] = ethread
            if ok:
                copied += 1
    return copied, ethreads


def _stage_one_handles(
    handles_src: Path, handles_dst: Path, name_src: Path, name_dst: Path, pid: str
) -> tuple[str, dict[str, str] | None, str | None, int]:
    """Copy/parse handles.txt and name.txt for one PID. Return files copied count."""
    handle_index: dict[str, str] | None = None
    vfs_name: str | None = None
    copied = 0
    try:
        if handles_src.is_file():
            text = handles_src.read_text(encoding="utf-8", errors="replace")
            _write_text(handles_dst, text)
            # Parse via temporary path helper: write then parse_handles_txt
            handle_index = parse_handles_txt(handles_dst)
            copied += 1
    except OSError:
        handle_index = None
    try:
        if name_src.is_file():
            name_text = name_src.read_text(encoding="utf-8", errors="replace").strip()
            _write_text(name_dst, name_text + ("\n" if name_text else ""))
            vfs_name = name_text or None
            copied += 1
    except OSError:
        vfs_name = None
    return pid, handle_index, vfs_name, copied


def _stage_handle_vfs(
    source_root: Path, stage_root: Path
) -> tuple[int, dict[str, dict[str, str] | None], dict[str, str | None]]:
    """Copy handle/name VFS files and return parsed maps."""
    handles_csv = _resolve_source_csv(source_root, "handles.csv")
    if handles_csv is None:
        return 0, {}, {}
    pids = [pid for (pid,) in _unique_csv_pairs(handles_csv, ("PID", "pid")) if pid]
    if not pids:
        return 0, {}, {}

    handle_indexes: dict[str, dict[str, str] | None] = {}
    vfs_names: dict[str, str | None] = {}
    copied = 0
    workers = min(_COPY_WORKERS, max(1, len(pids)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                _stage_one_handles,
                source_root / "pid" / pid / "handles" / "handles.txt",
                stage_root / "pid" / pid / "handles" / "handles.txt",
                source_root / "pid" / pid / "name.txt",
                stage_root / "pid" / pid / "name.txt",
                pid,
            )
            for pid in pids
        ]
        for fut in as_completed(futures):
            pid, handle_index, vfs_name, n = fut.result()
            handle_indexes[pid] = handle_index
            vfs_names[pid] = vfs_name
            copied += n
    return copied, handle_indexes, vfs_names


def stage_memprocfs_tree(
    source_root: Path,
    stage_root: Path,
    *,
    need_thread_vfs: bool = True,
    need_handle_vfs: bool = True,
) -> StageResult:
    """Build a local MemProcFS stage under *stage_root*.

    Replaces any existing *stage_root*. Copies forensic CSVs plus selective
    ``pid/`` VFS files required for thread/handle ownership gates. Parsed VFS
    values are returned so extractors can avoid a second disk pass.
    """
    source_root = Path(source_root)
    stage_root = Path(stage_root)

    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True, exist_ok=True)

    logger.info("Staging MemProcFS tree from %s -> %s", source_root, stage_root)
    csv_count = _copy_forensic_csvs(source_root, stage_root)
    logger.info("  staged forensic/csv files: %d", csv_count)

    ethreads: dict[tuple[str, str], str | None] = {}
    handle_indexes: dict[str, dict[str, str] | None] = {}
    vfs_names: dict[str, str | None] = {}
    vfs_count = 0

    if need_thread_vfs:
        n, ethreads = _stage_thread_vfs(source_root, stage_root)
        vfs_count += n
        logger.info("  staged thread info.txt files: %d", n)
    if need_handle_vfs:
        n, handle_indexes, vfs_names = _stage_handle_vfs(source_root, stage_root)
        vfs_count += n
        logger.info("  staged handle/name VFS files: %d", n)

    logger.info("MemProcFS stage ready (%d csv + %d vfs files)", csv_count, vfs_count)
    return StageResult(
        root=stage_root,
        ethreads=ethreads,
        handle_indexes=handle_indexes,
        vfs_names=vfs_names,
    )

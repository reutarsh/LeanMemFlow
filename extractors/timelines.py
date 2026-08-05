"""Extract all timeline CSVs from the forensic output.

MemProcFS produces a family of ``timeline_*.csv`` files (timeline_all,
timeline_ntfs, timeline_process, timeline_thread, timeline_task,
timeline_net, timeline_kernelobject, timeline_prefetch, timeline_web, etc.).
This extractor copies all of them in one pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult
from extractors.timeline_process_text import (
    TIMELINE_PROCESS_FILENAME,
    enrich_timeline_process_csv,
)
from extractors.timeline_registry_text import (
    TIMELINE_REGISTRY_FILENAME,
    enrich_timeline_registry_csv,
)
from extractors.timeline_kernelobject_text import (
    TIMELINE_KERNELOBJECT_FILENAME,
    enrich_timeline_kernelobject_csv,
)
from extractors.timeline_net_text import (
    TIMELINE_NET_FILENAME,
    enrich_timeline_net_csv,
)
from extractors.timeline_task_text import (
    TIMELINE_TASK_FILENAME,
    enrich_timeline_task_csv,
)
from extractors.timeline_ntfs_text import (
    TIMELINE_NTFS_FILENAME,
    enrich_timeline_ntfs_csv,
)
from extractors.timeline_thread_text import (
    TIMELINE_THREAD_FILENAME,
    enrich_timeline_thread_csv,
)


def _files_written_contains(files_written: list[str], filename: str) -> bool:
    """True if *filename* appears in ExtractResult.files_written (str or Path)."""
    for entry in files_written:
        name = entry.name if isinstance(entry, Path) else str(entry)
        if Path(name).name == filename:
            return True
    return False


class TimelinesExtractor(BaseExtractor):
    name = "timelines"
    output_filename = "timeline_all.csv"
    source = "forensic_csv"

    def extract(self, memprocfs_root: Any, out_dir: Path) -> ExtractResult:
        result = self.copy_forensic_csvs_matching(Path(memprocfs_root), "timeline_", out_dir)
        if result.ok and _files_written_contains(result.files_written, TIMELINE_PROCESS_FILENAME):
            enrich_timeline_process_csv(out_dir / TIMELINE_PROCESS_FILENAME)
        if result.ok and _files_written_contains(result.files_written, TIMELINE_REGISTRY_FILENAME):
            enrich_timeline_registry_csv(out_dir / TIMELINE_REGISTRY_FILENAME)
        if result.ok and _files_written_contains(result.files_written, TIMELINE_TASK_FILENAME):
            enrich_timeline_task_csv(out_dir / TIMELINE_TASK_FILENAME)
        if result.ok and _files_written_contains(result.files_written, TIMELINE_NET_FILENAME):
            enrich_timeline_net_csv(out_dir / TIMELINE_NET_FILENAME)
        if result.ok and _files_written_contains(result.files_written, TIMELINE_KERNELOBJECT_FILENAME):
            enrich_timeline_kernelobject_csv(out_dir / TIMELINE_KERNELOBJECT_FILENAME)
        if result.ok and _files_written_contains(result.files_written, TIMELINE_NTFS_FILENAME):
            enrich_timeline_ntfs_csv(out_dir / TIMELINE_NTFS_FILENAME)
        if result.ok and _files_written_contains(result.files_written, TIMELINE_THREAD_FILENAME):
            enrich_timeline_thread_csv(out_dir / TIMELINE_THREAD_FILENAME)
        return result

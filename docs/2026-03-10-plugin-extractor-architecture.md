# Plugin-Based Extractor Architecture

**Date:** 2026-03-10  
**Scope:** Refactor monolithic extraction into per-ability plugin files

## Goal

Replace the monolithic `run_extract.py` (which extracted everything in one script) with a plugin-based architecture where each MemProcFS capability lives in its own file under `extractors/`. Adding a new data type = adding one `.py` file.

## Changes

### New files

| File | Type | Description |
|------|------|-------------|
| `extractors/__init__.py` | Auto-discovery | Scans package, finds all `BaseExtractor` subclasses |
| `extractors/base.py` | ABC + helpers | `BaseExtractor`, `ExtractResult`, shared CSV/VFS methods |
| `extractors/processes.py` | API | Process list via `vmm.process_list()` |
| `extractors/dlls.py` | API | Per-process loaded DLLs via `proc.module_list()` (NEW) |
| `extractors/netstat.py` | VFS | Network connections from `/sys/net/netstat.txt` |
| `extractors/modules.py` | Forensic CSV | System-wide kernel modules |
| `extractors/handles.py` | Forensic CSV | Handle table |
| `extractors/files.py` | Forensic CSV | Open files |
| `extractors/threads.py` | Forensic CSV | Thread information |
| `extractors/tasks.py` | Forensic CSV | Scheduled tasks |
| `extractors/drivers.py` | Forensic CSV | Kernel drivers |
| `extractors/devices.py` | Forensic CSV | Device objects |
| `extractors/unloaded_modules.py` | Forensic CSV | Unloaded modules |
| `extractors/findevil.py` | Forensic CSV | FindEvil scan results |
| `extractors/services.py` | Forensic CSV | Windows services |
| `extractors/timelines.py` | Forensic CSV | All `timeline_*.csv` files (incl. `timeline_registry.csv`) |

### Modified files

| File | Change |
|------|--------|
| `run_extract.py` | Rewritten as thin orchestrator with `--only`/`--exclude`/`--list` flags |
| `pyproject.toml` | Added `memflow-extract` entry point + `extractors` package discovery |
| `README.md` | Documented extractor plugin pattern and how to add new abilities |

## Architecture

Three extractor source strategies:
- **api** — direct MemProcFS Python objects (processes, DLLs)
- **vfs** — parse VFS text files (netstat)
- **forensic_csv** — copy pre-built CSVs from `/forensic/csv/`

Orchestrator opens VMM once, enables forensic mode if needed, then iterates all discovered plugins.

## Deduplication Note

`registry.py` was removed — it independently copied `timeline_registry.csv`, which `timelines.py` already covers via its `timeline_` prefix match. Running both caused a race-condition duplicate write. Registry data is now exclusively handled by `timelines`.

## How to add a new ability

1. Create `extractors/<name>.py`
2. Define a class inheriting from `BaseExtractor`
3. Set `name`, `output_filename`, `source`
4. Implement `extract(self, vmm, out_dir) -> ExtractResult`
5. Done — auto-discovered on next run

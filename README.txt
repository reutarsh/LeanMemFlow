LeanMemFlow
===========

Lean slice of MemFlow: run extractors only. Input is MemProcFS forensic CSV
output; output is the same CSVs after extractor copy/enrichment.

Out of scope (kept in full MemFlow, not here):
  - YAML parse/normalization (typed_*.csv)
  - SQL import / database layer
  - Alert rules, inventory, entropy, C# runner/API

Layout
------
  run_extract.py          CLI orchestrator
  extractors/             Plugin extractors + timeline enrichers
  memflow_common/         Shared CSV read/write helpers
  tests/                  Unit tests for extractors and csv_io
  docs/                   Extractor field reference and plugin notes

Requirements
------------
  Python 3.10+
  Stdlib only for CSV extractors.
  Optional: memprocfs>=4.0 for dlls.csv entry_point / entry_point_rva
  enrichment from --dump-path. Without it, dlls still builds from
  modules.csv; those fields stay empty unless already in CSV.

Install (optional)
------------------
  python -m venv .venv
  .venv\Scripts\activate          (Windows)
  pip install -e ".[test]"

Run
---
  List extractors:
    python run_extract.py --list

  Extract all:
    python run_extract.py ^
      --dump-path C:\path\to\memory.dmp ^
      --memprocfs-path C:\path\to\MemProcFS_output ^
      --case C:\path\to\case

  CSVs are written to <case>\csv\ unless --out is set.

  Subset:
    python run_extract.py ... --only processes,dlls,timelines
    python run_extract.py ... --exclude timelines

MemProcFS input layout
----------------------
Extractors look for forensic CSVs under (first match wins):
  <memprocfs-path>\forensic\csv\*.csv
  <memprocfs-path>\csv\*.csv
  <memprocfs-path>\*.csv

By default run_extract stages a local copy under:
  <case>\.leanmemflow_memprocfs_stage\
This copies forensic CSVs plus only the pid\ VFS files needed for thread /
handle ownership gates (never memory.vmem or other huge binaries). While
copying, ETHREAD / handle-table / name.txt values are parsed into an in-memory
cache so extractors do not re-read those files. The stage folder is deleted
when the run finishes (success or failure).
Use --no-stage-memprocfs to read --memprocfs-path directly (extractors then
parallel-preload thread info.txt instead).

Threads module enrichment (StartModule*) also requires the MemProcFS
process/thread VFS tree by default:
  <memprocfs-path>\pid\<PID>\threads\<TID>\info.txt
so CSV ETHREAD can be checked against MemProcFS's PID/TID listing.
CSV-only trees (no pid\): use --threads-allow-csv-only (range join only;
less safe for PID-reuse cases).

Handles ProcessName enrichment also requires the process handle VFS tree
by default:
  <memprocfs-path>\pid\<PID>\handles\handles.txt
  <memprocfs-path>\pid\<PID>\name.txt   (preferred name source)
so CSV Handle+Object can be checked against MemProcFS's per-PID handle table.
CSV-only trees (no pid\): use --handles-allow-csv-only (PID join to
process.csv / name.txt only; less safe for PID-reuse cases).

When several extractors run in one pass, run_extract shares an in-memory
VFS/process-name cache (lazy, CSV-driven) across handles, threads, and
netstat — no full pid\ tree walk.

--dump-path must point at an existing memory dump file. Most extractors use
only MemProcFS CSV/VFS output. The dlls extractor also opens the dump (via
the optional memprocfs Python package) to fill empty entry_point and
entry_point_rva when possible. module_type is derived from Name prefixes
even without dump enrichment.

Exit codes
----------
  0  all selected extractors succeeded
  1  partial failure (some OK, some FAIL)
  2  fatal (missing inputs, or all extractors failed)

Tests
-----
  pytest
  pytest tests/test_timeline_process_text.py -q

Adding an extractor
-------------------
  1. Add extractors/<name>.py with a BaseExtractor subclass
     (set name, output_filename, source; implement extract()).
  2. discover_extractors() picks it up automatically — no registry edit.
  3. Add tests under tests/.
  4. Document columns in docs/10_extractor_field_reference.md if the
     schema is non-obvious (especially timeline_* enrichers).

Timeline enrichers
------------------
  timelines.py copies timeline_*.csv then calls timeline_*_text helpers
  that rewrite schemas (semantic columns). Helpers use memflow_common.csv_io.

Origin
------
  Split from MemFlow-main for CSV-only extraction workflows.
  Keep extractor logic in sync with MemFlow when porting fixes.

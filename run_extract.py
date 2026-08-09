"""LeanMemFlow Extract — file-based plugin orchestrator (CSV out only)."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from extractors import discover_extractors
from extractors.base import ExtractResult

logger = logging.getLogger(__name__)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_extract",
        description=(
            "LeanMemFlow Extract — copy and enrich MemProcFS forensic CSVs. "
            "No parse/SQL stage; output is the post-extractor CSV set."
        ),
    )
    parser.add_argument(
        "--dump-path",
        type=Path,
        help="Path to an existing raw memory dump file (validated only; not read).",
    )
    parser.add_argument(
        "--memprocfs-path",
        type=Path,
        help="Path to existing MemProcFS output root.",
    )
    parser.add_argument(
        "--case", "-c",
        type=Path,
        help="Investigation root directory.",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for CSVs (default: <case>/csv/).",
    )
    parser.add_argument(
        "--only",
        type=str,
        default=None,
        help="Comma-separated list of extractor names to run (e.g. processes,dlls).",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default=None,
        help="Comma-separated list of extractor names to skip.",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        default=False,
        help="List all discovered extractors and exit.",
    )
    parser.add_argument(
        "--threads-allow-csv-only",
        action="store_true",
        default=False,
        help=(
            "Skip MemProcFS pid/<PID>/threads/<TID> VFS ownership check when "
            "enriching threads.csv (range join only). Default requires VFS."
        ),
    )
    return parser


def resolve_extractors(
    registry: Dict[str, Any],
    only: Optional[str],
    exclude: Optional[str],
) -> Dict[str, Any]:
    """Filter the extractor registry by --only / --exclude flags."""
    if only:
        names = {n.strip() for n in only.split(",")}
        unknown = names - set(registry)
        if unknown:
            logger.warning("Unknown extractor(s) in --only: %s", ", ".join(sorted(unknown)))
        return {k: v for k, v in registry.items() if k in names}

    if exclude:
        names = {n.strip() for n in exclude.split(",")}
        return {k: v for k, v in registry.items() if k not in names}

    return registry


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    registry = discover_extractors()

    if args.list:
        print("Available extractors:")
        for name, cls in registry.items():
            print(f"  {name:24s}  source={cls.source:14s}  -> {cls.output_filename}")
        return 0

    if not args.dump_path or not args.memprocfs_path or not args.case:
        parser.error("--dump-path, --memprocfs-path, and --case are required (unless using --list).")

    dump_path: Path = args.dump_path.resolve()
    memprocfs_root: Path = args.memprocfs_path.resolve()
    case_dir: Path = args.case.resolve()
    out_dir: Path = (args.out or (case_dir / "csv")).resolve()

    if not dump_path.is_file():
        logger.error("Dump file not found: %s", dump_path)
        return 2
    if not memprocfs_root.exists():
        logger.error("MemProcFS path not found: %s", memprocfs_root)
        return 2

    case_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = resolve_extractors(registry, args.only, args.exclude)
    if not selected:
        logger.error("No extractors selected after filtering.")
        return 2

    print("=" * 60)
    print("LeanMemFlow Extract — File-Based Orchestrator")
    print("=" * 60)
    print(f"Dump:          {dump_path}")
    print(f"MemProcFS:     {memprocfs_root}")
    print(f"Case:          {case_dir}")
    print(f"Output:        {out_dir}")
    print(f"Extractors: {', '.join(selected)}")
    print()

    results: Dict[str, ExtractResult] = {}
    for name, cls in selected.items():
        logger.info("  RUN   %-24s (source=%s)", name, cls.source)
        try:
            if name == "threads":
                extractor = cls(allow_csv_only=args.threads_allow_csv_only)
            else:
                extractor = cls()
            result = extractor.extract(memprocfs_root, out_dir)
            results[name] = result
            status = "OK" if result.ok else "FAIL"
            logger.info(
                "  %-4s  %-24s  %d rows  %s",
                status, name, result.rows,
                ", ".join(result.files_written) if result.files_written else "",
            )
        except Exception as exc:
            results[name] = ExtractResult(ok=False, error=str(exc))
            logger.error("  FAIL  %-24s  %s", name, exc)

    print()
    print("=" * 60)
    print("Extraction Summary")
    print("=" * 60)
    ok_count = sum(1 for r in results.values() if r.ok)
    fail_count = sum(1 for r in results.values() if not r.ok)
    total_rows = sum(r.rows for r in results.values())

    for name, r in results.items():
        tag = "OK  " if r.ok else "FAIL"
        detail = f"{r.rows} rows" if r.ok else (r.error or "unknown error")
        print(f"  [{tag}] {name:24s}  {detail}")

    print()
    print(f"  Succeeded: {ok_count}  |  Failed: {fail_count}  |  Total rows: {total_rows}")
    print(f"  Output: {out_dir}")
    print("=" * 60)

    if ok_count == 0 and fail_count > 0:
        return 2
    if fail_count > 0 and ok_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

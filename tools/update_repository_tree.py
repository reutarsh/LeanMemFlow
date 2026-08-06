"""Regenerate REPOSITORY_TREE.txt at the repository root."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "REPOSITORY_TREE.txt"

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "venv",
        "bin",
        "obj",
        ".vs",
        "dist",
        "build",
    }
)


def should_skip(rel_posix: str, name: str) -> bool:
    if name in SKIP_DIRS:
        return True
    return any(part in SKIP_DIRS for part in rel_posix.split("/"))


def format_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.1f} MB"


def walk(dir_path: Path, prefix: str, lines: list[str], stats: dict) -> None:
    try:
        entries = sorted(
            dir_path.iterdir(),
            key=lambda p: (not p.is_dir(), p.name.lower()),
        )
    except PermissionError:
        lines.append(f"{prefix}[permission denied]")
        return

    visible: list[Path] = []
    for entry in entries:
        rel = entry.relative_to(ROOT).as_posix()
        if should_skip(rel, entry.name):
            continue
        visible.append(entry)

    for index, entry in enumerate(visible):
        is_last = index == len(visible) - 1
        branch = "└── " if is_last else "├── "
        rel = entry.relative_to(ROOT).as_posix()

        if entry.is_dir():
            lines.append(f"{prefix}{branch}{entry.name}/")
            stats["dirs"] += 1
            extension = "    " if is_last else "│   "
            walk(entry, prefix + extension, lines, stats)
            continue

        size = entry.stat().st_size
        stats["files"] += 1
        stats["bytes"] += size
        stats["extensions"][entry.suffix.lower() or "(no ext)"] += 1
        lines.append(f"{prefix}{branch}{entry.name}  ({format_size(size)})  [{rel}]")


def main() -> None:
    stats = {"dirs": 0, "files": 0, "bytes": 0, "extensions": Counter()}
    tree_lines: list[str] = []
    walk(ROOT, "", tree_lines, stats)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = [
        "LeanMemFlow repository tree",
        f"Generated: {generated}",
        f"Root: {ROOT}",
        "",
        "Excluded directories: .git, node_modules, __pycache__, .pytest_cache,",
        "  .venv, venv, bin, obj, .vs, dist, build",
        "",
        f"Totals: {stats['dirs']} directories, {stats['files']} files, {format_size(stats['bytes'])}",
        "",
        "Extension counts:",
    ]
    for ext, count in sorted(stats["extensions"].items(), key=lambda item: (-item[1], item[0])):
        header.append(f"  {ext}: {count}")
    header.extend(
        [
            "",
            "Key areas:",
            "  extractors/     Python MemProcFS CSV extractors and timeline enrichers",
            "  memflow_common/ Shared CSV read/write helpers",
            "  tests/          Python unit tests",
            "  docs/           Extractor field reference and plugin notes",
            "  tools/          CLI utilities and this tree generator",
            "",
            "Tree (directories end with /; files show size and repo-relative path):",
            "",
            str(ROOT) + "/",
        ]
    )

    content = "\n".join(header + tree_lines) + "\n"
    OUT.write_text(content, encoding="utf-8")
    print(f"Wrote {OUT} ({stats['files']} files, {stats['dirs']} dirs)")


if __name__ == "__main__":
    main()

"""Build canonical ``net.csv`` from MemProcFS forensic export or VFS netstat text.

**Primary source:** ``forensic/csv/net.csv`` (or ``csv/net.csv``) — MemProcFS
forensic network table. Column names vary by version; this module maps common
aliases into the canonical MemFlow schema.

**Fallback:** ``sys/net/netstat.txt`` or ``netstat.txt`` (whitespace-separated
``netstat -ano`` style lines) when forensic ``net.csv`` is absent.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult
from extractors.pid_ownership import VfsContext, build_process_name_map

logger = logging.getLogger(__name__)

NETSTAT_CANDIDATES = (
    ("sys", "net", "netstat.txt"),
    ("netstat.txt",),
)


def _norm_key(key: str) -> str:
    return key.strip().lower().replace(" ", "").replace("_", "").replace("-", "")


def _row_index(row: dict[str, str]) -> dict[str, str]:
    """Map normalised header -> cell value."""
    out: dict[str, str] = {}
    for k, v in row.items():
        if k is None:
            continue
        nk = _norm_key(k)
        if nk and v is not None:
            out[nk] = v.strip()
    return out


def _get(idx: dict[str, str], *aliases: str) -> str:
    for a in aliases:
        na = _norm_key(a)
        if na in idx:
            return idx[na]
    return ""


def split_host_port(endpoint: str) -> tuple[str, str]:
    """Split ``host:port``; supports bracketed IPv6 ``[::1]:443``."""
    s = (endpoint or "").strip().strip('"')
    if not s or s == "*":
        return "", ""
    if s.startswith("["):
        end = s.find("]")
        if end != -1 and end + 1 < len(s) and s[end + 1] == ":":
            return s[: end + 1], s[end + 2 :].strip()
        return s, ""
    if s.count(":") == 1:
        host, port = s.rsplit(":", 1)
        if port == "*" or port.isdigit():
            return host, port
    return s, ""


class NetstatExtractor(BaseExtractor):
    name = "netstat"
    output_filename = "net.csv"
    source = "forensic_csv"

    HEADERS = [
        "pid", "process_name", "protocol", "state",
        "src-addr", "src-port", "dst-addr", "dst-port",
    ]

    def __init__(self, *, ctx: VfsContext | None = None) -> None:
        self.ctx = ctx

    @staticmethod
    def _resolve_netstat_path(memprocfs_root: Path) -> Path | None:
        for parts in NETSTAT_CANDIDATES:
            candidate = memprocfs_root.joinpath(*parts)
            if candidate.is_file():
                return candidate
        return None

    def _build_process_name_map(self, memprocfs_root: Path) -> dict[str, str]:
        if self.ctx is not None:
            return self.ctx.get_process_name_map()
        return build_process_name_map(memprocfs_root)

    @staticmethod
    def _row_from_forensic(idx: dict[str, str]) -> list[str] | None:
        """Map one forensic row to canonical HEADERS; return None if row is unusable."""
        pid = _get(idx, "pid", "PID")
        proc = _get(idx, "process_name", "process", "Process")
        proto = _get(idx, "protocol", "proto", "Proto")
        state = _get(idx, "state", "State")

        src_a = _get(idx, "srcaddr", "localaddr", "localaddress", "local")
        src_p = _get(idx, "srcport", "localport")
        dst_a = _get(idx, "dstaddr", "remoteaddr", "foreignaddress", "foreignaddr", "remote")
        dst_p = _get(idx, "dstport", "remoteport")

        if not src_p and src_a:
            src_a, src_p = split_host_port(src_a)
        if not dst_p and dst_a:
            dst_a, dst_p = split_host_port(dst_a)

        if not proto and not pid and not src_a and not dst_a:
            return None

        return [pid, proc, proto, state, src_a, src_p, dst_a, dst_p]

    def _extract_from_forensic_csv(self, memprocfs_root: Path, out_dir: Path) -> ExtractResult | None:
        """If forensic ``net.csv`` exists, write canonical ``net.csv`` and return result."""
        net_csv = self._resolve_forensic_csv(memprocfs_root, "net.csv")
        if net_csv is None:
            return None
        rows: list[list[str]] = []
        with net_csv.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for raw in reader:
                idx = _row_index(raw)
                mapped = self._row_from_forensic(idx)
                if mapped is None:
                    continue
                rows.append(mapped)
        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

    def _extract_from_netstat_txt(self, memprocfs_root: Path, out_dir: Path) -> ExtractResult:
        rows: list[list[str]] = []
        root = Path(memprocfs_root)
        pid_to_name = self._build_process_name_map(root)
        netstat_path = self._resolve_netstat_path(root)
        if netstat_path is None:
            return ExtractResult(
                ok=False,
                error=f"Neither forensic net.csv nor netstat.txt found under {root}",
            )
        text = netstat_path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Proto"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue

            proto = parts[0]
            local = parts[1]
            remote = parts[2]
            state = parts[3] if len(parts) > 3 else ""
            pid = parts[4] if len(parts) > 4 else ""
            proc_name = pid_to_name.get(pid, "")

            src_addr, src_port = split_host_port(local)
            dst_addr, dst_port = split_host_port(remote)

            rows.append([pid, proc_name, proto, state, src_addr, src_port, dst_addr, dst_port])

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

    def extract(self, memprocfs_root: Any, out_dir: Path) -> ExtractResult:
        root = Path(memprocfs_root)
        try:
            forensic = self._extract_from_forensic_csv(root, out_dir)
            if forensic is not None:
                return forensic
            return self._extract_from_netstat_txt(root, out_dir)
        except Exception as exc:
            logger.error("Network extraction failed: %s", exc)
            return ExtractResult(ok=False, error=str(exc))

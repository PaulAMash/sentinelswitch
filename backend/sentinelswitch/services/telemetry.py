"""File-backed telemetry store over the generated Zeek logs (used for evidence bundles at demo time)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

_CACHE: dict[tuple[str, float], list[dict[str, Any]]] = {}


class FileTelemetry:
    def __init__(self, zeek_dir: Path):
        self.zeek_dir = zeek_dir

    def _load(self, name: str) -> list[dict[str, Any]]:
        path = self.zeek_dir / name
        if not path.exists():
            return []
        key = (str(path), path.stat().st_mtime)
        if key not in _CACHE:
            _CACHE.clear()
            with path.open("r", encoding="utf-8") as fh:
                _CACHE[key] = [json.loads(line) for line in fh if line.strip()]
        return _CACHE[key]

    def flows_for(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        lo, hi = start.timestamp(), end.timestamp()
        return [
            f
            for f in self._load("conn.log")
            if (f.get("id.orig_h") == ip or f.get("id.resp_h") == ip) and lo <= float(f["ts"]) <= hi
        ]

    def dns_for(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        lo, hi = start.timestamp(), end.timestamp()
        return [d for d in self._load("dns.log") if d.get("id.orig_h") == ip and lo <= float(d["ts"]) <= hi]

    def flow_count(self) -> int:
        return len(self._load("conn.log"))

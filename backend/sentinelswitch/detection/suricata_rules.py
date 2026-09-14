"""Parse `detections/suricata/local.rules` so generated alerts always match the rule text."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from simulator.canonical import ROOT

RULES_PATH = ROOT / "detections" / "suricata" / "local.rules"

CLASSTYPE_CATEGORY = {
    "network-scan": "Detection of a Network Scan",
    "attempted-recon": "Attempted Information Leak",
    "policy-violation": "Potential Corporate Privacy Violation",
    "bad-unknown": "Potentially Bad Traffic",
    "trojan-activity": "A Network Trojan was detected",
}
SEVERITY_NUM = {"high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class SuricataRule:
    sid: int
    rev: int
    msg: str
    classtype: str
    category: str
    sentinel_class: str
    sentinel_severity: str
    proto: str
    raw: str
    track: str = "by_src"

    @property
    def severity(self) -> int:
        return SEVERITY_NUM.get(self.sentinel_severity, 3)


_OPT = re.compile(r"(\w[\w.]*):\s*([^;]*);")


@lru_cache(maxsize=1)
def load_rules(path: Path = RULES_PATH) -> dict[int, SuricataRule]:
    rules: dict[int, SuricataRule] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        head, _, body = line.partition("(")
        parts = head.split()
        proto = parts[1] if len(parts) > 1 else "ip"
        opts = {}
        for m in _OPT.finditer(body):
            key, val = m.group(1), m.group(2).strip().strip('"')
            if key == "metadata":
                for kv in val.split(","):
                    k, _, v = kv.strip().partition(" ")
                    opts["meta_" + k] = v
            else:
                opts.setdefault(key, val)
        sid = int(opts["sid"])
        classtype = opts.get("classtype", "bad-unknown")
        track = "by_dst" if "track by_dst" in body else "by_src"
        rules[sid] = SuricataRule(
            sid=sid,
            rev=int(opts.get("rev", 1)),
            msg=opts["msg"],
            classtype=classtype,
            category=CLASSTYPE_CATEGORY.get(classtype, "Misc activity"),
            sentinel_class=opts.get("meta_sentinel_class", "misc"),
            sentinel_severity=opts.get("meta_sentinel_severity", "low"),
            proto=proto,
            raw=line,
            track=track,
        )
    return rules

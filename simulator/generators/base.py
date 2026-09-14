"""Shared primitives for the generators: stable RNGs, record types and time helpers."""

from __future__ import annotations

import random
import string
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from simulator.canonical import Environment, add_seconds

ALNUM = string.ascii_letters + string.digits


def stable_rng(env: Environment, *keys: Any) -> random.Random:
    """A random generator whose stream depends only on the dataset seed and the given keys, never on
    process hash randomisation or generation order."""
    h = env.seed & 0xFFFFFFFF
    for k in keys:
        h = zlib.crc32(str(k).encode("utf-8"), h)
    return random.Random(h)


def zeek_uid(rng: random.Random) -> str:
    return "C" + "".join(rng.choice(ALNUM) for _ in range(17))


@dataclass
class Flow:
    ts: datetime
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str | None
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    history: str
    orig_pkts: int
    resp_pkts: int
    scenario: str | None = None
    instance: str | None = None
    uid: str = ""
    tags: dict[str, Any] = field(default_factory=dict)

    @property
    def local_orig(self) -> bool:
        return self.orig_h.startswith("10.")

    @property
    def local_resp(self) -> bool:
        return self.resp_h.startswith("10.")


@dataclass
class DnsRecord:
    ts: datetime
    orig_h: str
    orig_p: int
    resp_h: str
    query: str
    qtype_name: str
    rcode_name: str
    answers: list[str]
    ttls: list[int]
    rtt: float
    trans_id: int
    scenario: str | None = None
    instance: str | None = None
    uid: str = ""


@dataclass
class HttpRecord:
    ts: datetime
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    method: str
    host: str
    uri: str
    user_agent: str
    status_code: int
    status_msg: str
    request_body_len: int
    response_body_len: int
    resp_mime: str
    uid: str = ""


@dataclass
class SslRecord:
    ts: datetime
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    server_name: str
    version: str
    cipher: str
    curve: str
    established: bool
    resumed: bool
    subject: str | None
    issuer: str | None
    validation_status: str
    uid: str = ""


def flow_bytes(rng: random.Random, kind: str) -> tuple[int, int, float, int, int]:
    """Return (orig_bytes, resp_bytes, duration, orig_pkts, resp_pkts) for a flow kind."""
    table = {
        "dns": (lambda: (rng.randint(38, 74), rng.randint(90, 420), rng.uniform(0.001, 0.030), 1, 1)),
        "https": (
            lambda: (
                rng.randint(1_200, 48_000),
                rng.randint(4_000, 950_000),
                rng.uniform(0.3, 45.0),
                rng.randint(12, 180),
                rng.randint(14, 900),
            )
        ),
        "https_long": (
            lambda: (
                rng.randint(20_000, 260_000),
                rng.randint(2_000_000, 48_000_000),
                rng.uniform(120.0, 1800.0),
                rng.randint(400, 3000),
                rng.randint(2000, 40000),
            )
        ),
        "smb": (
            lambda: (
                rng.randint(2_400, 120_000),
                rng.randint(3_000, 2_400_000),
                rng.uniform(0.8, 120.0),
                rng.randint(20, 900),
                rng.randint(20, 2200),
            )
        ),
        "kerberos": (lambda: (rng.randint(1_200, 2_400), rng.randint(1_300, 2_600), rng.uniform(0.01, 0.08), 3, 3)),
        "ldap": (
            lambda: (
                rng.randint(600, 4_200),
                rng.randint(800, 16_000),
                rng.uniform(0.05, 2.5),
                rng.randint(6, 40),
                rng.randint(6, 48),
            )
        ),
        "ntp": (lambda: (48, 48, 0.0, 1, 1)),
        "radius": (
            lambda: (
                rng.randint(180, 420),
                rng.randint(60, 240),
                rng.uniform(0.004, 0.06),
                rng.randint(1, 6),
                rng.randint(1, 6),
            )
        ),
        "ssh": (
            lambda: (
                rng.randint(6_000, 180_000),
                rng.randint(8_000, 620_000),
                rng.uniform(15.0, 2400.0),
                rng.randint(60, 2400),
                rng.randint(60, 3000),
            )
        ),
        "http": (
            lambda: (
                rng.randint(300, 900),
                rng.randint(400, 6_000),
                rng.uniform(0.01, 0.4),
                rng.randint(4, 9),
                rng.randint(4, 10),
            )
        ),
        "print": (
            lambda: (
                rng.randint(40_000, 2_600_000),
                rng.randint(200, 1_200),
                rng.uniform(1.0, 20.0),
                rng.randint(40, 1800),
                rng.randint(20, 900),
            )
        ),
        "update": (
            lambda: (
                rng.randint(4_000, 30_000),
                rng.randint(8_000_000, 420_000_000),
                rng.uniform(30.0, 900.0),
                rng.randint(800, 12000),
                rng.randint(6000, 300000),
            )
        ),
        "backup": (
            lambda: (
                rng.randint(1_900_000_000, 2_400_000_000),
                rng.randint(9_000_000, 40_000_000),
                rng.uniform(1500.0, 2900.0),
                rng.randint(1_400_000, 1_900_000),
                rng.randint(600_000, 900_000),
            )
        ),
        "syslog": (lambda: (rng.randint(120, 380), 0, 0.0, 1, 0)),
    }
    return table[kind]()


def jitter(rng: random.Random, base: datetime, spread_seconds: float) -> datetime:
    return add_seconds(base, rng.uniform(0, spread_seconds))

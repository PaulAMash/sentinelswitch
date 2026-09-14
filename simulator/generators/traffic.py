"""Background (benign) traffic model for the dataset day.

The model is intentionally modest: it produces enough connections, DNS lookups, TLS sessions and HTTP
requests for the dashboard to look like a real small-enterprise SPAN feed without creating huge files.
Every quantity is drawn from a stable per-device RNG so the output is byte-for-byte reproducible.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from simulator.canonical import Device, Environment, add_seconds

from .base import DnsRecord, Flow, HttpRecord, SslRecord, flow_bytes, stable_rng

# Activity multiplier per UTC hour for desktops that stay powered on all day.
HOURLY_ACTIVITY = {
    0: 0.06,
    1: 0.05,
    2: 0.06,
    3: 0.05,
    4: 0.05,
    5: 0.06,
    6: 0.15,
    7: 0.55,
    8: 0.85,
    9: 1.0,
    10: 1.0,
    11: 0.95,
    12: 0.55,
    13: 0.9,
    14: 1.0,
    15: 1.0,
    16: 0.9,
    17: 0.55,
    18: 0.3,
    19: 0.18,
    20: 0.14,
    21: 0.12,
    22: 0.09,
    23: 0.07,
}

# Mean events per active hour (multiplier 1.0) for a workstation.
WORKSTATION_RATES = {
    "dns": 10.5,
    "https_internal": 4.2,
    "https_external": 6.4,
    "smb": 2.2,
    "kerberos": 1.4,
    "ldap": 0.8,
    "ntp": 0.5,
    "update": 0.25,
    "print": 0.22,
    "http": 0.35,
    "ssh": 0.0,
    "mail": 1.1,
}
ROLE_RATE_OVERRIDES = {
    "laptop": {"ssh": 0.9, "https_external": 5.0},
    "guest-laptop": {
        "dns": 8.0,
        "https_internal": 0.0,
        "https_external": 9.0,
        "smb": 0.0,
        "kerberos": 0.0,
        "ldap": 0.0,
        "ntp": 0.2,
        "update": 0.1,
        "print": 0.0,
        "http": 0.6,
        "mail": 0.8,
    },
    "display": {
        "dns": 2.0,
        "https_internal": 0.0,
        "https_external": 0.6,
        "smb": 0.0,
        "kerberos": 0.0,
        "ldap": 0.0,
        "ntp": 0.15,
        "update": 0.02,
        "print": 0.0,
        "http": 0.1,
        "mail": 0.0,
    },
    "printer": {
        "dns": 0.4,
        "https_internal": 0.0,
        "https_external": 0.0,
        "smb": 0.0,
        "kerberos": 0.0,
        "ldap": 0.2,
        "ntp": 0.2,
        "update": 0.0,
        "print": 0.0,
        "http": 0.0,
        "mail": 0.0,
    },
}

TLS_CIPHERS = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]
USER_AGENTS = {
    "Windows 11 Enterprise": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Ubuntu 24.04 LTS": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "macOS": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Windows 11 Home": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
}
INTERNAL_FQDNS = {
    "dc01.corp.example.com": "10.30.0.10",
    "files.corp.example.com": "10.30.0.20",
    "intranet.corp.example.com": "10.30.0.40",
    "git.corp.example.com": "10.30.0.50",
    "updates.corp.example.com": "10.30.0.60",
    "print01.corp.example.com": "10.20.0.200",
    "radius01.corp.example.com": "10.30.0.30",
}


class TrafficModel:
    def __init__(self, env: Environment):
        self.env = env
        self.flows: list[Flow] = []
        self.dns: list[DnsRecord] = []
        self.http: list[HttpRecord] = []
        self.ssl: list[SslRecord] = []
        self.external = {e.fqdn: e for e in env.external_services}
        self.dns_server = env.dhcp["server"]
        self.ports_used: dict[str, int] = {}

    # ---- helpers ------------------------------------------------------------------------------
    def _eph(self, rng, host: str) -> int:
        return rng.randint(49152, 65535)

    def _dns_for(self, dev: Device) -> str:
        return "10.40.0.1" if dev.vlan == 40 else self.dns_server

    def _add_dns(
        self,
        rng,
        dev: Device,
        ts: datetime,
        name: str,
        answer: str | None,
        qtype: str = "A",
        scenario: str | None = None,
    ):
        server = self._dns_for(dev)
        ob, rb, dur, op, rp = flow_bytes(rng, "dns")
        rcode = "NOERROR" if answer else "NXDOMAIN"
        rtt = round(rng.uniform(0.0008, 0.018), 6)
        sp = self._eph(rng, dev.ip or "")
        self.flows.append(
            Flow(ts, dev.ip, sp, server, 53, "udp", "dns", dur, ob, rb, "SF", "Dd", op, rp, scenario=scenario)
        )
        self.dns.append(
            DnsRecord(
                ts,
                dev.ip,
                sp,
                server,
                name,
                qtype,
                rcode,
                [answer] if answer else [],
                [rng.choice([60, 300, 3600])] if answer else [],
                rtt,
                rng.randint(1, 65535),
                scenario=scenario,
            )
        )

    def _add_https(self, rng, dev: Device, ts: datetime, fqdn: str, ip: str, kind: str = "https", port: int = 443):
        ob, rb, dur, op, rp = flow_bytes(rng, kind)
        sp = self._eph(rng, dev.ip or "")
        self.flows.append(Flow(ts, dev.ip, sp, ip, port, "tcp", "ssl", dur, ob, rb, "SF", "ShADadFf", op, rp))
        self.ssl.append(
            SslRecord(
                ts,
                dev.ip,
                sp,
                ip,
                port,
                fqdn,
                "TLSv13",
                rng.choice(TLS_CIPHERS),
                "x25519",
                True,
                rng.random() < 0.35,
                None,
                None,
                "ok",
            )
        )

    def _add_flow(
        self,
        rng,
        dev: Device,
        ts: datetime,
        resp_h: str,
        resp_p: int,
        proto: str,
        service: str | None,
        kind: str,
        state: str = "SF",
        history: str = "ShADadFf",
        orig: str | None = None,
    ):
        ob, rb, dur, op, rp = flow_bytes(rng, kind)
        sp = self._eph(rng, dev.ip or "")
        self.flows.append(
            Flow(ts, orig or dev.ip, sp, resp_h, resp_p, proto, service, dur, ob, rb, state, history, op, rp)
        )

    def _active_hours(self, dev: Device) -> list[tuple[datetime, float]]:
        """Return (hour_start, multiplier) for every hour the device is attached."""
        out = []
        start = self.env.day_start
        for h in range(24):
            hs = start + timedelta(hours=h)
            he = hs + timedelta(hours=1)
            if dev.schedule:
                s, e = dev.schedule
                if he <= s or hs >= e:
                    continue
                mult = 1.0 if dev.role != "display" else HOURLY_ACTIVITY[h] * 1.4
                if dev.role == "guest-laptop":
                    mult = 1.0
            else:
                mult = HOURLY_ACTIVITY[h]
            out.append((hs, mult))
        return out

    # ---- endpoint traffic ---------------------------------------------------------------------
    def generate_endpoint(self, dev: Device) -> None:
        rng = stable_rng(self.env, "traffic", dev.hostname)
        rates = dict(WORKSTATION_RATES)
        rates.update(ROLE_RATE_OVERRIDES.get(dev.role, {}))
        if dev.role == "workstation" and dev.os.startswith("Ubuntu"):
            rates["ssh"] = 0.6
        for hs, mult in self._active_hours(dev):
            lo = hs
            if dev.schedule:
                lo = max(hs, dev.schedule[0])
            hi = hs + timedelta(hours=1)
            if dev.schedule:
                hi = min(hi, dev.schedule[1])
            span = (hi - lo).total_seconds()
            if span <= 0:
                continue

            def n(kind: str, mult: float = mult, span: float = span) -> int:
                lam = rates.get(kind, 0.0) * mult * (span / 3600.0)
                # Poisson via inverse transform for small lambdas
                if lam <= 0:
                    return 0
                return _poisson(rng, lam)

            def t(lo: datetime = lo, span: float = span) -> datetime:
                return add_seconds(lo, rng.uniform(0, span))

            for _ in range(n("dns")):
                name, ip = self._pick_dns_target(rng, dev)
                self._add_dns(rng, dev, t(), name, ip)
            for _ in range(n("https_internal")):
                fqdn = rng.choice(
                    [
                        "intranet.corp.example.com",
                        "git.corp.example.com",
                        "intranet.corp.example.com",
                        "updates.corp.example.com",
                    ]
                )
                self._add_https(rng, dev, t(), fqdn, INTERNAL_FQDNS[fqdn])
            for _ in range(n("https_external")):
                svc = self._pick_external(rng, dev)
                self._add_https(
                    rng, dev, t(), svc.fqdn, svc.ip, kind="https_long" if svc.kind == "streaming" else "https"
                )
            for _ in range(n("mail")):
                self._add_https(rng, dev, t(), "mail.example.com", "198.51.100.25")
            for _ in range(n("smb")):
                self._add_flow(rng, dev, t(), "10.30.0.20", 445, "tcp", "smb", "smb")
            for _ in range(n("kerberos")):
                self._add_flow(rng, dev, t(), "10.30.0.10", 88, "tcp", "krb_tcp", "kerberos")
            for _ in range(n("ldap")):
                self._add_flow(rng, dev, t(), "10.30.0.10", 389, "tcp", "ldap", "ldap")
            for _ in range(n("ntp")):
                target = "10.30.0.10" if dev.vlan != 40 else "10.40.0.1"
                self._add_flow(rng, dev, t(), target, 123, "udp", "ntp", "ntp", state="SF", history="Dd")
            for _ in range(n("update")):
                self._add_https(rng, dev, t(), "updates.corp.example.com", "10.30.0.60", kind="update")
            for _ in range(n("print")):
                self._add_flow(
                    rng,
                    dev,
                    t(),
                    "10.20.0.200",
                    rng.choice([631, 9100]),
                    "tcp",
                    "ipp" if rng.random() < 0.5 else None,
                    "print",
                )
            for _ in range(n("http")):
                self._add_http(rng, dev, t())
            for _ in range(n("ssh")):
                target = rng.choice(["10.30.0.50", "10.30.0.50", "198.51.100.60"])
                self._add_flow(rng, dev, t(), target, 22, "tcp", "ssh", "ssh")

    def _add_http(self, rng, dev: Device, ts: datetime) -> None:
        ob, rb, dur, op, rp = flow_bytes(rng, "http")
        sp = self._eph(rng, dev.ip or "")
        if dev.vlan == 40:
            host, ip, uri, status, msg, mime = (
                "www.example.com",
                "203.0.113.30",
                "/",
                301,
                "Moved Permanently",
                "text/html",
            )
        else:
            host, ip, uri, status, msg, mime = (
                "intranet.corp.example.com",
                "10.30.0.40",
                rng.choice(["/", "/status", "/health", "/it/announcements"]),
                rng.choice([301, 200, 200]),
                "OK",
                "text/html",
            )
            if status == 301:
                msg = "Moved Permanently"
        self.flows.append(Flow(ts, dev.ip, sp, ip, 80, "tcp", "http", dur, ob, rb, "SF", "ShADadFf", op, rp))
        self.http.append(
            HttpRecord(
                ts,
                dev.ip,
                sp,
                ip,
                80,
                "GET",
                host,
                uri,
                USER_AGENTS.get(dev.os, USER_AGENTS["Windows 11 Enterprise"]),
                status,
                msg,
                0,
                rb - 240 if rb > 240 else rb,
                mime,
            )
        )

    def _pick_dns_target(self, rng, dev: Device) -> tuple[str, str | None]:
        if dev.vlan == 40:
            svc = self._pick_external(rng, dev)
            return svc.fqdn, svc.ip
        r = rng.random()
        if r < 0.42:
            name = rng.choice(list(INTERNAL_FQDNS))
            return name, INTERNAL_FQDNS[name]
        if r < 0.95:
            svc = self._pick_external(rng, dev)
            return svc.fqdn, svc.ip
        # occasional NXDOMAIN for a typo / stale entry
        return rng.choice(
            ["wpad.corp.example.com", "isatap.corp.example.com", "_ldap._tcp.dc._msdcs.corp.example.com"]
        ), None

    def _pick_external(self, rng, dev: Device):
        pool = [e for e in self.env.external_services if e.approved and e.kind != "agent-telemetry"]
        weights = {
            "cdn": 5,
            "web": 4,
            "saas-api": 3,
            "mail": 2,
            "git-hosting": 2,
            "streaming": 1,
            "os-updates": 1,
            "package-mirror": 1,
        }
        if dev.role == "display":
            pool = [e for e in pool if e.kind in {"streaming", "cdn"}]
        if dev.role == "guest-laptop":
            weights["streaming"] = 3
        return rng.choices(pool, weights=[weights.get(e.kind, 1) for e in pool], k=1)[0]

    # ---- servers -------------------------------------------------------------------------------
    def generate_servers(self) -> None:
        env = self.env
        rng = stable_rng(env, "traffic", "servers")
        day = env.day_start
        # DC01 forwards a share of client lookups upstream (visible on VLAN 30).
        upstream = "198.51.100.53"
        for d in list(self.dns):
            if d.resp_h == self.dns_server and rng.random() < 0.22 and not d.query.endswith("corp.example.com"):
                ts = add_seconds(d.ts, rng.uniform(0.0005, 0.003))
                ob, rb, dur, op, rp = flow_bytes(rng, "dns")
                sp = rng.randint(49152, 65535)
                self.flows.append(
                    Flow(ts, "10.30.0.10", sp, upstream, 53, "udp", "dns", dur, ob, rb, "SF", "Dd", op, rp)
                )
                self.dns.append(
                    DnsRecord(
                        ts,
                        "10.30.0.10",
                        sp,
                        upstream,
                        d.query,
                        d.qtype_name,
                        d.rcode_name,
                        d.answers,
                        d.ttls,
                        round(rng.uniform(0.008, 0.045), 6),
                        rng.randint(1, 65535),
                    )
                )
        # Nightly mirror sync and backup.
        srv = {d.hostname: d for d in env.devices}
        self._add_https(
            rng,
            srv["SRV-UPD01"],
            add_seconds(day, 2 * 3600 + 14),
            "updates.example.net",
            "198.51.100.20",
            kind="https_long",
        )
        self._add_https(
            rng,
            srv["SRV-UPD01"],
            add_seconds(day, 2 * 3600 + 1900),
            "pkg.example.org",
            "198.51.100.80",
            kind="https_long",
        )
        ob, rb, dur, op, rp = flow_bytes(rng, "backup")
        self.flows.append(
            Flow(
                add_seconds(day, 3 * 3600 + 15 * 60),
                "10.30.0.50",
                51522,
                "10.30.0.20",
                445,
                "tcp",
                "smb",
                dur,
                ob,
                rb,
                "SF",
                "ShADadFf",
                op,
                rp,
            )
        )
        # CI on GIT01 pulls upstream hourly.
        for h in range(24):
            self._add_https(
                rng,
                srv["SRV-GIT01"],
                add_seconds(day, h * 3600 + rng.uniform(60, 600)),
                "git.example.org",
                "198.51.100.60",
            )
        # Jump host SSH sessions into the servers VLAN (visible on the server side).
        jump = srv["LAB-JUMP01"]
        for _ in range(11):
            ts = add_seconds(day, rng.choice([8, 9, 10, 11, 13, 14, 15, 16]) * 3600 + rng.uniform(0, 3600))
            target = rng.choice(["10.30.0.30", "10.30.0.40", "10.30.0.50", "10.30.0.60", "10.30.0.10"])
            self._add_flow(
                rng,
                jump,
                ts,
                target,
                22 if target != "10.30.0.10" else 3389,
                "tcp",
                "ssh" if target != "10.30.0.10" else "rdp",
                "ssh",
            )
        # Servers sync time and resolve names too.
        for name in ("SRV-FILE01", "SRV-RADIUS01", "SRV-WEB01", "SRV-GIT01", "SRV-UPD01"):
            dev = srv[name]
            for h in range(0, 24, 4):
                self._add_flow(
                    rng,
                    dev,
                    add_seconds(day, h * 3600 + rng.uniform(0, 240)),
                    "10.30.0.10",
                    123,
                    "udp",
                    "ntp",
                    "ntp",
                    history="Dd",
                )
            for _ in range(rng.randint(6, 14)):
                fq = rng.choice(["updates.example.net", "pkg.example.org", "git.example.org", "api.example.org"])
                self._add_dns(rng, dev, add_seconds(day, rng.uniform(0, 86399)), fq, self.external[fq].ip)

    def generate_radius(self, auth_events: list[dict]) -> None:
        """One RADIUS exchange per authentication event (switch -> SRV-RADIUS01), visible on VLAN 30."""
        rng = stable_rng(self.env, "traffic", "radius")
        from simulator.canonical import parse_ts

        for ev in auth_events:
            ts = add_seconds(parse_ts(ev["timestamp"]), -rng.uniform(0.004, 0.04))
            ob, rb, dur, op, rp = flow_bytes(rng, "radius")
            self.flows.append(
                Flow(
                    ts,
                    "10.10.10.2",
                    rng.randint(1645, 1646) + rng.randint(0, 20000),
                    "10.30.0.30",
                    1812,
                    "udp",
                    "radius",
                    dur,
                    ob,
                    rb,
                    "SF",
                    "Dd",
                    op,
                    rp,
                    tags={"session_id": ev.get("session_id")},
                )
            )

    def generate_policy_violation(self) -> list[Flow]:
        """FIN-WS-015 syncs time with a non-approved public NTP server shortly after midnight."""
        rng = stable_rng(self.env, "traffic", "ntp-policy")
        dev = self.env.device_by_hostname("FIN-WS-015")
        ts = add_seconds(self.env.day_start, 47 * 60 + 12.418)
        self._add_dns(rng, dev, add_seconds(ts, -0.031), "time.example.net", "192.0.2.123")
        ob, rb, dur, op, rp = flow_bytes(rng, "ntp")
        f = Flow(
            ts, dev.ip, 123, "192.0.2.123", 123, "udp", "ntp", dur, ob, rb, "SF", "Dd", op, rp, tags={"policy": "ntp"}
        )
        self.flows.append(f)
        return [f]

    def generate_all(self, auth_events: list[dict]) -> None:
        for dev in self.env.devices:
            if dev.role in {
                "firewall",
                "security-stack",
                "pdu",
                "jump-host",
                "directory",
                "file-server",
                "aaa",
                "web",
                "git",
                "update-mirror",
            }:
                continue
            self.generate_endpoint(dev)
        self.generate_servers()
        self.generate_radius(auth_events)
        self.generate_policy_violation()


def _poisson(rng, lam: float) -> int:
    if lam > 30:
        return max(0, int(rng.gauss(lam, lam**0.5) + 0.5))
    import math

    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1

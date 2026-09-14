"""Scenario event emitters.

Each emitter turns a scenario instance (see simulator/scenarios/*.yaml) into the raw telemetry that
the sensors would have produced: Suricata alerts, Zeek notices, RADIUS results, IOS syslog, plus the
underlying Zeek conn/dns records for evidence. Alert timestamps are *derived* from the traffic model
(rates and thresholds) so the dataset, the rules and the documentation cannot disagree.
"""

from __future__ import annotations

import ipaddress
import string
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from simulator.canonical import Device, Environment, Scenario, ScenarioInstance, add_seconds, mac_cisco, ts_iso

from .base import DnsRecord, Flow, flow_bytes, stable_rng
from .events import RecordFactory
from .radius import session_id

ROLE_OPEN_PORTS = {
    "workstation": {445, 135, 139, 3389},
    "laptop": {22},
    "printer": {139, 445},
    "directory": {445, 135, 139, 3389},
    "file-server": {445, 135, 139, 3389},
    "aaa": {22},
    "web": {22},
    "git": {22},
    "update-mirror": {22},
    "firewall": {22},
}


@dataclass
class ScenarioOutput:
    scenario: Scenario
    instance: ScenarioInstance
    actor: dict[str, Any]
    records: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    dns: list[DnsRecord] = field(default_factory=list)
    narrative: list[dict[str, Any]] = field(default_factory=list)
    switch_effects: list[dict[str, Any]] = field(default_factory=list)  # native switch behaviour to apply in the twin
    derived: dict[str, Any] = field(default_factory=dict)  # derived timestamps for documentation

    def note(self, ts: datetime, message: str, phase: str = "telemetry") -> None:
        self.narrative.append({"ts": ts_iso(ts), "phase": phase, "message": message})


def _windows_like(dev: Device) -> bool:
    return dev.os.startswith("Windows") or dev.role in {"directory", "file-server"}


def _responders(env: Environment, at: datetime, subnet: str) -> list[tuple[str, Device | None]]:
    net = ipaddress.ip_network(subnet)
    out: list[tuple[str, Device | None]] = []
    gw = next((v.gateway for v in env.vlans.values() if v.subnet == subnet), None)
    if gw:
        out.append((gw, env.device_by_hostname("LAB-FW01")))
    for d in env.devices:
        if d.ip and ipaddress.ip_address(d.ip) in net and d.present_at(at) and not d.via_trunk:
            out.append((d.ip, d))
    return out


def emit(env: Environment, scenario: Scenario, instance_name: str) -> ScenarioOutput:
    inst = scenario.instances[instance_name]
    actor = scenario.actor_for(instance_name)
    out = ScenarioOutput(scenario, inst, actor)
    fn = EMITTERS[scenario.id]
    rf = RecordFactory(env, scenario.id, instance_name)
    fn(env, out, rf)
    out.records = list(rf.records)
    out.records.sort(key=lambda r: r[1].get("_ts_iso") or r[1].get("timestamp") or r[1].get("ts"))
    return out


# -------------------------------------------------------------------------------------------------
# Flagship: lateral reconnaissance
# -------------------------------------------------------------------------------------------------
def emit_lateral(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    actor_ip = out.actor["ip"]
    rng = stable_rng(env, "scenario", out.scenario.id, out.instance.name)
    sensor = float(p["sensor_latency"])
    tag = dict(scenario=out.scenario.id, instance=out.instance.name)

    # 1. ICMP echo sweep across two /24s
    icmp_rate = float(p["icmp_rate_pps"])
    responders: dict[str, Device | None] = {}
    idx = 0
    icmp_200: datetime | None = None
    for subnet in p["icmp_sweep_subnets"]:
        live = dict(_responders(env, t0, subnet))
        for host in ipaddress.ip_network(subnet).hosts():
            ip = str(host)
            if ip == actor_ip:
                continue
            ts = add_seconds(t0, idx / icmp_rate)
            idx += 1
            if idx == 200:
                icmp_200 = ts
            answered = ip in live
            if answered:
                responders[ip] = live[ip]
            out.flows.append(
                Flow(
                    ts,
                    actor_ip,
                    8,
                    ip,
                    0,
                    "icmp",
                    None,
                    0.0009 if answered else 0.0,
                    56,
                    56 if answered else 0,
                    "OTH",
                    "",
                    1,
                    1 if answered else 0,
                    **tag,
                )
            )
    out.note(
        t0, f"unusual ICMP echo fan-out from {actor_ip}: {idx} addresses across {', '.join(p['icmp_sweep_subnets'])}"
    )
    icmp_alert_ts = add_seconds(icmp_200, sensor)
    rf.suricata_alert(icmp_alert_ts, 1000010, actor_ip, 8, "10.20.0.201", 0, "icmp")
    out.derived["icmp_sweep_alert"] = ts_iso(icmp_alert_ts)

    # 2. Reverse DNS burst for the SERVERS subnet
    ptr_start = add_seconds(t0, float(p["ptr_burst_offset"]))
    ptr_rate = float(p["ptr_rate_qps"])
    names = {d.ip: f"{d.hostname.lower()}.corp.example.com" for d in env.devices if d.ip}
    ptr_50: datetime | None = None
    for i, host in enumerate(ipaddress.ip_network("10.30.0.0/24").hosts()):
        ip = str(host)
        ts = add_seconds(ptr_start, i / ptr_rate)
        if i == 49:
            ptr_50 = ts
        q = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        answer = names.get(ip) or ("lab-fw01.corp.example.com" if ip == "10.30.0.1" else None)
        sp = rng.randint(49152, 65535)
        ob, rb, dur, op, rp = flow_bytes(rng, "dns")
        out.flows.append(Flow(ts, actor_ip, sp, "10.30.0.10", 53, "udp", "dns", dur, ob, rb, "SF", "Dd", op, rp, **tag))
        out.dns.append(
            DnsRecord(
                ts,
                actor_ip,
                sp,
                "10.30.0.10",
                q,
                "PTR",
                "NOERROR" if answer else "NXDOMAIN",
                [answer] if answer else [],
                [3600] if answer else [],
                round(rng.uniform(0.0008, 0.004), 6),
                rng.randint(1, 65535),
                **tag,
            )
        )
    out.note(ptr_start, f"reverse DNS lookup burst from {actor_ip} for 10.30.0.0/24 ({int(ptr_rate)} queries/s)")
    ptr_alert_ts = add_seconds(ptr_50, sensor)
    rf.suricata_alert(
        ptr_alert_ts, 1000014, actor_ip, rng.randint(49152, 65535), "10.30.0.10", 53, "udp", app_proto="dns"
    )
    out.derived["ptr_burst_alert"] = ts_iso(ptr_alert_ts)

    # 3. TCP probe fan-out, host-major, to every responder
    probe_start = add_seconds(t0, float(p["tcp_probe_offset"]))
    rate = float(p["tcp_probe_rate_pps"])
    ports = [int(x) for x in p["tcp_probe_ports"]]
    targets = [(ip, dev) for ip, dev in responders.items() if ip != actor_ip]
    targets.sort(key=lambda x: ipaddress.ip_address(x[0]))
    smb_hosts: list[datetime] = []
    rdp_hosts: list[datetime] = []
    first_winrm: datetime | None = None
    n = 0
    probe_flows: list[Flow] = []
    for ip, dev in targets:
        open_ports = ROLE_OPEN_PORTS.get(dev.role if dev else "", set()) if dev else set()
        for port in ports:
            ts = add_seconds(probe_start, n / rate)
            n += 1
            sp = rng.randint(49152, 65535)
            if port in open_ports:
                state, hist, ob, rb, op, rp, dur = "RSTO", "ShAR", 0, 0, 2, 1, 0.0012
                svc = {445: "smb", 135: "dce_rpc", 139: "netbios", 3389: "rdp", 22: "ssh", 5985: "http"}.get(port)
                if port == 445:
                    state, hist, ob, rb, op, rp, dur = "SF", "ShADadFf", 142, 96, 5, 4, 0.021
            else:
                state, hist, ob, rb, op, rp, dur, svc = "REJ", "Sr", 0, 0, 1, 1, 0.0007, None
                if dev is None or dev.role in {"laptop"} and port != 22:
                    state, hist, rp = "S0", "S", 0
            probe_flows.append(Flow(ts, actor_ip, sp, ip, port, "tcp", svc, dur, ob, rb, state, hist, op, rp, **tag))
            if port == 445:
                smb_hosts.append(ts)
            if port == 3389:
                rdp_hosts.append(ts)
            if port == 5985 and first_winrm is None:
                first_winrm = ts
    out.note(
        probe_start,
        f"TCP connection fan-out from {actor_ip} to {len(targets)} responding hosts on ports {', '.join(str(x) for x in ports)}",
    )
    smb_alert_ts = add_seconds(smb_hosts[7], sensor)
    rdp_alert_ts = add_seconds(rdp_hosts[7], sensor)
    winrm_alert_ts = add_seconds(first_winrm, sensor)
    zeek_scan_ts = add_seconds(smb_hosts[14], 0.150)
    rf.suricata_alert(winrm_alert_ts, 1000024, actor_ip, rng.randint(49152, 65535), targets[0][0], 5985, "tcp")
    rf.suricata_alert(smb_alert_ts, 1000021, actor_ip, rng.randint(49152, 65535), targets[7][0], 445, "tcp")
    rf.suricata_alert(rdp_alert_ts, 1000022, actor_ip, rng.randint(49152, 65535), targets[7][0], 3389, "tcp")
    rf.zeek_notice(
        zeek_scan_ts,
        "Scan::Address_Scan",
        f"{actor_ip} scanned at least 15 unique hosts on port 445/tcp in 0m{int((smb_hosts[14] - smb_hosts[0]).total_seconds())}s",
        "",
        actor_ip,
        p=445,
        proto="tcp",
        n=15,
    )
    out.derived.update(
        {
            "smb_fanout_alert": ts_iso(smb_alert_ts),
            "rdp_fanout_alert": ts_iso(rdp_alert_ts),
            "winrm_alert": ts_iso(winrm_alert_ts),
            "zeek_address_scan": ts_iso(zeek_scan_ts),
        }
    )

    # 4. Anonymous SMB session attempt against the file server (rejected)
    null_ts = add_seconds(t0, float(p["smb_null_session_offset"]))
    sp = rng.randint(49152, 65535)
    probe_flows.append(
        Flow(
            null_ts,
            actor_ip,
            sp,
            "10.30.0.20",
            445,
            "tcp",
            "smb",
            0.412,
            1240,
            812,
            "SF",
            "ShADadFf",
            9,
            7,
            tags={"ntlm": "anonymous", "status": "STATUS_ACCESS_DENIED"},
            **tag,
        )
    )
    rf.suricata_alert(add_seconds(null_ts, 0.226), 1000023, actor_ip, sp, "10.30.0.20", 445, "tcp", app_proto="smb")
    out.note(null_ts, "anonymous SMB session setup against SRV-FILE01 rejected (STATUS_ACCESS_DENIED)")
    out.derived["smb_null_session_alert"] = ts_iso(add_seconds(null_ts, 0.226))

    # Flows after containment are no longer visible on the SPAN feed; the runner truncates them once
    # the quarantine timestamp is known (see ScenarioRunner.finalize_flows).
    out.flows.extend(sorted(probe_flows, key=lambda f: f.ts))
    out.derived["probe_flow_count"] = len(probe_flows)


# -------------------------------------------------------------------------------------------------
# Unauthorized endpoint
# -------------------------------------------------------------------------------------------------
def emit_unauthorized(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    iface, mac = out.actor["interface"], out.actor["mac"]
    rf.link_up(t0, iface)
    out.note(t0, f"link up on {iface}: unregistered device {mac_cisco(mac)} ({env.vendor_for_mac(mac)} OUI)")
    reject_ts = add_seconds(t0, float(p["mab_reject_offset"]))
    sid = session_id(iface, mac, 3)
    rf.radius(
        {
            "timestamp": ts_iso(reject_ts),
            "event_id": f"RAD-S-{out.scenario.id[:4].upper()}-{out.instance.name}",
            "username": mac_cisco(mac).replace(".", ""),
            "identity": mac.replace(":", "-"),
            "user": None,
            "device": None,
            "calling_station_id": mac.replace(":", "-"),
            "called_station_id": env.switch["base_mac"].replace(":", "-"),
            "nas_identifier": env.hostname,
            "nas_ip_address": env.switch["management_ip"],
            "nas_port": 50000 + int(iface.rsplit("/", 1)[-1]),
            "nas_port_id": iface.replace("Gi", "GigabitEthernet"),
            "nas_port_type": "Ethernet",
            "service_type": "Call-Check",
            "result": "Access-Reject",
            "method": "MAB",
            "eap_type": None,
            "assigned_vlan": None,
            "vlan_source": None,
            "session_timeout": None,
            "reason": "MAC not found in endpoint database",
            "audit_session_id": sid,
        }
    )
    rf.mab_fail(add_seconds(reject_ts, 0.026), iface, mac, sid)
    out.note(reject_ts, f"MAB Access-Reject for {mac_cisco(mac)} on {iface}: MAC not in endpoint database", phase="aaa")
    out.derived["mab_reject"] = ts_iso(reject_ts)


# -------------------------------------------------------------------------------------------------
# ARP spoofing
# -------------------------------------------------------------------------------------------------
def emit_arp(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    iface, mac, vlan = out.actor["interface"], out.actor["mac"], int(out.actor["vlan"])
    count, interval, spoofed = int(p["invalid_arp_count"]), float(p["interval"]), p["spoofed_ip"]
    for i in range(count):
        ts = add_seconds(t0, i * interval)
        rf.dai_deny(
            ts, iface, vlan, mac, spoofed, "0.0.0.0" if i % 2 == 0 else out.actor["ip"], op="Res" if i % 3 else "Req"
        )
    out.note(
        t0,
        f"Dynamic ARP Inspection dropping ARP from {mac_cisco(mac)} on {iface} claiming {spoofed} (binding says {out.actor['ip']})",
    )
    out.derived["first_deny"] = ts_iso(t0)
    out.derived["last_deny"] = ts_iso(add_seconds(t0, (count - 1) * interval))


# -------------------------------------------------------------------------------------------------
# Rogue DHCP
# -------------------------------------------------------------------------------------------------
def emit_rogue_dhcp(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    iface, mac, ip = out.actor["interface"], out.actor["mac"], out.actor["ip"]
    client = env.device_by_hostname(p["client_device"])
    rng = stable_rng(env, "scenario", out.scenario.id, out.instance.name)
    tag = dict(scenario=out.scenario.id, instance=out.instance.name)
    # The client broadcasts DISCOVER; the legitimate server answers through the relay, the rogue answers directly.
    for i, (offset, msg_type) in enumerate(p["drops"]):
        ts = add_seconds(t0, float(offset))
        if msg_type == "DHCPOFFER":
            out.flows.append(
                Flow(
                    add_seconds(ts, -0.031),
                    "0.0.0.0",
                    68,
                    "255.255.255.255",
                    67,
                    "udp",
                    "dhcp",
                    0.028,
                    342,
                    0,
                    "S0",
                    "D",
                    1,
                    0,
                    tags={"client_mac": client.mac, "message": "DHCPDISCOVER"},
                    **tag,
                )
            )
        rf.snooping_drop(ts, iface, msg_type, mac)
        if i == 0:
            rf.suricata_alert(
                add_seconds(ts, float(p["sensor_latency"])),
                1000040,
                ip,
                67,
                "255.255.255.255",
                68,
                "udp",
                app_proto="dhcp",
            )
            out.derived["suricata_alert"] = ts_iso(add_seconds(ts, float(p["sensor_latency"])))
        out.flows.append(
            Flow(
                ts,
                ip,
                67,
                "255.255.255.255",
                68,
                "udp",
                "dhcp",
                0.0,
                548,
                0,
                "S0",
                "D",
                1,
                0,
                tags={"message": msg_type, "dropped_by": "dhcp-snooping"},
                **tag,
            )
        )
    out.note(
        t0,
        f"DHCP snooping dropping {p['drops'][0][1]} from {mac_cisco(mac)} on untrusted port {iface} (client {client.hostname} broadcast DHCPDISCOVER)",
    )
    rng.random()


# -------------------------------------------------------------------------------------------------
# MAC address change
# -------------------------------------------------------------------------------------------------
def emit_mac_change(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    iface = out.actor["interface"]
    new_mac = p["new_mac"]
    rf.link_down(add_seconds(t0, float(p["unplug_offset"])), iface)
    rf.link_up(add_seconds(t0, -2.3), iface)
    rf.psecure_violation(t0, iface, new_mac)
    out.note(
        t0,
        f"port-security violation on {iface}: {mac_cisco(new_mac)} differs from sticky address {mac_cisco(out.actor['mac'])}",
    )
    reject_ts = add_seconds(t0, float(p["radius_reject_offset"]))
    method = p["radius_reject_method"]
    sid = session_id(iface, new_mac, 5)
    impersonated = env.device_by_hostname(p["impersonated_device"]) if p.get("impersonated_device") else None
    rf.radius(
        {
            "timestamp": ts_iso(reject_ts),
            "event_id": f"RAD-S-MACC-{out.instance.name}",
            "username": mac_cisco(new_mac).replace(".", "") if method == "MAB" else "host/unknown",
            "identity": new_mac.replace(":", "-") if method == "MAB" else "CN=unknown",
            "user": None,
            "device": impersonated.hostname if impersonated else None,
            "calling_station_id": new_mac.replace(":", "-"),
            "called_station_id": env.switch["base_mac"].replace(":", "-"),
            "nas_identifier": env.hostname,
            "nas_ip_address": env.switch["management_ip"],
            "nas_port": 50000 + int(iface.rsplit("/", 1)[-1]),
            "nas_port_id": iface.replace("Gi", "GigabitEthernet"),
            "nas_port_type": "Ethernet",
            "service_type": "Call-Check" if method == "MAB" else "Framed-User",
            "result": "Access-Reject",
            "method": method,
            "eap_type": 13 if method == "EAP-TLS" else None,
            "assigned_vlan": None,
            "vlan_source": None,
            "session_timeout": None,
            "reason": p["radius_reject_reason"],
            "audit_session_id": sid,
        }
    )
    if method == "MAB":
        rf.mab_fail(add_seconds(reject_ts, 0.026), iface, new_mac, sid)
    else:
        rf.dot1x_fail(add_seconds(reject_ts, 0.026), iface, new_mac, sid)
    out.switch_effects.append({"op": "psecure_violation", "interface": iface, "mac": new_mac, "ts": ts_iso(t0)})
    out.derived["radius_reject"] = ts_iso(reject_ts)


# -------------------------------------------------------------------------------------------------
# Port scan
# -------------------------------------------------------------------------------------------------
TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    81,
    88,
    110,
    111,
    113,
    119,
    135,
    139,
    143,
    161,
    179,
    199,
    389,
    427,
    443,
    445,
    465,
    513,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    636,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1110,
    1433,
    1720,
    1723,
    1755,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    3986,
    4899,
    5000,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    5985,
    6000,
    6001,
    6646,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9100,
    9999,
    10000,
    32768,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
    1521,
    1812,
    1813,
    5001,
    8530,
    8531,
]
SERVER_OPEN = {
    "10.30.0.10": {53, 88, 135, 139, 389, 445, 636, 3389},
    "10.30.0.20": {135, 139, 445, 3389},
    "10.30.0.30": {22, 1812, 1813},
    "10.30.0.40": {22, 80, 443},
    "10.30.0.50": {22, 443, 3000},
    "10.30.0.60": {22, 443, 8530, 8531},
}


def emit_port_scan(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    actor_ip = out.actor["ip"]
    rng = stable_rng(env, "scenario", out.scenario.id, out.instance.name)
    tag = dict(scenario=out.scenario.id, instance=out.instance.name)
    rate = float(p["rate_pps"])
    ports = TOP_PORTS[: int(p["ports_per_host"])]
    n = 0
    zeek_ts: datetime | None = None
    sur_ts: datetime | None = None
    for target in p["targets"]:
        opened = SERVER_OPEN.get(target, set())
        order = list(ports)
        rng.shuffle(order)
        for k, port in enumerate(order):
            ts = add_seconds(t0, n / rate)
            n += 1
            if n == 600:
                sur_ts = ts
            if zeek_ts is None and k == len(order) - 1:
                zeek_ts = add_seconds(ts, 0.150)
            sp = rng.randint(49152, 65535)
            if port in opened:
                out.flows.append(
                    Flow(ts, actor_ip, sp, target, port, "tcp", None, 0.0011, 0, 0, "RSTO", "ShAR", 2, 1, **tag)
                )
            else:
                out.flows.append(
                    Flow(ts, actor_ip, sp, target, port, "tcp", None, 0.0006, 0, 0, "REJ", "Sr", 1, 1, **tag)
                )
    out.note(
        t0,
        f"TCP port sweep from {actor_ip}: {len(ports)} ports x {len(p['targets'])} hosts in 10.30.0.0/24 ({int(rate)} probes/s)",
    )
    sur_alert = add_seconds(sur_ts, float(p["sensor_latency"]))
    rf.zeek_notice(
        zeek_ts,
        "Scan::Port_Scan",
        f"{actor_ip} scanned at least {len(ports)} unique ports of host {p['targets'][0]} in 0m0s",
        "",
        actor_ip,
        dst=p["targets"][0],
        proto="tcp",
        n=len(ports),
        alarm=out.instance.name == "validation",
    )
    rf.suricata_alert(sur_alert, 1000011, actor_ip, rng.randint(49152, 65535), p["targets"][2], TOP_PORTS[41], "tcp")
    out.derived.update({"zeek_port_scan": ts_iso(zeek_ts), "suricata_alert": ts_iso(sur_alert)})


# -------------------------------------------------------------------------------------------------
# DNS anomaly
# -------------------------------------------------------------------------------------------------
def emit_dns(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    actor_ip = out.actor["ip"]
    rng = stable_rng(env, "scenario", out.scenario.id, out.instance.name)
    tag = dict(scenario=out.scenario.id, instance=out.instance.name)
    qpm = float(p["queries_per_minute"])
    total = int(qpm * float(p["burst_minutes"]))
    nx_ratio = float(p["nxdomain_ratio"])
    unique = int(p["unique_domains"])
    pattern = p["domain_pattern"]
    names: list[str] = []
    for i in range(unique):
        if "{rand}" in pattern:
            label = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(rng.randint(11, 16)))
            names.append(pattern.replace("{rand}", label))
        else:
            names.append(pattern.replace("{n}", f"n{i + 1:02d}"))
    nx_count = 0
    nx_60: datetime | None = None
    q_120: datetime | None = None
    for i in range(total):
        ts = add_seconds(t0, i * 60.0 / qpm + rng.uniform(-0.05, 0.05))
        if i == 119:
            q_120 = ts
        name = names[i % unique]
        is_nx = rng.random() < nx_ratio
        if not is_nx and "{rand}" not in pattern:
            name = "agent.telemetry.example.net"
        answer = None if is_nx else ("203.0.113.77" if "{rand}" not in pattern else "203.0.113.55")
        if is_nx:
            nx_count += 1
            if nx_count == 60:
                nx_60 = ts
        sp = rng.randint(49152, 65535)
        ob, rb, dur, op, rp = flow_bytes(rng, "dns")
        out.flows.append(Flow(ts, actor_ip, sp, "10.30.0.10", 53, "udp", "dns", dur, ob, rb, "SF", "Dd", op, rp, **tag))
        out.dns.append(
            DnsRecord(
                ts,
                actor_ip,
                sp,
                "10.30.0.10",
                name,
                "A",
                "NXDOMAIN" if is_nx else "NOERROR",
                [answer] if answer else [],
                [300] if answer else [],
                round(rng.uniform(0.0009, 0.006), 6),
                rng.randint(1, 65535),
                **tag,
            )
        )
    out.note(
        t0,
        f"DNS query burst from {actor_ip}: ~{int(qpm)} queries/min, {int(nx_ratio * 100)}% NXDOMAIN, {unique} unique names",
    )
    sensor = float(p["sensor_latency"])
    nx_alert = add_seconds(nx_60, sensor)
    rate_alert = add_seconds(q_120, sensor)
    rf.suricata_alert(nx_alert, 1000031, "10.30.0.10", 53, actor_ip, rng.randint(49152, 65535), "udp", app_proto="dns")
    rf.suricata_alert(
        rate_alert, 1000030, actor_ip, rng.randint(49152, 65535), "10.30.0.10", 53, "udp", app_proto="dns"
    )
    zeek_ts = add_seconds(t0, 60.1)
    sub = f"queries_per_minute={int(qpm)} nxdomain_ratio={nx_ratio:.2f} unique_domains={unique} dga_like={'T' if p['dga_like'] else 'F'}"
    rf.zeek_notice(zeek_ts, "SentinelDNS::NXDomain_Burst", f"{actor_ip} DNS NXDOMAIN burst", sub, actor_ip, n=int(qpm))
    out.derived.update(
        {
            "nxdomain_alert": ts_iso(nx_alert),
            "rate_alert": ts_iso(rate_alert),
            "zeek_notice": ts_iso(zeek_ts),
            "query_count": total,
        }
    )


# -------------------------------------------------------------------------------------------------
# BPDU guard
# -------------------------------------------------------------------------------------------------
def emit_bpdu(env: Environment, out: ScenarioOutput, rf: RecordFactory) -> None:
    p = out.instance.parameters
    t0 = out.instance.start
    iface = out.actor["interface"]
    rf.bpdu_guard(t0, iface)
    rf.link_down(add_seconds(t0, float(p["link_down_offset"])), iface)
    out.note(
        t0,
        f"BPDU received on access port {iface} (unmanaged switch inserted in front of {out.actor['device']}); BPDU Guard err-disabled the port",
    )
    out.switch_effects.append({"op": "errdisable", "interface": iface, "reason": "bpduguard", "ts": ts_iso(t0)})
    out.derived["errdisable"] = ts_iso(add_seconds(t0, float(p["errdisable_offset"])))


EMITTERS = {
    "lateral-reconnaissance": emit_lateral,
    "unauthorized-endpoint": emit_unauthorized,
    "arp-spoofing": emit_arp,
    "rogue-dhcp": emit_rogue_dhcp,
    "mac-address-change": emit_mac_change,
    "port-scan": emit_port_scan,
    "dns-anomaly": emit_dns,
    "bpdu-violation": emit_bpdu,
}

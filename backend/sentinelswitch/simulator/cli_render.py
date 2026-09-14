"""Render Cisco IOS-style command output from the digital twin.

These renderers are used by the API (`/api/switch/show`), by the evidence bundles, and by the generator
that writes `cisco/show-output/*`. Because they read the twin, the transcripts are always consistent
with the state the dashboard displays.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from simulator.canonical import long_ifname, mac_cisco, parse_ts, short_ifname

from .twin import Interface, SwitchTwin

SHOW_COMMANDS = [
    "show version",
    "show vlan brief",
    "show vlan id 50",
    "show interfaces status",
    "show interfaces trunk",
    "show mac address-table",
    "show ip dhcp snooping",
    "show ip dhcp snooping binding",
    "show ip arp inspection",
    "show port-security",
    "show spanning-tree summary",
    "show errdisable recovery",
    "show monitor session 1",
    "show logging",
    "show authentication sessions",
]


def _uptime(twin: SwitchTwin) -> str:
    delta = twin.now - parse_ts(twin.uptime_reference)
    weeks, rem = divmod(int(delta.total_seconds()), 7 * 86400)
    days, rem = divmod(rem, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if weeks:
        parts.append(f"{weeks} week{'s' if weeks != 1 else ''}")
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    return ", ".join(parts)


def _vlan_name(twin: SwitchTwin, vlan: int | None) -> str:
    if vlan is None:
        return "none"
    v = twin.vlans.get(vlan)
    return v["name"] if v else f"VLAN{vlan:04d}"


def _ports_in_vlan(twin: SwitchTwin, vlan: int) -> list[str]:
    return [i.name for i in twin.interfaces.values() if i.mode == "access" and i.access_vlan == vlan]


def _wrap_ports(ports: list[str], indent: int = 48, per_line: int = 4) -> list[str]:
    lines = []
    for i in range(0, len(ports), per_line):
        chunk = ", ".join(ports[i : i + per_line])
        lines.append(chunk if i == 0 else " " * indent + chunk)
    return lines or [""]


def show_version(twin: SwitchTwin) -> str:
    return "\n".join(
        [
            "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version "
            + twin.ios_version
            + ", RELEASE SOFTWARE (fc2)",
            "Technical Support: http://www.cisco.com/techsupport",
            "Copyright (c) 1986-2023 by Cisco Systems, Inc.",
            "",
            "ROM: Bootstrap program is C2960X boot loader",
            "BOOTLDR: C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(7r)E3, RELEASE SOFTWARE (fc1)",
            "",
            f"{twin.hostname} uptime is {_uptime(twin)}",
            f'System image file is "flash:/{twin.image}"',
            "",
            f"cisco {twin.model} (APM86XXX) processor (revision N0) with 524288K bytes of memory.",
            f"Processor board ID {twin.serial}",
            "Last reset from power-on",
            "1 Virtual Ethernet interface",
            "48 Gigabit Ethernet interfaces",
            "2 Ten Gigabit Ethernet interfaces",
            "The password-recovery mechanism is enabled.",
            "",
            "512K bytes of flash-simulated non-volatile configuration memory.",
            f"Base ethernet MAC Address       : {twin.base_mac}",
            "Motherboard assembly number     : 73-15925-03",
            f"System serial number            : {twin.serial}",
            "",
            "Switch Ports Model                     SW Version            SW Image",
            "------ ----- -----                     ----------            ----------",
            f"*    1 52    {twin.model:<26}{twin.ios_version:<22}C2960X-UNIVERSALK9-M",
            "",
            "Configuration register is 0xF",
        ]
    )


def show_vlan_brief(twin: SwitchTwin) -> str:
    out = [
        "VLAN Name                             Status    Ports",
        "---- -------------------------------- --------- -------------------------------",
    ]
    out.append(f"{'1':<4} {'default':<32} active    ")
    for vid in sorted(twin.vlans):
        v = twin.vlans[vid]
        ports = _ports_in_vlan(twin, vid)
        wrapped = _wrap_ports(ports)
        out.append(f"{vid:<4} {v['name']:<32} active    {wrapped[0]}")
        out.extend(wrapped[1:])
    for vid, name in (
        (1002, "fddi-default"),
        (1003, "token-ring-default"),
        (1004, "fddinet-default"),
        (1005, "trnet-default"),
    ):
        out.append(f"{vid:<4} {name:<32} act/unsup ")
    return "\n".join(out)


def show_vlan_id(twin: SwitchTwin, vlan: int) -> str:
    v = twin.vlans.get(vlan)
    if not v:
        return f"VLAN id {vlan} not found in current VLAN database"
    ports = _wrap_ports(_ports_in_vlan(twin, vlan))
    out = [
        "VLAN Name                             Status    Ports",
        "---- -------------------------------- --------- -------------------------------",
    ]
    out.append(f"{vlan:<4} {v['name']:<32} active    {ports[0]}")
    out.extend(ports[1:])
    out += [
        "",
        "VLAN Type  SAID       MTU   Parent RingNo BridgeNo Stp  BrdgMode Trans1 Trans2",
        "---- ----- ---------- ----- ------ ------ -------- ---- -------- ------ ------",
        f"{vlan:<4} enet  {100000 + vlan:<10} 1500  -      -      -        -    -        0      0",
        "",
        "Remote SPAN VLAN",
        "----------------",
        "Disabled",
        "",
        "Primary Secondary Type              Ports",
        "------- --------- ----------------- ------------------------------------------",
    ]
    return "\n".join(out)


def _status_word(i: Interface) -> str:
    return {
        "connected": "connected",
        "notconnect": "notconnect",
        "disabled": "disabled",
        "err-disabled": "err-disabled",
        "monitoring": "monitoring",
    }[i.oper_status]


def show_interfaces_status(twin: SwitchTwin) -> str:
    out = ["Port      Name               Status       Vlan       Duplex  Speed Type"]
    for name, i in twin.interfaces.items():
        vlan = (
            "trunk"
            if i.is_trunk
            else str(i.oper_vlan if i.oper_status == "connected" and i.oper_vlan else i.access_vlan)
        )
        if i.oper_status in {"disabled", "notconnect", "err-disabled", "monitoring"}:
            vlan = "trunk" if i.is_trunk else str(i.access_vlan)
        duplex = i.duplex if i.oper_status in {"connected", "monitoring"} else "auto"
        speed = i.speed if i.oper_status in {"connected", "monitoring"} else "auto"
        ptype = "10/100/1000BaseTX" if name.startswith("Gi") else "Not Present" if name.startswith("Te") else "unknown"
        out.append(
            f"{name:<9} {i.description[:18]:<18} {_status_word(i):<12} {vlan:<10} {duplex:>6} {speed:>6} {ptype}"
        )
    return "\n".join(out)


def show_interfaces_trunk(twin: SwitchTwin) -> str:
    trunks = [i for i in twin.interfaces.values() if i.is_trunk and i.oper_status == "connected"]
    out = ["Port        Mode             Encapsulation  Status        Native vlan"]
    for i in trunks:
        out.append(f"{i.name:<11} {'on':<16} {'802.1q':<14} {'trunking':<13} {i.native_vlan}")
    out += ["", "Port        Vlans allowed on trunk"]
    for i in trunks:
        out.append(f"{i.name:<11} {','.join(str(v) for v in i.allowed_vlans)}")
    out += ["", "Port        Vlans allowed and active in management domain"]
    for i in trunks:
        out.append(f"{i.name:<11} {','.join(str(v) for v in i.allowed_vlans if v in twin.vlans)}")
    out += ["", "Port        Vlans in spanning tree forwarding state and not pruned"]
    for i in trunks:
        out.append(f"{i.name:<11} {','.join(str(v) for v in i.allowed_vlans if v in twin.vlans)}")
    return "\n".join(out)


def show_mac_address_table(twin: SwitchTwin, interface: str | None = None, address: str | None = None) -> str:
    entries = list(twin.mac_table)
    if interface:
        entries = [e for e in entries if e.interface == short_ifname(interface)]
    if address:
        entries = [e for e in entries if mac_cisco(e.mac) == mac_cisco(address)]
    entries.sort(key=lambda e: (e.vlan, e.mac))
    out = [
        "          Mac Address Table",
        "-------------------------------------------",
        "",
        "Vlan    Mac Address       Type        Ports",
        "----    -----------       --------    -----",
    ]
    if not interface and not address:
        for special in ("0100.0ccc.cccc", "0100.0ccc.cccd", "0180.c200.0000", "0180.c200.000e"):
            out.append(f" All    {special}    STATIC      CPU")
    for e in entries:
        out.append(f"{e.vlan:>4}    {mac_cisco(e.mac)}    {e.entry_type:<8}    {e.interface}")
    total = len(entries) + (0 if (interface or address) else 4)
    out.append(f"Total Mac Addresses for this criterion: {total}")
    return "\n".join(out)


def show_ip_dhcp_snooping(twin: SwitchTwin) -> str:
    vl = ",".join(str(v) for v in twin.dhcp_snooping_vlans)
    out = [
        "Switch DHCP snooping is enabled",
        "Switch DHCP gleaning is disabled",
        "DHCP snooping is configured on following VLANs:",
        vl,
        "DHCP snooping is operational on following VLANs:",
        vl,
        "DHCP snooping is configured on the following L3 Interfaces:",
        "",
        "Insertion of option 82 is disabled",
        "   circuit-id default format: vlan-mod-port",
        f"   remote-id: {mac_cisco(twin.base_mac)} (MAC)",
        "Option 82 on untrusted port is not allowed",
        "Verification of hwaddr field is enabled",
        "Verification of giaddr field is enabled",
        "DHCP snooping trust/rate is configured on the following Interfaces:",
        "",
        "Interface                  Trusted    Allow option    Rate limit (pps)",
        "-----------------------    -------    ------------    ----------------",
    ]
    for i in twin.interfaces.values():
        if i.port_class == "unused":
            continue
        trusted = bool(i.settings.get("dhcp_snooping_trust"))
        out.append(
            f"{i.long_name:<27}{'yes' if trusted else 'no':<11}{'yes' if trusted else 'no':<16}{'unlimited' if trusted else '15'}"
        )
        if trusted:
            out.append("  Custom circuit-ids:")
    return "\n".join(out)


def show_ip_dhcp_snooping_binding(twin: SwitchTwin) -> str:
    out = [
        "MacAddress          IpAddress        Lease(sec)  Type           VLAN  Interface",
        "------------------  ---------------  ----------  -------------  ----  --------------------",
    ]
    bindings = sorted(twin.dhcp_bindings, key=lambda b: (b.vlan, b.interface, b.ip))
    for b in bindings:
        remaining: str = (
            "infinite"
            if b.binding_type == "static"
            else str(max(0, int((parse_ts(b.lease_expires) - twin.now).total_seconds())))
        )
        out.append(
            f"{b.mac:<18}  {b.ip:<15}  {remaining:<10}  {b.binding_type:<13}  {b.vlan:<4}  {long_ifname(b.interface)}"
        )
    out.append(f"Total number of bindings: {len(bindings)}")
    return "\n".join(out)


def show_ip_arp_inspection(twin: SwitchTwin) -> str:
    out = [
        "Source Mac Validation      : Enabled",
        "Destination Mac Validation : Enabled",
        "IP Address Validation      : Enabled",
        "",
        " Vlan     Configuration    Operation   ACL Match          Static ACL",
        " ----     -------------    ---------   ---------          ----------",
    ]
    for v in twin.dai_vlans:
        out.append(f" {v:<8} Enabled          Active")
    out += [
        "",
        " Vlan     ACL Logging      DHCP Logging      Probe Logging",
        " ----     -----------      ------------      -------------",
    ]
    for v in twin.dai_vlans:
        out.append(f" {v:<8} Deny             Deny              Off")
    out += [
        "",
        " Vlan      Forwarded        Dropped     DHCP Drops      ACL Drops",
        " ----      ---------        -------     ----------      ---------",
    ]
    drops = {20: 0, 30: 0, 40: 5, 50: 0}
    fwd = {20: 118_402, 30: 61_337, 40: 4_918, 50: 0}
    for v in twin.dai_vlans:
        out.append(f" {v:<8} {fwd.get(v, 0):>11}     {drops.get(v, 0):>8}     {drops.get(v, 0):>10}      {0:>9}")
    return "\n".join(out)


def show_port_security(twin: SwitchTwin) -> str:
    out = [
        "Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action",
        "                (Count)       (Count)          (Count)",
        "---------------------------------------------------------------------------",
    ]
    total = 0
    for i in twin.interfaces.values():
        ps = i.settings.get("port_security", {})
        if not ps.get("enabled"):
            continue
        current = len(twin.macs_on_interface(i.name)) if i.oper_status == "connected" else 0
        total += max(0, current - 1)
        out.append(
            f"{i.name:>12} {ps.get('maximum', 1):>14} {current:>12} {i.port_security.get('violation_count', 0):>18} {str(ps.get('violation', 'shutdown')).capitalize():>16}"
        )
    out += [
        "---------------------------------------------------------------------------",
        f"Total Addresses in System (excluding one mac per port)     : {total}",
        "Max Addresses limit in System (excluding one mac per port) : 8192",
    ]
    return "\n".join(out)


def show_port_security_interface(twin: SwitchTwin, interface: str) -> str:
    i = twin.interfaces[short_ifname(interface)]
    ps = i.settings.get("port_security", {})
    if not ps.get("enabled"):
        return "Port Security              : Disabled\nPort Status                : Secure-down\nViolation Mode             : Shutdown"
    macs = twin.macs_on_interface(i.name)
    status = {"connected": "Secure-up", "err-disabled": "Secure-shutdown"}.get(i.oper_status, "Secure-down")
    last = i.port_security.get("last_source")
    last_vlan = i.oper_vlan if i.oper_status == "connected" else i.access_vlan
    lines = [
        "Port Security              : Enabled",
        f"Port Status                : {status}",
        f"Violation Mode             : {str(ps.get('violation', 'shutdown')).capitalize()}",
        "Aging Time                 : 0 mins",
        "Aging Type                 : Absolute",
        "SecureStatic Address Aging : Disabled",
        f"Maximum MAC Addresses      : {ps.get('maximum', 1)}",
        f"Total MAC Addresses        : {len(macs)}",
        "Configured MAC Addresses   : 0",
        f"Sticky MAC Addresses       : {len(i.sticky_macs)}",
        f"Last Source Address:Vlan   : {mac_cisco(last) if last else '0000.0000.0000'}:{last_vlan if last else 0}",
        f"Security Violation Count   : {i.port_security.get('violation_count', 0)}",
    ]
    return "\n".join(lines)


def show_spanning_tree_summary(twin: SwitchTwin) -> str:
    out = [
        "Switch is in rapid-pvst mode",
        "Root bridge for: none",
        "Extended system ID           is enabled",
        "Portfast Default             is disabled",
        "PortFast BPDU Guard Default  is enabled",
        "Portfast BPDU Filter Default is disabled",
        "Loopguard Default            is disabled",
        "EtherChannel misconfig guard is enabled",
        "UplinkFast                   is disabled",
        "BackboneFast                 is disabled",
        "Configured Pathcost method used is short",
        "",
        "Name                   Blocking Listening Learning Forwarding STP Active",
        "---------------------- -------- --------- -------- ---------- ----------",
    ]
    total = 0
    count = 0
    for vid in sorted(twin.vlans):
        if vid == 999:
            continue
        fwd = sum(
            1
            for i in twin.interfaces.values()
            if i.oper_status == "connected"
            and ((i.is_trunk and vid in i.allowed_vlans) or (not i.is_trunk and i.oper_vlan == vid))
        )
        if fwd == 0 and vid != 50:
            continue
        count += 1
        total += fwd
        out.append(f"VLAN{vid:04d}                     0         0        0 {fwd:>10} {fwd:>10}")
    out.append("---------------------- -------- --------- -------- ---------- ----------")
    out.append(f"{count} vlans                      0         0        0 {total:>10} {total:>10}")
    return "\n".join(out)


def show_errdisable_recovery(twin: SwitchTwin) -> str:
    out = ["ErrDisable Reason            Timer Status", "-----------------            --------------"]
    reasons = [
        "arp-inspection",
        "bpduguard",
        "channel-misconfig (STP)",
        "dhcp-rate-limit",
        "dtp-flap",
        "gbic-invalid",
        "inline-power",
        "l2ptguard",
        "link-flap",
        "loopback",
        "mac-limit",
        "pagp-flap",
        "port-mode-failure",
        "pppoe-ia-rate-limit",
        "psecure-violation",
        "security-violation",
        "sfp-config-mismatch",
        "small-frame",
        "storm-control",
        "udld",
        "vmps",
    ]
    enabled = {"arp-inspection", "dhcp-rate-limit", "psecure-violation", "storm-control"}
    for r in reasons:
        out.append(f"{r:<28} {'Enabled' if r in enabled else 'Disabled'}")
    out += [
        "",
        "Timer interval: 300 seconds",
        "",
        "Interfaces that will be enabled at the next timeout:",
        "",
        "Interface       Errdisable reason       Time left(sec)",
        "---------       -----------------       --------------",
    ]
    for i in twin.interfaces.values():
        if i.oper_status == "err-disabled" and i.errdisable_reason in enabled:
            out.append(f"{i.name:<15} {i.errdisable_reason:<23} 300")
    return "\n".join(out)


def show_monitor_session(twin: SwitchTwin, session: int = 1) -> str:
    s = twin.span
    return "\n".join(
        [
            f"Session {session}",
            "---------",
            "Type                   : Local Session",
            "Source VLANs           : ",
            f"    Both               : {','.join(str(v) for v in s['source_vlans'])}",
            f"Destination Ports      : {s['destination']}",
            "    Encapsulation      : Native",
            "          Ingress      : Disabled",
        ]
    )


def show_logging(twin: SwitchTwin, limit: int | None = None) -> str:
    lines = twin.log if limit is None else twin.log[-limit:]
    out = [
        "Syslog logging: enabled (0 messages dropped, 0 messages rate-limited, 0 flushes, 0 overruns, xml disabled, filtering disabled)",
        "",
        "No Active Message Discriminator.",
        "",
        "No Inactive Message Discriminator.",
        "",
        "    Console logging: level informational, 0 messages logged, xml disabled, filtering disabled",
        "    Monitor logging: level debugging, 0 messages logged, xml disabled, filtering disabled",
        f"    Buffer logging:  level informational, {twin.log_seq} messages logged, xml disabled, filtering disabled",
        "    Exception Logging: size (4096 bytes)",
        "    Count and timestamp logging messages: disabled",
        "    File logging: disabled",
        "    Persistent logging: disabled",
        "",
        "No active filter modules.",
        "",
        f"    Trap logging: level informational, {twin.log_seq} message lines logged",
        "        Logging to 10.99.0.10  (udp port 514, audit disabled, link up), 0 message lines rate-limited, 0 message lines dropped-by-MD, xml disabled, sequence number disabled, filtering disabled",
        "",
        "Log Buffer (65536 bytes):",
        "",
    ]
    out += [line.render() for line in lines]
    return "\n".join(out)


def show_interface_switchport(twin: SwitchTwin, interface: str) -> str:
    i = twin.interfaces[short_ifname(interface)]
    if i.is_trunk:
        mode_admin, mode_oper = "trunk", "trunk"
        access_line = "Access Mode VLAN: 1 (default)"
        native = f"{i.native_vlan} ({_vlan_name(twin, i.native_vlan)})"
        allowed = ",".join(str(v) for v in i.allowed_vlans)
    else:
        mode_admin, mode_oper = "static access", "static access" if i.oper_status == "connected" else "down"
        access_line = f"Access Mode VLAN: {i.access_vlan} ({_vlan_name(twin, i.access_vlan)})"
        native = "1 (default)"
        allowed = "ALL"
    return "\n".join(
        [
            f"Name: {i.name}",
            "Switchport: Enabled",
            f"Administrative Mode: {mode_admin}",
            f"Operational Mode: {mode_oper}",
            "Administrative Trunking Encapsulation: dot1q",
            f"Operational Trunking Encapsulation: {'dot1q' if i.is_trunk else 'native'}",
            "Negotiation of Trunking: Off",
            access_line,
            f"Trunking Native Mode VLAN: {native}",
            "Administrative Native VLAN tagging: enabled",
            "Voice VLAN: none",
            "Administrative private-vlan host-association: none",
            "Administrative private-vlan mapping: none",
            "Administrative private-vlan trunk native VLAN: none",
            "Administrative private-vlan trunk Native VLAN tagging: enabled",
            "Administrative private-vlan trunk encapsulation: dot1q",
            "Administrative private-vlan trunk normal VLANs: none",
            "Administrative private-vlan trunk associations: none",
            "Administrative private-vlan trunk mappings: none",
            "Operational private-vlan: none",
            f"Trunking VLANs Enabled: {allowed}",
            "Pruning VLANs Enabled: 2-1001",
            "Capture Mode Disabled",
            "Capture VLANs Allowed: ALL",
            "",
            "Protected: false",
            "Unknown unicast blocked: disabled",
            "Unknown multicast blocked: disabled",
            "Appliance trust: none",
        ]
    )


def show_interface_status_single(twin: SwitchTwin, interface: str) -> str:
    i = twin.interfaces[short_ifname(interface)]
    vlan = (
        "trunk" if i.is_trunk else str(i.oper_vlan if i.oper_status == "connected" and i.oper_vlan else i.access_vlan)
    )
    duplex = i.duplex if i.oper_status in {"connected", "monitoring"} else "auto"
    speed = i.speed if i.oper_status in {"connected", "monitoring"} else "auto"
    return "\n".join(
        [
            "Port      Name               Status       Vlan       Duplex  Speed Type",
            f"{i.name:<9} {i.description[:18]:<18} {_status_word(i):<12} {vlan:<10} {duplex:>6} {speed:>6} 10/100/1000BaseTX",
        ]
    )


def show_interface(twin: SwitchTwin, interface: str) -> str:
    i = twin.interfaces[short_ifname(interface)]
    c = i.counters
    up = "up" if i.oper_status in {"connected", "monitoring"} else "down"
    line_proto = (
        "up (connected)"
        if i.oper_status == "connected"
        else "down (notconnect)"
        if i.oper_status == "notconnect"
        else "down (err-disabled)"
        if i.oper_status == "err-disabled"
        else "down (monitoring)"
        if i.oper_status == "monitoring"
        else "down (disabled)"
    )
    admin = "administratively down" if i.admin_status == "down" else up
    idx = int(i.name.rsplit("/", 1)[-1])
    mac_hex = int(twin.base_mac.replace(":", ""), 16) + idx
    ifmac = ":".join(f"{mac_hex:012X}"[k : k + 2] for k in range(0, 12, 2))
    last_change = parse_ts(i.last_change) if i.last_change else twin.now
    age = twin.now - last_change
    return "\n".join(
        [
            f"{i.long_name} is {admin}, line protocol is {line_proto}",
            f"  Hardware is Gigabit Ethernet, address is {mac_cisco(ifmac)} (bia {mac_cisco(ifmac)})",
            f"  Description: {i.description}",
            "  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,",
            "     reliability 255/255, txload 1/255, rxload 1/255",
            "  Encapsulation ARPA, loopback not set",
            "  Keepalive set (10 sec)",
            f"  {'Full' if i.oper_status == 'connected' else 'Auto'}-duplex, {'1000Mb/s' if i.oper_status == 'connected' else 'Auto-speed'}, media type is 10/100/1000BaseTX",
            "  input flow-control is off, output flow-control is unsupported",
            "  ARP type: ARPA, ARP Timeout 04:00:00",
            f"  Last input {_age(i.last_input, twin.now)}, output {_age(i.last_output, twin.now)}, output hang never",
            '  Last clearing of "show interface" counters never',
            "  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0",
            "  Queueing strategy: fifo",
            "  Output queue: 0/40 (size/max)",
            "  5 minute input rate 0 bits/sec, 0 packets/sec",
            "  5 minute output rate 0 bits/sec, 0 packets/sec",
            f"     {c.get('in_packets', 0)} packets input, {c.get('in_bytes', 0)} bytes, 0 no buffer",
            "     Received 0 broadcasts (0 multicasts)",
            "     0 runts, 0 giants, 0 throttles",
            f"     {c.get('input_errors', 0)} input errors, {c.get('crc', 0)} CRC, 0 frame, 0 overrun, 0 ignored",
            "     0 watchdog, 0 multicast, 0 pause input",
            "     0 input packets with dribble condition detected",
            f"     {c.get('out_packets', 0)} packets output, {c.get('out_bytes', 0)} bytes, 0 underruns",
            f"     {c.get('output_errors', 0)} output errors, 0 collisions, 1 interface resets",
            "     0 unknown protocol drops",
            "     0 babbles, 0 late collision, 0 deferred",
            "     0 lost carrier, 0 no carrier, 0 pause output",
            "     0 output buffer failures, 0 output buffers swapped out",
            f"  (state age {str(timedelta(seconds=int(age.total_seconds())))})",
        ]
    )


def _age(ts: str | None, now: datetime) -> str:
    if not ts:
        return "never"
    delta = now - parse_ts(ts)
    secs = int(delta.total_seconds())
    if secs < 0:
        secs = 0
    return f"{secs // 3600:02d}:{(secs % 3600) // 60:02d}:{secs % 60:02d}"


def show_authentication_sessions(twin: SwitchTwin, interface: str | None = None) -> str:
    if interface:
        i = twin.interfaces[short_ifname(interface)]
        macs = twin.macs_on_interface(i.name)
        if i.auth_state in {None, "n/a"} or not macs:
            return (
                "No sessions match supplied criteria."
                if i.auth_state != "unauthorized"
                else _auth_session_block(twin, i, None)
            )
        return "\n\n".join(_auth_session_block(twin, i, m.mac) for m in macs)
    out = ["Interface    MAC Address     Method   Domain   Status Fg  Session ID"]
    for i in twin.interfaces.values():
        if i.auth_state in {None, "n/a"}:
            continue
        for m in twin.macs_on_interface(i.name):
            method = {"dot1x": "dot1x", "mab": "mab", "dot1x-timeout": "dot1x"}.get(i.auth_method or "", "N/A")
            status = "Auth" if i.auth_state in {"authorized", "guest"} else "Unauth"
            out.append(
                f"{i.name:<12} {mac_cisco(m.mac):<15} {method:<8} DATA     {status:<6} X   {_session_id(twin, i, m.mac)}"
            )
    out.append("")
    out.append(f"Session count = {len(out) - 2}")
    out.append("")
    out.append("Key to Session Events Blocked Status Flags:")
    out.append("  X - Unknown Blocked Status")
    return "\n".join(out)


def _session_id(twin: SwitchTwin, i: Interface, mac: str) -> str:
    idx = int(i.name.rsplit("/", 1)[-1])
    return f"0A0A0A02{idx:08X}{int(mac.replace(':', '')[-6:], 16):08X}"


def _auth_session_block(twin: SwitchTwin, i: Interface, mac: str | None) -> str:
    binding = next((b for b in twin.dhcp_bindings if b.interface == i.name), None)
    if i.auth_state == "unauthorized":
        status, authz, method_state, user = "Unauthorized", "N/A", "Authc Failed", "(unknown)"
    elif i.auth_method == "mab":
        status, authz, method_state, user = (
            "Authz Success",
            "Authentication Server",
            "Authc Success",
            mac_cisco(mac or ""),
        )
    elif i.auth_method == "dot1x-timeout":
        status, authz, method_state, user = "Authz Success", "Guest Vlan", "Authc Failed", "(unknown)"
    else:
        status, authz, method_state, user = (
            "Authz Success",
            "Authentication Server",
            "Authc Success",
            i.auth_user or "(unknown)",
        )
    vlan_policy = f"{i.oper_vlan}" if i.auth_method == "dot1x-timeout" else "N/A"
    return "\n".join(
        [
            f"            Interface:  {i.long_name}",
            f"          MAC Address:  {mac_cisco(mac) if mac else 'Unknown'}",
            f"           IP Address:  {binding.ip if binding else 'Unknown'}",
            f"            User-Name:  {user}",
            f"               Status:  {status}",
            "               Domain:  DATA",
            "      Security Policy:  Should Secure",
            "      Security Status:  Unsecure",
            "       Oper host mode:  single-host",
            "     Oper control dir:  both",
            f"        Authorized By:  {authz}",
            f"          Vlan Policy:  {vlan_policy}",
            "      Session timeout:  N/A",
            "         Idle timeout:  N/A",
            f"    Common Session ID:  {_session_id(twin, i, mac or '00:00:00:00:00:00')}",
            f"      Acct Session ID:  0x{int(i.name.rsplit('/', 1)[-1]) * 7 + 200:08X}",
            f"               Handle:  0x{int(i.name.rsplit('/', 1)[-1]) * 13 + 0xC7000000:08X}",
            "",
            "Runnable methods list:",
            "       Method   State",
            f"       mab      {'Authc Success' if i.auth_method == 'mab' else 'Failed over' if i.auth_state != 'n/a' else 'Not run'}",
            f"       dot1x    {method_state if i.auth_method != 'mab' else 'Not run'}",
        ]
    )


# -------------------------------------------------------------------------------------------------
# Running configuration
# -------------------------------------------------------------------------------------------------
def interface_config_lines(twin: SwitchTwin, i: Interface) -> list[str]:
    s = i.settings
    lines = [f"interface {i.long_name}"]
    if i.description and i.description != "UNUSED":
        lines.append(f" description {i.description}")
    elif i.port_class == "unused":
        lines.append(" description UNUSED - parked in VLAN 999")
    if i.is_trunk:
        lines.append(f" switchport trunk native vlan {i.native_vlan}")
        lines.append(f" switchport trunk allowed vlan {','.join(str(v) for v in i.allowed_vlans)}")
        lines.append(" switchport mode trunk")
        lines.append(" switchport nonegotiate")
    else:
        lines.append(f" switchport access vlan {i.access_vlan}")
        lines.append(" switchport mode access")
    ps = s.get("port_security", {})
    if ps.get("enabled"):
        lines.append(" switchport port-security")
        if int(ps.get("maximum", 1)) != 1:
            lines.append(f" switchport port-security maximum {ps['maximum']}")
        lines.append(f" switchport port-security violation {ps.get('violation', 'shutdown')}")
        if ps.get("sticky"):
            lines.append(" switchport port-security mac-address sticky")
            for mac in i.sticky_macs:
                lines.append(f" switchport port-security mac-address sticky {mac_cisco(mac)}")
    if s.get("dhcp_snooping_trust"):
        lines.append(" ip dhcp snooping trust")
    if s.get("dai_trust"):
        lines.append(" ip arp inspection trust")
    else:
        if not i.is_trunk and i.port_class not in {"unused", "management", "monitoring"}:
            lines.append(" ip arp inspection limit rate 15")
    if s.get("dot1x"):
        lines.append(" authentication event fail action next-method")
        if s.get("guest_vlan"):
            lines.append(f" authentication event no-response action authorize vlan {s['guest_vlan']}")
        lines.append(" authentication order mab dot1x")
        lines.append(" authentication priority dot1x mab")
        lines.append(" authentication port-control auto")
        lines.append(" authentication periodic")
        lines.append(" authentication timer reauthenticate server")
        if s.get("mab"):
            lines.append(" mab")
        lines.append(" dot1x pae authenticator")
        lines.append(" dot1x timeout tx-period 3")
    sc = s.get("storm_control")
    if sc:
        for kind in ("broadcast", "multicast"):
            if kind in sc:
                lines.append(f" storm-control {kind} level {sc[kind]}")
        lines.append(" storm-control action trap")
    if s.get("spanning_tree_portfast"):
        lines.append(" spanning-tree portfast")
    if s.get("bpduguard"):
        lines.append(" spanning-tree bpduguard enable")
    if s.get("ip_source_guard"):
        lines.append(" ip verify source")
    if i.span_destination:
        pass
    if i.admin_status == "down":
        lines.append(" shutdown")
    return lines


def render_running_config(twin: SwitchTwin, header: bool = True) -> str:
    out: list[str] = []
    if header:
        out += ["Building configuration...", "", f"Current configuration : {0} bytes", "!"]
    out += [
        f"! Last configuration change at {twin.now.strftime('%H:%M:%S UTC %a %b %d %Y')}",
        "!",
        "version 15.2",
        "no service pad",
        "service timestamps debug datetime msec",
        "service timestamps log datetime msec",
        "service password-encryption",
        "service sequence-numbers",
        "!",
        f"hostname {twin.hostname}",
        "!",
        "boot-start-marker",
        "boot-end-marker",
        "!",
        "enable secret 9 <REDACTED-ENABLE-SECRET>",
        "!",
        "username sentinel privilege 15 view SENTINEL-RESPONSE secret 9 <REDACTED-SERVICE-ACCOUNT-SECRET>",
        "!",
        "aaa new-model",
        "!",
        "aaa group server radius LAB-RADIUS",
        " server name SRV-RADIUS01",
        "!",
        "aaa authentication login default group LAB-RADIUS local",
        "aaa authentication dot1x default group LAB-RADIUS",
        "aaa authorization exec default group LAB-RADIUS local",
        "aaa authorization network default group LAB-RADIUS",
        "aaa accounting dot1x default start-stop group LAB-RADIUS",
        "aaa accounting exec default start-stop group LAB-RADIUS",
        "!",
        "aaa server radius dynamic-author",
        " client 10.30.0.30 server-key 7 <REDACTED>",
        "!",
        "aaa session-id common",
        "clock timezone UTC 0 0",
        "system mtu routing 1500",
        "!",
        "ip dhcp snooping vlan " + ",".join(str(v) for v in twin.dhcp_snooping_vlans),
        "no ip dhcp snooping information option",
        "ip dhcp snooping",
        "ip arp inspection vlan " + ",".join(str(v) for v in twin.dai_vlans),
        "ip arp inspection validate src-mac dst-mac ip",
        "!",
        "ip domain-name corp.example.com",
        "ip name-server 10.30.0.10",
        "login block-for 120 attempts 3 within 60",
        "login on-failure log",
        "login on-success log",
        "!",
        "dot1x system-auth-control",
        "!",
        "errdisable recovery cause arp-inspection",
        "errdisable recovery cause dhcp-rate-limit",
        "errdisable recovery cause psecure-violation",
        "errdisable recovery cause storm-control",
        "errdisable recovery interval 300",
        "!",
        "spanning-tree mode rapid-pvst",
        "spanning-tree portfast bpduguard default",
        "spanning-tree extend system-id",
        "!",
        "vlan internal allocation policy ascending",
        "!",
    ]
    for vid in sorted(twin.vlans):
        out += [f"vlan {vid}", f" name {twin.vlans[vid]['name']}", "!"]
    out += [
        "ip ssh version 2",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 2",
        "!",
        "interface Loopback0",
        " no ip address",
        "!",
    ]
    for i in twin.interfaces.values():
        out += interface_config_lines(twin, i)
        out.append("!")
    out += [
        f"interface Vlan{twin.management_vlan}",
        " description MANAGEMENT",
        f" ip address {twin.management_ip} 255.255.255.0",
        " no ip route-cache",
        "!",
        f"ip default-gateway {twin.env.switch['default_gateway']}",
        "ip http server disabled",
        "no ip http server",
        "no ip http secure-server",
        "!",
        "ip access-list standard MGMT-ACCESS",
        " remark Management plane: jump host and SentinelSwitch controller only",
        " permit 10.10.10.20",
        " permit 10.99.0.10",
        " deny   any log",
        "!",
        "ip access-list standard SNMP-RO",
        " permit 10.99.0.10",
        "!",
        "logging trap informational",
        "logging origin-id hostname",
        f"logging host {twin.env.switch['syslog_host']}",
        "!",
        "snmp-server community <REDACTED-COMMUNITY> RO SNMP-RO",
        "snmp-server trap-source Vlan10",
        "snmp-server enable traps port-security",
        "snmp-server enable traps mac-notification change move",
        f"snmp-server host {twin.env.switch['snmp_trap_host']} version 2c <REDACTED-COMMUNITY>",
        "!",
        "radius server SRV-RADIUS01",
        f" address ipv4 {twin.env.switch['radius_server']} auth-port {twin.env.switch['radius_auth_port']} acct-port {twin.env.switch['radius_acct_port']}",
        " key 7 <REDACTED-RADIUS-SHARED-SECRET>",
        "!",
        "radius-server attribute 6 on-for-login-auth",
        "radius-server attribute 8 include-in-access-req",
        "radius-server attribute 25 access-request include",
        "radius-server dead-criteria time 10 tries 3",
        "!",
        "banner motd ^C",
        "  SW01 - Meridian Labs access layer. Authorized administrators only.",
        "  All sessions are logged to the SentinelSwitch collector.",
        "^C",
        "!",
        "line con 0",
        " exec-timeout 10 0",
        " logging synchronous",
        "line vty 0 4",
        " access-class MGMT-ACCESS in",
        " exec-timeout 10 0",
        " logging synchronous",
        " transport input ssh",
        "line vty 5 15",
        " access-class MGMT-ACCESS in",
        " transport input ssh",
        "!",
        f"monitor session {twin.span['id']} source vlan {' , '.join(str(v) for v in twin.span['source_vlans'])} {twin.span.get('direction', 'both')}",
        f"monitor session {twin.span['id']} destination interface {twin.span['destination']}",
        "!",
        f"ntp server {twin.env.switch['ntp_server']} prefer",
        "!",
        "end",
    ]
    text = "\n".join(out)
    if header:
        text = text.replace(f"Current configuration : {0} bytes", f"Current configuration : {len(text.encode())} bytes")
    return text


def show_running_config_interface(twin: SwitchTwin, interface: str) -> str:
    i = twin.interfaces[short_ifname(interface)]
    lines = interface_config_lines(twin, i) + ["end"]
    body = "\n".join(lines)
    return f"Building configuration...\n\nCurrent configuration : {len(body.encode()) + 24} bytes\n!\n{body}"


# -------------------------------------------------------------------------------------------------
# Command dispatcher
# -------------------------------------------------------------------------------------------------
def run_show(twin: SwitchTwin, command: str) -> str:
    """Dispatch a `show ...` command string against the twin. Unknown commands return the IOS-style
    ambiguity error rather than raising, mirroring the real CLI."""
    cmd = " ".join(command.strip().lower().split())
    cmd = cmd.replace("gigabitethernet", "gi").replace("tengigabitethernet", "te").replace("interface ", "interfaces ")
    handlers: list[tuple[str, Callable[..., str]]] = [
        ("show version", lambda: show_version(twin)),
        ("show vlan brief", lambda: show_vlan_brief(twin)),
        ("show interfaces status", lambda: show_interfaces_status(twin)),
        ("show interfaces trunk", lambda: show_interfaces_trunk(twin)),
        ("show ip dhcp snooping binding", lambda: show_ip_dhcp_snooping_binding(twin)),
        ("show ip dhcp snooping", lambda: show_ip_dhcp_snooping(twin)),
        ("show ip arp inspection", lambda: show_ip_arp_inspection(twin)),
        ("show spanning-tree summary", lambda: show_spanning_tree_summary(twin)),
        ("show errdisable recovery", lambda: show_errdisable_recovery(twin)),
        ("show monitor session 1", lambda: show_monitor_session(twin)),
        ("show monitor", lambda: show_monitor_session(twin)),
        ("show logging", lambda: show_logging(twin)),
        ("show authentication sessions", lambda: show_authentication_sessions(twin)),
        ("show port-security", lambda: show_port_security(twin)),
        ("show mac address-table", lambda: show_mac_address_table(twin)),
        ("show running-config", lambda: render_running_config(twin)),
    ]
    tokens = cmd.split()
    if cmd.startswith("show vlan id "):
        return show_vlan_id(twin, int(tokens[3]))
    if cmd.startswith("show mac address-table interfaces "):
        return show_mac_address_table(twin, interface=_ifarg(tokens[4]))
    if cmd.startswith("show mac address-table address "):
        return show_mac_address_table(twin, address=tokens[4])
    if cmd.startswith("show port-security interfaces "):
        return show_port_security_interface(twin, _ifarg(tokens[3]))
    if cmd.startswith("show authentication sessions interfaces "):
        return show_authentication_sessions(twin, _ifarg(tokens[4]))
    if cmd.startswith("show running-config interfaces "):
        return show_running_config_interface(twin, _ifarg(tokens[3]))
    if cmd.startswith("show interfaces ") and cmd.endswith(" switchport"):
        return show_interface_switchport(twin, _ifarg(tokens[2]))
    if cmd.startswith("show interfaces ") and cmd.endswith(" status") and len(tokens) == 4:
        return show_interface_status_single(twin, _ifarg(tokens[2]))
    if cmd.startswith("show interfaces ") and len(tokens) == 3 and tokens[2] not in {"status", "trunk"}:
        return show_interface(twin, _ifarg(tokens[2]))
    for prefix, fn in handlers:
        if cmd == prefix or cmd.startswith(prefix + " "):
            return fn()
    return '% Ambiguous command or unsupported in the digital twin: "' + command + '"'


def _ifarg(token: str) -> str:
    t = token
    if t.startswith("gi"):
        t = "Gi" + t[2:]
    elif t.startswith("te"):
        t = "Te" + t[2:]
    return t

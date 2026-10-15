# INC-2026-0041 — Rogue DHCP — VENDOR-LT-01

**Severity:** high  
**Confidence:** 0.95  
**Status:** contained  
**Opened:** 2026-03-17T11:23:47.191Z  
**Rule:** `rogue-dhcp`  
**Endpoint:** VENDOR-LT-01 (no user)  
**Switch / interface:** SW01 Gi1/0/31  
**VLAN:** 40 → 40  

> Simulated lab telemetry. This bundle was produced by the SentinelSwitch digital twin; no production
> system was involved.

## Summary

A vendor laptop on the guest VLAN enables internet connection sharing, which starts a DHCP server on its wired interface. When the conference display is power-cycled and broadcasts DHCPDISCOVER, the laptop answers. DHCP snooping drops every OFFER and NAK arriving on the untrusted port and logs each drop; Suricata sees the offers on the SPAN feed and raises a local rule. SentinelSwitch attributes the server MAC to the port and shuts it down.

## Attribution chain

```
10.40.0.104 → 3C:D9:2B:71:31:04 → SW01 → Gi1/0/31 → VLAN 40 → shutdown
```

| step | status | source | evidence |
| --- | --- | --- | --- |
| dhcp_binding | resolved | show ip dhcp snooping binding | 3C:D9:2B:71:31:04 -> 10.40.0.104 (VLAN 40, Gi1/0/31) |
| mac_table | resolved | show mac address-table address | 3C:D9:2B:71:31:04 -> SW01 Gi1/0/31 (VLAN 40, DYNAMIC) |
| interface | resolved | show interfaces switchport | Gi1/0/31 'VENDOR DROP (guest fallback)' mode=access access_vlan=20 oper_vlan=40 class=conference status=connected |
| identity | resolved | asset inventory / AAA session | VENDOR-LT-01 (guest-laptop, HP, Windows 11 Home) criticality=low |

## Policy decision

- Disposition: **automatic_containment**
- Action: `port_shutdown`
- Reason: Automatic containment approved (severity=high confidence=0.95); action=port_shutdown

## Containment

- Workflow: `WF-2026-0041-04`
- Mechanism: SentinelSwitch administrative shutdown
- Interface: Gi1/0/31
- Applied: 2026-03-17T11:23:48.244Z
- Verified: 2026-03-17T11:23:48.366Z (OK)
- Status: verified

```
SW01#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
SW01(config)#interface GigabitEthernet1/0/31
SW01(config-if)#shutdown
SW01(config-if)#end
SW01#write memory
Building configuration...
[OK]
```

## Timeline

| time (UTC) | phase | event |
| --- | --- | --- |
| 11:23:44.106 | telemetry | DHCP snooping dropping DHCPOFFER from 3cd9.2b71.3104 on untrusted port Gi1/0/31 (client CONF-A-TV01 broadcast DHCPDISCOVER) |
| 11:23:44.106 | switch | SW01 %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 3cd9.2b71.3104 |
| 11:23:44.131 | alert | Suricata sid 1000040 (high): SENTINELSWITCH ROGUE DHCP server message from non-authorized host |
| 11:23:44.612 | switch | SW01 %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPNAK, MAC sa: 3cd9.2b71.3104 |
| 11:23:45.130 | switch | SW01 %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 3cd9.2b71.3104 |
| 11:23:45.655 | switch | SW01 %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPNAK, MAC sa: 3cd9.2b71.3104 |
| 11:23:46.170 | switch | SW01 %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 3cd9.2b71.3104 |
| 11:23:47.191 | detection | Rule rogue-dhcp matched: severity high, confidence 0.95 (base 0.80; repeated_drops+0.08, suricata_offer+0.07) |
| 11:23:47.260 | correlation | Resolving actor 3C:D9:2B:71:31:04 through DHCP snooping, MAC table and inventory |
| 11:23:47.399 | correlation | dhcp_binding [resolved] 3C:D9:2B:71:31:04 -> 10.40.0.104 (VLAN 40, Gi1/0/31) |
| 11:23:47.618 | correlation | mac_table [resolved] 3C:D9:2B:71:31:04 -> SW01 Gi1/0/31 (VLAN 40, DYNAMIC) |
| 11:23:47.618 | correlation | interface [resolved] Gi1/0/31 'VENDOR DROP (guest fallback)' mode=access access_vlan=20 oper_vlan=40 class=conference status=connected |
| 11:23:47.699 | correlation | identity [resolved] VENDOR-LT-01 (guest-laptop, HP, Windows 11 Home) criticality=low |
| 11:23:47.848 | policy | Disposition automatic_containment: Automatic containment approved (severity=high confidence=0.95); action=port_shutdown |
| 11:23:47.850 | authorization | Containment authorized by policy-engine (policy tier automatic_containment); action port_shutdown |
| 11:23:47.852 | incident | Incident INC-2026-0041 opened |
| 11:23:48.244 | containment | SW01 Gi1/0/31: administrative shutdown (workflow WF-2026-0041-04) — SentinelSwitch administrative shutdown |
| 11:23:48.366 | verification | Verification succeeded: admin down, no MAC addresses learned |

## Source detections

| time (UTC) | source | severity | detail |
| --- | --- | --- | --- |
| 11:23:44.106 | syslog | medium | %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 3cd9.2b71.3104 |
| 11:23:44.131 | suricata | high | SENTINELSWITCH ROGUE DHCP server message from non-authorized host |
| 11:23:44.612 | syslog | medium | %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPNAK, MAC sa: 3cd9.2b71.3104 |
| 11:23:45.130 | syslog | medium | %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 3cd9.2b71.3104 |
| 11:23:45.655 | syslog | medium | %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPNAK, MAC sa: 3cd9.2b71.3104 |
| 11:23:46.170 | syslog | medium | %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 3cd9.2b71.3104 |

## Switch port

```
Name: Gi1/0/31
Switchport: Enabled
Administrative Mode: static access
Operational Mode: down
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 20 (USERS)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
Voice VLAN: none
Administrative private-vlan host-association: none
Administrative private-vlan mapping: none
Administrative private-vlan trunk native VLAN: none
Administrative private-vlan trunk Native VLAN tagging: enabled
Administrative private-vlan trunk encapsulation: dot1q
Administrative private-vlan trunk normal VLANs: none
Administrative private-vlan trunk associations: none
Administrative private-vlan trunk mappings: none
Operational private-vlan: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Protected: false
Unknown unicast blocked: disabled
Unknown multicast blocked: disabled
Appliance trust: none
```

Related connections: 8, related DNS records: 0 (see JSON artifacts).

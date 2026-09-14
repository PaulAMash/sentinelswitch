# INC-2026-0040 — Unauthorized Endpoint — unknown device DC:A6:32:19:77:C1

**Severity:** high  
**Confidence:** 0.96  
**Status:** contained  
**Opened:** 2026-03-17T09:41:05.573Z  
**Rule:** `unauthorized-endpoint`  
**Endpoint:** unknown (no user)  
**Switch / interface:** SW01 Gi1/0/17  
**VLAN:** 20 → 20  

> Simulated lab telemetry. This bundle was produced by the SentinelSwitch digital twin; no production
> system was involved.

## Summary

A single-board computer that is not in the asset inventory is connected to a spare corporate drop. MAC Authentication Bypass is rejected by FreeRADIUS, no 802.1X supplicant responds, and SentinelSwitch attributes the MAC to the physical interface using the AAA and syslog telemetry (the MAC address table has no entry because the port never became authorized).

## Attribution chain

```
DC:A6:32:19:77:C1 → SW01 → Gi1/0/17 → VLAN 20 → shutdown
```

| step | status | source | evidence |
| --- | --- | --- | --- |
| dhcp_binding | missing | show ip dhcp snooping binding | No binding for this MAC (expected when the port never authorised or the device is static) |
| mac_table | fallback | show mac address-table address | No MAC table entry for DC:A6:32:19:77:C1 (port not authorised); interface Gi1/0/17 taken from RADIUS NAS-Port-Id |
| interface | resolved | show interfaces switchport | Gi1/0/17 'OPS SPARE DROP (corporate asset only)' mode=access access_vlan=20 oper_vlan=20 class=workstation status=connected |
| identity | missing | asset inventory / AAA session | DC:A6:32:19:77:C1 is not in the asset inventory (OUI vendor: Raspberry Pi Foundation) |

## Policy decision

- Disposition: **automatic_containment**
- Action: `port_shutdown`
- Reason: Automatic containment approved (severity=high confidence=0.96); action=port_shutdown

## Containment

- Workflow: `WF-2026-0040-02`
- Mechanism: SentinelSwitch administrative shutdown
- Interface: Gi1/0/17
- Applied: 2026-03-17T09:41:06.601Z
- Verified: 2026-03-17T09:41:06.718Z (OK)
- Status: verified

```
SW01#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
SW01(config)#interface GigabitEthernet1/0/17
SW01(config-if)#shutdown
SW01(config-if)#end
SW01#write memory
Building configuration...
[OK]
```

## Timeline

| time (UTC) | phase | event |
| --- | --- | --- |
| 09:41:05.112 | telemetry | link up on Gi1/0/17: unregistered device dca6.3219.77c1 (Raspberry Pi Foundation OUI) |
| 09:41:05.418 | aaa | MAB Access-Reject for dca6.3219.77c1 on Gi1/0/17: MAC not in endpoint database |
| 09:41:05.418 | aaa | RADIUS Access-Reject (MAB) for DC:A6:32:19:77:C1 on Gi1/0/17: MAC not found in endpoint database |
| 09:41:05.444 | switch | SW01 %MAB-5-FAIL: Authentication failed for client (dca6.3219.77c1) on Interface Gi1/0/17 AuditSessionID 0A0A0A02000000110019D48E |
| 09:41:05.573 | detection | Rule unauthorized-endpoint matched: severity high, confidence 0.96 (base 0.70; corporate_port+0.20, unknown_mac+0.06) |
| 09:41:05.644 | correlation | Resolving actor DC:A6:32:19:77:C1 through DHCP snooping, MAC table and inventory |
| 09:41:05.775 | correlation | dhcp_binding [missing] No binding for this MAC (expected when the port never authorised or the device is static) |
| 09:41:05.971 | correlation | mac_table [fallback] No MAC table entry for DC:A6:32:19:77:C1 (port not authorised); interface Gi1/0/17 taken from RADIUS NAS-Port-Id |
| 09:41:05.971 | correlation | interface [resolved] Gi1/0/17 'OPS SPARE DROP (corporate asset only)' mode=access access_vlan=20 oper_vlan=20 class=workstation status=connected |
| 09:41:06.048 | correlation | identity [missing] DC:A6:32:19:77:C1 is not in the asset inventory (OUI vendor: Raspberry Pi Foundation) |
| 09:41:06.200 | policy | Disposition automatic_containment: Automatic containment approved (severity=high confidence=0.96); action=port_shutdown |
| 09:41:06.204 | incident | Incident INC-2026-0040 opened |
| 09:41:06.601 | containment | SW01 Gi1/0/17: administrative shutdown (workflow WF-2026-0040-02) — SentinelSwitch administrative shutdown |
| 09:41:06.718 | verification | Verification succeeded: admin down, no MAC addresses learned |

## Source detections

| time (UTC) | source | severity | detail |
| --- | --- | --- | --- |
| 09:41:05.418 | radius | low | Access-Reject MAB dca6321977c1 on Gi1/0/17: MAC not found in endpoint database |
| 09:41:05.444 | syslog | medium | %MAB-5-FAIL: Authentication failed for client (dca6.3219.77c1) on Interface Gi1/0/17 AuditSessionID 0A0A0A02000000110019D48E |

## Switch port

```
Name: Gi1/0/17
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

Related connections: 0, related DNS records: 0 (see JSON artifacts).

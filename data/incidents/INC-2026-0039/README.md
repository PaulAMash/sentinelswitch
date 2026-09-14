# INC-2026-0039 — STP/BPDU Violation — CONF-A-TV01

**Severity:** high  
**Confidence:** 0.96  
**Status:** contained  
**Opened:** 2026-03-17T09:12:44.447Z  
**Rule:** `bpdu-violation`  
**Endpoint:** CONF-A-TV01 (no user)  
**Switch / interface:** SW01 Gi1/0/30  
**VLAN:** 40 → 40  

> Simulated lab telemetry. This bundle was produced by the SentinelSwitch digital twin; no production
> system was involved.

## Summary

An unmanaged switch with spanning tree enabled is inserted between the conference display and its access port. The first BPDU triggers BPDU Guard, which err-disables the port. SentinelSwitch confirms the err-disable from syslog, attributes the port to the last known endpoint, applies an administrative hold so errdisable auto-recovery cannot re-enable the port, and records the evidence.

## Attribution chain

```
SW01 → Gi1/0/30 → VLAN 40 → shutdown
```

| step | status | source | evidence |
| --- | --- | --- | --- |
| dhcp_binding | skipped | show ip dhcp snooping binding | No IP or MAC to look up |
| mac_table | fallback | show mac address-table address | No MAC table entry for unknown MAC (port not authorised); interface Gi1/0/30 taken from syslog interface field |
| interface | resolved | show interfaces switchport | Gi1/0/30 'CONF-A DISPLAY (guest fallback)' mode=access access_vlan=20 oper_vlan=40 class=conference status=err-disabled |
| identity | fallback | asset inventory (port assignment) | No MAC in the event; CONF-A-TV01 is the endpoint assigned to Gi1/0/30 (display, criticality=low) |

## Policy decision

- Disposition: **automatic_containment**
- Action: `port_shutdown`
- Reason: Automatic containment approved (severity=high confidence=0.96); action=port_shutdown

## Containment

- Workflow: `WF-2026-0039-01`
- Mechanism: BPDU Guard err-disable (switch-native) + SentinelSwitch administrative hold
- Interface: Gi1/0/30
- Applied: 2026-03-17T09:12:45.469Z
- Verified: 2026-03-17T09:12:45.588Z (OK)
- Status: verified

```
SW01#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
SW01(config)#interface GigabitEthernet1/0/30
SW01(config-if)#shutdown
SW01(config-if)#end
SW01#write memory
Building configuration...
[OK]
```

## Timeline

| time (UTC) | phase | event |
| --- | --- | --- |
| 09:12:44.271 | telemetry | BPDU received on access port Gi1/0/30 (unmanaged switch inserted in front of CONF-A-TV01); BPDU Guard err-disabled the port |
| 09:12:44.271 | switch | SW01 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/30 with BPDU Guard enabled. Disabling port. |
| 09:12:44.276 | switch | SW01 %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/30, putting Gi1/0/30 in err-disable state |
| 09:12:44.447 | detection | Rule bpdu-violation matched: severity high, confidence 0.96 (base 0.90; errdisable_confirmed+0.06) |
| 09:12:44.513 | correlation | Resolving actor Gi1/0/30 through DHCP snooping, MAC table and inventory |
| 09:12:44.650 | correlation | dhcp_binding [skipped] No IP or MAC to look up |
| 09:12:44.858 | correlation | mac_table [fallback] No MAC table entry for unknown MAC (port not authorised); interface Gi1/0/30 taken from syslog interface field |
| 09:12:44.858 | correlation | interface [resolved] Gi1/0/30 'CONF-A DISPLAY (guest fallback)' mode=access access_vlan=20 oper_vlan=40 class=conference status=err-disabled |
| 09:12:44.937 | correlation | identity [fallback] No MAC in the event; CONF-A-TV01 is the endpoint assigned to Gi1/0/30 (display, criticality=low) |
| 09:12:45.081 | policy | Disposition automatic_containment: Automatic containment approved (severity=high confidence=0.96); action=port_shutdown |
| 09:12:45.085 | incident | Incident INC-2026-0039 opened |
| 09:12:45.469 | containment | SW01 Gi1/0/30: administrative shutdown (workflow WF-2026-0039-01) — BPDU Guard err-disable (switch-native) + SentinelSwitch administrative hold |
| 09:12:45.588 | verification | Verification succeeded: admin down, no MAC addresses learned |

## Source detections

| time (UTC) | source | severity | detail |
| --- | --- | --- | --- |
| 09:12:44.271 | syslog | high | %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/30 with BPDU Guard enabled. Disabling port. |
| 09:12:44.276 | syslog | medium | %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/30, putting Gi1/0/30 in err-disable state |

## Switch port

```
Name: Gi1/0/30
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

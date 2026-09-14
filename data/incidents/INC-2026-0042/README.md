# INC-2026-0042 — Lateral Reconnaissance — ENG-LT-047

**Severity:** high  
**Confidence:** 0.97  
**Status:** contained  
**Opened:** 2026-03-17T21:14:39.867Z  
**Rule:** `lateral-reconnaissance`  
**Endpoint:** ENG-LT-047 (jchen)  
**Switch / interface:** SW01 Gi1/0/23  
**VLAN:** 20 → 50  

> Simulated lab telemetry. This bundle was produced by the SentinelSwitch digital twin; no production
> system was involved.

## Summary

An authenticated engineering laptop (ENG-LT-047) begins host discovery across the USERS and SERVERS VLANs, performs a burst of reverse DNS lookups for responding hosts, then fans out TCP probes to SMB, RPC, RDP, SSH and WinRM ports on every host that answered. Suricata raises a high-confidence fan-out signature, Zeek corroborates with an address-scan notice, and SentinelSwitch correlates the source IP to the switch port and quarantines it.

## Attribution chain

```
10.20.0.47 → A4:83:E7:12:34:56 → SW01 → Gi1/0/23 → VLAN 20 → VLAN 50
```

| step | status | source | evidence |
| --- | --- | --- | --- |
| dhcp_binding | resolved | show ip dhcp snooping binding | 10.20.0.47 -> A4:83:E7:12:34:56 (dhcp-snooping, VLAN 20, Gi1/0/23, 23841s remaining) |
| mac_table | resolved | show mac address-table address | A4:83:E7:12:34:56 -> SW01 Gi1/0/23 (VLAN 20, DYNAMIC) |
| interface | resolved | show interfaces switchport | Gi1/0/23 'ENG-LT-047' mode=access access_vlan=20 oper_vlan=20 class=workstation status=connected |
| identity | resolved | asset inventory / AAA session | ENG-LT-047 (laptop, Lenovo, Ubuntu 24.04 LTS) criticality=standard user=jchen (Jia Chen, Engineering) |

## Policy decision

- Disposition: **automatic_containment**
- Action: `quarantine_vlan`
- Reason: Automatic containment approved (severity=high confidence=0.97); action=quarantine_vlan

## Containment

- Workflow: `WF-2026-0042-01`
- Mechanism: SentinelSwitch VLAN reassignment (quarantine VLAN)
- Interface: Gi1/0/23 (20 → 50)
- Applied: 2026-03-17T21:14:41.000Z
- Verified: 2026-03-17T21:14:41.125Z (OK)
- Status: verified

```
SW01#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
SW01(config)#interface GigabitEthernet1/0/23
SW01(config-if)#switchport access vlan 50
SW01(config-if)#end
SW01#write memory
Building configuration...
[OK]
```

## Timeline

| time (UTC) | phase | event |
| --- | --- | --- |
| 21:14:31.284 | telemetry | unusual ICMP echo fan-out from 10.20.0.47: 507 addresses across 10.20.0.0/24, 10.30.0.0/24 |
| 21:14:33.507 | alert | Suricata sid 1000010 (medium): SENTINELSWITCH RECON ICMP echo sweep from internal host |
| 21:14:35.116 | telemetry | reverse DNS lookup burst from 10.20.0.47 for 10.30.0.0/24 (50 queries/s) |
| 21:14:36.108 | alert | Suricata sid 1000014 (low): SENTINELSWITCH RECON reverse DNS lookup burst |
| 21:14:36.874 | telemetry | TCP connection fan-out from 10.20.0.47 to 26 responding hosts on ports 445, 139, 135, 3389, 22, 5985 |
| 21:14:37.042 | alert | Suricata sid 1000024 (low): SENTINELSWITCH LATERAL WinRM probe from workstation VLAN |
| 21:14:38.198 | alert | Suricata sid 1000021 (high): SENTINELSWITCH LATERAL SMB probe fan-out to multiple internal hosts |
| 21:14:38.292 | alert | Suricata sid 1000022 (high): SENTINELSWITCH LATERAL RDP probe fan-out to multiple internal hosts |
| 21:14:39.600 | telemetry | anonymous SMB session setup against SRV-FILE01 rejected (STATUS_ACCESS_DENIED) |
| 21:14:39.649 | alert | Zeek notice Scan::Address_Scan: 10.20.0.47 scanned at least 15 unique hosts on port 445/tcp in 0m2s |
| 21:14:39.826 | alert | Suricata sid 1000023 (low): SENTINELSWITCH LATERAL SMB session setup with anonymous credentials |
| 21:14:39.867 | detection | Rule lateral-reconnaissance matched: severity high, confidence 0.97 (base 0.75; zeek_address_scan+0.10, prior_icmp_sweep+0.07, ptr_burst+0.05) |
| 21:14:39.950 | correlation | Resolving actor 10.20.0.47 through DHCP snooping, MAC table and inventory |
| 21:14:40.092 | correlation | dhcp_binding [resolved] 10.20.0.47 -> A4:83:E7:12:34:56 (dhcp-snooping, VLAN 20, Gi1/0/23, 23841s remaining) |
| 21:14:40.346 | correlation | mac_table [resolved] A4:83:E7:12:34:56 -> SW01 Gi1/0/23 (VLAN 20, DYNAMIC) |
| 21:14:40.346 | correlation | interface [resolved] Gi1/0/23 'ENG-LT-047' mode=access access_vlan=20 oper_vlan=20 class=workstation status=connected |
| 21:14:40.439 | correlation | identity [resolved] ENG-LT-047 (laptop, Lenovo, Ubuntu 24.04 LTS) criticality=standard user=jchen (Jia Chen, Engineering) |
| 21:14:40.585 | policy | Disposition automatic_containment: Automatic containment approved (severity=high confidence=0.97); action=quarantine_vlan |
| 21:14:40.589 | incident | Incident INC-2026-0042 opened |
| 21:14:41.000 | containment | SW01 Gi1/0/23: switchport access vlan 20 → 50 (workflow WF-2026-0042-01) |
| 21:14:41.050 | telemetry | Telemetry from 10.20.0.47 no longer observed on monitored VLANs (23 further probe flows not seen) |
| 21:14:41.125 | verification | Verification succeeded: Access Mode VLAN: 50 |

## Source detections

| time (UTC) | source | severity | detail |
| --- | --- | --- | --- |
| 21:14:33.507 | suricata | medium | SENTINELSWITCH RECON ICMP echo sweep from internal host |
| 21:14:36.108 | suricata | low | SENTINELSWITCH RECON reverse DNS lookup burst |
| 21:14:37.042 | suricata | low | SENTINELSWITCH LATERAL WinRM probe from workstation VLAN |
| 21:14:38.198 | suricata | high | SENTINELSWITCH LATERAL SMB probe fan-out to multiple internal hosts |
| 21:14:38.292 | suricata | high | SENTINELSWITCH LATERAL RDP probe fan-out to multiple internal hosts |
| 21:14:39.649 | zeek | high | Scan::Address_Scan: 10.20.0.47 scanned at least 15 unique hosts on port 445/tcp in 0m2s |
| 21:14:39.826 | suricata | low | SENTINELSWITCH LATERAL SMB session setup with anonymous credentials |

## Switch port

```
Name: Gi1/0/23
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 50 (QUARANTINE)
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

Related connections: 896, related DNS records: 255 (see JSON artifacts).

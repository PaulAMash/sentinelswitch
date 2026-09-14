# Threat model

## Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Server VLAN (SRV-DC01, SRV-FILE01, SRV-RADIUS01, …) | identity, files, AAA; compromise ends the lab | VLAN 30, `Gi1/0/8`–`Gi1/0/13` |
| Workstation VLAN | initial access surface; lateral movement source | VLAN 20, `Gi1/0/5`–`Gi1/0/37` |
| Management plane | switch SVI, jump host, controller credentials | VLAN 10 / 99, trunks `Gi1/0/1`, `Gi1/0/48` |
| Telemetry integrity | SPAN feed, syslog, RADIUS accounting; losing them blinds detection | `Gi1/0/47` SPAN destination, collector 10.99.0.10 |
| Containment path | the `sentinel` service account can change access VLANs | management ACL, parser view, adapter guards |

## Adversary assumptions

* The adversary already controls (or is) an endpoint on an access port: a compromised corporate
  laptop, a contractor device on a spare drop, a guest laptop, a device inserted between an endpoint
  and its port.
* The adversary does not control the switch, the firewall or the security stack.
* The adversary may spoof link-layer identity (MAC), claim addresses it was not leased (ARP/IP),
  answer DHCP, or inject BPDUs. It cannot break EAP-TLS.
* Reconnaissance precedes lateral movement: host sweeps, port sweeps, reverse DNS, SMB/RDP probing.

## Attack surfaces and controls

| Surface | Technique (MITRE) | Native switch control | SentinelSwitch detection | Response |
| --- | --- | --- | --- | --- |
| Corporate drop | Unauthorized device (T1200) | 802.1X + MAB, port security | `unauthorized-endpoint` on MAB reject for unknown MAC on a workstation port | administrative shutdown |
| Any access port | ARP spoofing (T1557.002) | Dynamic ARP Inspection against the snooping table | `arp-spoofing` aggregates DAI denials, scores gateway claims | quarantine VLAN |
| Guest / conference drop | Rogue DHCP (T1557) | DHCP snooping drops server messages on untrusted ports | `rogue-dhcp` on snooping drops + Suricata corroboration | administrative shutdown |
| Workstation drop | MAC change / impersonation (T1036.005) | sticky port security, restrict mode | `mac-address-change` scores unknown MAC, impersonated asset, AAA reject | administrative shutdown |
| Workstation VLAN | Port scan (T1046) | — | `port-scan` from Suricata sweep + Zeek `Scan::Port_Scan`; authorized scanners scored down | quarantine VLAN |
| Workstation VLAN | DNS anomaly / DGA (T1071.004, T1568.002) | — | `dns-anomaly` from query rate, NXDOMAIN ratio, label entropy | quarantine VLAN |
| Workstation VLAN | Lateral reconnaissance (T1018, T1021.002) | — | `lateral-reconnaissance` from SMB/RDP fan-out + Zeek address scan + prior discovery | quarantine VLAN |
| Any access port | Unmanaged switch / STP manipulation (T1200) | BPDU Guard err-disable | `bpdu-violation` confirms err-disable | administrative hold |

## What the design deliberately does not automate

* **Infrastructure ports.** `Gi1/0/1` and `Gi1/0/48` are protected; trunks and the SPAN destination
  are never changed automatically. Blinding the sensor or cutting the uplink is a worse outcome than
  a delayed containment.
* **Critical assets.** A detection sourced from a server or the firewall is downgraded to manual
  review; isolating SRV-DC01 automatically would be self-inflicted denial of service.
* **Low-confidence detections.** Authorized scanners, guest-fallback ports and port-security cases
  reduce confidence explicitly, so a routine vulnerability scan or a personal laptop on a docking
  station ends in the review queue rather than on VLAN 50.

## Residual risks

* Static-VLAN containment can be undone by a subsequent 802.1X re-authentication if the RADIUS
  server assigns a VLAN dynamically. The lab assigns no VLAN to corporate users, so the port's
  configured VLAN wins; a production deployment should pair the adapter with RADIUS CoA.
* A quarantined host keeps its IP address until the lease expires; the quarantine VLAN's ACLs, not
  addressing, provide isolation.
* Telemetry after quarantine is intentionally absent from the SPAN feed; forensic capture inside
  VLAN 50 would need a second SPAN source.
* The twin does not model CPU exhaustion, control-plane policing or physical-layer attacks.

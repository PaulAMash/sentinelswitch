# LinkedIn post draft

> I built a digital twin of an enterprise access layer to practise the part of network security
> that is hardest to rehearse: getting from a suspicious flow to a physical switch port, and
> containing it, automatically and with evidence.

**SentinelSwitch — Autonomous Network Detection & Response Lab**

The environment is modelled around a Cisco Catalyst 2960-X (WS-C2960X-48FPD-L) and an older Linux
ThinkPad running the security stack. Instead of driving physical hardware, the project ships a
deterministic simulation of the whole day: 802.1X/MAB via FreeRADIUS, DHCP snooping, Dynamic ARP
Inspection, IP Source Guard, sticky port security, BPDU Guard, a VLAN SPAN session feeding Zeek and
Suricata, and IOS syslog to a collector. The telemetry is synthetic, but it is internally consistent
down to the millisecond, and the detection and response code that consumes it is real.

The flagship scenario: at 21:14 an authenticated engineering laptop starts sweeping two subnets,
bursts reverse DNS, then fans out SMB and RDP probes. Suricata raises a high-severity fan-out
signature, Zeek corroborates with an address-scan notice, and a correlation rule scores the actor at
0.97. SentinelSwitch then resolves the source IP through the switch's own tables — DHCP snooping
binding → MAC address → MAC table → Gi1/0/23 → VLAN 20 → asset inventory — checks the policy (high
severity, confidence ≥ 0.95, unprotected access port), moves the port to the quarantine VLAN through
a switch adapter, reads the interface back to verify, and writes an evidence bundle. Detection to
verified containment: 1.26 seconds on the simulated clock; first anomalous packet to containment:
9.8 seconds.

Eight adversary scenarios (unauthorized endpoint, ARP spoofing, rogue DHCP, MAC change, port scan,
DNS anomaly, lateral reconnaissance, BPDU violation) run through the same pipeline in a validation
harness — all detect, attribute and contain, with measured mean times to detect / attribute /
contain. The same behaviour scores differently in context: an authorized vulnerability scanner is
logged, a personal laptop on a docking station goes to review, a compromised host is quarantined.
Infrastructure trunks and the SPAN destination can never be changed automatically.

Stack: Python 3 · FastAPI · Pydantic · SQLite · React · TypeScript · Vite · Recharts · Playwright ·
Cisco IOS configuration-as-code with drift detection · Zeek and Suricata rule sources · MITRE ATT&CK
mapping.

What I took away: attribution is where most "automated response" ideas fall apart, because the
data lives in three places (DHCP, the MAC table, the inventory) and each of them can be stale, missing
or contradictory. Modelling those failure modes explicitly — expired bindings, MAC movement,
impersonated addresses, unresolved hosts — changed the policy design more than any detection rule did.

Repository, diagrams, dataset and a terminal demo are on GitHub. The physical build-out with the
switch and the ThinkPad is in progress; the twin is what I test against first.

#NetworkSecurity #Cisco #Linux #Zeek #Suricata #DetectionEngineering #IncidentResponse #Python #FastAPI #React #SOC

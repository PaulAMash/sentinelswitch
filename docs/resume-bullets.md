# Resume bullets

Three truthful alternatives; pick the one that fits the role.

**Network security / SOC**

* Built SentinelSwitch, a digital twin of a Cisco Catalyst 2960-X access layer with synthetic Zeek,
  Suricata, 802.1X and IOS syslog telemetry; implemented IP → DHCP binding → MAC → switch-port
  attribution and policy-driven automated quarantine (VLAN reassignment / port shutdown) with
  read-back verification, evidence bundles and rollback, validated across eight adversary scenarios
  (mean time to contain 1.2 s on the simulated clock).

**Detection engineering**

* Designed a declarative correlation layer (YAML rules with aggregation windows and additive
  evidence features) over normalized Suricata, Zeek, RADIUS and syslog events, with asset-context
  scoring that separates authorized scanners and guest-VLAN fallbacks from compromised hosts;
  authored the accompanying Suricata local rules and Zeek SumStats policy and a reproducible
  validation harness reporting MTTD/MTTA/MTTC.

**Software engineering**

* Delivered a self-contained FastAPI + React application (SQLite, Server-Sent Events, 51 backend
  tests, Playwright-generated media) whose deterministic simulator derives every dataset, Cisco IOS
  transcript, dashboard metric and incident evidence bundle from one canonical model, with
  configuration-as-code drift detection and a Docker Compose deployment.

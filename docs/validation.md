# Security validation

`make validate-security` (or `python -m sentinelswitch validate`) replays eight adversary scenarios
through the complete pipeline — normalization, correlation, attribution, policy, containment,
verification — against an isolated copy of the switch twin, then prints a matrix and timing metrics.

```
SENTINELSWITCH SECURITY VALIDATION
Scenario                Detect  Attribute  Contain  Conf   TTD       TTA      TTC      Mechanism
Unauthorized Endpoint   PASS    PASS       PASS     0.96   0.461s    0.475s   1.145s   SentinelSwitch administrative shutdown
ARP Spoofing Attempt    PASS    PASS       PASS     0.99   5.087s    0.547s   1.257s   SentinelSwitch VLAN reassignment (quarantine VLAN)
Rogue DHCP              PASS    PASS       PASS     0.95   3.085s    0.508s   1.175s   SentinelSwitch administrative shutdown
MAC Address Change      PASS    PASS       PASS     0.95   5.084s    0.543s   1.238s   SentinelSwitch administrative shutdown
Port Scan               PASS    PASS       PASS     0.96   3.768s    0.560s   1.261s   SentinelSwitch VLAN reassignment (quarantine VLAN)
DNS Anomaly             PASS    PASS       PASS     0.99   64.004s   0.543s   1.239s   SentinelSwitch VLAN reassignment (quarantine VLAN)
Lateral Reconnaissance  PASS    PASS       PASS     0.97   8.583s    0.572s   1.258s   SentinelSwitch VLAN reassignment (quarantine VLAN)
STP/BPDU Violation      PASS    PASS       PASS     0.96   0.176s    0.490s   1.141s   BPDU Guard err-disable (switch-native) + SentinelSwitch administrative hold

Mean Time To Detect     11.281 s   (range 0.176–64.004 s; DNS anomalies need a minute of volume)
Mean Time To Attribute   0.530 s
Mean Time To Contain     1.214 s   (detection → switch state verified)
```

## What each column means

| column | pass condition |
| --- | --- |
| Detect | the scenario's rule produced a detection with the expected severity and confidence (±0.005) |
| Attribute | attribution resolved to the expected physical interface (and MAC, except for the impersonation case where the MAC is deliberately wrong) |
| Contain | the policy produced the expected disposition; for automatic containment the action was applied *and verified* on the twin; for review scenarios the twin was untouched |

## How the timings are measured

All timestamps come from the scenario's simulated clock, never from wall-clock time, so the metrics
are reproducible on any machine.

* **t0** — the first anomalous event in the scenario's telemetry (first ICMP echo of the sweep,
  first DAI denial, link-up of the unknown device, …).
* **Detection** — trigger event + the rule's aggregation window + the engine latency declared in
  the scenario (`detect_latency`, 50–200 ms).
* **Attribution complete** — detection + declared lookup latencies for DHCP binding, MAC table and
  identity resolution (roughly 0.5 s in total, modelled on interactive `show` command round-trips).
* **Verified** — attribution + policy evaluation + adapter apply + read-back verification.

Alert timestamps inside a scenario are *derived* from the traffic model: the ICMP sweep signature
fires on the 200th echo request at 90 pps, the SMB fan-out on the eighth host probed on 445 at
32 probes/s, the Zeek address scan on the fifteenth host plus 150 ms of analysis delay, the DNS
signatures on the 120th query / 60th NXDOMAIN. Changing a rate in `simulator/scenarios/*.yaml`
changes every dependent number consistently.

## Why the DNS scenario is slow

DNS anomalies are statistical: the Suricata thresholds need 120 queries or 60 NXDOMAIN responses in
a minute and Zeek's SumStats epoch closes once a minute. A 64-second detection is what such a
detection honestly looks like; it is the reason the mean is 11.3 s while the median-like scenarios
detect in under six seconds.

## Running the harness

```bash
make validate-security            # table + metrics
python -m sentinelswitch validate --json   # machine-readable
```

The API exposes the same results at `GET /api/validation` and re-runs them with
`POST /api/validation/run`; the dashboard's *Detection Coverage* view renders the matrix and lets
you open each scenario's timeline and evidence features.

## Test suite

`make test` runs 51 backend tests covering the twin, correlation edge cases (unknown MAC, expired
binding, MAC movement, impersonation, protected ports, missing data), policy thresholds and guards,
containment and rollback, detection scoring, evidence bundles, drift, generator determinism and the
API (including demo run / restore / reset), plus the frontend type-check.

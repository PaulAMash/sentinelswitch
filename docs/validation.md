# Security validation

`make validate-security` (or `python -m sentinelswitch validate`) replays nine adversary scenarios
through the complete pipeline — normalization, correlation, attribution, policy, containment,
verification — against an isolated copy of the switch twin, then prints a matrix and timing metrics.

```
SENTINELSWITCH SECURITY VALIDATION
Scenario                Detect  Attribute  Response   Conf   TTD       TTA      TTC      Mechanism
Unauthorized Endpoint   PASS    PASS       CONTAINED  0.96   0.461s    0.475s   1.145s   SentinelSwitch administrative shutdown
ARP Spoofing Attempt    PASS    PASS       CONTAINED  0.99   5.087s    0.547s   1.257s   SentinelSwitch VLAN reassignment (quarantine VLAN)
Rogue DHCP              PASS    PASS       CONTAINED  0.95   3.085s    0.508s   1.175s   SentinelSwitch administrative shutdown
MAC Address Change      PASS    PASS       CONTAINED  0.95   5.084s    0.543s   1.238s   SentinelSwitch administrative shutdown
Port Scan               PASS    PASS       CONTAINED  0.96   3.768s    0.560s   1.261s   SentinelSwitch VLAN reassignment (quarantine VLAN)
DNS Anomaly             PASS    PASS       CONTAINED  0.99   64.004s   0.543s   1.239s   SentinelSwitch VLAN reassignment (quarantine VLAN)
Lateral Reconnaissance  PASS    PASS       CONTAINED  0.97   8.583s    0.572s   1.258s   SentinelSwitch VLAN reassignment (quarantine VLAN)
STP/BPDU Violation      PASS    PASS       CONTAINED  0.96   0.176s    0.490s   1.141s   BPDU Guard err-disable (switch-native) + SentinelSwitch administrative hold
Critical Asset Scan     PASS    PASS       WITHHELD   0.96   3.768s    0.560s   -        manual review — critical_assets guard

Mean Time To Detect     10.446 s   (range 0.176–64.004 s; DNS anomalies need a minute of volume)
Mean Time To Attribute   0.533 s
Mean Time To Contain     1.214 s   (detection → switch state verified; eight contained scenarios)
```

The ninth scenario is the negative path: a high-confidence port sweep from SRV-GIT01 (criticality high)
is scored for automatic containment, but the `critical_assets` guard downgrades it to manual review.
Its expected outcome is "no automatic action, attribution attached, analyst decision required", so a
pass here is a **validated safety decision, not a containment**: the harness verifies that the twin was
not changed and that the guard fired, reports the response as WITHHELD, and records no time to
contain. The analyst decision itself (rejecting containment, with the switch still untouched) is not
part of the harness; it is step 5 of `make demo-2` and is covered by `backend/tests/test_response.py`.
Means are taken over the scenarios that produce each measurement: MTTD and MTTA over all nine, MTTC
over the eight contained scenarios.

Comparing these means with the 1.0 release (eight scenarios, MTTD 11.281 s, MTTA 0.530 s) does not show
a speed-up. The eight shared scenarios produce identical per-scenario timings in both releases; the
means moved only because the ninth scenario (TTD 3.768 s, TTA 0.560 s) joined the sample.

## What each column means

| column | pass condition |
| --- | --- |
| Detect | the scenario's rule produced a detection with the expected severity and confidence (±0.005) |
| Attribute | attribution resolved to the expected physical interface (and MAC, except for the impersonation case where the MAC is deliberately wrong) |
| Response | the policy produced the expected disposition. CONTAINED: automatic containment was applied *and verified* on the twin. WITHHELD: a review scenario where the twin was untouched and the expected guard fired; this validates a safety decision and is never counted as a containment |

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
detect in under six seconds. The mean over the nine scenarios of the 2.0 harness is 10.4 s.

## Running the harness

```bash
make validate-security            # table + metrics
python -m sentinelswitch validate --json   # machine-readable
```

The API exposes the same results at `GET /api/validation` and re-runs them with
`POST /api/validation/run`; the dashboard's *Detection Coverage* view renders the matrix and lets
you open each scenario's timeline and evidence features.

## Test suite

`make test` runs the backend test suite covering the twin, correlation edge cases (unknown MAC, expired
binding, MAC movement, impersonation, protected ports, missing data), policy thresholds and guards,
containment and rollback, detection scoring, evidence bundles, drift, generator determinism and the
API (including demo run / restore / reset), plus the frontend type-check.

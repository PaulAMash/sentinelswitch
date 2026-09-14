# Switch adapters

`SwitchAdapter` (backend/sentinelswitch/containment/adapters.py) is the only interface the response
engine uses to read or change access-layer state. Two implementations exist:

| adapter | status | notes |
| --- | --- | --- |
| `SimulatedCisco2960XAdapter` | shipped | operates on the deterministic digital twin in SQLite; renders IOS-style command output |
| `IOSSSHAdapter` | design only | would run the IOS command sequences in `simulated-cisco-2960x.yaml` over SSH with a least-privilege service account; not included because the repository never touches physical hardware |

Both adapters share the same guarantees: protected interfaces (`Gi1/0/1`, `Gi1/0/48`), trunk ports
and the SPAN destination are refused at the adapter layer as well as in the policy engine.

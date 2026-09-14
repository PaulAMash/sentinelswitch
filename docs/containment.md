# Containment

## Policy

`automation/policies/containment-policy.yaml` is evaluated for every scored detection.

```
tiers:      automatic_containment  confidence >= 0.95 and severity in [high, critical]
            manual_review          confidence >= 0.75
            monitor                otherwise
actions:    compromised_host -> quarantine_vlan (VLAN 50)
            rogue_device     -> port_shutdown
            identity, policy -> none
guards:     protected_ports (Gi1/0/1, Gi1/0/48), trunk_ports, span_destination,
            critical_assets (critical / high), unresolved_attribution   -> manual_review
```

Guards run after the tier is chosen and can only downgrade. The decision record keeps the tier
before guards, the guards that fired, and every factor considered, so an analyst can see why a
high-confidence detection on the firewall ended in the review queue.

## Actions

| action | what the adapter does | when |
| --- | --- | --- |
| `quarantine_vlan` | `interface GigabitEthernet1/0/N` / `switchport access vlan 50` / `write memory` | authenticated corporate hosts showing compromise: the host stays reachable from the remediation network |
| `port_shutdown` | `interface GigabitEthernet1/0/N` / `shutdown` | rogue devices with no legitimate session: unknown endpoints, rogue DHCP servers, MAC impersonation |
| administrative hold | `shutdown` on a port the switch already err-disabled | BPDU Guard violations, so `errdisable recovery` cannot re-enable the port before a human looks |

Every action gets a workflow id (`WF-2026-0042-01`), the initiating detection, requested/applied/
verified timestamps, the exact command sequence and an IOS-style transcript.

## Verification

The controller never trusts its own write. After a VLAN move it reads back
`show interfaces … switchport` and `show mac address-table interface …` and requires
`Access Mode VLAN: 50` plus every learned MAC in VLAN 50. After a shutdown it requires
`admin down`, `disabled`, and no MAC addresses on the port. A failed verification marks the
action `failed` and the incident `containment_failed`.

## Protected interfaces

Two layers refuse to touch infrastructure:

1. The policy guard downgrades any automatic decision whose attribution lands on a protected port,
   a trunk or the SPAN destination.
2. `SimulatedCisco2960XAdapter._guard()` raises `ProtectedInterfaceError` for the same interfaces,
   so even a hand-crafted decision cannot change them. `backend/tests/test_containment.py`
   exercises both layers.

## Rollback

`POST /api/incidents/{id}/restore` (or the analyst's restore in the dashboard) reverses the action:
`switchport access vlan <original>` or `no shutdown`, records who released containment and why,
updates the incident to `resolved`, and appends the transcript to the timeline. The historical
incidents in the dataset (INC-2026-0039 … 0041) all went through this path.

## Containment mechanics in the lab

The lab assigns no VLAN to corporate users in the RADIUS Access-Accept, so the port's configured
access VLAN is authoritative and a static change is enough to isolate the host immediately. In a
deployment where RADIUS assigns VLANs dynamically the adapter should also send a RADIUS CoA
(RFC 5176) so re-authentication cannot undo the quarantine; that is listed under future work.
Changing the access VLAN flushes the port's DHCP snooping bindings and re-learns its MAC in VLAN 50,
which is what the post-quarantine transcripts show.

## Workflows

`automation/workflows/*.yaml` describe the same steps declaratively (open incident → correlate →
guard → apply → verify → evidence → notify, with a rollback block). `automation/adapters/` documents
the IOS command mapping a production `IOSSSHAdapter` would use.

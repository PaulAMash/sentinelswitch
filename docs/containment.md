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

## Authorization record

Since 2.0 the policy decision (what *should* happen) and the authorization (who *allowed* it and
when) are recorded separately. `authorization_record()` in `containment/controller.py` builds the
record right after the policy decision; `ScenarioRunner` attaches it to the incident or the review,
and the controller stores it on the containment action.

| field | value |
| --- | --- |
| `mode` | `automatic` (policy tier), `analyst` (manual approval), `rejected` (explicitly declined) |
| `status` | `authorized` when the tier is `automatic_containment` or an analyst approved; `rejected`; otherwise `pending` |
| `authorized_by` | `policy-engine` or the analyst username |
| `authorized_at` | set when authorized or rejected; `null` while pending |
| `basis` | `policy tier <disposition>` plus `(before guards: <tier>)` when a guard downgraded it |
| `reason`, `guards`, `action` | copied from the decision |
| `note` | analyst note |

The controller refuses to execute unless `status == authorized` (the action is recorded as
`not_applicable`), and the timeline gains an `authorization` phase: `Containment authorized by
policy-engine (policy tier automatic_containment); action quarantine_vlan`, or `Automatic
containment NOT authorized: guard(s) critical_assets require analyst approval`. The control
`CTL-RESPONSE-AUTHORIZED` later verifies that every executed action's `authorized_at` precedes its
`applied_at` ([controls.md](controls.md)).

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

## Analyst decisions

Detections that policy routed to `manual_review` wait in the review queue with their attribution
and decision attached and a `pending` authorization. `services/response.py` records the analyst's
decision without rewriting the original policy decision:

| | `POST /api/reviews/{detection_id}/approve` | `POST /api/reviews/{detection_id}/reject` |
| --- | --- | --- |
| precondition | review status `review`; the detection class maps to an action; attribution has an interface that is not protected or a trunk (otherwise 409) | review status `review` (otherwise 409) |
| authorization | mode `analyst`, status `authorized`, reason `Analyst approval by <actor>: <note>`, `tier_before_guards` = the original disposition | mode `rejected`, status `rejected`, note |
| execution | the same `ContainmentController` + `SimulatedCisco2960XAdapter` as the automatic path (apply 0.41 s, verify 0.13 s on the simulated clock), 120 s after the later of the twin clock and the review's `opened_at` | none |
| records | new incident `INC-2026-<next>` (`disposition: analyst_approved`, status `contained` or `containment_failed`), containment action, timeline entries `authorization` / `containment` / `verification` / `evidence`, the eleven-artifact evidence bundle under `data/incidents/<id>/`, review → `approved` with `incident_id`, detection and alerts updated; the API route then runs a `post-containment-<incident>` assessment | review → `closed` with `closed_by` and note, timeline `resolution` entry `Containment declined by <actor>: <note>`, alerts closed |

Approval writes the same evidence bundle the automatic path writes (`_write_evidence()` in
`services/response.py`: timeline, alerts, binding, MAC table, port before/after, decision, action,
related Zeek records and the rendered README), so `CTL-EVIDENCE-COMPLETE`, `CTL-RESPONSE-AUTHORIZED`
and `CTL-QUARANTINE-VERIFIED` are all evaluated for the new incident. Rejection changes nothing on
the twin. Both paths are exercised by `sentinelswitch demo2`, which rejects the
`critical-asset-scan` review ([workflow-2.0.md](workflow-2.0.md#negative-path)).

## Verification failure handling

A failed read-back is a first-class state, not an exception:

1. The controller marks the action `failed` (`verification.ok = false`, expected string and
   transcript kept) and the incident `containment_failed`; the timeline records `Verification FAILED`.
2. `CTL-QUARANTINE-VERIFIED` assesses every `contained` or `containment_failed` incident and fails
   when the read-back failed **or** the twin no longer reports the containment state (access VLAN
   and every learned MAC in the quarantine VLAN, or admin down with no MACs). The finding carries
   the original commands as guidance but has no executable action: `POST /api/findings/{id}/remediate`
   answers 409 `manual follow-up required`, and the analyst re-applies containment from the incident
   page or releases it.
3. `CTL-RESPONSE-AUTHORIZED` still assesses the failed action, so an unauthorized attempt is
   reported even when it did not take effect.
4. After a restore, `CTL-RECOVERY-VERIFIED` fails if the interface is not back in its intended VLAN,
   administratively up, and free of quarantine/hold flags.

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

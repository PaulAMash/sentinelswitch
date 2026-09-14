"""Load the generated dataset (data/seed/*.json) into SQLite and run the validation harness."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from sentinelswitch.simulator.twin import SwitchTwin
from sentinelswitch.validation.harness import run_validation
from simulator.canonical import Environment, ts_iso

from .store import Store


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def seed_database(
    store: Store, env: Environment, seed_dir: Path, incidents_dir: Path, *, run_validation_suite: bool = True
) -> dict[str, Any]:
    if not (seed_dir / "switch-state.json").exists():
        raise FileNotFoundError(f"{seed_dir}/switch-state.json missing; run `sentinelswitch generate` first")
    store.reset()
    twin_data = _read(seed_dir / "switch-state.json")
    store.kv_set("twin", twin_data)
    store.kv_set("twin_baseline", twin_data)
    store.kv_set("dataset", env.dataset)
    store.kv_set("demo", {"stage": "baseline", "flagship_incident": None, "ran_at": None})
    store.bulk(store.put_device, _read(seed_dir / "inventory.json"))
    store.bulk(store.put_user, _read(seed_dir / "users.json"))
    store.bulk(store.put_alert, _read(seed_dir / "alerts.json"))
    store.bulk(store.put_detection, _read(seed_dir / "detections.json"))
    store.bulk(store.put_incident, _read(seed_dir / "incidents.json"))
    store.bulk(store.put_review, _read(seed_dir / "reviews.json"))
    for owner, tl in _read(seed_dir / "timelines.json").items():
        store.put_timeline(owner, tl)
    store.bulk(store.put_action, _read(seed_dir / "containment-actions.json"))
    store.bulk(store.put_auth_event, [e for e in _read_jsonl(seed_dir.parent / "radius" / "auth-events.jsonl")])
    store.bulk(store.put_bucket, _read(seed_dir / "traffic-buckets.json"))
    store.bulk(store.put_scenario, _read(seed_dir / "scenarios.json"))
    # Remove a stale flagship bundle so the demo recreates it deterministically.
    flagship_id = env.flagship().instances["day"].incident_id
    if flagship_id and (incidents_dir / flagship_id).exists():
        shutil.rmtree(incidents_dir / flagship_id)
    summary = {"seeded_at": ts_iso(env.baseline_now), "counts": store.counts()}
    if run_validation_suite:
        report = run_validation(env, SwitchTwin.from_dict(env, twin_data))
        for row in report.results:
            store.put_validation(row)
        store.kv_set("validation_metrics", report.metrics | {"all_passed": report.all_passed})
        summary["validation"] = report.metrics
    return summary


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]

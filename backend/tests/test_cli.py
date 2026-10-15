"""The 2.0 CLI commands run as a user would run them: separate processes against a temporary database,
incidents directory and artifacts directory (configured through SENTINEL_* environment variables)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

from simulator.canonical import ROOT

HISTORICAL = ("INC-2026-0039", "INC-2026-0040", "INC-2026-0041")


def _cli(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinelswitch", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


@pytest.fixture(scope="module")
def cli_env(tmp_path_factory, seed_ready):
    root = tmp_path_factory.mktemp("cli")
    incidents = root / "incidents"
    for name in HISTORICAL:
        shutil.copytree(ROOT / "data" / "incidents" / name, incidents / name)
    env = dict(
        os.environ,
        SENTINEL_DB=str(root / "cli.db"),
        SENTINEL_INCIDENTS_DIR=str(incidents),
        SENTINEL_ARTIFACTS_DIR=str(root / "artifacts"),
        COLUMNS="220",
    )
    return env, root


def test_assess_findings_remediate_report(cli_env):
    env, root = cli_env
    r = _cli(env, "assess", "--json")
    assert r.returncode == 0, r.stderr
    run = json.loads(r.stdout)
    assert run["counts"] == {"PASS": 200, "FAIL": 4, "UNKNOWN": 1, "STALE": 1} and run["findings_open"] == 5

    r = _cli(env, "findings")
    assert r.returncode == 0, r.stderr
    assert "FND-SENSOR-COVERAGE-vlan-50" in r.stdout and "FND-UNUSED-PORTS-Gi1-0-41" in r.stdout

    assert _cli(env, "remediate", "FND-NOPE").returncode == 1
    r = _cli(env, "remediate", "FND-SENSOR-COVERAGE-vlan-50")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "FND-SENSOR-COVERAGE-vlan-50 → verified" in r.stdout
    assert "monitor session 1 source vlan" in r.stdout  # the IOS transcript is printed
    again = _cli(env, "remediate", "FND-SENSOR-COVERAGE-vlan-50")
    assert again.returncode == 1 and "already verified" in again.stdout

    out = root / "out"
    r = _cli(env, "report", "--no-pdf", "--out", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((out / "security-posture-report.json").read_text(encoding="utf-8"))
    assert doc["schema_version"] == "2.0" and doc["posture"]["findings_open"] == 4
    assert (out / "security-posture-report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert not (out / "security-posture-report.pdf").exists()

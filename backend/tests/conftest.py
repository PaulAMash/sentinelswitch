from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import ROOT, load_environment


@pytest.fixture(scope="session")
def env():
    return load_environment()


@pytest.fixture()
def twin(env) -> SwitchTwin:
    return SwitchTwin.baseline(env)


@pytest.fixture(scope="session")
def seed_ready():
    """The generated dataset must exist for store/API tests; generate it if the checkout lacks it."""
    if not (ROOT / "data" / "seed" / "switch-state.json").exists():
        from simulator.generators.run import generate

        generate(quiet=True)
    return ROOT / "data" / "seed"


@pytest.fixture(scope="session")
def baseline_db(tmp_path_factory, seed_ready, env) -> Path:
    """Seed the dataset baseline once (validation harness included) into a template database.

    The template is seeded against an empty incidents directory, matching the per-test directories
    below, so every copy starts from the same state the API would reach after `POST /api/demo/reset`.
    """
    from sentinelswitch.services.seed import seed_database
    from sentinelswitch.services.store import Store

    root = tmp_path_factory.mktemp("baseline")
    (root / "incidents").mkdir()
    store = Store(env, root / "baseline.db")
    seed_database(store, env, seed_ready, root / "incidents")
    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # fold the WAL into the file before copying
    store.conn.close()
    return root / "baseline.db"


@pytest.fixture()
def api_client(tmp_path, baseline_db):
    """A fresh application per test: its own copy of the baseline database and its own empty incidents
    and artifacts directories, so no test can observe state (rows, evidence bundles, exported reports)
    created by another test, whatever the execution order. Everything lives under pytest's tmp_path."""
    from fastapi.testclient import TestClient

    from sentinelswitch.app.config import Settings
    from sentinelswitch.app.main import create_app

    db = tmp_path / "test.db"
    shutil.copyfile(baseline_db, db)
    incidents = tmp_path / "incidents"
    artifacts = tmp_path / "artifacts"
    incidents.mkdir()
    artifacts.mkdir()
    settings = Settings(
        db_path=db,
        data_dir=ROOT / "data",
        incidents_dir=incidents,
        artifacts_dir=artifacts,
        frontend_dist=Path("/nonexistent"),
        auto_seed=False,
        auto_demo=False,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield client


os.environ.setdefault("SENTINEL_AUTO_DEMO", "0")

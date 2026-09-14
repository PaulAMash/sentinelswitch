from __future__ import annotations

import os
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
def api_client(tmp_path_factory, seed_ready):
    from fastapi.testclient import TestClient

    from sentinelswitch.app.config import Settings
    from sentinelswitch.app.main import create_app

    db = tmp_path_factory.mktemp("db") / "test.db"
    incidents = tmp_path_factory.mktemp("incidents")
    settings = Settings(db_path=db, data_dir=ROOT / "data", frontend_dist=Path("/nonexistent"))
    # Evidence for API-triggered demos goes to a temporary directory.
    object.__setattr__(settings, "data_dir", ROOT / "data")
    app = create_app(settings)
    app.state.settings = _override_incidents(settings, incidents)
    with TestClient(app) as client:
        yield client


def _override_incidents(settings, incidents_dir: Path):
    class _S:
        def __getattr__(self, name):
            if name == "incidents_dir":
                return incidents_dir
            return getattr(settings, name)

    return _S()


os.environ.setdefault("SENTINEL_AUTO_DEMO", "0")

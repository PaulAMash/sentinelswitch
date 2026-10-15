"""Runtime settings (environment variables prefixed SENTINEL_)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from simulator.canonical import ROOT


@dataclass(frozen=True)
class Settings:
    root: Path = ROOT
    data_dir: Path = Path(os.environ.get("SENTINEL_DATA_DIR", str(ROOT / "data")))
    db_path: Path = Path(os.environ.get("SENTINEL_DB", str(ROOT / "data" / "generated" / "sentinelswitch.db")))
    incidents_dir: Path = Path(os.environ.get("SENTINEL_INCIDENTS_DIR", str(ROOT / "data" / "incidents")))
    artifacts_dir: Path = Path(os.environ.get("SENTINEL_ARTIFACTS_DIR", str(ROOT / "artifacts" / "sentinelswitch-2.0")))
    host: str = os.environ.get("SENTINEL_HOST", "127.0.0.1")
    port: int = int(os.environ.get("SENTINEL_PORT", "8000"))
    frontend_dist: Path = Path(os.environ.get("SENTINEL_FRONTEND_DIST", str(ROOT / "frontend" / "dist")))
    auto_seed: bool = os.environ.get("SENTINEL_AUTO_SEED", "1") == "1"
    auto_demo: bool = os.environ.get("SENTINEL_AUTO_DEMO", "0") == "1"
    cors_origins: tuple[str, ...] = tuple(
        o for o in os.environ.get("SENTINEL_CORS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o
    )

    @property
    def seed_dir(self) -> Path:
        return self.data_dir / "seed"

    @property
    def zeek_dir(self) -> Path:
        return self.data_dir / "zeek"


def get_settings() -> Settings:
    return Settings()

"""FastAPI application factory. Serves the API and, when built, the React dashboard."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sentinelswitch import __version__
from sentinelswitch.api.assurance_routes import router as assurance_router
from sentinelswitch.api.routes import router
from sentinelswitch.app.config import Settings, get_settings
from sentinelswitch.services import demo as demo_service
from sentinelswitch.services.seed import seed_database
from sentinelswitch.services.store import Store
from simulator.canonical import load_environment


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    env = load_environment()
    store = Store(env, settings.db_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if store.kv_get("twin") is None and settings.auto_seed:
            seed_database(store, env, settings.seed_dir, settings.incidents_dir)
        if settings.auto_demo and demo_service.demo_status(store).get("stage") == "baseline":
            demo_service.run_flagship(store, env, settings)
            if settings.demo_analyst:
                demo_service.apply_scripted_decisions(store, env, settings)
        yield

    app = FastAPI(
        title="SentinelSwitch",
        version=__version__,
        description="Evidence-Driven Network Security & Response Lab (digital twin)",
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.env = env
    app.state.settings = settings
    app.add_middleware(
        CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["*"], allow_headers=["*"]
    )
    app.include_router(router)
    app.include_router(assurance_router)

    dist = settings.frontend_dist
    if dist.exists() and (dist / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
        for static in ("favicon.svg", "logo.svg", "wordmark.svg"):
            if (dist / static).exists():

                def _serve(path: Path = dist / static):
                    return FileResponse(path)

                app.add_api_route(f"/{static}", _serve, methods=["GET"], include_in_schema=False)
        diagrams = settings.root / "diagrams" / "svg"
        if diagrams.exists():
            app.mount("/diagrams", StaticFiles(directory=diagrams), name="diagrams")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            candidate = dist / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")

    return app


app = create_app()

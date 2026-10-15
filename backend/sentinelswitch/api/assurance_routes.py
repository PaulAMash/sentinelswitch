"""SentinelSwitch 2.0 assurance API: posture, controls, assessments, findings, remediation, reports,
and analyst response decisions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from sentinelswitch.app.events import bus
from sentinelswitch.app.locks import serialized
from sentinelswitch.assurance.controls import catalog
from sentinelswitch.assurance.engine import FINDING_OPEN_STATES, AssessmentEngine
from sentinelswitch.assurance.export import build_export, render_html, write_html, write_json, write_pdf
from sentinelswitch.assurance.posture import summary
from sentinelswitch.assurance.remediation import RemediationError, RemediationService
from sentinelswitch.services import response as response_service

router = APIRouter(prefix="/api")


def _ctx(request: Request):
    return request.app.state.store, request.app.state.env, request.app.state.settings


def _engine(request: Request) -> AssessmentEngine:
    store, env, settings = _ctx(request)
    return AssessmentEngine(env, store, settings.incidents_dir)


class ActorBody(BaseModel):
    actor: str = Field(default="tlee", max_length=64)
    note: str = Field(default="", max_length=500)


# ---- posture / controls ------------------------------------------------------------------------
@router.get("/posture")
def posture(request: Request) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    return summary(store, env)


@router.get("/controls")
def controls(request: Request) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    post = summary(store, env)
    return {"catalog": catalog(), "status": post["by_control"], "last_run": post["last_run"]}


@router.get("/controls/{control_id}")
def control(request: Request, control_id: str) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    cat = next((c for c in catalog() if c["id"] == control_id), None)
    if cat is None:
        raise HTTPException(404, "control not found")
    return {
        "control": cat,
        # live results only; retired rows (scope no longer exists) stay reachable by id and in the export
        "assessments": [a for a in store.assessments(control_id=control_id) if a["status"] != "RETIRED"],
        "findings": [f for f in store.findings() if f["control_id"] == control_id],
    }


# ---- assessments --------------------------------------------------------------------------------
@router.get("/assessments")
def assessments(
    request: Request, status: str | None = None, control_id: str | None = None, include_retired: bool = False
) -> list[dict[str, Any]]:
    """Latest result per (control, scope). Retired rows are excluded unless asked for explicitly (or by status)."""
    store, _, _ = _ctx(request)
    rows = store.assessments(status=status, control_id=control_id)
    if include_retired or status == "RETIRED":
        return rows
    return [a for a in rows if a["status"] != "RETIRED"]


@router.get("/assessments/runs")
def assessment_runs(request: Request) -> list[dict[str, Any]]:
    store, _, _ = _ctx(request)
    return store.assessment_runs()


@router.get("/assessments/runs/{run_id}")
def assessment_run(request: Request, run_id: str) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    run = store.assessment_run(run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return {"run": run, "assessments": store.assessment_history(run_id=run_id)}


@router.get("/assessments/{assessment_id}")
def assessment(request: Request, assessment_id: str) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    a = store.assessment(assessment_id)
    if a is None:
        raise HTTPException(404, "assessment not found")
    return {
        "assessment": a,
        "history": store.assessment_history(assessment_id=assessment_id),
        "finding": store.finding(a["finding_id"]) if a.get("finding_id") else None,
        "control": next((c for c in catalog() if c["id"] == a["control_id"]), None),
    }


@router.post("/assessments/run")
@serialized
def run_assessment(request: Request, body: ActorBody | None = None) -> dict[str, Any]:
    run = _engine(request).run("api", actor=(body.actor if body else "api"))
    bus.publish("assessment", {"run_id": run["run_id"], "counts": run["counts"]})
    bus.publish("state", {"reason": "assessment"})
    return run


# ---- findings -----------------------------------------------------------------------------------
@router.get("/findings")
def findings(request: Request, status: str | None = None, open_only: bool = Query(False)) -> list[dict[str, Any]]:
    store, _, _ = _ctx(request)
    rows = store.findings(status=status)
    if open_only:
        rows = [f for f in rows if f["status"] in FINDING_OPEN_STATES]
    return rows


@router.get("/findings/{finding_id}")
def finding(request: Request, finding_id: str) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    f = store.finding(finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    return {
        "finding": f,
        "events": store.finding_events(finding_id),
        "assessment": store.assessment(f["assessment_id"]) if f.get("assessment_id") else None,
        "history": store.assessment_history(assessment_id=f.get("assessment_id")) if f.get("assessment_id") else [],
        "control": next((c for c in catalog() if c["id"] == f["control_id"]), None),
    }


@router.post("/findings/{finding_id}/remediate")
@serialized
def remediate(request: Request, finding_id: str, body: ActorBody | None = None) -> dict[str, Any]:
    store, env, settings = _ctx(request)
    svc = RemediationService(env, store, AssessmentEngine(env, store, settings.incidents_dir))
    try:
        result = svc.remediate(finding_id, actor=(body.actor if body else "tlee"), note=(body.note if body else ""))
    except KeyError:
        raise HTTPException(404, "finding not found") from None
    except RemediationError as exc:
        raise HTTPException(409, str(exc)) from None
    bus.publish("finding", {"id": finding_id, "status": result["finding"]["status"]})
    bus.publish("state", {"reason": "remediation"})
    return result


# ---- reviews (authorization decisions) ----------------------------------------------------------
@router.get("/reviews/{detection_id}")
def review(request: Request, detection_id: str) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    r = store.review(detection_id)
    if r is None:
        raise HTTPException(404, "review not found")
    return r


@router.post("/reviews/{detection_id}/approve")
@serialized
def approve(request: Request, detection_id: str, body: ActorBody) -> dict[str, Any]:
    store, env, settings = _ctx(request)
    try:
        result = response_service.approve_review(
            store, env, settings, detection_id, actor=body.actor, note=body.note or "approved after analyst review"
        )
    except KeyError:
        raise HTTPException(404, "review not found") from None
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from None
    # The new incident is assessed immediately, like the automatic path after the flagship incident.
    result["assessment_run"] = AssessmentEngine(env, store, settings.incidents_dir).run(
        f"post-containment-{result['incident']['id']}", actor=body.actor
    )
    bus.publish("incident", {"id": result["incident"]["id"], "status": result["incident"]["status"]})
    bus.publish(
        "assessment", {"run_id": result["assessment_run"]["run_id"], "counts": result["assessment_run"]["counts"]}
    )
    bus.publish("state", {"reason": "approve"})
    return result


@router.post("/reviews/{detection_id}/reject")
@serialized
def reject(request: Request, detection_id: str, body: ActorBody) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    try:
        result = response_service.reject_review(
            store, env, detection_id, actor=body.actor, note=body.note or "containment declined after analyst review"
        )
    except KeyError:
        raise HTTPException(404, "review not found") from None
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from None
    bus.publish("state", {"reason": "reject"})
    return result


# ---- reports ------------------------------------------------------------------------------------
@router.get("/reports/posture.json")
def report_json(request: Request) -> dict[str, Any]:
    store, env, settings = _ctx(request)
    return build_export(store, env, settings.incidents_dir)


@router.get("/reports/posture.html", response_class=HTMLResponse)
def report_html(request: Request) -> str:
    store, env, settings = _ctx(request)
    return render_html(build_export(store, env, settings.incidents_dir))


@router.post("/reports/generate")
@serialized
def report_generate(request: Request) -> dict[str, Any]:
    """Write the JSON and HTML (and PDF when Chromium is available) reports under the artifacts directory."""
    store, env, settings = _ctx(request)
    out_dir: Path = settings.artifacts_dir / "reports"
    doc = build_export(store, env, settings.incidents_dir)
    j = write_json(doc, out_dir / "security-posture-report.json")
    h = write_html(doc, out_dir / "security-posture-report.html")
    pdf = write_pdf(h, out_dir / "security-posture-report.pdf")
    return {
        "json": str(j),
        "html": str(h),
        "pdf": str(pdf) if pdf else None,
        "assessments": len(doc["assessments"]),
        "findings": len(doc["findings"]),
    }


@router.get("/reports/posture.pdf")
def report_pdf(request: Request):
    _, _, settings = _ctx(request)
    pdf = settings.artifacts_dir / "reports" / "security-posture-report.pdf"
    if not pdf.exists():
        raise HTTPException(404, "PDF not generated yet; POST /api/reports/generate first")
    return FileResponse(pdf, media_type="application/pdf", filename="security-posture-report.pdf")

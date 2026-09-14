"""Pydantic models describing the main API payloads (used for OpenAPI documentation and tests)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AttributionStep(BaseModel):
    name: str
    status: str
    source: str
    input: str | None = None
    output: str | None = None
    detail: str
    ts: str


class AttributionModel(BaseModel):
    ip: str | None
    mac: str | None
    switch: str
    interface: str | None
    vlan: int | None
    access_vlan: int | None = None
    port_class: str | None = None
    protected: bool
    trunk: bool
    device: str | None
    user: str | None
    resolved: bool
    confidence: float
    flags: list[str]
    steps: list[AttributionStep]


class DecisionModel(BaseModel):
    disposition: str
    action: str
    reason: str
    guards_triggered: list[str] = Field(default_factory=list)
    quarantine_vlan: int | None = None


class IncidentModel(BaseModel):
    id: str
    title: str
    severity: str
    confidence: float
    status: str
    opened_at: str
    closed_at: str | None = None
    rule: str
    device: str | None = None
    user: str | None = None
    ip: str | None = None
    mac: str | None = None
    switch: str
    interface: str | None = None
    original_vlan: int | None = None
    current_vlan: int | None = None
    chain: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class ValidationRow(BaseModel):
    scenario_id: str
    name: str
    detect: bool
    attribute: bool
    contain: bool
    ttd: float | None
    tta: float | None
    ttc: float | None
    mechanism: str | None = None

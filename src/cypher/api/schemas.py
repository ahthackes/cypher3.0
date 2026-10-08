"""Pydantic schemas for API request/response bodies — kept separate from
cypher.models (the internal dataclasses) so the wire format can evolve
independently of the internal pipeline representation.
"""
from __future__ import annotations

from pydantic import BaseModel


class EventOut(BaseModel):
    id: str
    timestamp: str
    source: str
    service: str
    event_type: str
    src_ip: str | None
    user: str | None
    http_status: int | None
    path: str | None
    message: str


class AlertOut(BaseModel):
    id: str
    timestamp: str
    src_ip: str | None
    score: float
    severity: str
    rule_hits: list[str]
    ml_score: float | None
    mitre_techniques: list[str]
    explanation: str


class BlockOut(BaseModel):
    id: str
    timestamp: str
    src_ip: str
    action: str
    reason: str | None
    expires_at: str | None
    backend: str
    actor: str


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual block from dashboard"


class LoginRequest(BaseModel):
    username: str
    password: str


class HealthOut(BaseModel):
    mode: str
    backend: str
    ingest_queue_size: int | None = None
    model_loaded: bool
    model_trained_at: str | None = None

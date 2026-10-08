"""Core data models shared by every module in the pipeline.

These are the contracts between ingestion, detection, storage, response,
and the API — every module speaks these shapes, not raw dicts.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


class EventType(str, Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    PRIV_ESCALATION_SUCCESS = "priv_escalation_success"
    PRIV_ESCALATION_FAILURE = "priv_escalation_failure"
    HTTP_REQUEST = "http_request"
    HTTP_DENIED = "http_denied"
    HTTP_NOTFOUND = "http_notfound"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Event:
    """A single normalized log line, after parsing."""

    id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_now)
    source: str = ""                     # e.g. "auth.log", "nginx-access"
    service: str = ""                    # e.g. "sshd", "sudo", "nginx"
    event_type: EventType = EventType.UNKNOWN
    src_ip: str | None = None
    user: str | None = None
    http_status: int | None = None
    path: str | None = None
    message: str = ""                    # original raw line, for audit/debug
    raw: dict[str, Any] = field(default_factory=dict)  # parser-specific extras

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "service": self.service,
            "event_type": self.event_type.value,
            "src_ip": self.src_ip,
            "user": self.user,
            "http_status": self.http_status,
            "path": self.path,
            "message": self.message,
        }
        return d


@dataclass
class Alert:
    """A scored, actionable finding produced by the fusion + policy stage."""

    id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_now)
    src_ip: str | None = None
    score: float = 0.0                   # 0-100 fused anomaly score
    severity: Severity = Severity.INFO
    rule_hits: list[str] = field(default_factory=list)   # rule ids that fired
    ml_score: float | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    contributing_event_ids: list[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "score": self.score,
            "severity": self.severity.value,
            "rule_hits": self.rule_hits,
            "ml_score": self.ml_score,
            "mitre_techniques": self.mitre_techniques,
            "explanation": self.explanation,
        }


class BlockAction(str, Enum):
    BLOCK = "block"
    UNBLOCK = "unblock"
    DRY_RUN_SKIPPED = "dry_run_skipped"
    ALLOWLISTED = "allowlisted"
    RATE_LIMITED = "rate_limited"


@dataclass
class Block:
    """A firewall action taken (or would-be taken) against an IP."""

    id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_now)
    src_ip: str = ""
    action: BlockAction = BlockAction.DRY_RUN_SKIPPED
    alert_id: str | None = None
    reason: str = ""
    ttl_seconds: int | None = None
    expires_at: datetime | None = None
    backend: str = ""
    actor: str = "system"                # "system" or an admin username for manual actions

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "action": self.action.value,
            "alert_id": self.alert_id,
            "reason": self.reason,
            "ttl_seconds": self.ttl_seconds,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "backend": self.backend,
            "actor": self.actor,
        }

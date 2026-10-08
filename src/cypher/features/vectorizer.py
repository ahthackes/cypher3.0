"""Builds the fixed-length numeric feature vector fed to the ML engine.

Feature schema (order matters — this is the contract between training
and inference, so FEATURE_NAMES is the single source of truth for both):

  0. hour_sin, hour_cos, dow_sin, dow_cos   — cyclical time (4 features)
  4. events_last_60s                        — this IP's event rate
  5. auth_failures_last_300s                — this IP's failed-login rate
  6. distinct_templates_last_300s           — template diversity (scanning signal)
  7. is_auth_failure, is_http_denied,
     is_http_notfound, is_priv_esc_failure  — one-hot event-type flags (4 features)
  11. http_status_bucket                    — 0=n/a, 1=2xx, 2=3xx, 3=4xx, 4=5xx
"""
from __future__ import annotations

from datetime import datetime

import numpy as np

from cypher.features.temporal import cyclical_time_features
from cypher.features.templating import template_id
from cypher.features.windows import SlidingWindowCounter
from cypher.models import Event, EventType

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "dow_sin", "dow_cos",
    "events_last_60s", "auth_failures_last_300s", "distinct_templates_last_300s",
    "is_auth_failure", "is_http_denied", "is_http_notfound", "is_priv_esc_failure",
    "http_status_bucket",
]


def _status_bucket(status: int | None) -> int:
    if status is None:
        return 0
    return {2: 1, 3: 2, 4: 3, 5: 4}.get(status // 100, 0)


class FeatureVectorizer:
    """Stateful: tracks per-IP sliding windows across calls to `transform`.

    One instance should live for the lifetime of the ingestion process so
    its windows reflect real recent activity; a fresh instance (with
    windows rebuilt from historical events) is used during training.
    """

    def __init__(self):
        self._activity = SlidingWindowCounter()
        self._auth_failures = SlidingWindowCounter()
        self._templates_seen: dict[str, set[str]] = {}

    def transform(self, event: Event) -> np.ndarray:
        ip = event.src_ip or "unknown"
        self._activity.add(ip, event.timestamp)
        if event.event_type == EventType.AUTH_FAILURE:
            self._auth_failures.add(ip, event.timestamp)

        tid = template_id(event.message)
        self._templates_seen.setdefault(ip, set()).add(tid)

        t = cyclical_time_features(event.timestamp)
        vec = [
            t["hour_sin"], t["hour_cos"], t["dow_sin"], t["dow_cos"],
            self._activity.count(ip, 60, now=event.timestamp),
            self._auth_failures.count(ip, 300, now=event.timestamp),
            len(self._templates_seen.get(ip, set())),
            float(event.event_type == EventType.AUTH_FAILURE),
            float(event.event_type == EventType.HTTP_DENIED),
            float(event.event_type == EventType.HTTP_NOTFOUND),
            float(event.event_type == EventType.PRIV_ESCALATION_FAILURE),
            _status_bucket(event.http_status),
        ]
        return np.array(vec, dtype=float)

    def transform_batch(self, events: list[Event]) -> np.ndarray:
        return np.vstack([self.transform(e) for e in events]) if events else np.empty((0, len(FEATURE_NAMES)))

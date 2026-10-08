"""Encodes a timestamp's hour-of-day and day-of-week as cyclical features
(sin/cos pairs) rather than raw integers, so that 23:00 and 00:00 are
recognized as adjacent rather than maximally far apart.
"""
from __future__ import annotations

import math
from datetime import datetime


def cyclical_time_features(ts: datetime) -> dict[str, float]:
    hour = ts.hour + ts.minute / 60.0
    dow = ts.weekday()
    return {
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
        "dow_sin": math.sin(2 * math.pi * dow / 7),
        "dow_cos": math.cos(2 * math.pi * dow / 7),
    }

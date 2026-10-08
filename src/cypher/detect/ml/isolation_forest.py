"""Isolation Forest anomaly scorer.

This is the primary, always-on ML detector (lightweight, fast, no GPU,
trains in seconds on modest data). It learns what "normal" feature
vectors look like and flags multidimensional outliers — e.g. an IP with
an unusual combination of high request rate + high template diversity
+ odd hour, even if no single rule caught it.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestScorer:
    def __init__(self, contamination: float = 0.02, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination, random_state=random_state, n_estimators=200
        )
        self._fitted = False

    def fit(self, X: np.ndarray) -> None:
        if X.shape[0] < 10:
            raise ValueError("Need at least 10 training samples to fit IsolationForest")
        self.model.fit(X)
        self._fitted = True

    def score(self, x: np.ndarray) -> float:
        """Return an anomaly score in [0, 100]; higher = more anomalous.

        sklearn's decision_function is higher for normal points and lower
        (often negative) for anomalies — we invert and rescale it.
        """
        if not self._fitted:
            return 0.0
        x = x.reshape(1, -1)
        raw = self.model.decision_function(x)[0]   # roughly in [-0.5, 0.5]
        score = (0.5 - raw) * 100
        return float(np.clip(score, 0, 100))

    def save(self, path: str | Path) -> None:
        joblib.dump({"model": self.model, "contamination": self.contamination}, path)

    @classmethod
    def load(cls, path: str | Path) -> "IsolationForestScorer":
        data = joblib.load(path)
        instance = cls(contamination=data["contamination"])
        instance.model = data["model"]
        instance._fitted = True
        return instance

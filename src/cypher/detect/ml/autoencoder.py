"""Reconstruction-error anomaly detector for per-IP template sequences.

HONEST STATUS: the proposal calls for a TensorFlow/Keras autoencoder.
That is a real option, but it needs a GPU-friendly environment and a
meaningfully larger training corpus to beat a much simpler baseline, and
it blows past the "under 15% CPU, i5, 8GB RAM" non-functional requirement
if run carelessly. This module implements the same idea — learn what a
normal sequence looks like, flag high reconstruction error — using PCA,
which is CPU-light, trains on modest data, and is deterministic.

It is disabled by default (see ml.autoencoder_enabled in cypher.toml).
Swapping this for a real Keras/PyTorch autoencoder later is a documented,
scoped follow-up (see docs/ml-evaluation.md): keep this exact
`fit(X) / score(x) -> float` interface and nothing else needs to change.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.decomposition import PCA


class ReconstructionScorer:
    def __init__(self, n_components: int = 6):
        self.n_components = n_components
        self.model: PCA | None = None
        self._fitted = False
        self._max_error = 1.0  # for rescaling; set during fit

    def fit(self, X: np.ndarray) -> None:
        if X.shape[0] < 20:
            raise ValueError("Need at least 20 samples to fit the reconstruction model")
        n_components = min(self.n_components, X.shape[1], X.shape[0] - 1)
        self.model = PCA(n_components=n_components, random_state=42)
        self.model.fit(X)
        reconstructed = self.model.inverse_transform(self.model.transform(X))
        errors = np.mean((X - reconstructed) ** 2, axis=1)
        # Use the 99th percentile of training errors as the "1.0" reference point,
        # so scores stay well-behaved instead of being skewed by rare outliers.
        self._max_error = float(np.percentile(errors, 99)) or 1.0
        self._fitted = True

    def score(self, x: np.ndarray) -> float:
        if not self._fitted or self.model is None:
            return 0.0
        x = x.reshape(1, -1)
        reconstructed = self.model.inverse_transform(self.model.transform(x))
        error = float(np.mean((x - reconstructed) ** 2))
        score = (error / self._max_error) * 100
        return float(np.clip(score, 0, 100))

    def save(self, path: str | Path) -> None:
        joblib.dump({"model": self.model, "max_error": self._max_error}, path)

    @classmethod
    def load(cls, path: str | Path) -> "ReconstructionScorer":
        data = joblib.load(path)
        instance = cls()
        instance.model = data["model"]
        instance._max_error = data["max_error"]
        instance._fitted = True
        return instance

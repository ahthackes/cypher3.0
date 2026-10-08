"""Optional ONNX export/inference path.

The joblib-loaded scikit-learn models (isolation_forest.py, autoencoder.py)
are what the detector uses by default — they already meet the project's
CPU budget on modest hardware, so ONNX is NOT required to hit the
performance non-functional requirement.

This module exists for the case where you want a smaller, dependency-free
inference footprint at deploy time (e.g. shipping the responder without a
scikit-learn install). It requires the optional `ml` extra:

    pip install -e ".[ml]"

Usage is intentionally a thin wrapper — export once during/after training,
then load with `ONNXScorer` wherever you'd otherwise import
IsolationForestScorer.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np


def export_isolation_forest_to_onnx(model, n_features: int, out_path: str | Path) -> None:
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError as exc:
        raise ImportError(
            "ONNX export needs the optional 'ml' extra: pip install -e '.[ml]'"
        ) from exc

    onnx_model = convert_sklearn(
        model, initial_types=[("input", FloatTensorType([None, n_features]))]
    )
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())


class ONNXScorer:
    def __init__(self, onnx_path: str | Path):
        try:
            import onnxruntime as ort
        except ImportError as exc:
            raise ImportError(
                "ONNX inference needs the optional 'ml' extra: pip install -e '.[ml]'"
            ) from exc
        self.session = ort.InferenceSession(str(onnx_path))
        self.input_name = self.session.get_inputs()[0].name

    def score_raw(self, x: np.ndarray) -> float:
        """Returns the raw model output; caller applies the same rescaling
        as the sklearn-native scorer (see isolation_forest.py `score`)."""
        result = self.session.run(None, {self.input_name: x.reshape(1, -1).astype(np.float32)})
        return float(result[0][0])

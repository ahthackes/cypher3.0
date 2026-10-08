"""Offline training entry point: turns a batch of historical Events into
fitted IsolationForestScorer / ReconstructionScorer models and registers
them via ModelRegistry.

Run via `cypher train` (see __main__.py). Training never touches the
live pipeline directly — a model is only picked up by the running
detector on the next scheduled reload (ml.retrain_interval_hours) or a
manual restart, so a bad training run can be inspected before it goes live.
"""
from __future__ import annotations

import logging
from pathlib import Path

from cypher.detect.ml.autoencoder import ReconstructionScorer
from cypher.detect.ml.isolation_forest import IsolationForestScorer
from cypher.detect.ml.registry import ModelRegistry
from cypher.features.vectorizer import FeatureVectorizer
from cypher.models import Event
from cypher.settings import MLSettings

logger = logging.getLogger("cypher.detect.ml.trainer")


def train_from_events(events: list[Event], ml_settings: MLSettings) -> dict:
    """Fit models on a list of historical Events and save them to disk.

    Returns a summary dict — used by the CLI to print what happened and
    by tests to assert training succeeded.
    """
    if len(events) < 20:
        raise ValueError(
            f"Need at least 20 historical events to train (got {len(events)}). "
            "Run scripts/generate_normal_traffic.py to build a sample dataset first."
        )

    vectorizer = FeatureVectorizer()
    X = vectorizer.transform_batch(sorted(events, key=lambda e: e.timestamp))

    registry = ModelRegistry(ml_settings.model_dir)
    model_dir = Path(ml_settings.model_dir)
    summary = {"n_samples": len(events)}

    if_scorer = IsolationForestScorer(contamination=ml_settings.isolation_forest_contamination)
    if_scorer.fit(X)
    if_meta = registry.register("isolation_forest", len(events), "")
    if_path = model_dir / f"isolation_forest_v{if_meta.version}.joblib"
    if_scorer.save(if_path)
    if_meta.file_name = if_path.name
    registry._save()
    summary["isolation_forest"] = {"version": if_meta.version, "path": str(if_path)}
    logger.info("Trained isolation_forest v%s on %d samples", if_meta.version, len(events))

    if ml_settings.autoencoder_enabled:
        rec_scorer = ReconstructionScorer()
        rec_scorer.fit(X)
        rec_meta = registry.register("reconstruction", len(events), "")
        rec_path = model_dir / f"reconstruction_v{rec_meta.version}.joblib"
        rec_scorer.save(rec_path)
        rec_meta.file_name = rec_path.name
        registry._save()
        summary["reconstruction"] = {"version": rec_meta.version, "path": str(rec_path)}
        logger.info("Trained reconstruction v%s on %d samples", rec_meta.version, len(events))

    return summary

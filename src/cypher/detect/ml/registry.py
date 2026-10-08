"""Tracks which trained model files exist and their metadata, so the
detection engine always knows which version is currently loaded and the
dashboard can show "model trained on <date>, <n> samples".

Layout on disk (under ml.model_dir):
    models/
      isolation_forest_v{n}.joblib
      reconstruction_v{n}.joblib
      registry.json
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class ModelMetadata:
    name: str                # "isolation_forest" | "reconstruction"
    version: int
    trained_at: str
    n_samples: int
    file_name: str
    notes: str = ""


class ModelRegistry:
    def __init__(self, model_dir: str | Path):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.model_dir / "registry.json"
        self._entries: list[ModelMetadata] = self._load()

    def _load(self) -> list[ModelMetadata]:
        if not self.registry_path.exists():
            return []
        with open(self.registry_path) as f:
            raw = json.load(f)
        return [ModelMetadata(**e) for e in raw]

    def _save(self) -> None:
        with open(self.registry_path, "w") as f:
            json.dump([asdict(e) for e in self._entries], f, indent=2)

    def register(self, name: str, n_samples: int, file_name: str, notes: str = "") -> ModelMetadata:
        next_version = 1 + max((e.version for e in self._entries if e.name == name), default=0)
        entry = ModelMetadata(
            name=name,
            version=next_version,
            trained_at=datetime.now().isoformat(),
            n_samples=n_samples,
            file_name=file_name,
            notes=notes,
        )
        self._entries.append(entry)
        self._save()
        return entry

    def latest(self, name: str) -> ModelMetadata | None:
        candidates = [e for e in self._entries if e.name == name]
        if not candidates:
            return None
        return max(candidates, key=lambda e: e.version)

    def all(self) -> list[ModelMetadata]:
        return list(self._entries)

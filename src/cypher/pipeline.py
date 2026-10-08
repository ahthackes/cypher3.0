"""Wires every component together into the running ingest+detect process.

This is what `cypher start` launches. It does NOT include the responder
(that's a separate root-privileged process/service) or the API (also
separate) — see docs/architecture.md for the three-process split and why
it exists.

Flow: one tailer thread per configured log source -> EventBus -> a single
detection-consumer loop that runs normalize -> rules -> ML -> fusion ->
policy -> storage, and calls the responder client only when policy says
to auto-block.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path

from cypher.bus import EventBus
from cypher.detect.fusion import fuse
from cypher.detect.ml.isolation_forest import IsolationForestScorer
from cypher.detect.ml.registry import ModelRegistry
from cypher.detect.mitre import techniques_for_rule_hits
from cypher.detect.policy import severity_for_score, should_auto_block
from cypher.detect.rules.engine import RuleEngine
from cypher.detect.rules.loader import load_rules
from cypher.features.vectorizer import FeatureVectorizer
from cypher.ingest.normalizer import normalize
from cypher.ingest.parsers import PARSERS_BY_SOURCE
from cypher.ingest.tailer import FileTailer
from cypher.ingest.win_tailer import WindowsEventLogTailer
from cypher.models import Alert
from cypher.respond.client import ResponderClient
from cypher.settings import Settings
from cypher.storage.db import Database

logger = logging.getLogger("cypher.pipeline")


class Pipeline:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.bus = EventBus()
        self.db = Database(settings.storage.sqlite_path)
        self.rule_engine = RuleEngine(load_rules(settings.detect.rules_dir))
        self.vectorizer = FeatureVectorizer()
        self.ml_scorer: IsolationForestScorer | None = self._load_latest_model()
        self.responder = ResponderClient.from_settings(settings) if settings.respond.enabled else None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def _load_latest_model(self) -> IsolationForestScorer | None:
        registry = ModelRegistry(self.settings.ml.model_dir)
        meta = registry.latest("isolation_forest")
        if not meta or not meta.file_name:
            logger.info("No trained isolation_forest model yet — ML scoring disabled until `cypher train` runs")
            return None
        model_path = Path(self.settings.ml.model_dir) / meta.file_name
        if not model_path.exists():
            return None
        return IsolationForestScorer.load(model_path)

    def start(self) -> None:
        for source_key, location in self.settings.sources.model_dump().items():
            if not location:
                continue  # empty string = this source is disabled in the config
            thread = threading.Thread(
                target=self._tail_source, args=(source_key, location), daemon=True
            )
            thread.start()
            self._threads.append(thread)

        detect_thread = threading.Thread(target=self._detect_loop, daemon=True)
        detect_thread.start()
        self._threads.append(detect_thread)
        logger.info("Pipeline started: %d source tailers + 1 detection loop", len(self._threads) - 1)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self.db.close()

    def _tail_source(self, source_key: str, location: str) -> None:
        parser_cls = PARSERS_BY_SOURCE.get(source_key)
        if parser_cls is None:
            return
        parser = parser_cls()
        try:
            if source_key == "windows_security_log":
                # `location` is an Event Log channel name ("Security"), not a path.
                tailer = WindowsEventLogTailer(channel=location)
            else:
                tailer = FileTailer(location)
        except RuntimeError as exc:
            logger.error("Cannot start source %s: %s", source_key, exc)
            return
        for line in tailer.follow(stop_flag=self._stop.is_set):
            event = parser.parse_line(line)
            if event is None:
                continue
            event = normalize(event)
            if event is None:
                continue
            self.bus.publish(event)

    def _detect_loop(self) -> None:
        while not self._stop.is_set():
            event = self.bus.consume(timeout=1.0)
            if event is None:
                continue
            self.db.insert_event(event)

            rule_hits = self.rule_engine.evaluate(event)
            ml_score = self.ml_scorer.score(self.vectorizer.transform(event)) if self.ml_scorer else None

            result = fuse(
                rule_hits, ml_score,
                weight_rules=self.settings.detect.score_weight_rules,
                weight_ml=self.settings.detect.score_weight_ml,
            )
            if result.score < self.settings.detect.thresholds.low:
                continue  # not interesting enough to record as an alert

            severity = severity_for_score(result.score, self.settings.detect.thresholds)
            alert = Alert(
                src_ip=event.src_ip,
                score=result.score,
                severity=severity,
                rule_hits=result.rule_hits,
                ml_score=result.ml_score,
                mitre_techniques=techniques_for_rule_hits(result.rule_hits),
                contributing_event_ids=[event.id],
                explanation=self._explain(result, event),
            )
            self.db.insert_alert(alert)

            if self.responder and event.src_ip and should_auto_block(severity):
                try:
                    response = self.responder.block(
                        event.src_ip, reason=alert.explanation, alert_id=alert.id
                    )
                    logger.info("Responder: %s", response)
                except OSError as exc:
                    logger.error("Could not reach responder daemon: %s", exc)

    @staticmethod
    def _explain(result, event) -> str:
        parts = []
        if result.rule_hits:
            parts.append(f"rules: {', '.join(result.rule_hits)}")
        if result.ml_score is not None:
            parts.append(f"ml_score: {result.ml_score:.1f}")
        return f"{event.src_ip or 'unknown'} — " + "; ".join(parts) if parts else "no signal"

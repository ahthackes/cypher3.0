"""CLI entry point. Usage:

    cypher start              # run ingestion + detection (foreground)
    cypher train               # train ML models from stored historical events
    cypher replay <file>        # feed a log file through the pipeline for testing/demo
    cypher status               # print recent alerts and active blocks
"""
from __future__ import annotations

import argparse
import logging
import sys
import time

from cypher.logging_setup import configure_logging
from cypher.settings import load_settings

logger = logging.getLogger("cypher.cli")


def _iter_records(path: str, source_type: str):
    """Yield one raw record at a time. Linux logs are one record per line;
    Windows Event Log XML exports are multi-line, so split on </Event>."""
    with open(path, encoding="utf-8", errors="replace") as f:
        if source_type == "windows_security_log":
            text = f.read()
            for chunk in text.split("</Event>"):
                chunk = chunk.strip()
                if chunk:
                    yield chunk + "</Event>"
        else:
            for line in f:
                yield line


def cmd_start(args: argparse.Namespace) -> None:
    from cypher.pipeline import Pipeline

    settings = load_settings(args.config)
    pipeline = Pipeline(settings)
    pipeline.start()
    logger.info("Cypher running in %s mode. Press Ctrl+C to stop.", settings.general.mode)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping...")
        pipeline.stop()


def cmd_train(args: argparse.Namespace) -> None:
    from cypher.detect.ml.trainer import train_from_events
    from cypher.models import Event, EventType
    from cypher.storage.db import Database
    from datetime import datetime

    settings = load_settings(args.config)
    db = Database(settings.storage.sqlite_path)
    rows = db.recent_events(limit=args.limit)
    events = [
        Event(
            id=r["id"], timestamp=datetime.fromisoformat(r["timestamp"]),
            source=r["source"], service=r["service"],
            event_type=EventType(r["event_type"]), src_ip=r["src_ip"], user=r["user"],
            http_status=r["http_status"], path=r["path"], message=r["message"],
        )
        for r in rows
    ]
    summary = train_from_events(events, settings.ml)
    print(f"Trained on {summary['n_samples']} events:")
    print(f"  isolation_forest v{summary['isolation_forest']['version']} -> {summary['isolation_forest']['path']}")
    if "reconstruction" in summary:
        print(f"  reconstruction v{summary['reconstruction']['version']} -> {summary['reconstruction']['path']}")


def cmd_replay(args: argparse.Namespace) -> None:
    """Feeds a log file line-by-line through the same parse -> normalize
    -> rules -> ML (if trained) -> fusion -> policy -> storage path the
    live pipeline uses, without needing root or a live system log. Useful
    for demos and for generating training data from sample datasets.
    Auto-block decisions are evaluated but only actually sent to the
    responder if one is reachable; otherwise they're just logged."""
    from cypher.detect.fusion import fuse
    from cypher.detect.mitre import techniques_for_rule_hits
    from cypher.detect.ml.isolation_forest import IsolationForestScorer
    from cypher.detect.ml.registry import ModelRegistry
    from cypher.detect.policy import severity_for_score, should_auto_block
    from cypher.detect.rules.engine import RuleEngine
    from cypher.detect.rules.loader import load_rules
    from cypher.features.vectorizer import FeatureVectorizer
    from cypher.ingest.normalizer import normalize
    from cypher.ingest.parsers import PARSERS_BY_SOURCE
    from cypher.models import Alert
    from cypher.storage.db import Database
    from pathlib import Path

    settings = load_settings(args.config)
    parser_cls = PARSERS_BY_SOURCE.get(args.source_type)
    if parser_cls is None:
        print(f"Unknown source type '{args.source_type}'. Options: {list(PARSERS_BY_SOURCE)}")
        sys.exit(1)
    parser = parser_cls()
    rule_engine = RuleEngine(load_rules(settings.detect.rules_dir))
    vectorizer = FeatureVectorizer()
    db = Database(settings.storage.sqlite_path)

    ml_scorer = None
    registry = ModelRegistry(settings.ml.model_dir)
    meta = registry.latest("isolation_forest")
    if meta and meta.file_name:
        model_path = Path(settings.ml.model_dir) / meta.file_name
        if model_path.exists():
            ml_scorer = IsolationForestScorer.load(model_path)

    n_events, n_alerts, n_would_block = 0, 0, 0
    for line in _iter_records(args.file, args.source_type):
        event = parser.parse_line(line)
        if event is None:
            continue
        event = normalize(event)
        if event is None:
            continue
        db.insert_event(event)
        n_events += 1

        rule_hits = rule_engine.evaluate(event)
        ml_score = ml_scorer.score(vectorizer.transform(event)) if ml_scorer else None
        result = fuse(rule_hits, ml_score,
                       weight_rules=settings.detect.score_weight_rules,
                       weight_ml=settings.detect.score_weight_ml)
        if result.score < settings.detect.thresholds.low:
            continue

        severity = severity_for_score(result.score, settings.detect.thresholds)
        explanation_parts = []
        if result.rule_hits:
            explanation_parts.append(f"rules: {', '.join(result.rule_hits)}")
        if result.ml_score is not None:
            explanation_parts.append(f"ml_score: {result.ml_score:.1f}")
        alert = Alert(
            src_ip=event.src_ip, score=result.score, severity=severity,
            rule_hits=result.rule_hits, ml_score=result.ml_score,
            mitre_techniques=techniques_for_rule_hits(result.rule_hits),
            contributing_event_ids=[event.id],
            explanation=f"{event.src_ip or 'unknown'} — " + "; ".join(explanation_parts),
        )
        db.insert_alert(alert)
        n_alerts += 1
        if should_auto_block(severity):
            n_would_block += 1

    print(f"Replayed {args.file}: {n_events} events stored, {n_alerts} alerts raised, "
          f"{n_would_block} would trigger auto-block (dry_run mode skips the real firewall call).")
    print("Run `cypher status` to see them, or open the dashboard.")


def cmd_status(args: argparse.Namespace) -> None:
    from cypher.storage.db import Database

    settings = load_settings(args.config)
    db = Database(settings.storage.sqlite_path)
    alerts = db.recent_alerts(limit=10)
    blocks = db.active_blocks()
    print(f"Mode: {settings.general.mode}   Backend: {settings.respond.backend}")
    print(f"\nRecent alerts ({len(alerts)}):")
    for a in alerts:
        print(f"  [{a['severity']:8}] score={a['score']:.0f}  ip={a['src_ip']}  {a['timestamp']}")
    print(f"\nActive blocks ({len(blocks)}):")
    for b in blocks:
        print(f"  {b['src_ip']}  expires={b['expires_at']}")


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser(prog="cypher")
    parser.add_argument("--config", default="config/cypher.toml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("start").set_defaults(func=cmd_start)

    train_p = sub.add_parser("train")
    train_p.add_argument("--limit", type=int, default=5000)
    train_p.set_defaults(func=cmd_train)

    replay_p = sub.add_parser("replay")
    replay_p.add_argument("file")
    replay_p.add_argument("--source-type", default="auth_log",
                           choices=["auth_log", "syslog", "web_access_log", "windows_security_log"])
    replay_p.set_defaults(func=cmd_replay)

    sub.add_parser("status").set_defaults(func=cmd_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

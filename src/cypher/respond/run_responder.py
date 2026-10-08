"""Entry point for the responder systemd service:
    python -m cypher.respond.run_responder --config /opt/cypher/config/cypher.toml

Kept separate from cypher/__main__.py's CLI since this one process runs
as root and should import as little of the rest of the codebase as
possible (see responder.py's module docstring).
"""
from __future__ import annotations

import argparse

from cypher.logging_setup import configure_logging
from cypher.respond.responder import run_responder
from cypher.settings import load_settings
from cypher.storage.db import Database


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/cypher.toml")
    args = parser.parse_args()

    settings = load_settings(args.config)
    db = Database(settings.storage.sqlite_path)
    run_responder(settings, db)


if __name__ == "__main__":
    main()

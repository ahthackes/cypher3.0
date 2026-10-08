# FYP Report — working document

This folder is built up incrementally as the project is built, per the
project's working agreement, rather than reconstructed at the end.

- `parts/00-foundation.md` — config, data models, settings loader
- `parts/01-ingestion.md` — tailer, parsers, normalizer
- `parts/02-detection.md` — rule engine, features, fusion, policy, MITRE mapping
- `parts/03-ml.md` — Isolation Forest, reconstruction model, trainer, registry
- `parts/04-active-defense.md` — safety gate, firewall backends, responder daemon
- `parts/05-api-dashboard.md` — FastAPI backend, auth, dashboard UI
- `parts/06-testing.md` — test suite structure and what each test file proves
- `parts/07-windows-support.md` — cross-platform design, the Windows additions, defects found, and what is still unverified

Each part covers: what the files do, how the code works, why it was
built that way, security considerations, and how it's tested — in
enough detail to paste into the final FYP document largely as-is, with
your own screenshots/results from lab testing added where noted.

When new phases are built, a new numbered part is added here following
the same template.

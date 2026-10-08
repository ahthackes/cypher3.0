# Software Requirements Specification — Cypher 2.0

## 1. Scope

Cypher 2.0 is a host-based, offline log anomaly detector and active
defense system for Linux, built as a BS Cyber Security final year
project at Riphah International University.

## 2. Functional requirements

| ID | Requirement | Status |
|---|---|---|
| FR-1 | Parse unstructured log files into structured events in real time | Implemented (`ingest/`) |
| FR-2 | Support custom rule-based heuristics via config files | Implemented (`config/rules.d/*.toml`) |
| FR-3 | Train ML models entirely locally on historical data | Implemented (`cypher train`) |
| FR-4 | Assign a numeric anomaly score (0-100) to live events | Implemented (`detect/fusion.py`) |
| FR-5 | Autonomously block IPs that trigger a critical anomaly score | Implemented, gated by safety checks (`respond/`) |
| FR-6 | Dashboard shall display real-time metrics, active blocks, system health | Implemented (`web/`, `api/`) |

## 3. Non-functional requirements

| ID | Requirement | How it's addressed |
|---|---|---|
| NFR-1 | ≤15% CPU at steady state on an i5 6th gen / 8GB RAM | Isolation Forest (not a deep net) by default; PCA, not TensorFlow, for the optional reconstruction model; `scripts/benchmark.py` measures per-line processing cost |
| NFR-2 | Log-to-block latency ≤2.5s | Single-process queue (no network broker); rules run before the (heavier) ML path |
| NFR-3 | 100% offline, no external API calls for core functionality | No network calls anywhere in `ingest/`, `detect/`, `respond/`, or `api/` — GeoIP and MITRE data are read from local files, not fetched |
| NFR-4 | Dashboard/ML failure must not crash log ingestion | Three separate OS processes (see `architecture.md`); ingestion has no import-time dependency on the API or responder |

| NFR-5 | Runs on Linux and Windows from one codebase | Platform-specific code (log reader, parser, firewall backend, service setup) sits behind interfaces; the OS is chosen by config (`config/cypher.toml` vs `config/cypher.windows.toml`) — see `architecture.md` |

## 4. Out of scope (for this version)

- Multi-host / distributed deployment (Cypher is host-based, by design,
  per the "privacy-preserving, local" brief)
- macOS support
- Windows log sources other than the Security channel (e.g. IIS W3C logs, Sysmon)
- A GUI installer — install is shell-script + systemd, documented in
  `docs/user-guide.md`

## 5. Actors

- **Administrator** — installs Cypher, reviews the dashboard, can
  manually block/unblock IPs, tunes thresholds and the allowlist.
- **The system itself** — auto-blocks only at CRITICAL severity, always
  through the safety gate, always logged to the audit trail.

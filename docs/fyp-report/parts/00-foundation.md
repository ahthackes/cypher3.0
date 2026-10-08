# Part 0 — Foundation: config, data models, settings

## Files covered

`pyproject.toml`, `config/cypher.toml`, `config/allowlist.toml`,
`config/rules.d/*.toml`, `src/cypher/models.py`, `src/cypher/settings.py`,
`src/cypher/logging_setup.py`, `src/cypher/bus.py`

## Purpose

This is the layer every other module depends on: the shapes of data
(`models.py`), how configuration is loaded and validated
(`settings.py`), and the queue connecting ingestion to detection
(`bus.py`). Nothing here does any actual security work — it exists so
the modules that do can agree on a common vocabulary.

## How it works

**`models.py`** defines four dataclasses that are the contract between
every other module: `Event` (one parsed log line), `Alert` (a scored
finding), `Block` (a firewall action taken or considered), and the
enums `EventType`, `Severity`, `BlockAction` that constrain their
fields to known values instead of free-text strings. Each has a
`to_dict()` for JSON serialization. Using dataclasses rather than plain
dicts means a typo in a field name (`event.src_ip` vs `event["src_ip"]`)
is caught by static analysis/IDE tooling instead of failing silently at
runtime.

**`settings.py`** uses Pydantic models to load and validate
`config/cypher.toml`. Every section has a typed class
(`SourcesSettings`, `DetectSettings`, etc.) with sensible defaults, so a
minimal or partially-filled config file still produces a fully usable
`Settings` object — `load_settings()` is the single function every
entry point calls; no other module reads the TOML file directly.

**`bus.py`** is a thread-safe `queue.Queue` wrapper with one
deliberate design choice: under backpressure (the queue is full because
detection is falling behind ingestion), it drops the *oldest* queued
event rather than blocking the tailer thread. The reasoning: a blocked
tailer thread risks losing log lines entirely if the OS's own log
rotation buffer fills up; a dropped *older* alert-candidate is a
smaller loss than a gap in raw ingestion.

## Configuration structure

`cypher.toml` is organized into sections matching the `Settings`
classes: `[general]` (mode, data dir), `[sources]` (log paths),
`[storage]`, `[detect]` (rules dir, window, fusion weights,
thresholds), `[ml]`, `[respond]` (backend, TTL, rate limit, allowlist
path, socket path), `[api]`, `[geo]`, `[mitre]`. Rules live in separate
files under `config/rules.d/` rather than inline in `cypher.toml`, so
rule changes don't require touching the main config and multiple rule
files can be organized by topic (`ssh_bruteforce.toml`,
`sudo_abuse.toml`, `web_attacks.toml`).

## Security considerations

- `general.mode` defaults to `"dry_run"` in the shipped config — see
  `docs/threat-model.md` for why this default matters.
- `allowlist.toml` is a separate file from `cypher.toml` specifically so
  it's easy to spot and review in a diff/code review before a
  deployment goes to `active` mode.

## Testing

Covered indirectly by every test that constructs a `Settings` or
`Event`/`Alert`/`Block` object (effectively all 49 tests). `settings`
fixture in `tests/conftest.py` builds a `Settings` instance pointed at
temp paths for isolated test runs.

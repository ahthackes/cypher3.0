# Part 2 — Detection: rules, features, fusion, policy

## Files covered

`src/cypher/features/windows.py`, `src/cypher/features/templating.py`,
`src/cypher/features/temporal.py`, `src/cypher/features/vectorizer.py`,
`src/cypher/detect/rules/loader.py`, `src/cypher/detect/rules/engine.py`,
`src/cypher/detect/fusion.py`, `src/cypher/detect/policy.py`,
`src/cypher/detect/mitre.py`

## Purpose

Implements FR-2 (custom rule-based heuristics) and FR-4 (a 0-100
anomaly score) from the SRS, and the "hybrid detection engine" from the
original proposal — rules for known, high-confidence patterns, ML for
everything else.

## How it works

**`features/windows.py`'s `SlidingWindowCounter`** is the shared
primitive both the rule engine and the ML feature pipeline use to
answer "how many matching events has this key produced in the last N
seconds?" Implemented as a `dict[str, deque[datetime]]` — appends are
O(1) amortized, and stale entries are pruned lazily on read (when
`count()` is called) rather than by a background sweep, so it's safe to
call from the hot ingestion path without extra synchronization.

**`detect/rules/loader.py`** reads every `*.toml` file in
`config/rules.d/` into a flat list of `Rule` objects. A malformed
individual rule (missing a required field) is skipped with a logged
warning rather than crashing startup — one typo in one rule file
shouldn't take down detection entirely.

**`detect/rules/engine.py`'s `RuleEngine`** evaluates each incoming
event against every loaded rule. Two rule shapes are supported:
threshold rules (`count_threshold` + `window_seconds`, backed by a
`SlidingWindowCounter` per rule) for "N times in M seconds" patterns
like SSH brute force, and single-shot pattern rules
(`match_contains`/`match_regex` against a named field) for things that
should fire the instant they're seen, like "user not in sudoers."

**`features/templating.py`** masks variable tokens (IPs, numbers,
ports, quoted strings) in a log message to produce a stable "template" —
this is what lets the ML feature `distinct_templates_last_300s` measure
genuine behavioral diversity (an IP hitting many different kinds of
endpoints) rather than being thrown off by every request having a
different IP or timestamp in the raw text.

**`features/vectorizer.py`'s `FeatureVectorizer`** turns one `Event`
into a fixed 12-element numeric vector: 4 cyclical time features
(hour/day-of-week as sin/cos pairs, so 23:00 and 00:00 are recognized
as close rather than maximally distant), 3 per-IP activity counts
(events in the last 60s, auth failures in the last 300s, distinct
templates in the last 300s), 4 one-hot event-type flags, and an HTTP
status bucket. `FEATURE_NAMES` is the single source of truth for this
order — training and inference both import it, so they can never drift
apart silently.

**`detect/fusion.py`** combines rule hits and the ML score into one
0-100 number. The chosen approach is `max(highest_rule_score,
weighted_average)` rather than a pure weighted sum — reasoning in the
module's own docstring: a single high-confidence rule shouldn't get
diluted by an ML score of 0 just because the model hasn't seen enough
data yet, but when both signals genuinely agree the fused score should
reflect that agreement rather than cap at the rule's own score.

**`detect/policy.py`** maps the fused score to a `Severity` via the
configurable thresholds, and — deliberately conservatively —
`should_auto_block()` only returns true at `CRITICAL`. HIGH and below
are surfaced for human review. This threshold can be loosened per
deployment once false-positive rates are actually measured (see
`docs/ml-evaluation.md`), but conservative-by-default is the right
starting point for a system with real-world firewall access.

**`detect/mitre.py`** maps rule IDs to MITRE ATT&CK technique IDs via a
small hand-curated dictionary (`RULE_TO_MITRE`) — kept as explicit code
rather than an automatic match against the full downloaded ATT&CK JSON,
since an automatic text match would be unreliable and a security tool
mis-attributing techniques is worse than not attributing them at all.

## Security considerations

- Rules run before ML on every event — cheap, deterministic,
  explainable detections never wait on the heavier ML path, which also
  means the system remains useful (for the patterns rules cover) even
  before any ML model has been trained.
- The fusion and policy logic is pure, side-effect-free code (no I/O,
  no network, no subprocess calls) — it's trivially unit-testable and
  has no attack surface of its own.

## Testing

`tests/unit/test_windows.py` (3 tests), `test_rule_engine.py` (5 tests,
loading the real shipped rule files — a rule-file typo breaks the test
suite, not just production), `test_fusion_policy.py` (7 tests covering
weighting, capping at 100, and the threshold boundaries),
`test_features.py` (4 tests for templating stability and vector shape).
`tests/integration/test_pipeline_replay.py` exercises the whole rules →
fusion → policy chain against a realistic brute-force log sequence.

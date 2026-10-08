-- Cypher 2.0 core schema. Kept deliberately simple (3 tables + audit log)
-- so it's easy to reason about under the fault-tolerance requirement.

CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    source          TEXT NOT NULL,
    service         TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    src_ip          TEXT,
    user            TEXT,
    http_status     INTEGER,
    path            TEXT,
    message         TEXT NOT NULL,
    raw_json        TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id                      TEXT PRIMARY KEY,
    timestamp               TEXT NOT NULL,
    src_ip                  TEXT,
    score                   REAL NOT NULL,
    severity                TEXT NOT NULL,
    rule_hits_json          TEXT,
    ml_score                REAL,
    mitre_techniques_json   TEXT,
    contributing_event_ids  TEXT,
    explanation             TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS blocks (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    src_ip          TEXT NOT NULL,
    action          TEXT NOT NULL,
    alert_id        TEXT,
    reason          TEXT,
    ttl_seconds     INTEGER,
    expires_at      TEXT,
    backend         TEXT,
    actor           TEXT NOT NULL DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS idx_blocks_src_ip ON blocks (src_ip);
CREATE INDEX IF NOT EXISTS idx_blocks_expires_at ON blocks (expires_at);

-- Append-only audit trail for every action the system takes (block, unblock,
-- override, model reload, config change). Never updated or deleted from
-- application code — only ever inserted into.
CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);

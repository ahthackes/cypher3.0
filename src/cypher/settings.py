"""Loads and validates config/cypher.toml into typed settings objects.

Nothing else in the codebase should read cypher.toml directly — go through
load_settings() so every module sees the same validated config.
"""
from __future__ import annotations

from pathlib import Path

import toml
from pydantic import BaseModel, Field


class SourcesSettings(BaseModel):
    # Linux text-log sources. Set any to "" (empty string) to disable it —
    # e.g. a Windows deployment with no nginx installed sets
    # web_access_log = "" and relies on windows_security_log instead.
    auth_log: str = "/var/log/auth.log"
    syslog: str = "/var/log/syslog"
    web_access_log: str = "/var/log/nginx/access.log"
    # Windows source: the Event Log *channel* name to read, not a file
    # path — "Security" is where logon/privilege events live. Empty
    # string (the default) disables it; a Linux deployment leaves this
    # unset. See ingest/win_tailer.py.
    windows_security_log: str = ""


class StorageSettings(BaseModel):
    sqlite_path: str = "./data/cypher.db"
    parquet_dir: str = "./data/processed"


class ThresholdSettings(BaseModel):
    low: int = 30
    medium: int = 60
    high: int = 80
    critical: int = 95


class DetectSettings(BaseModel):
    rules_dir: str = "./config/rules.d"
    window_seconds: int = 60
    score_weight_rules: float = 0.5
    score_weight_ml: float = 0.5
    thresholds: ThresholdSettings = Field(default_factory=ThresholdSettings)


class MLSettings(BaseModel):
    model_dir: str = "./data/models"
    isolation_forest_contamination: float = 0.02
    autoencoder_enabled: bool = False
    retrain_interval_hours: int = 24


class RespondSettings(BaseModel):
    enabled: bool = True
    # "nftables" | "iptables" | "ufw" | "windows_firewall"
    backend: str = "nftables"
    block_ttl_seconds: int = 3600
    max_blocks_per_hour: int = 20
    expiry_check_seconds: int = 30   # how often the responder releases blocks past their TTL
    allowlist_file: str = "./config/allowlist.toml"
    # Responder IPC: a loopback-only TCP socket + a shared-secret token,
    # rather than a Unix domain socket — Unix sockets don't exist on
    # Windows, and a TCP socket bound to 127.0.0.1 behaves identically
    # on both OSes, so this one mechanism covers both platforms. See
    # respond/responder.py and respond/client.py.
    ipc_host: str = "127.0.0.1"
    ipc_port: int = 8765
    ipc_token_file: str = "./data/responder.token"


class APISettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    session_secret_env: str = "CYPHER_SESSION_SECRET"


class GeoSettings(BaseModel):
    geolite_db: str = "./data/geo/GeoLite2-City.mmdb"


class MitreSettings(BaseModel):
    attack_json: str = "./data/mitre/enterprise-attack.json"


class GeneralSettings(BaseModel):
    mode: str = "dry_run"           # "dry_run" | "active"
    data_dir: str = "./data"
    timezone: str = "local"


class Settings(BaseModel):
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    sources: SourcesSettings = Field(default_factory=SourcesSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    detect: DetectSettings = Field(default_factory=DetectSettings)
    ml: MLSettings = Field(default_factory=MLSettings)
    respond: RespondSettings = Field(default_factory=RespondSettings)
    api: APISettings = Field(default_factory=APISettings)
    geo: GeoSettings = Field(default_factory=GeoSettings)
    mitre: MitreSettings = Field(default_factory=MitreSettings)

    @property
    def is_dry_run(self) -> bool:
        return self.general.mode != "active"


def load_settings(config_path: str | Path = "config/cypher.toml") -> Settings:
    """Read the TOML config file and return a validated Settings object.

    Falls back to defaults for any section that's missing, so a minimal
    config file still produces a fully usable Settings instance.
    """
    path = Path(config_path)
    if not path.exists():
        return Settings()
    raw = toml.load(path)
    return Settings.model_validate(raw)

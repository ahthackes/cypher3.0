import pytest

from cypher.settings import Settings


@pytest.fixture
def tmp_db(tmp_path):
    from cypher.storage.db import Database
    db = Database(tmp_path / "test.db")
    yield db
    db.close()


@pytest.fixture
def settings(tmp_path) -> Settings:
    s = Settings()
    s.storage.sqlite_path = str(tmp_path / "cypher.db")
    s.ml.model_dir = str(tmp_path / "models")
    s.detect.rules_dir = "config/rules.d"
    s.respond.allowlist_file = "config/allowlist.toml"
    s.respond.ipc_token_file = str(tmp_path / "responder.token")
    return s

import pytest
from fastapi.testclient import TestClient

from app.main import app

TOKEN = "test-token-0123456789-abcdefghij"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A client backed by an empty, throwaway database."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("AGENT_TOKEN", TOKEN)
    monkeypatch.delenv("SAMPLE_DATA", raising=False)
    monkeypatch.delenv("SOFTWARE_ALLOWLIST", raising=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def sample_client(tmp_path, monkeypatch):
    """A client whose database is pre-filled with the made-up sample company."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "sample.db"))
    monkeypatch.setenv("AGENT_TOKEN", TOKEN)
    monkeypatch.setenv("SAMPLE_DATA", "1")
    with TestClient(app) as c:
        yield c


def report(hostname="LNX-IT-1", **overrides):
    base = {"hostname": hostname, "department": "IT", "os": "Debian 12", "av_enabled": False,
            "pending_critical": 0, "pending_security": 0, "pending_optional": 0,
            "packages": ["bash", "curl"], "processes": []}
    base.update(overrides)
    return base

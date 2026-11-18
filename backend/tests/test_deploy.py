"""Deployment safety: startup checks, backups, retention and the compose/Caddy setup."""

import gzip
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app import backup, db
from app.main import app
from conftest import AUTH, report

REPO = Path(__file__).resolve().parents[2]


# --- startup checks --------------------------------------------------------

@pytest.mark.parametrize("token", ["", "short", "change-me-to-a-long-random-string-xyz"])
def test_server_refuses_to_start_with_weak_token(tmp_path, monkeypatch, token):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("AGENT_TOKEN", token)
    with pytest.raises(RuntimeError, match="AGENT_TOKEN"):
        with TestClient(app):
            pass


def test_api_docs_are_off_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


# --- retention -------------------------------------------------------------

def test_old_events_are_purged(client, tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat(timespec="seconds")
    new = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    client.post("/api/ingest", json=report(), headers=AUTH)
    with db.connect() as conn:
        for t in (old, new):
            conn.execute("INSERT INTO events (hostname, time, process, command_line, reason) VALUES ('h',?,'p',?, 'r')", (t, t))
    assert db.purge_old_events(30) == 1
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


# --- backups ---------------------------------------------------------------

def test_backup_is_a_consistent_copy(client, tmp_path):
    client.post("/api/ingest", json=report("BACKED-UP"), headers=AUTH)
    dest = tmp_path / "copy.db"
    backup.backup_to(dest)
    rows = sqlite3.connect(dest).execute("SELECT hostname FROM endpoints").fetchall()
    assert rows == [("BACKED-UP",)]


def test_backup_cli_writes_valid_gzip(client, tmp_path, capfd, monkeypatch):
    import io
    import sys

    client.post("/api/ingest", json=report("CLI-HOST"), headers=AUTH)
    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", type("O", (), {"buffer": buf, "flush": lambda s: None})())
    backup.main()
    restored = tmp_path / "restored.db"
    restored.write_bytes(gzip.decompress(buf.getvalue()))
    assert sqlite3.connect(restored).execute("SELECT hostname FROM endpoints").fetchone() == ("CLI-HOST",)


# --- compose and proxy configuration ---------------------------------------

@pytest.fixture(scope="module")
def compose():
    path = REPO / "docker-compose.yml"
    if not path.exists():
        pytest.skip("docker-compose.yml not available (running inside the image)")
    return yaml.safe_load(path.read_text())


def test_only_the_proxy_publishes_ports(compose):
    published = {name for name, s in compose["services"].items() if s.get("ports")}
    assert published == {"caddy"}


def test_every_service_restarts_and_has_a_healthcheck(compose):
    for name, s in compose["services"].items():
        assert s.get("restart") == "unless-stopped", name
        assert "healthcheck" in s, name


def test_images_are_pinned(compose):
    for name, s in compose["services"].items():
        if "image" in s:
            tag = s["image"].split(":", 1)[1]
            assert tag != "latest" and any(c.isdigit() for c in tag), name
    for dockerfile in (REPO / "backend" / "Dockerfile", REPO / "collector" / "Dockerfile"):
        base = next(l for l in dockerfile.read_text().splitlines() if l.startswith("FROM"))
        assert ":latest" not in base and base.count(".") >= 2, base


def test_secrets_have_no_defaults(compose):
    text = (REPO / "docker-compose.yml").read_text()
    for var in ("AGENT_TOKEN", "DASHBOARD_PASSWORD_HASH", "DASHBOARD_USER"):
        assert f"${{{var}:?" in text, var
    assert "AGENT_TOKEN=" in (REPO / ".env.example").read_text()
    assert "AGENT_TOKEN=change" not in (REPO / ".env.example").read_text()


def test_backend_container_is_locked_down(compose):
    b = compose["services"]["backend"]
    assert b["read_only"] is True and b["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in b["security_opt"]


def test_caddy_requires_login_and_hides_ingest():
    caddyfile = (REPO / "proxy" / "Caddyfile").read_text()
    assert "basic_auth" in caddyfile
    assert "handle /api/ingest" in caddyfile and "respond 404" in caddyfile
    assert "Strict-Transport-Security" in caddyfile


def test_dependencies_are_pinned():
    for line in (REPO / "backend" / "requirements.txt").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            assert "==" in line, line


def test_runtime_files_are_not_committed():
    ignored = (REPO / ".gitignore").read_text().split()
    assert ".env" in ignored and "backups/" in ignored

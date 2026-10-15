"""Basic tests: every API route answers and the numbers add up."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_summary_counts_add_up():
    s = client.get("/api/summary").json()
    assert s["online"] + s["offline"] == s["total_endpoints"]
    assert 0 <= s["av_coverage_percent"] <= 100


def test_other_routes_return_data():
    for path in ["/api/patches", "/api/endpoints", "/api/suspicious-processes", "/api/unauthorized-software"]:
        res = client.get(path)
        assert res.status_code == 200, path
        assert res.json(), path


def test_dashboard_page_served():
    res = client.get("/")
    assert res.status_code == 200
    assert "Endpoint Security Dashboard" in res.text

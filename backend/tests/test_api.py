"""Basic tests: every API route answers and the numbers add up (on sample data)."""


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_summary_counts_add_up(sample_client):
    s = sample_client.get("/api/summary").json()
    assert s["total_endpoints"] == 10
    assert s["online"] + s["offline"] == s["total_endpoints"]
    assert 0 <= s["av_coverage_percent"] <= 100


def test_other_routes_return_data(sample_client):
    for path in ["/api/patches", "/api/endpoints", "/api/suspicious-processes", "/api/unauthorized-software"]:
        res = sample_client.get(path)
        assert res.status_code == 200, path
        assert res.json(), path


def test_sample_endpoints_keep_fixed_online_state(sample_client):
    by_host = {e["hostname"]: e for e in sample_client.get("/api/endpoints").json()}
    assert by_host["WKS-034"]["online"] is True
    assert by_host["WKS-089"]["online"] is False


def test_empty_database_is_valid(client):
    assert client.get("/api/summary").json()["total_endpoints"] == 0
    assert client.get("/api/patches").json()["critical"] == 0
    assert client.get("/api/suspicious-processes").json() == []


def test_dashboard_page_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "Endpoint Security Dashboard" in res.text

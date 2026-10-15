"""FastAPI backend for the endpoint security dashboard.

It does two jobs:
1. Serves JSON data under /api/... (the "API").
2. Serves the dashboard web page (HTML/CSS/JS in the static folder).
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import sample_data

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Endpoint Security Dashboard", version="0.1.0")


@app.get("/api/health")
def health():
    """Tiny check that the server is up. Docker uses this too."""
    return {"status": "ok"}


@app.get("/api/summary")
def summary():
    """Numbers for the top tiles: endpoint counts and antivirus coverage."""
    endpoints = sample_data.ENDPOINTS
    total = len(endpoints)
    online = sum(1 for e in endpoints if e["online"])
    av_on = sum(1 for e in endpoints if e["av_enabled"])
    return {
        "total_endpoints": total,
        "online": online,
        "offline": total - online,
        "av_coverage_percent": round(av_on / total * 100, 1) if total else 0.0,
        "av_needs_attention": [e["hostname"] for e in endpoints if not e["av_enabled"]],
    }


@app.get("/api/patches")
def patches():
    """Patch compliance bars, plus which machines miss critical patches."""
    missing = [e["hostname"] for e in sample_data.ENDPOINTS if e["missing_critical"] > 0]
    return {**sample_data.PATCH_COMPLIANCE, "systems_missing_critical": missing}


@app.get("/api/endpoints")
def endpoints():
    """Full list of endpoints."""
    return sample_data.ENDPOINTS


@app.get("/api/suspicious-processes")
def suspicious_processes():
    """Suspicious process executions, newest first."""
    return sorted(sample_data.SUSPICIOUS_PROCESSES, key=lambda p: p["time"], reverse=True)


@app.get("/api/unauthorized-software")
def unauthorized_software():
    """Software installed without approval."""
    return sample_data.UNAUTHORIZED_SOFTWARE


# The dashboard page itself. Mounted last so /api/... routes win.
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

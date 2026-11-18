"""FastAPI backend for the endpoint security dashboard.

It does three jobs:
1. Accepts reports from collector agents at POST /api/ingest (token required).
2. Serves JSON under /api/... computed from the SQLite database.
3. Serves the dashboard web page (HTML/CSS/JS in the static folder).
"""

import hmac
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import connect, init_db, purge_old_events
from .rules import match_rule
from .seed import seed_sample

STATIC_DIR = Path(__file__).parent / "static"

# Package names that deserve a "high" flag when they appear after the baseline.
RISKY_SOFTWARE = {"netcat", "netcat-openbsd", "netcat-traditional", "ncat", "nmap", "socat", "tor",
                  "hydra", "john", "tcpdump", "anydesk", "teamviewer"}


log = logging.getLogger("uvicorn.error")

MIN_TOKEN_LENGTH = 24
_last_purge = 0.0


def check_agent_token() -> None:
    """Refuse to start with a missing, short or placeholder token."""
    token = os.environ.get("AGENT_TOKEN", "")
    if len(token) < MIN_TOKEN_LENGTH or token.lower().startswith("change-me"):
        raise RuntimeError(
            f"AGENT_TOKEN must be set to a random string of at least {MIN_TOKEN_LENGTH} characters "
            "(run scripts/init-env.sh)"
        )


def retention_days() -> int:
    return int(os.environ.get("RETENTION_DAYS", "30"))


def maybe_purge() -> None:
    """Drop old events at most once an hour, piggybacking on check-ins."""
    global _last_purge
    if time.monotonic() - _last_purge >= 3600:
        _last_purge = time.monotonic()
        removed = purge_old_events(retention_days())
        if removed:
            log.info("retention: removed %d events older than %d days", removed, retention_days())


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def online_window() -> timedelta:
    return timedelta(seconds=int(os.environ.get("ONLINE_SECONDS", "90")))


def extra_allowlist() -> set[str]:
    return {n.strip() for n in os.environ.get("SOFTWARE_ALLOWLIST", "").split(",") if n.strip()}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    check_agent_token()
    init_db()
    maybe_purge()
    if os.environ.get("SAMPLE_DATA", "").lower() in ("1", "true", "yes"):
        seed_sample()
    yield


# The interactive API docs are off unless ENABLE_DOCS=true (they list every route).
_docs = os.environ.get("ENABLE_DOCS", "").lower() in ("1", "true", "yes")
app = FastAPI(
    title="Endpoint Security Dashboard", version="0.3.0", lifespan=lifespan,
    docs_url="/docs" if _docs else None, redoc_url=None, openapi_url="/openapi.json" if _docs else None,
)


def require_agent_token(request: Request, authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("AGENT_TOKEN", "")
    if not expected:
        raise HTTPException(503, "AGENT_TOKEN is not configured on the server")
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        log.warning("rejected ingest from %s: bad or missing agent token", request.client.host if request.client else "?")
        raise HTTPException(401, "Invalid or missing agent token")


class ProcessEvent(BaseModel):
    time: datetime
    name: str = Field(max_length=128)
    command_line: str = Field(max_length=2000)


class IngestReport(BaseModel):
    hostname: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    department: str = Field(default="Unassigned", max_length=64)
    os: str = Field(default="unknown", max_length=128)
    av_enabled: bool = False
    pending_critical: int = Field(default=0, ge=0)
    pending_security: int = Field(default=0, ge=0)
    pending_optional: int = Field(default=0, ge=0)
    packages: list[str] = Field(default_factory=list, max_length=5000)
    processes: list[ProcessEvent] = Field(default_factory=list, max_length=500)


@app.post("/api/ingest", dependencies=[Depends(require_agent_token)])
def ingest(report: IngestReport):
    """Store one check-in: it doubles as the heartbeat."""
    stamp = iso(now())
    flagged = 0
    maybe_purge()
    with connect() as conn:
        conn.execute(
            """INSERT INTO endpoints (hostname, department, os, av_enabled, pending_critical,
                   pending_security, pending_optional, last_seen, forced_online)
               VALUES (?,?,?,?,?,?,?,?,NULL)
               ON CONFLICT(hostname) DO UPDATE SET department=excluded.department, os=excluded.os,
                   av_enabled=excluded.av_enabled, pending_critical=excluded.pending_critical,
                   pending_security=excluded.pending_security, pending_optional=excluded.pending_optional,
                   last_seen=excluded.last_seen, forced_online=NULL""",
            (report.hostname, report.department, report.os, int(report.av_enabled),
             report.pending_critical, report.pending_security, report.pending_optional, stamp),
        )

        # Package baseline: whatever is installed on the first check-in is trusted.
        # Anything that appears later (and is not allowlisted) is "unauthorized".
        known = {r["name"] for r in conn.execute("SELECT name FROM packages WHERE hostname=?", (report.hostname,))}
        first_report = not known and bool(report.packages)
        for name in report.packages:
            if name not in known:
                conn.execute("INSERT INTO packages VALUES (?,?,?,?)",
                             (report.hostname, name, int(first_report), stamp))
        installed = set(report.packages)
        if report.packages:
            for name in known - installed:  # uninstalled since last time
                conn.execute("DELETE FROM packages WHERE hostname=? AND name=?", (report.hostname, name))

        for p in report.processes:
            reason = match_rule(p.command_line)
            if reason:
                when = iso(p.time if p.time.tzinfo else p.time.replace(tzinfo=timezone.utc))
                cur = conn.execute(
                    "INSERT OR IGNORE INTO events (hostname, time, process, command_line, reason) VALUES (?,?,?,?,?)",
                    (report.hostname, when, p.name, p.command_line, reason),
                )
                flagged += cur.rowcount
    return {"status": "ok", "flagged": flagged}


def _rows(sql: str, args: tuple = ()):
    with connect() as conn:
        return conn.execute(sql, args).fetchall()


def _endpoint_list() -> list[dict]:
    cutoff = now() - online_window()
    out = []
    for r in _rows("SELECT * FROM endpoints ORDER BY hostname"):
        if r["forced_online"] is not None:
            online = bool(r["forced_online"])
        else:
            online = datetime.fromisoformat(r["last_seen"]) >= cutoff
        out.append({
            "hostname": r["hostname"], "department": r["department"], "os": r["os"], "online": online,
            "av_enabled": bool(r["av_enabled"]), "missing_critical": r["pending_critical"],
            "pending_security": r["pending_security"], "pending_optional": r["pending_optional"],
            "last_seen": r["last_seen"],
        })
    return out


@app.get("/api/health")
def health():
    """Tiny check that the server is up. Docker uses this too."""
    return {"status": "ok"}


@app.get("/api/summary")
def summary():
    """Numbers for the top tiles: endpoint counts and antivirus coverage."""
    endpoints = _endpoint_list()
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
    """Percent of endpoints with nothing pending, per category, plus machines missing critical patches."""
    endpoints = _endpoint_list()
    total = len(endpoints)

    def pct(key: str) -> int:
        return round(sum(1 for e in endpoints if e[key] == 0) / total * 100) if total else 0

    return {
        "critical": pct("missing_critical"),
        "security": pct("pending_security"),
        "optional": pct("pending_optional"),
        "systems_missing_critical": [e["hostname"] for e in endpoints if e["missing_critical"] > 0],
    }


@app.get("/api/endpoints")
def endpoints():
    """Full list of endpoints."""
    return _endpoint_list()


@app.get("/api/suspicious-processes")
def suspicious_processes():
    """Suspicious process executions from the last 24 hours, newest first."""
    since = iso(now() - timedelta(hours=24))
    rows = _rows("SELECT hostname, time, process, command_line, reason FROM events WHERE time >= ? "
                 "ORDER BY time DESC LIMIT 200", (since,))
    return [dict(r) for r in rows]


@app.get("/api/unauthorized-software")
def unauthorized_software():
    """Packages installed after a host's baseline and not on the allowlist."""
    allowed = extra_allowlist()
    rows = _rows("""SELECT p.name, p.hostname, e.department FROM packages p
                    JOIN endpoints e ON e.hostname = p.hostname
                    WHERE p.baseline = 0 ORDER BY p.first_seen DESC""")
    return [{"software": r["name"], "hostname": r["hostname"], "department": r["department"],
             "severity": "high" if r["name"].lower() in RISKY_SOFTWARE else "medium"}
            for r in rows if r["name"] not in allowed]


# The dashboard page itself. Mounted last so /api/... routes win.
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

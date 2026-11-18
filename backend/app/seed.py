"""Optional demo data: load the made-up company from sample_data.py into the database."""

from datetime import datetime, timedelta, timezone

from . import sample_data
from .db import connect


def seed_sample() -> None:
    now = datetime.now(timezone.utc)
    with connect() as conn:
        for e in sample_data.ENDPOINTS:
            seen = now if e["online"] else now - timedelta(hours=2)
            conn.execute(
                "INSERT OR IGNORE INTO endpoints VALUES (?,?,?,?,?,?,?,?,?)",
                (e["hostname"], e["department"], e["os"], int(e["av_enabled"]), e["missing_critical"],
                 e["missing_critical"], 0 if e["missing_critical"] == 0 else 1,
                 seen.isoformat(timespec="seconds"), int(e["online"])),
            )
        for p in sample_data.SUSPICIOUS_PROCESSES:
            conn.execute(
                "INSERT OR IGNORE INTO events (hostname, time, process, command_line, reason) VALUES (?,?,?,?,?)",
                (p["hostname"], p["time"], p["process"], p["command_line"], p["reason"]),
            )
        for s in sample_data.UNAUTHORIZED_SOFTWARE:
            conn.execute(
                "INSERT OR IGNORE INTO packages VALUES (?,?,0,?)",
                (s["hostname"], s["software"], now.isoformat(timespec="seconds")),
            )

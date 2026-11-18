"""Linux collector: reports this machine's state to the dashboard backend.

Every INTERVAL seconds it sends one check-in (this is also the heartbeat):
OS, pending apt updates, installed packages, and command lines of processes
that started since the last check-in. Uses only the Python standard library.
"""

import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:8000")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
DEPARTMENT = os.environ.get("DEPARTMENT", "Unassigned")
INTERVAL = int(os.environ.get("INTERVAL_SECONDS", "5"))
SCAN_INTERVAL = float(os.environ.get("SCAN_SECONDS", "1"))
APT_UPDATE = os.environ.get("COLLECTOR_APT_UPDATE", "").lower() in ("1", "true", "yes")
MAX_PROCESSES_PER_REPORT = 200
HEALTH_FILE = os.environ.get("HEALTH_FILE", "/tmp/last_checkin")


def hostname() -> str:
    return os.environ.get("COLLECTOR_HOSTNAME") or f"LNX-{DEPARTMENT.upper()}-{socket.gethostname()[:6]}"


def os_name(path: str = "/etc/os-release") -> str:
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Linux"


def parse_apt_simulation(output: str) -> tuple[int, int, int]:
    """Count pending updates from `apt-get -s upgrade` output.

    Returns (critical, security, optional). Updates from a *-security pocket
    count as critical and security; everything else is optional.
    """
    security = other = 0
    for line in output.splitlines():
        if line.startswith("Inst "):
            if re.search(r"-security|/security", line):
                security += 1
            else:
                other += 1
    return security, security, other


def pending_updates() -> tuple[int, int, int]:
    try:
        if APT_UPDATE:
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
        out = subprocess.run(["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=60).stdout
        return parse_apt_simulation(out)
    except (OSError, subprocess.SubprocessError):
        return 0, 0, 0


def installed_packages() -> list[str]:
    try:
        out = subprocess.run(["dpkg-query", "-W", "-f=${Package}\\n"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def read_processes(proc_dir: str = "/proc") -> dict[tuple[str, str], tuple[str, str]]:
    """Return {(pid, start_time): (name, command_line)} for every visible process.

    The start time distinguishes a new process that reused an old PID.
    """
    found = {}
    for pid in os.listdir(proc_dir):
        if not pid.isdigit():
            continue
        try:
            with open(f"{proc_dir}/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
            with open(f"{proc_dir}/{pid}/stat") as f:
                stat = f.read()
        except OSError:
            continue  # process exited while we looked
        if not cmd:
            continue  # kernel threads have no command line
        after_name = stat[stat.rfind(")") + 2:].split()
        start = after_name[19] if len(after_name) > 19 else "0"
        name = os.path.basename(cmd.split(" ", 1)[0])
        found[(pid, start)] = (name, cmd[:2000])
    return found


def av_active(procs) -> bool:
    return any(name in ("clamd", "clamav-daemon") for name, _ in procs.values())


def post(report: dict) -> None:
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/ingest",
        data=json.dumps(report).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    urllib.request.urlopen(req, timeout=15).read()


def main() -> None:
    me = os.getpid()
    seen = set(read_processes())  # processes that existed at startup are not "new"
    pending: list[dict] = []
    last_report = 0.0
    packages: list[str] = []
    updates = (0, 0, 0)
    last_slow = 0.0
    print(f"collector {hostname()} ({DEPARTMENT}) -> {BACKEND_URL}", flush=True)
    while True:
        procs = read_processes()
        for key, (name, cmd) in procs.items():
            if key not in seen and key[0] != str(me):
                seen.add(key)
                pending.append({"time": datetime.now(timezone.utc).isoformat(), "name": name, "command_line": cmd})
        seen &= set(procs)  # forget exited processes so the set stays small

        if time.monotonic() - last_report >= INTERVAL:
            if time.monotonic() - last_slow >= 60 or not packages:  # apt/dpkg are slow; refresh each minute
                packages, updates, last_slow = installed_packages(), pending_updates(), time.monotonic()
            report = {
                "hostname": hostname(), "department": DEPARTMENT, "os": os_name(),
                "av_enabled": av_active(procs),
                "pending_critical": updates[0], "pending_security": updates[1], "pending_optional": updates[2],
                "packages": packages,
                "processes": pending[:MAX_PROCESSES_PER_REPORT],
            }
            try:
                post(report)
                Path(HEALTH_FILE).touch()  # the container healthcheck looks at this file's age
                pending = pending[MAX_PROCESSES_PER_REPORT:]
            except (urllib.error.URLError, OSError) as exc:
                print(f"check-in failed: {exc}", flush=True)  # keep pending events, retry next interval
            last_report = time.monotonic()
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()

# Endpoint Security Dashboard

A self-hosted dashboard that shows the security health of the machines
("endpoints") in a homelab: how many are online, antivirus coverage, patch
compliance, suspicious process executions and unauthorized software.

Linux collector containers (one compose network per department) check in to the
backend every few seconds; the backend stores everything in SQLite.

## Deploy it (single Docker host)

Needs Docker with the Compose plugin on the host (the Ubuntu Server VM or any Linux box).

```bash
git clone <your repo> endpoint-sec-dashboard && cd endpoint-sec-dashboard
scripts/init-env.sh          # creates .env with random secrets, prints the dashboard password ONCE
nano .env                    # set SITE_ADDRESS (and TLS_MODE / BIND_ADDRESS if needed)
docker compose up --build -d
```

Open `https://<SITE_ADDRESS>` and log in as `admin` with the printed password. Three
endpoints (IT, Sales, Finance) appear within seconds.

| Task | Command |
|---|---|
| Start / rebuild | `docker compose up --build -d` |
| Stop (keeps data) | `docker compose down` |
| Stop and DELETE all data | `docker compose down -v` |
| Status / health | `docker compose ps` |
| Logs | `docker compose logs -f backend` (also `caddy`, `endpoint-it` ...) |
| Update (backs up first) | `scripts/update.sh` |
| Backup now | `scripts/backup.sh` (writes `backups/esd-<time>.db.gz`, keeps 14) |
| Restore | `scripts/restore.sh backups/esd-<time>.db.gz` |
| More endpoints | `docker compose up -d --scale endpoint-it=5` (also `-sales`, `-finance`) |
| Attack drill | `bash scripts/drill.sh [endpoint-it]` |

**What protects it**

- Only Caddy is published (ports 80/443). HTTP redirects to HTTPS; the dashboard and
  every `/api/*` route need the login. `POST /api/ingest` is never served to the outside:
  collectors reach the backend directly over the internal Docker networks.
- Collectors authenticate with `AGENT_TOKEN`. The backend refuses to start if it is
  missing, shorter than 24 characters or still the placeholder; compose refuses to start
  without any of the secrets. Rejected tokens are logged with the source address.
- The backend and Caddy run with a read-only filesystem, all Linux capabilities dropped
  (Caddy keeps only the one that lets it bind 80/443) and `no-new-privileges`. The backend
  runs as a non-root user. All containers restart automatically, have health checks and
  rotated logs (3 x 10 MB each). Base images and every Python dependency are pinned.
- Events older than `RETENTION_DAYS` (30) are deleted automatically.
- The endpoint containers stand in for lab machines, so they are deliberately not locked
  down (the drill installs packages as root inside them).

**Certificates:** with `TLS_MODE=internal` Caddy signs with its own private CA, so browsers
warn until you trust it (export the root from the `caddy-data` volume, or just accept the
warning for a homelab). For a public domain pointing at the host with ports 80/443
reachable, set `SITE_ADDRESS=dash.example.com` and `TLS_MODE=you@example.com` for Let's Encrypt.

**Backups on a schedule** (cron, daily at 03:00): `0 3 * * * cd /path/to/endpoint-sec-dashboard && scripts/backup.sh`.
Copy `backups/` off the host too. Rotating secrets: delete `.env`, run `scripts/init-env.sh`,
then `docker compose up -d` (new token is picked up by backend and collectors together).

**Known limits:** one shared agent token for all collectors; no login rate limiting
(keep it on a trusted network or behind a VPN rather than the open internet);
the container-based endpoints give no kernel-level telemetry.

## How the data works

- **Ingest:** collectors `POST /api/ingest` with `Authorization: Bearer <AGENT_TOKEN>`.
  Without the right token the request is rejected (401).
- **Heartbeat:** every check-in updates `last_seen`; an endpoint is offline when it
  has been silent for `ONLINE_SECONDS` (default 90).
- **Suspicious processes:** the collector polls `/proc` each second and sends new
  command lines. `backend/app/rules.py` flags encoded shell, download-and-run,
  `/dev/tcp` reverse shells and `python -c`/`perl -e` one-liners (plus the original
  Windows patterns). Short-lived processes can be missed between polls.
- **Unauthorized software:** packages present at an endpoint's first check-in are its
  baseline. Anything installed later is flagged (high for tools like nmap/netcat).
  `SOFTWARE_ALLOWLIST=htop,vim` exempts names.
- **Patches:** from `apt-get -s upgrade` in each container (security-pocket updates count as
  critical). Slim images have no package lists, so this is 0 unless you set
  `COLLECTOR_APT_UPDATE=true` on a collector. Percent = share of endpoints with nothing pending.
- **Antivirus:** shows "no AV" unless a `clamd` process is running in the container.

## What each file does

```
endpoint-sec-dashboard/
├── docker-compose.yml        # backend + department endpoint containers + networks
├── .env.example              # Settings template (init-env.sh fills in secrets)
├── proxy/Caddyfile           # HTTPS, login, headers
├── scripts/                  # init-env, backup, restore, update, drill
├── collector/
│   ├── Dockerfile            # Collector image
│   ├── collector.py          # Check-in loop: /proc scan, dpkg, apt
│   └── test_collector.py
├── backend/
│   ├── Dockerfile            # Recipe for building the backend container image
│   ├── requirements.txt      # Python packages the app needs
│   ├── requirements-dev.txt  # Extra packages for running tests
│   ├── app/
│   │   ├── main.py           # FastAPI app: the /api/... routes and serving the page
│   │   ├── db.py             # SQLite schema, connection, retention
│   │   ├── backup.py         # Consistent online database backup
│   │   ├── rules.py          # Suspicious-process patterns
│   │   ├── seed.py           # Loads sample data when SAMPLE_DATA=true
│   │   ├── sample_data.py    # Made-up endpoints and events (demo only)
│   │   └── static/
│   │       ├── index.html    # Page layout: the tiles and tables
│   │       ├── style.css     # Colours and layout
│   │       └── app.js        # Calls the API and fills in the page
│   └── tests/
│       ├── conftest.py
│       ├── test_api.py       # API routes on sample data
│       ├── test_ingest.py    # Token, heartbeat, rules, allowlist, patches
│       └── test_deploy.py    # Startup checks, backups, retention, compose/Caddy config
└── README.md
```

The page reloads its data every 10 seconds.

## API routes

| Route | Returns |
|---|---|
| `POST /api/ingest` | Collector check-in (needs the agent token) |
| `GET /api/health` | `{"status": "ok"}` if the server is up |
| `GET /api/summary` | Endpoint counts and antivirus coverage |
| `GET /api/patches` | Patch compliance percentages and machines missing critical patches |
| `GET /api/endpoints` | Every endpoint |
| `GET /api/suspicious-processes` | Flagged process executions, newest first |
| `GET /api/unauthorized-software` | Unapproved installs |

## Run the tests (without Docker)

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest            # backend
python -m pytest ../collector
```

## Roadmap

1. Build the lab (VMware Workstation, Ubuntu Server + Docker, Windows VMs)
2. Simulate the company and scale endpoints with containers
3. Replace sample data with real data from collector agents; add Ollama analysis
4. Attack drills to generate real suspicious events

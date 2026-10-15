# Endpoint Security Dashboard

A self-hosted dashboard that shows the security health of the machines
("endpoints") in a homelab: how many are online, antivirus coverage, patch
compliance, suspicious process executions and unauthorized software.

Right now it runs on **sample data**. Later steps add collector agents on the
lab VMs/containers and a local LLM (Ollama) to explain suspicious events.

## Run it

You need Docker (Docker Desktop on Windows, or Docker Engine on the Ubuntu
Server VM).

```bash
docker compose up --build
```

Then open <http://localhost:8000>. Stop it with `Ctrl+C`
(or `docker compose down` if you started it with `-d`).

| Command | What it does |
|---|---|
| `docker compose up --build` | Builds the image from `backend/Dockerfile`, then starts the container and shows its logs |
| `docker compose up --build -d` | Same, but runs in the background ("detached") |
| `docker compose ps` | Lists running containers and their health |
| `docker compose logs -f` | Follows the logs of a background container |
| `docker compose down` | Stops and removes the containers |

The API has automatic docs at <http://localhost:8000/docs>; try each route there.

## What each file does

```
endpoint-sec-dashboard/
├── docker-compose.yml        # Which containers to run, which ports to open
├── backend/
│   ├── Dockerfile            # Recipe for building the backend container image
│   ├── requirements.txt      # Python packages the app needs
│   ├── requirements-dev.txt  # Extra packages for running tests
│   ├── app/
│   │   ├── main.py           # FastAPI app: the /api/... routes and serving the page
│   │   ├── sample_data.py    # Made-up endpoints and events (replaced by real data later)
│   │   └── static/
│   │       ├── index.html    # Page layout: the tiles and tables
│   │       ├── style.css     # Colours and layout
│   │       └── app.js        # Calls the API and fills in the page
│   └── tests/
│       └── test_api.py       # Automated checks that the API works
└── README.md
```

How a page load works: your browser asks for `/`, FastAPI sends
`index.html`, the page loads `app.js`, and `app.js` calls `/api/summary`,
`/api/patches`, `/api/suspicious-processes` and `/api/unauthorized-software`
to get JSON, which it draws into the page.

## API routes

| Route | Returns |
|---|---|
| `GET /api/health` | `{"status": "ok"}` if the server is up |
| `GET /api/summary` | Endpoint counts and antivirus coverage |
| `GET /api/patches` | Patch compliance percentages and machines missing critical patches |
| `GET /api/endpoints` | Every endpoint |
| `GET /api/suspicious-processes` | Flagged process executions, newest first |
| `GET /api/unauthorized-software` | Unapproved installs |

## Run the tests (optional, without Docker)

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
```

## Roadmap

1. Build the lab (VMware Workstation, Ubuntu Server + Docker, Windows VMs)
2. Simulate the company and scale endpoints with containers
3. Replace sample data with real data from collector agents; add Ollama analysis
4. Attack drills to generate real suspicious events

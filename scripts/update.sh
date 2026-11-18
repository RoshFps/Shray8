#!/usr/bin/env bash
# Updates a running deployment: backup, pull new code (if this is a git checkout),
# rebuild, restart, and wait until everything is healthy.
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/backup.sh
[ -d .git ] && git pull --ff-only
docker compose up -d --build --remove-orphans

echo "Waiting for containers to become healthy..."
for _ in $(seq 1 30); do
  if [ -z "$(docker compose ps --format '{{.Health}}' | grep -E 'starting|unhealthy' || true)" ]; then
    docker compose ps; exit 0
  fi
  sleep 3
done
docker compose ps; echo "Some containers are not healthy yet; check: docker compose logs" >&2; exit 1

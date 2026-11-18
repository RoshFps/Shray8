#!/usr/bin/env bash
# Attack drill: runs harmless suspicious-looking commands inside one endpoint container.
# Usage: scripts/drill.sh [service]      (default: endpoint-it)
# Each command stays alive a few seconds so the collector's /proc scan sees it.
set -euo pipefail
svc="${1:-endpoint-it}"
run() { docker compose exec -T "$svc" sh -c "$1; sleep 6" >/dev/null 2>&1 || true; }

echo "Encoded command..."      ; run "echo ZWNobyBoaQ== | base64 -d | sh"
echo "Scripted one-liner..."   ; run "python3 -c 'import time; time.sleep(5)'"
echo "Reverse-shell pattern (nothing listens; aimed at a dead address)..."
run "bash -c 'true # /dev/tcp/203.0.113.7/4444'"
echo "Unauthorized software (needs internet for apt; shows within ~1 min)..."
docker compose exec -T -u root "$svc" sh -c "apt-get update -qq && apt-get install -y -qq netcat-openbsd" >/dev/null 2>&1 \
  || echo "  apt install failed (offline?) - skipped"
echo "Done. Suspicious Processes on the dashboard should update within ~10s."

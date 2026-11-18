#!/usr/bin/env bash
# Backs up the dashboard database to backups/esd-<timestamp>.db.gz (safe while running).
# Keeps the newest BACKUP_KEEP files (default 14). Run it from cron, e.g.:
#   0 3 * * *  cd /opt/endpoint-sec-dashboard && scripts/backup.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p backups
out="backups/esd-$(date +%Y%m%d-%H%M%S).db.gz"

docker compose exec -T backend python -m app.backup > "$out.partial"
gzip -t "$out.partial"                       # refuse to keep a truncated backup
mv "$out.partial" "$out"
echo "Wrote $out ($(du -h "$out" | cut -f1))"

ls -1t backups/esd-*.db.gz | tail -n +"$(( ${BACKUP_KEEP:-14} + 1 ))" | xargs -r rm --

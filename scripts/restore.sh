#!/usr/bin/env bash
# Replaces the dashboard database with a backup.
# Usage: scripts/restore.sh backups/esd-YYYYMMDD-HHMMSS.db.gz [--yes]
set -euo pipefail
cd "$(dirname "$0")/.."

file="${1:?usage: scripts/restore.sh <backup.db.gz> [--yes]}"
[ -f "$file" ] && gzip -t "$file" || { echo "Not a valid backup: $file" >&2; exit 1; }
if [ "${2:-}" != "--yes" ]; then
  read -r -p "This REPLACES the current database with $file. Type 'yes' to continue: " answer
  [ "$answer" = "yes" ] || { echo "Aborted."; exit 1; }
fi

docker compose stop backend
gunzip -c "$file" | docker compose run --rm -T --no-deps --entrypoint sh backend \
  -c 'rm -f /data/esd.db /data/esd.db-wal /data/esd.db-shm && cat > /data/esd.db'
docker compose up -d
echo "Restored from $file."

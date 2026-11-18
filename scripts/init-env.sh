#!/usr/bin/env bash
# Creates .env with fresh random secrets and prints the dashboard password once.
# Usage: scripts/init-env.sh            (refuses to overwrite an existing .env)
# Needs Docker (the password hash is made with Caddy's own tool).
set -euo pipefail
cd "$(dirname "$0")/.."

[ -e .env ] && { echo ".env already exists; delete it first if you really want new secrets." >&2; exit 1; }

caddy_image="${CADDY_IMAGE:-$(sed -n 's/^ *image: *\(caddy:[^ ]*\).*/\1/p' docker-compose.yml)}"
rand() { python3 -c "import secrets; print(secrets.token_urlsafe($1))" 2>/dev/null || openssl rand -base64 "$1" | tr -d '=+/\n'; }

password="${DASHBOARD_PASSWORD:-$(rand 18)}"
hash="$(docker run --rm "$caddy_image" caddy hash-password --plaintext "$password")"

umask 077
sed -e "s|^AGENT_TOKEN=.*|AGENT_TOKEN=$(rand 32)|" \
    -e "s|^DASHBOARD_PASSWORD_HASH=.*|DASHBOARD_PASSWORD_HASH='$hash'|" .env.example > .env

echo "Created .env (readable only by you)."
echo "Dashboard login:  user = admin   password = $password"
echo "Save the password now; only its hash is stored."

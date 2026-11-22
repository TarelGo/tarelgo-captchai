#!/usr/bin/env bash
# TarelGo CaptchAI installer for a bare Ubuntu 24.04 VPS (no Docker).
#
# Usage:
#   sudo bash deploy/install.sh [postgres|mariadb|memory]
#
# What it does:
#   1. creates a dedicated non-root user tarelgo-captchai
#   2. deploys the project to /opt/tarelgo-captchai (venv inside)
#   3. generates /opt/tarelgo-captchai/.env with fresh secrets
#   4. creates the database schema (postgres / mariadb)
#   5. installs and starts the hardened systemd unit
#
# The service then listens on 127.0.0.1:8008 behind your proxy chain.

set -euo pipefail

APP_HOME=/opt/tarelgo-captchai
SERVICE_USER=tarelgo-captchai
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_KIND="${1:-postgres}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/install.sh [postgres|mariadb|memory]" >&2
  exit 1
fi

echo "==> Creating user ${SERVICE_USER}"
id -u "${SERVICE_USER}" >/dev/null 2>&1 || useradd --system --home "${APP_HOME}" --shell /usr/sbin/nologin "${SERVICE_USER}"

echo "==> Deploying to ${APP_HOME}"
mkdir -p "${APP_HOME}/var"
rsync -a --delete \
  --exclude ".git" --exclude ".venv" --exclude "__pycache__" \
  --exclude "*.egg-info" --exclude ".pytest_cache" --exclude ".ruff_cache" \
  "${SRC_DIR}/" "${APP_HOME}/"

echo "==> Python virtualenv"
python3 -m venv "${APP_HOME}/.venv"
"${APP_HOME}/.venv/bin/pip" install --upgrade pip -q
case "${DB_KIND}" in
  postgres) "${APP_HOME}/.venv/bin/pip" install -q ".[postgres]" ;;
  mariadb)  "${APP_HOME}/.venv/bin/pip" install -q ".[mariadb]" ;;
  memory)   "${APP_HOME}/.venv/bin/pip" install -q "." ;;
  *) echo "Unknown backend: ${DB_KIND} (use postgres|mariadb|memory)" >&2; exit 1 ;;
esac

echo "==> Generating ${APP_HOME}/.env"
if [[ -f "${APP_HOME}/.env" ]]; then
  echo "    .env already exists - keeping it (secrets are preserved)."
else
  SECRET=$(openssl rand -base64 36 | tr -d '\n' | tr '/+' '_-')
  cat > "${APP_HOME}/.env" <<EOF
# TarelGo CaptchAI configuration (TarelGo Development - https://tarelgo.com)
TARELGO_CAPTCHAI_MODE=best_effort
TARELGO_CAPTCHAI_SECRETS=${SECRET}
TARELGO_CAPTCHAI_TOKEN_TTL=120
TARELGO_CAPTCHAI_THRESHOLD=3
TARELGO_CAPTCHAI_BIND_HOST=127.0.0.1
TARELGO_CAPTCHAI_BIND_PORT=8008
TARELGO_CAPTCHAI_TRUSTED_PROXIES=127.0.0.1/32,::1/128
TARELGO_CAPTCHAI_RATELIMIT_AI_TOKEN=5/600
TARELGO_CAPTCHAI_BAN_SECONDS=900
EOF
  case "${DB_KIND}" in
    postgres) echo "TARELGO_CAPTCHAI_DB_DSN=postgresql://tarelgo:CHANGE_ME@127.0.0.1:5432/tarelgo_captchai" >> "${APP_HOME}/.env" ;;
    mariadb)  echo "TARELGO_CAPTCHAI_DB_DSN=mysql://tarelgo:CHANGE_ME@127.0.0.1:3306/tarelgo_captchai" >> "${APP_HOME}/.env" ;;
    memory)   echo "TARELGO_CAPTCHAI_ALLOW_MEMORY=true" >> "${APP_HOME}/.env" ;;
  esac
  chmod 600 "${APP_HOME}/.env"
fi

echo "==> Creating the database schema"
set -a; source "${APP_HOME}/.env"; set +a
"${APP_HOME}/.venv/bin/python" - <<'PY'
import asyncio
from tarelgo_captchai.config import Settings
from tarelgo_captchai.storage import create_storage

settings = Settings()
storage = create_storage(settings.db_dsn, settings.allow_memory)

async def main() -> None:
    await storage.connect(retries=1)
    await storage.ensure_schema()
    await storage.close()
    print("    schema ready")

asyncio.run(main())
PY

echo "==> Installing the systemd unit"
cp "${SRC_DIR}/deploy/tarelgo-captchai.service" /etc/systemd/system/
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_HOME}"
systemctl daemon-reload
systemctl enable --now tarelgo-captchai

echo "==> Done. Check:  systemctl status tarelgo-captchai"
echo "    Probe:      curl -s http://127.0.0.1:8008/healthz"
echo "    Next: put the matching proxy config from deploy/ in front of port 8008."

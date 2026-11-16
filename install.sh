#!/usr/bin/env bash
# Installs NPM Discovery on Debian 12 (run as root from the project directory).
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/npm-discovery
CONF=/etc/npm-discovery
DATA=/var/lib/npm-discovery

apt-get update
apt-get install -y python3 python3-venv python3-pip nmap

id npm-discovery >/dev/null 2>&1 || \
  useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin npm-discovery

mkdir -p "$APP" "$CONF" "$DATA"
rm -rf "$APP/app"
cp -r "$SRC/app" "$APP/app"
cp "$SRC/requirements.txt" "$APP/"
find "$APP/app" -name __pycache__ -prune -exec rm -rf {} +

python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip
"$APP/venv/bin/pip" install -r "$APP/requirements.txt"

if [ ! -f "$CONF/config.env" ]; then
  cp "$SRC/config.env.example" "$CONF/config.env"
  echo ">>> Created $CONF/config.env - edit it before starting."
fi
chown root:npm-discovery "$CONF" "$CONF/config.env"
chmod 750 "$CONF"
chmod 640 "$CONF/config.env"
chown -R npm-discovery:npm-discovery "$DATA"
chown -R root:root "$APP"

cp "$SRC/npm-discovery.service" /etc/systemd/system/npm-discovery.service
systemctl daemon-reload
systemctl enable npm-discovery
if grep -q '^NPM_PASSWORD="changeme"' "$CONF/config.env"; then
  echo "Config still has default values. Edit $CONF/config.env then run:"
  echo "  systemctl restart npm-discovery"
else
  systemctl restart npm-discovery
  echo "Started. Logs: journalctl -u npm-discovery -f"
fi

#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${PREFIX:-/usr/local}
CONFIG_DIR=${UPT_CONFIG_DIR:-${DUM_CONFIG_DIR:-/etc/docker-update-manager}}
STATE_DIR=${UPT_STATE_DIR:-${DUM_STATE_DIR:-/var/lib/docker-update-manager}}
LOG_DIR=${UPT_LOG_DIR:-${DUM_LOG_DIR:-/var/log/docker-update-manager}}
WEB_STATE_DIR=${UPT_WEB_STATE_DIR:-${DUM_WEB_STATE_DIR:-/var/lib/docker-update-manager-web}}
WEB_CONFIG=${UPT_WEB_CONFIG:-/etc/docker-update-manager/web.yml}
case "$WEB_STATE_DIR" in
  /var/lib/docker-update-manager-web|/var/lib/docker-update-manager-web/*) ;;
  *) echo "WEB_STATE_DIR must remain under /var/lib/docker-update-manager-web" >&2; exit 2 ;;
esac
python3 -m venv "$PREFIX/lib/docker-update-manager/venv"
"$PREFIX/lib/docker-update-manager/venv/bin/pip" install "$SCRIPT_DIR"
install -d -m 0755 "$CONFIG_DIR" "$LOG_DIR"
install -d -m 0700 "$STATE_DIR" "$STATE_DIR/backups" "$WEB_STATE_DIR"
if [ ! -e "$CONFIG_DIR/config.yml" ]; then
  install -m 0600 "$SCRIPT_DIR/config/config.example.yml" "$CONFIG_DIR/config.yml"
fi
if [ ! -e "$WEB_CONFIG" ]; then
  install -m 0640 "$SCRIPT_DIR/config/web.example.yml" "$WEB_CONFIG"
fi
# An existing web.yml is operator-owned and never overwritten; report (without
# changing) a session lifetime shorter than the documented 30-day defaults.
"$PREFIX/lib/docker-update-manager/venv/bin/python3" - "$WEB_CONFIG" <<'PY' || true
import sys
from docker_update_manager.config import WebConfig, session_policy_warnings
try:
    for warning in session_policy_warnings(WebConfig(sys.argv[1]).settings):
        print("WARNING: " + warning, file=sys.stderr)
except Exception as exc:
    print(f"WARNING: could not check web session policy in {sys.argv[1]}: {exc}", file=sys.stderr)
PY
ln -sfn "$PREFIX/lib/docker-update-manager/venv/bin/upt" "$PREFIX/bin/upt"
ln -sfn "$PREFIX/lib/docker-update-manager/venv/bin/upt-web" "$PREFIX/bin/upt-web"
ln -sfn "$PREFIX/lib/docker-update-manager/venv/bin/upt-agent" "$PREFIX/bin/upt-agent"
rm -f "$PREFIX/bin/check-updates"
printf 'Installed: %s/bin/upt\n' "$PREFIX"

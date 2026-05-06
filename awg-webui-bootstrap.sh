#!/usr/bin/env bash
set -euo pipefail

ROOTDIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
WEBUI_SRC="$ROOTDIR/webui"
LIB_SRC="$ROOTDIR/lib"
SYSTEMD_SRC="$ROOTDIR/systemd"

APP_DIR=${AWG_WEBUI_APP_DIR:-/opt/awg-uplink/webui}
APP_ROOT=$(dirname "$APP_DIR")
CFG_DIR=${AWG_WEBUI_CFG_DIR:-/etc/awg-uplink-webui}

WEBUI_SERVICE=awg-uplink-webui.service
IFACE_SERVICE=awg-webui-ifaces.service

log() { echo "[awg-webui-bootstrap] $*"; }
die() { echo "[awg-webui-bootstrap] ERROR: $*" >&2; exit 1; }

ensure_env_key() {
  local file=$1 key=$2 value=$3
  if ! rg -q "^${key}=" "$file"; then
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

usage() {
  cat <<EOF
Usage: $0 [--no-start]

Installs AWG Web UI runtime:
  - app files to $APP_DIR
  - iface routing script to /usr/local/sbin/awg-webui-iface-routing-apply.sh
  - systemd units: $WEBUI_SERVICE, $IFACE_SERVICE
  - config dir: $CFG_DIR
  - env file: $CFG_DIR/webui.env
EOF
}

NO_START=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --no-start) NO_START=1 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[[ ${EUID:-0} -eq 0 ]] || die "run as root: sudo $0"
[[ -d "$WEBUI_SRC" ]] || die "missing $WEBUI_SRC"
[[ -f "$LIB_SRC/awg-webui-iface-routing-apply.sh" ]] || die "missing iface script in lib/"
[[ -f "$SYSTEMD_SRC/$WEBUI_SERVICE" ]] || die "missing $SYSTEMD_SRC/$WEBUI_SERVICE"
[[ -f "$SYSTEMD_SRC/$IFACE_SERVICE" ]] || die "missing $SYSTEMD_SRC/$IFACE_SERVICE"

if command -v apt-get >/dev/null 2>&1; then
  log "Installing dependencies (python3, iproute2, netplan.io)..."
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 iproute2 netplan.io >/dev/null
fi

log "Creating directories..."
install -d -m 755 "$APP_DIR"
install -d -m 755 "$APP_ROOT/lib"
install -d -m 755 "$APP_ROOT/systemd"
install -d -m 700 "$CFG_DIR"

log "Installing webui files..."
cp -a "$WEBUI_SRC/." "$APP_DIR/"

log "Installing runtime source files..."
install -m 755 "$LIB_SRC/awg-webui-iface-routing-apply.sh" "$APP_ROOT/lib/awg-webui-iface-routing-apply.sh"
install -m 644 "$SYSTEMD_SRC/$IFACE_SERVICE" "$APP_ROOT/systemd/$IFACE_SERVICE"

log "Installing routing apply script..."
install -m 755 "$LIB_SRC/awg-webui-iface-routing-apply.sh" /usr/local/sbin/awg-webui-iface-routing-apply.sh

log "Installing systemd units..."
install -m 644 "$SYSTEMD_SRC/$WEBUI_SERVICE" "/etc/systemd/system/$WEBUI_SERVICE"
install -m 644 "$SYSTEMD_SRC/$IFACE_SERVICE" "/etc/systemd/system/$IFACE_SERVICE"

if [[ ! -f "$CFG_DIR/webui.env" ]]; then
  log "Creating default $CFG_DIR/webui.env"
  cat >"$CFG_DIR/webui.env" <<'EOF'
AWG_WEBUI_HOST=0.0.0.0
AWG_WEBUI_PORT=8080
AWG_WEBUI_BASE_PATH=/
AWG_WEBUI_NO_AUTH=0
AWG_UI_USER=admin
AWG_UI_PASS=change-me
AWG_WEBUI_CFG_DIR=/etc/awg-uplink-webui
EOF
  chmod 600 "$CFG_DIR/webui.env"
fi

# Backward-compatible defaults for existing configs.
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_HOST" "0.0.0.0"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_PORT" "8080"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_BASE_PATH" "/"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_NO_AUTH" "0"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_CFG_DIR" "/etc/awg-uplink-webui"
chmod 600 "$CFG_DIR/webui.env"

log "Reloading systemd daemon..."
systemctl daemon-reload
systemctl enable "$WEBUI_SERVICE" >/dev/null

if [[ $NO_START -eq 0 ]]; then
  log "Restarting web UI service..."
  systemctl restart "$WEBUI_SERVICE"
  systemctl status --no-pager --lines=3 "$WEBUI_SERVICE" || true
fi

log "Bootstrap completed."


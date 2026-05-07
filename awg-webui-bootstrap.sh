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
AMNEZIA_APT_LIST=/etc/apt/sources.list.d/amnezia-ppa.list
AMNEZIAWG_SRC_CACHE=${AMNEZIAWG_SRC_CACHE:-/var/cache/awg-uplink-amneziawg}
AMNEZIAWG_KERNEL_REPO=${AMNEZIAWG_KERNEL_REPO:-https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git}
AMNEZIAWG_TOOLS_REPO=${AMNEZIAWG_TOOLS_REPO:-https://github.com/amnezia-vpn/amneziawg-tools.git}

log() { echo "[awg-webui-bootstrap] $*"; }
die() { echo "[awg-webui-bootstrap] ERROR: $*" >&2; exit 1; }

awg_quick_present() {
  command -v awg-quick >/dev/null 2>&1
}

add_amnezia_apt_debian() {
  apt-get install -y gnupg2 ca-certificates curl software-properties-common
  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828 2>/dev/null \
    || die "failed to import Amnezia PPA key"
  {
    echo 'deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main'
    echo 'deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main'
  } >"$AMNEZIA_APT_LIST"
}

add_amnezia_apt_ubuntu() {
  apt-get install -y software-properties-common gnupg2 "linux-headers-$(uname -r)" 2>/dev/null \
    || apt-get install -y software-properties-common gnupg2
  add-apt-repository -y ppa:amnezia/ppa
}

ensure_amneziawg() {
  if awg_quick_present; then
    log "awg-quick already present."
    return 0
  fi
  [[ -f /etc/os-release ]] || die "missing /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y ca-certificates curl
  case "${ID:-}" in
    ubuntu|pop) add_amnezia_apt_ubuntu ;;
    debian|devuan|raspbian) add_amnezia_apt_debian ;;
    *) die "unsupported distro for auto amneziawg install: ${ID:-unknown}" ;;
  esac
  apt-get update -qq
  if apt-get install -y amneziawg; then
    awg_quick_present || die "amneziawg installed but awg-quick not found"
    log "amneziawg installed from apt."
    return 0
  fi
  log "amneziawg apt install failed, fallback to source build..."
  ensure_amneziawg_from_source
}

ensure_amneziawg_from_source() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y ca-certificates git dkms build-essential pkg-config \
    libmnl-dev libelf-dev libssl-dev debhelper dh-python iproute2

  mkdir -p "$AMNEZIAWG_SRC_CACHE"
  local kroot="$AMNEZIAWG_SRC_CACHE/amneziawg-linux-kernel-module"
  local troot="$AMNEZIAWG_SRC_CACHE/amneziawg-tools"

  if [[ -d "$kroot/.git" ]]; then
    git -C "$kroot" fetch --all --tags --prune
    git -C "$kroot" reset --hard origin/HEAD
  else
    rm -rf "$kroot"
    git clone "$AMNEZIAWG_KERNEL_REPO" "$kroot"
  fi
  if [[ -d "$troot/.git" ]]; then
    git -C "$troot" fetch --all --tags --prune
    git -C "$troot" reset --hard origin/HEAD
  else
    rm -rf "$troot"
    git clone "$AMNEZIAWG_TOOLS_REPO" "$troot"
  fi

  local dver
  dver=$(sed -n 's/^PACKAGE_VERSION="\([^"]*\)".*/\1/p' "$kroot/dkms.conf" | head -1)
  [[ -n "$dver" ]] || die "cannot read PACKAGE_VERSION from $kroot/dkms.conf"

  dkms remove -m amneziawg -v "$dver" --all --force 2>/dev/null || true
  rm -rf /usr/src/amneziawg-* 2>/dev/null || true

  cp -a "$kroot" "/usr/src/amneziawg-$dver"
  dkms add -m amneziawg -v "$dver" || true
  dkms build -m amneziawg -v "$dver" || die "dkms build failed"
  dkms install -m amneziawg -v "$dver" || die "dkms install failed"

  make -C "$troot/src" tools
  install -m 755 "$troot/src/awg" /usr/bin/awg
  install -m 755 "$troot/src/awg-quick/linux.bash" /usr/bin/awg-quick

  modprobe amneziawg 2>/dev/null || true
  awg_quick_present || die "source build completed but awg-quick missing"
  log "amneziawg installed from source fallback."
}

ensure_env_key() {
  local file=$1 key=$2 value=$3
  if ! awk -F= -v k="$key" '$1==k {found=1} END {exit found?0:1}' "$file"; then
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

dedupe_env_file() {
  local file=$1 tmp
  tmp="${file}.tmp.$$"
  awk '
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*$/ { print; next }
    {
      split($0, a, "=")
      k=a[1]
      if (!(k in seen)) {
        seen[k]=1
        print
      }
    }
  ' "$file" >"$tmp"
  mv -f -- "$tmp" "$file"
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
[[ -f "$LIB_SRC/awg-uplink-geo-ip-refresh.py" ]] || die "missing geo ip refresh script in lib/"
[[ -f "$LIB_SRC/awg-uplink-geo-domain-refresh.py" ]] || die "missing geo domain refresh script in lib/"
[[ -f "$SYSTEMD_SRC/$WEBUI_SERVICE" ]] || die "missing $SYSTEMD_SRC/$WEBUI_SERVICE"
[[ -f "$SYSTEMD_SRC/$IFACE_SERVICE" ]] || die "missing $SYSTEMD_SRC/$IFACE_SERVICE"
[[ -f "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.service" ]] || die "missing geo ip refresh unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.timer" ]] || die "missing geo ip refresh timer in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.service" ]] || die "missing geo domain refresh unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.timer" ]] || die "missing geo domain refresh timer in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.service" ]] || die "missing geo domain nft-rotate unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.timer" ]] || die "missing geo domain nft-rotate timer in systemd/"

if command -v apt-get >/dev/null 2>&1; then
  log "Installing dependencies (python3, iproute2, netplan.io, nftables)..."
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 iproute2 netplan.io nftables >/dev/null
fi

ensure_amneziawg

log "Creating directories..."
install -d -m 755 "$APP_DIR"
install -d -m 755 "$APP_ROOT/lib"
install -d -m 755 "$APP_ROOT/systemd"
install -d -m 700 "$CFG_DIR"

log "Installing webui files..."
cp -a "$WEBUI_SRC/." "$APP_DIR/"

log "Installing runtime source files..."
install -m 755 "$LIB_SRC/awg-webui-iface-routing-apply.sh" "$APP_ROOT/lib/awg-webui-iface-routing-apply.sh"
install -m 755 "$LIB_SRC/awg-uplink-geo-ip-refresh.py" "$APP_ROOT/lib/awg-uplink-geo-ip-refresh.py"
install -m 755 "$LIB_SRC/awg-uplink-geo-domain-refresh.py" "$APP_ROOT/lib/awg-uplink-geo-domain-refresh.py"
install -m 644 "$SYSTEMD_SRC/$IFACE_SERVICE" "$APP_ROOT/systemd/$IFACE_SERVICE"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.service" "$APP_ROOT/systemd/awg-uplink-geo-ip-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.timer" "$APP_ROOT/systemd/awg-uplink-geo-ip-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.service" "$APP_ROOT/systemd/awg-uplink-geo-domain-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.timer" "$APP_ROOT/systemd/awg-uplink-geo-domain-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.service" "$APP_ROOT/systemd/awg-uplink-geo-domain-nft-rotate.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.timer" "$APP_ROOT/systemd/awg-uplink-geo-domain-nft-rotate.timer"

log "Installing routing apply script..."
install -m 755 "$LIB_SRC/awg-webui-iface-routing-apply.sh" /usr/local/sbin/awg-webui-iface-routing-apply.sh
install -m 755 "$LIB_SRC/awg-uplink-geo-ip-refresh.py" /usr/local/sbin/awg-uplink-geo-ip-refresh.py
install -m 755 "$LIB_SRC/awg-uplink-geo-domain-refresh.py" /usr/local/sbin/awg-uplink-geo-domain-refresh.py

log "Installing systemd units..."
install -m 644 "$SYSTEMD_SRC/$WEBUI_SERVICE" "/etc/systemd/system/$WEBUI_SERVICE"
install -m 644 "$SYSTEMD_SRC/$IFACE_SERVICE" "/etc/systemd/system/$IFACE_SERVICE"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.service" "/etc/systemd/system/awg-uplink-geo-ip-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.timer" "/etc/systemd/system/awg-uplink-geo-ip-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.service" "/etc/systemd/system/awg-uplink-geo-domain-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.timer" "/etc/systemd/system/awg-uplink-geo-domain-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.service" "/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.timer" "/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.timer"

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

if [[ ! -f "$CFG_DIR/georouting.json" ]]; then
  log "Creating default $CFG_DIR/georouting.json"
  cat >"$CFG_DIR/georouting.json" <<'EOF'
{
  "target": "tunnel",
  "ipMode": false,
  "domainMode": false,
  "readyLinks": {
    "ip": [
      {
        "url": "https://antifilter.download/list/allyouneed.lst",
        "status": "ожидает проверки",
        "enabled": true,
        "protected": true
      }
    ],
    "domain": [
      {
        "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
        "status": "ожидает проверки",
        "enabled": true,
        "protected": true
      }
    ]
  },
  "lists": {
    "ipInclude": "",
    "ipExclude": "",
    "domainInclude": "",
    "domainExclude": ""
  }
}
EOF
  chmod 600 "$CFG_DIR/georouting.json"
fi

# Backward-compatible defaults for existing configs.
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_HOST" "0.0.0.0"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_PORT" "8080"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_BASE_PATH" "/"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_NO_AUTH" "0"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_CFG_DIR" "/etc/awg-uplink-webui"
dedupe_env_file "$CFG_DIR/webui.env"
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


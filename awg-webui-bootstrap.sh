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
[[ -f "$LIB_SRC/awg-uplink-dns-refresh.py" ]] || die "missing dns refresh script in lib/"
[[ -f "$LIB_SRC/awg-uplink-amnezia-dns-watch.py" ]] || die "missing amnezia dns watch script in lib/"
[[ -f "$LIB_SRC/awg-uplink-dns-transport-lock.py" ]] || die "missing dns transport lock script in lib/"
[[ -f "$LIB_SRC/awg-uplink-firewall-apply.py" ]] || die "missing firewall apply script in lib/"
[[ -f "$SYSTEMD_SRC/awg-uplink-dns-refresh.service" ]] || die "missing dns refresh unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-dns-refresh.timer" ]] || die "missing dns refresh timer in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-amnezia-dns-watch.service" ]] || die "missing amnezia dns watch unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-dns-transport-lock.service" ]] || die "missing dns transport lock unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-firewall.service" ]] || die "missing firewall unit in systemd/"
[[ -f "$SYSTEMD_SRC/dnscrypt-proxy.service" ]] || die "missing dnscrypt-proxy systemd unit (awg-uplink override)"

if command -v apt-get >/dev/null 2>&1; then
  log "Installing dependencies (python3, iproute2, netplan.io, nftables, dnsmasq, dnscrypt-proxy, curl, minisign, openssl)..."
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 iproute2 netplan.io nftables dnsmasq dnscrypt-proxy curl minisign openssl >/dev/null
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
install -m 755 "$LIB_SRC/awg-uplink-dns-refresh.py" "$APP_ROOT/lib/awg-uplink-dns-refresh.py"
install -m 755 "$LIB_SRC/awg-uplink-amnezia-dns-watch.py" "$APP_ROOT/lib/awg-uplink-amnezia-dns-watch.py"
install -m 755 "$LIB_SRC/awg-uplink-dns-transport-lock.py" "$APP_ROOT/lib/awg-uplink-dns-transport-lock.py"
install -m 755 "$LIB_SRC/awg-uplink-firewall-apply.py" "$APP_ROOT/lib/awg-uplink-firewall-apply.py"
install -m 644 "$SYSTEMD_SRC/awg-uplink-dns-refresh.service" "$APP_ROOT/systemd/awg-uplink-dns-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-dns-refresh.timer" "$APP_ROOT/systemd/awg-uplink-dns-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-amnezia-dns-watch.service" "$APP_ROOT/systemd/awg-uplink-amnezia-dns-watch.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-dns-transport-lock.service" "$APP_ROOT/systemd/awg-uplink-dns-transport-lock.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-firewall.service" "$APP_ROOT/systemd/awg-uplink-firewall.service"
install -m 644 "$SYSTEMD_SRC/dnscrypt-proxy.service" "$APP_ROOT/systemd/dnscrypt-proxy.service"

log "Installing routing apply script..."
install -m 755 "$LIB_SRC/awg-webui-iface-routing-apply.sh" /usr/local/sbin/awg-webui-iface-routing-apply.sh
install -m 755 "$LIB_SRC/awg-uplink-geo-ip-refresh.py" /usr/local/sbin/awg-uplink-geo-ip-refresh.py
install -m 755 "$LIB_SRC/awg-uplink-geo-domain-refresh.py" /usr/local/sbin/awg-uplink-geo-domain-refresh.py
install -m 755 "$LIB_SRC/awg-uplink-dns-refresh.py" /usr/local/sbin/awg-uplink-dns-refresh.py
install -m 755 "$LIB_SRC/awg-uplink-amnezia-dns-watch.py" /usr/local/sbin/awg-uplink-amnezia-dns-watch.py
install -m 755 "$LIB_SRC/awg-uplink-dns-transport-lock.py" /usr/local/sbin/awg-uplink-dns-transport-lock.py
install -m 755 "$LIB_SRC/awg-uplink-firewall-apply.py" /usr/local/sbin/awg-uplink-firewall-apply.py

log "Installing systemd units..."
install -m 644 "$SYSTEMD_SRC/$WEBUI_SERVICE" "/etc/systemd/system/$WEBUI_SERVICE"
install -m 644 "$SYSTEMD_SRC/$IFACE_SERVICE" "/etc/systemd/system/$IFACE_SERVICE"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.service" "/etc/systemd/system/awg-uplink-geo-ip-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-ip-refresh.timer" "/etc/systemd/system/awg-uplink-geo-ip-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.service" "/etc/systemd/system/awg-uplink-geo-domain-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-refresh.timer" "/etc/systemd/system/awg-uplink-geo-domain-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.service" "/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-geo-domain-nft-rotate.timer" "/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-dns-refresh.service" "/etc/systemd/system/awg-uplink-dns-refresh.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-dns-refresh.timer" "/etc/systemd/system/awg-uplink-dns-refresh.timer"
install -m 644 "$SYSTEMD_SRC/awg-uplink-amnezia-dns-watch.service" "/etc/systemd/system/awg-uplink-amnezia-dns-watch.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-dns-transport-lock.service" "/etc/systemd/system/awg-uplink-dns-transport-lock.service"
install -m 644 "$SYSTEMD_SRC/awg-uplink-firewall.service" "/etc/systemd/system/awg-uplink-firewall.service"
install -m 644 "$SYSTEMD_SRC/dnscrypt-proxy.service" "/etc/systemd/system/dnscrypt-proxy.service"

systemctl disable dnscrypt-proxy.socket >/dev/null 2>&1 || true
systemctl stop dnscrypt-proxy.socket >/dev/null 2>&1 || true
rm -f /etc/systemd/system/dnscrypt-proxy.socket.d/awg-uplink.conf

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

if [[ ! -f "$CFG_DIR/dns.json" ]]; then
  log "Creating default $CFG_DIR/dns.json"
  cat >"$CFG_DIR/dns.json" <<'EOF'
{
  "upstream_servers": ["77.88.8.8", "77.88.8.1"],
  "dnscrypt_server_names": ["cloudflare", "google"],
  "domains_list_updated_at": null,
  "amnezia_dns_watch_enabled": true,
  "amnezia_dns_container": "amnezia-dns",
  "amnezia_dns_network": "amnezia-dns-net",
  "amnezia_dns_forward_ip": "",
  "dns_transport_lock_enabled": false
}
EOF
  chmod 600 "$CFG_DIR/dns.json"
fi

log "Configuring local DNS (systemd-resolved stub off, dnsmasq base, caches)..."
install -d -m 755 /var/cache/dnscrypt-proxy
install -d -m 755 /var/lib/awg-uplink/geo-domain
if id dnscrypt-proxy &>/dev/null; then
  chown dnscrypt-proxy:dnscrypt-proxy /var/cache/dnscrypt-proxy 2>/dev/null || true
fi
install -d -m 755 /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/awg-uplink-dns.conf <<'EOF'
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
EOF
install -d -m 755 /var/lib/awg-uplink/dnsmasq-package-snippets
if [[ -f /etc/dnsmasq.d/ubuntu-fan ]]; then
  mv /etc/dnsmasq.d/ubuntu-fan /var/lib/awg-uplink/dnsmasq-package-snippets/ubuntu-fan.bak
fi
rm -f /etc/dnsmasq.d/ubuntu-fan.awg-disabled /etc/dnsmasq.d/awg-uplink-base.conf
cat >/etc/dnsmasq.d/zzz-awg-uplink-base.conf <<'EOF'
# awg-uplink: DNS на всех интерфейсах. Сниппет ubuntu-fan отключаем: там bind-interfaces, он конфликтует с bind-dynamic и listen-address.
except-interface=fan-*
bind-dynamic
cache-size=10000
EOF
if systemctl is-active --quiet systemd-resolved 2>/dev/null || systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
  systemctl restart systemd-resolved || true
  if [[ -f /run/systemd/resolve/resolv.conf ]]; then
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  fi
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
systemctl enable dnsmasq.service >/dev/null 2>&1 || true
systemctl enable dnscrypt-proxy.service >/dev/null 2>&1 || true
systemctl enable awg-uplink-dns-refresh.timer >/dev/null 2>&1 || true
systemctl enable awg-uplink-amnezia-dns-watch.service >/dev/null 2>&1 || true
systemctl enable awg-uplink-firewall.service >/dev/null 2>&1 || true
systemctl enable awg-uplink-dns-transport-lock.service >/dev/null 2>&1 || true
systemctl enable awg-uplink-geo-domain-nft-rotate.timer >/dev/null 2>&1 || true
systemctl start awg-uplink-geo-domain-nft-rotate.timer >/dev/null 2>&1 || true

log "Generating dnsmasq/dnscrypt configs (awg-uplink-dns-refresh)..."
AWG_WEBUI_CFG_DIR="$CFG_DIR" python3 /usr/local/sbin/awg-uplink-dns-refresh.py || log "warning: initial dns-refresh failed (check logs)"

systemctl start awg-uplink-dns-refresh.timer >/dev/null 2>&1 || true
systemctl start awg-uplink-amnezia-dns-watch.service >/dev/null 2>&1 || true
systemctl start awg-uplink-firewall.service >/dev/null 2>&1 || true
systemctl restart awg-uplink-dns-transport-lock.service >/dev/null 2>&1 || true

if [[ $NO_START -eq 0 ]]; then
  log "Restarting web UI service..."
  systemctl restart "$WEBUI_SERVICE"
  systemctl status --no-pager --lines=3 "$WEBUI_SERVICE" || true
fi

log "Bootstrap completed."


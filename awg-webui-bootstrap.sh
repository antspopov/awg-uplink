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

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_CYAN=""
fi

log() { echo "${C_BLUE}[awg-webui-bootstrap]${C_RESET} $*"; }
die() { echo "${C_RED}[awg-webui-bootstrap] ERROR:${C_RESET} $*" >&2; exit 1; }

# ubuntu-fan (и аналоги) подключают bind-interfaces; наш zzz-awg-uplink-base.conf задаёт bind-dynamic → dnsmasq падает.
dnsmasq_quarantine_bind_interfaces_snippets() {
  local quarantine=/var/lib/awg-uplink/dnsmasq-package-snippets
  install -d -m 755 "$quarantine"
  local f
  for f in /etc/dnsmasq.d/ubuntu-fan; do
    [[ -f "$f" ]] || continue
    log "Отключаю $(basename "$f"): bind-interfaces несовместим с bind-dynamic в awg-uplink (переношу в $quarantine)."
    mv -f -- "$f" "$quarantine/$(basename "$f").awg-disabled"
  done
  command -v dpkg-divert >/dev/null 2>&1 || return 0
  if ! dpkg-divert --list | grep -Fq 'dnsmasq.d/ubuntu-fan'; then
    dpkg-divert --quiet --local --no-rename \
      --divert "$quarantine/ubuntu-fan.diverted" \
      --add /etc/dnsmasq.d/ubuntu-fan 2>/dev/null || true
  fi
}

WEBUI_DOMAIN=""
WEBUI_USER="admin"
WEBUI_PASS=""
USE_LETSENCRYPT=0
SELF_SIGNED_CERT_DIR="/etc/ssl/awg-uplink-webui"
NGINX_SITE_PATH="/etc/nginx/sites-available/awg-uplink-webui.conf"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/awg-uplink-webui.conf"
WEBUI_MASK_PORT="${AWG_UI_MASK_PORT:-5000}"
EXISTING_LE_DOMAIN=""
LE_RENEW_SELECTED=1

generate_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24
    return
  fi
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24
}

set_env_key() {
  local file=$1 key=$2 value=$3 tmp
  tmp="${file}.tmp.$$"
  awk -F= -v k="$key" -v v="$value" '
    BEGIN { updated=0 }
    $0 ~ "^[[:space:]]*" k "=" {
      print k "=" v
      updated=1
      next
    }
    { print }
    END {
      if (!updated) print k "=" v
    }
  ' "$file" >"$tmp"
  mv -f -- "$tmp" "$file"
}

collect_interface_urls() {
  local urls=()
  while IFS=' ' read -r iface ip; do
    [[ -n "$iface" && -n "$ip" ]] || continue
    [[ "$iface" == lo* ]] && continue
    [[ "$iface" == docker* ]] && continue
    [[ "$iface" == amn* ]] && continue
    [[ "$iface" == awg* ]] && continue
    [[ "$iface" == veth* ]] && continue
    urls+=("https://$ip:${WEBUI_MASK_PORT}")
  done < <(ip -o -4 addr show scope global | awk '{split($4,a,"/"); print $2, a[1]}')
  if [[ ${#urls[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\n' "${urls[@]}" | sort -u
}

prompt_install_profile() {
  local choice
  cat <<'EOF'

Выберите профиль HTTPS для Web UI и MaskingTLS MTProto:
  1) Реальный домен + Let's Encrypt (рекомендуется)
  2) Подставной (fake) домен + самоподписанный сертификат

Пояснения:
  — Вариант 1: домен должен указывать на этот сервер; для выпуска Let's Encrypt порты 80 и 443 должны быть доступны из интернета.
  — Вариант 2: в сертификате может быть любое имя для SNI — например, вымышленный хост (в т.ч. «свой» несуществующий) или публичное имя чужого сайта (например, example.com, wb.ru); браузер покажет предупреждение о недоверенном сертификате.
EOF
  while true; do
    read -r -p "Введите 1 или 2 [1]: " choice
    choice=${choice:-1}
    case "$choice" in
      1) USE_LETSENCRYPT=1; return 0 ;;
      2) USE_LETSENCRYPT=0; return 0 ;;
      *) echo "Неверный выбор. Введите 1 или 2." ;;
    esac
  done
}

prompt_webui_settings() {
  local prompt_domain prompt_user prompt_pass default_domain reuse_choice
  if [[ $USE_LETSENCRYPT -eq 1 ]]; then
    EXISTING_LE_DOMAIN=$(detect_existing_letsencrypt_domain)
    default_domain=${EXISTING_LE_DOMAIN:-}
    prompt_domain="Введите ваш домен для Let's Encrypt"
    if [[ -n "$default_domain" ]]; then
      prompt_domain+=" [$default_domain]"
    fi
    prompt_domain+=": "
  else
    default_domain="wb.ru"
    prompt_domain="Введите домен для самоподписанного сертификата (SNI) [wb.ru]: "
  fi

  while true; do
    read -r -p "$prompt_domain" WEBUI_DOMAIN
    WEBUI_DOMAIN=${WEBUI_DOMAIN// /}
    if [[ -z "$WEBUI_DOMAIN" && -n "$default_domain" ]]; then
      WEBUI_DOMAIN="$default_domain"
    fi
    [[ -n "$WEBUI_DOMAIN" ]] && break
    echo "Домен не может быть пустым."
  done

  if [[ $USE_LETSENCRYPT -eq 1 && -n "$EXISTING_LE_DOMAIN" && "$WEBUI_DOMAIN" == "$EXISTING_LE_DOMAIN" ]]; then
    while true; do
      read -r -p "Найден существующий сертификат для $EXISTING_LE_DOMAIN. Обновить/перевыпустить сейчас? [y/N]: " reuse_choice
      reuse_choice=${reuse_choice:-N}
      case "${reuse_choice,,}" in
        y|yes) LE_RENEW_SELECTED=1; break ;;
        n|no) LE_RENEW_SELECTED=0; break ;;
        *) echo "Введите y или n." ;;
      esac
    done
  fi

  read -r -p "Логин для Web UI [admin]: " prompt_user
  WEBUI_USER=${prompt_user:-admin}

  read -r -s -p "Пароль для Web UI (Enter = сгенерировать): " prompt_pass
  echo
  if [[ -n "$prompt_pass" ]]; then
    WEBUI_PASS="$prompt_pass"
  else
    WEBUI_PASS=$(generate_password)
    echo "Сгенерирован пароль: $WEBUI_PASS"
  fi
}

detect_existing_letsencrypt_domain() {
  local cert_dir domain
  cert_dir="/etc/letsencrypt/live"
  [[ -d "$cert_dir" ]] || return 0
  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    [[ "$domain" == "README" ]] && continue
    if [[ -f "$cert_dir/$domain/fullchain.pem" && -f "$cert_dir/$domain/privkey.pem" ]]; then
      echo "$domain"
      return 0
    fi
  done < <(ls -1 "$cert_dir" 2>/dev/null || true)
}

write_nginx_config() {
  local cert_path=$1
  local key_path=$2
  install -d -m 755 /var/www/certbot
  cat >"$NGINX_SITE_PATH" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $WEBUI_DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host:${WEBUI_MASK_PORT}\$request_uri;
    }
}

server {
    listen ${WEBUI_MASK_PORT} ssl;
    listen [::]:${WEBUI_MASK_PORT} ssl;
    server_name $WEBUI_DOMAIN;

    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        send_timeout 300s;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
  ln -sf "$NGINX_SITE_PATH" "$NGINX_SITE_LINK"
  rm -f /etc/nginx/sites-enabled/default
}

setup_self_signed_cert() {
  local cert_path="$SELF_SIGNED_CERT_DIR/fullchain.pem"
  local key_path="$SELF_SIGNED_CERT_DIR/privkey.pem"
  install -d -m 700 "$SELF_SIGNED_CERT_DIR"
  log "Generating self-signed certificate for $WEBUI_DOMAIN..."
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$key_path" \
    -out "$cert_path" \
    -days 825 \
    -subj "/CN=$WEBUI_DOMAIN" >/dev/null 2>&1
  chmod 600 "$key_path"
  chmod 644 "$cert_path"
  write_nginx_config "$cert_path" "$key_path"
}

setup_letsencrypt_cert() {
  local cert_path="/etc/letsencrypt/live/$WEBUI_DOMAIN/fullchain.pem"
  local key_path="/etc/letsencrypt/live/$WEBUI_DOMAIN/privkey.pem"
  install -d -m 755 /var/www/certbot

  cat >"$NGINX_SITE_PATH" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $WEBUI_DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 200 "ACME challenge endpoint ready\n";
        add_header Content-Type text/plain;
    }
}
EOF
  ln -sf "$NGINX_SITE_PATH" "$NGINX_SITE_LINK"
  rm -f /etc/nginx/sites-enabled/default

  nginx -t >/dev/null
  systemctl restart nginx

  if [[ ! -f "$cert_path" || ! -f "$key_path" || $LE_RENEW_SELECTED -eq 1 ]]; then
    log "Requesting Let's Encrypt certificate for $WEBUI_DOMAIN..."
    certbot certonly --webroot -w /var/www/certbot -d "$WEBUI_DOMAIN" \
      --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring
  else
    log "Using existing Let's Encrypt certificate for $WEBUI_DOMAIN (renew skipped by user)."
  fi

  [[ -f "$cert_path" && -f "$key_path" ]] || die "Let's Encrypt certificate files not found after certbot run"
  systemctl enable certbot.timer >/dev/null 2>&1 || true
  systemctl start certbot.timer >/dev/null 2>&1 || true
  write_nginx_config "$cert_path" "$key_path"
}

configure_nginx_reverse_proxy() {
  systemctl enable nginx >/dev/null 2>&1 || true
  if [[ $USE_LETSENCRYPT -eq 1 ]]; then
    setup_letsencrypt_cert
  else
    setup_self_signed_cert
  fi
  nginx -t >/dev/null || die "nginx configuration test failed"
  systemctl restart nginx
}

print_final_summary() {
  local iface_url
  echo
  echo "${C_CYAN}${C_BOLD}================ AWG Web UI Setup Summary ================${C_RESET}"
  echo "${C_YELLOW}HTTPS mode:${C_RESET} $( [[ $USE_LETSENCRYPT -eq 1 ]] && echo "Let's Encrypt" || echo "Self-signed certificate" )"
  if [[ $USE_LETSENCRYPT -eq 1 ]]; then
    echo "${C_YELLOW}${C_BOLD}Primary URL:${C_RESET} ${C_GREEN}${C_BOLD}https://$WEBUI_DOMAIN:${WEBUI_MASK_PORT}${C_RESET}"
  fi
  echo "${C_YELLOW}${C_BOLD}Login:${C_RESET} ${C_CYAN}${C_BOLD}$WEBUI_USER${C_RESET}"
  echo "${C_YELLOW}${C_BOLD}Password:${C_RESET} ${C_GREEN}${C_BOLD}$WEBUI_PASS${C_RESET}"
  echo
  echo "${C_YELLOW}Interface URLs:${C_RESET}"
  while IFS= read -r iface_url; do
    echo "  - ${C_GREEN}$iface_url${C_RESET}"
  done < <(collect_interface_urls || true)
  echo "${C_CYAN}${C_BOLD}==========================================================${C_RESET}"
}

awg_quick_present() {
  command -v awg-quick >/dev/null 2>&1
}

# Не полагаемся на dpkg/DKMS в одиночку: в dkms status бывает «added/built» без модуля для текущего ядра,
# а awg-quick может остаться от amneziawg-tools. «Готово» только если утилита есть и ядро видит модуль.
amneziawg_stack_ready() {
  awg_quick_present || return 1
  modprobe -n amneziawg &>/dev/null || return 1
  return 0
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

# После apt install метапакет amneziawg не гарантирует, что DKMS уже собрал .ko под текущее ядро
# (типично: нет linux-headers на момент postinst). Без модуля «awg-quick up» падает с Unknown device type.
ensure_amneziawg_kmod_after_apt() {
  if modprobe -n amneziawg &>/dev/null; then
    return 0
  fi
  local hdr="linux-headers-$(uname -r)"
  log "модуль amneziawg для ядра $(uname -r) не в дереве — догонка DKMS (нужны ${hdr})"
  if ! dpkg-query -W -f='${Status}' "$hdr" 2>/dev/null | grep -q 'install ok installed'; then
    apt-get install -y "$hdr" || log "warning: не удалось установить ${hdr}"
  fi
  if command -v dkms >/dev/null 2>&1; then
    dkms autoinstall || true
  fi
  depmod -a 2>/dev/null || true
  if modprobe -n amneziawg &>/dev/null; then
    return 0
  fi
  log "DKMS autoinstall не помог — пробую переустановить amneziawg-dkms"
  apt-get install --reinstall -y amneziawg-dkms 2>/dev/null || true
  if command -v dkms >/dev/null 2>&1; then
    dkms autoinstall || true
  fi
  depmod -a 2>/dev/null || true
  modprobe -n amneziawg &>/dev/null
}

ensure_amneziawg() {
  if amneziawg_stack_ready; then
    log "AmneziaWG (awg-quick и модуль/DKMS) уже в порядке — шаг пропускается."
    return 0
  fi
  if awg_quick_present; then
    log "awg-quick в PATH, но стек AmneziaWG неполный — доустановка через apt/источник…"
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
    ensure_amneziawg_kmod_after_apt || die "amneziawg из apt установлен, но модуль ядра недоступен для $(uname -r) (проверьте dkms status, /var/lib/dkms/amneziawg/*/build/make.log; после смены ядра может понадобиться reboot)"
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
Usage: $0 [--no-start] [--update-files-only [--install-deps]] [--uninstall]

Installs AWG Web UI runtime:
  - app files to $APP_DIR
  - iface routing script to /usr/local/sbin/awg-webui-iface-routing-apply.sh
  - systemd units: $WEBUI_SERVICE, $IFACE_SERVICE
  - config dir: $CFG_DIR
  - env file: $CFG_DIR/webui.env

  --uninstall   Полное удаление того, что ставит этот bootstrap (юниты, конфиги, nginx, пакеты apt,
                amneziawg). См. lib/uninstall-awg-webui-bootstrap.sh.

  --update-files-only --install-deps   Вместе с копированием файлов: apt-get install зависимостей и ensure_amneziawg
                (без смены webui.env, nginx и сертификатов).

EOF
}

NO_START=0
UPDATE_FILES_ONLY=0
INSTALL_DEPS_ON_UPDATE=0
UNINSTALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --no-start) NO_START=1 ;;
    --update-files-only) UPDATE_FILES_ONLY=1 ;;
    --install-deps) INSTALL_DEPS_ON_UPDATE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[[ ${EUID:-0} -eq 0 ]] || die "run as root: sudo $0"
if [[ $INSTALL_DEPS_ON_UPDATE -eq 1 && $UPDATE_FILES_ONLY -ne 1 ]]; then
  die "--install-deps requires --update-files-only"
fi
if [[ $UNINSTALL -eq 1 ]]; then
  if [[ $UPDATE_FILES_ONLY -eq 1 || $NO_START -eq 1 ]]; then
    die "--uninstall cannot be combined with --update-files-only or --no-start"
  fi
  exec bash "$ROOTDIR/lib/uninstall-awg-webui-bootstrap.sh"
fi
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
[[ -f "$LIB_SRC/awg-mtproto-install.sh" ]] || die "missing mtproto install script in lib/"
[[ -f "$SYSTEMD_SRC/awg-uplink-dns-refresh.service" ]] || die "missing dns refresh unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-dns-refresh.timer" ]] || die "missing dns refresh timer in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-amnezia-dns-watch.service" ]] || die "missing amnezia dns watch unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-dns-transport-lock.service" ]] || die "missing dns transport lock unit in systemd/"
[[ -f "$SYSTEMD_SRC/awg-uplink-firewall.service" ]] || die "missing firewall unit in systemd/"
[[ -f "$SYSTEMD_SRC/dnscrypt-proxy.service" ]] || die "missing dnscrypt-proxy systemd unit (awg-uplink override)"

if [[ $UPDATE_FILES_ONLY -eq 0 ]]; then
  prompt_install_profile
  prompt_webui_settings
fi

if [[ $UPDATE_FILES_ONLY -eq 0 || $INSTALL_DEPS_ON_UPDATE -eq 1 ]] && command -v apt-get >/dev/null 2>&1; then
  log "Installing dependencies (python3, iproute2, netplan.io, nftables, ufw, dnsmasq, dnscrypt-proxy, curl, minisign, openssl, nginx, certbot, build-essential)..."
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 iproute2 netplan.io nftables ufw dnsmasq dnscrypt-proxy curl minisign openssl nginx certbot python3-certbot-nginx build-essential gcc g++ make libc6-dev >/dev/null
  dnsmasq_quarantine_bind_interfaces_snippets
fi

if [[ $UPDATE_FILES_ONLY -eq 0 || $INSTALL_DEPS_ON_UPDATE -eq 1 ]]; then
ensure_amneziawg
fi

log "Creating directories..."
install -d -m 755 "$APP_DIR"
install -d -m 755 "$APP_ROOT/lib"
install -d -m 755 "$APP_ROOT/systemd"
install -d -m 700 "$CFG_DIR"

log "Installing webui files..."
cp -a "$WEBUI_SRC/." "$APP_DIR/"

if [[ -f "$ROOTDIR/VERSION" ]]; then
  install -m 644 "$ROOTDIR/VERSION" "$APP_ROOT/VERSION"
fi

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
install -m 755 "$LIB_SRC/awg-mtproto-install.sh" "$APP_ROOT/lib/awg-mtproto-install.sh"
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
install -m 755 "$LIB_SRC/awg-mtproto-install.sh" /usr/local/sbin/awg-mtproto-install.sh
install -m 755 "$LIB_SRC/awg-webui-self-update.sh" /usr/local/sbin/awg-webui-self-update.sh

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

if [[ $UPDATE_FILES_ONLY -eq 1 ]]; then
  log "Update-only mode: skip configuration changes and prompts."
  systemctl daemon-reload
  if [[ "${AWG_WEBUI_RESTART_DEFER:-0}" == "1" ]]; then
    # Только когда bootstrap дергает сам awg-uplink-webui (self-update из панели): иначе HTTP-ответ не успеет.
    log "Scheduling web UI service restart in 4s (AWG_WEBUI_RESTART_DEFER=1)..."
    nohup bash -c "sleep 4; systemctl restart ${WEBUI_SERVICE}" </dev/null >/dev/null 2>&1 &
  else
    log "Restarting web UI service..."
    systemctl restart "$WEBUI_SERVICE"
    systemctl status --no-pager --lines=3 "$WEBUI_SERVICE" || true
  fi
  log "Update-only completed."
  exit 0
fi

systemctl disable dnscrypt-proxy.socket >/dev/null 2>&1 || true
systemctl stop dnscrypt-proxy.socket >/dev/null 2>&1 || true
rm -f /etc/systemd/system/dnscrypt-proxy.socket.d/awg-uplink.conf

if [[ ! -f "$CFG_DIR/webui.env" ]]; then
  log "Creating default $CFG_DIR/webui.env"
  cat >"$CFG_DIR/webui.env" <<'EOF'
AWG_WEBUI_HOST=127.0.0.1
AWG_WEBUI_PORT=8080
AWG_WEBUI_BASE_PATH=/
AWG_WEBUI_NO_AUTH=0
AWG_UI_USER=admin
AWG_UI_PASS=change-me
AWG_WEBUI_CFG_DIR=/etc/awg-uplink-webui
AWG_UI_DOMAIN=wb.ru
AWG_UI_TLS_MODE=self-signed
AWG_UI_MASK_PORT=5000
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
  "firewall": {
    "enabled": true,
    "egress_tcp_ports": [22],
    "ingress_tcp_ports": [22, 80, 443, 5000]
  },
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
dnsmasq_quarantine_bind_interfaces_snippets
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
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_HOST" "127.0.0.1"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_PORT" "8080"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_BASE_PATH" "/"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_NO_AUTH" "0"
ensure_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_CFG_DIR" "/etc/awg-uplink-webui"
set_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_HOST" "127.0.0.1"
set_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_PORT" "8080"
set_env_key "$CFG_DIR/webui.env" "AWG_WEBUI_NO_AUTH" "0"
set_env_key "$CFG_DIR/webui.env" "AWG_UI_USER" "$WEBUI_USER"
set_env_key "$CFG_DIR/webui.env" "AWG_UI_PASS" "$WEBUI_PASS"
set_env_key "$CFG_DIR/webui.env" "AWG_UI_DOMAIN" "$WEBUI_DOMAIN"
set_env_key "$CFG_DIR/webui.env" "AWG_UI_TLS_MODE" "$( [[ $USE_LETSENCRYPT -eq 1 ]] && echo "letsencrypt" || echo "self-signed" )"
set_env_key "$CFG_DIR/webui.env" "AWG_UI_MASK_PORT" "$WEBUI_MASK_PORT"
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
dnsmasq_quarantine_bind_interfaces_snippets
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

configure_nginx_reverse_proxy

log "Bootstrap completed."
print_final_summary


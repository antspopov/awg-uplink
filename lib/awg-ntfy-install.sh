#!/usr/bin/env bash
# Установка и провизионинг ntfy для AWG Split Gate (push-уведомления Android/iOS).
set -euo pipefail

CFG_DIR=${AWG_WEBUI_CFG_DIR:-/etc/awg-uplink-webui}
NOTIFY_JSON="$CFG_DIR/notifications.json"
NTFY_CONF="/etc/ntfy/server.yml"
NGINX_SITE_PATH="${AWG_NTFY_NGINX_SITE:-/etc/nginx/sites-available/awg-uplink-webui.conf}"
NTFY_LISTEN="${AWG_NTFY_LISTEN:-127.0.0.1:8093}"
UPDATE_ONLY=${AWG_NTFY_UPDATE_ONLY:-0}

log() { echo "[awg-ntfy-install] $*"; }
die() { echo "[awg-ntfy-install] ERROR: $*" >&2; exit 1; }

generate_secret() {
  local n="${1:-24}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$n" | head -c "$((n * 2))"
    return
  fi
  tr -dc 'a-f0-9' </dev/urandom | head -c "$((n * 2))"
}

read_env_from_webui() {
  local f="$CFG_DIR/webui.env"
  AWG_UI_DOMAIN="${AWG_UI_DOMAIN:-}"
  AWG_UI_MASK_PORT="${AWG_UI_MASK_PORT:-5000}"
  AWG_UI_NTFY_PORT="${AWG_UI_NTFY_PORT:-5001}"
  [[ -f "$f" ]] || return 0
  if [[ -z "$AWG_UI_DOMAIN" ]]; then
    AWG_UI_DOMAIN=$(grep -E '^[[:space:]]*AWG_UI_DOMAIN=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "'\"" | tr -d '[:space:]')
  fi
  if [[ -z "${AWG_UI_MASK_PORT:-}" ]]; then
    AWG_UI_MASK_PORT=$(grep -E '^[[:space:]]*AWG_UI_MASK_PORT=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "'\"" | tr -d '[:space:]')
  fi
  if grep -qE '^[[:space:]]*AWG_UI_NTFY_PORT=' "$f" 2>/dev/null; then
    AWG_UI_NTFY_PORT=$(grep -E '^[[:space:]]*AWG_UI_NTFY_PORT=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "'\"" | tr -d '[:space:]')
  fi
  AWG_UI_MASK_PORT="${AWG_UI_MASK_PORT:-5000}"
  AWG_UI_NTFY_PORT="${AWG_UI_NTFY_PORT:-5001}"
}

public_server_url() {
  local domain="$1"
  local _webui_port="$2"
  local ntfy_port="${AWG_UI_NTFY_PORT:-5001}"
  echo "https://${domain}:${ntfy_port}"
}

ensure_ntfy_package() {
  if command -v ntfy >/dev/null 2>&1; then
    return 0
  fi
  command -v apt-get >/dev/null 2>&1 || die "apt-get required to install ntfy"

  local arch deb_url tmpdeb
  arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
  case "$arch" in
    amd64|x86_64) deb_url="https://github.com/binwiederhier/ntfy/releases/download/v2.23.0/ntfy_2.23.0_linux_amd64.deb" ;;
    arm64|aarch64) deb_url="https://github.com/binwiederhier/ntfy/releases/download/v2.23.0/ntfy_2.23.0_linux_arm64.deb" ;;
    armhf|armv7l) deb_url="https://github.com/binwiederhier/ntfy/releases/download/v2.23.0/ntfy_2.23.0_linux_armv7.deb" ;;
    armv6l) deb_url="https://github.com/binwiederhier/ntfy/releases/download/v2.23.0/ntfy_2.23.0_linux_armv6.deb" ;;
    *) die "unsupported architecture for ntfy deb: $arch" ;;
  esac

  log "Installing ntfy from GitHub release (.deb)..."
  tmpdeb=$(mktemp /tmp/ntfy-XXXXXX.deb)
  curl -fsSL -o "$tmpdeb" "$deb_url" || die "failed to download ntfy deb from GitHub"
  DEBIAN_FRONTEND=noninteractive dpkg -i "$tmpdeb" || apt-get install -f -y
  rm -f "$tmpdeb"
  command -v ntfy >/dev/null 2>&1 || die "ntfy binary missing after deb install"
}

load_or_create_notifications_json() {
  local domain="$1"
  local port="$2"
  local server_url topic token pub_pass
  server_url=$(public_server_url "$domain" "$port")

  if [[ -f "$NOTIFY_JSON" ]]; then
    topic=$(python3 - <<'PY' "$NOTIFY_JSON"
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
try:
    d = json.loads(p.read_text(encoding="utf-8"))
    print(str(d.get("topic") or "").strip())
except Exception:
    print("")
PY
)
    token=$(python3 - <<'PY' "$NOTIFY_JSON"
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
try:
    d = json.loads(p.read_text(encoding="utf-8"))
    print(str(d.get("publish_token") or "").strip())
except Exception:
    print("")
PY
)
    pub_pass=$(python3 - <<'PY' "$NOTIFY_JSON"
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
try:
    d = json.loads(p.read_text(encoding="utf-8"))
    print(str(d.get("_publisher_pass") or "").strip())
except Exception:
    print("")
PY
)
    if [[ -n "$topic" && -n "$token" ]]; then
      if ! token_valid "$token"; then
        log "Regenerating invalid publish token (wrong length/format)"
        token=$(generate_publish_token)
        python3 - <<'PY' "$NOTIFY_JSON" "$token"
import json, sys
from pathlib import Path
p, token = Path(sys.argv[1]), sys.argv[2]
d = json.loads(p.read_text(encoding="utf-8"))
d["publish_token"] = token
p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
        rm -f /var/lib/ntfy/user.db
      fi
      log "Using existing notifications.json (topic=$topic)"
      if [[ -z "$pub_pass" ]]; then
        pub_pass=$(generate_secret 16)
        python3 - <<'PY' "$NOTIFY_JSON" "$pub_pass"
import json, sys
from pathlib import Path
p, pw = Path(sys.argv[1]), sys.argv[2]
d = json.loads(p.read_text(encoding="utf-8"))
d["_publisher_pass"] = pw
p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
        rm -f /var/lib/ntfy/user.db
      fi
      export AWG_NTFY_TOPIC="$topic"
      export AWG_NTFY_TOKEN="$token"
      export AWG_NTFY_PUBLISHER_PASS="$pub_pass"
      export AWG_NTFY_SERVER_URL="$server_url"
      return 0
    fi
  fi

  topic="awg-uplink-$(generate_secret 12)"
  token=$(generate_publish_token)
  pub_pass=$(generate_secret 16)
  install -d -m 700 "$CFG_DIR"
  cat >"$NOTIFY_JSON" <<EOF
{
  "enabled": true,
  "server_url": "$server_url",
  "topic": "$topic",
  "publish_token": "$token",
  "publisher_user": "awg-publisher",
  "_publisher_pass": "$pub_pass",
  "alerts": {
    "tunnels": true,
    "list_update_errors": true,
    "service_start_errors": true
  },
  "notify_state": {
    "tunnel_down_active": false,
    "tunnel_unavailable_notified": {},
    "last_tunnel_failover_ts": 0,
    "last_tunnel_down_ts": 0
  }
}
EOF
  chmod 600 "$NOTIFY_JSON"
  log "Created $NOTIFY_JSON (topic=$topic)"
  export AWG_NTFY_TOPIC="$topic"
  export AWG_NTFY_TOKEN="$token"
  export AWG_NTFY_PUBLISHER_PASS="$pub_pass"
  export AWG_NTFY_SERVER_URL="$server_url"
}

generate_publish_token() {
  if command -v ntfy >/dev/null 2>&1; then
    ntfy token generate
    return
  fi
  die "ntfy required to generate publish token"
}

publisher_password_hash() {
  local pass="$1"
  python3 - "$pass" <<'PY'
import crypt, sys
print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_BLOWFISH)))
PY
}

token_valid() {
  local token="$1"
  [[ "$token" =~ ^tk_[a-z0-9]{29}$ ]]
}

write_ntfy_server_yml() {
  local server_url="$1"
  local topic="$2"
  local token="$3"
  local pub_pass="$4"
  local pub_hash
  pub_hash=$(publisher_password_hash "$pub_pass")
  install -d -m 755 /var/cache/ntfy /var/lib/ntfy
  cat >"$NTFY_CONF" <<EOF
# Managed by awg-ntfy-install.sh (AWG Split Gate)
base-url: "$server_url"
listen-http: "$NTFY_LISTEN"
behind-proxy: true
proxy-forwarded-header: "X-Forwarded-For"
cache-file: "/var/cache/ntfy/cache.db"
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"
auth-users:
  - "awg-publisher:${pub_hash}:user"
auth-access:
  - "awg-publisher:${topic}:rw"
  - "*:${topic}:ro"
auth-tokens:
  - "awg-publisher:${token}:awg-panel"
EOF
  chmod 644 "$NTFY_CONF"
}

patch_nginx_ntfy_server() {
  [[ -f "$NGINX_SITE_PATH" ]] || return 0
  local ntfy_port="${AWG_UI_NTFY_PORT:-5001}"
  ensure_nginx_connection_upgrade_map
  if grep -q "listen ${ntfy_port} ssl" "$NGINX_SITE_PATH" 2>/dev/null; then
    upgrade_nginx_ntfy_websocket "${ntfy_port}"
    return 0
  fi
  local cert_path key_path domain
  cert_path=$(grep -m1 'ssl_certificate ' "$NGINX_SITE_PATH" | awk '{print $2}' | tr -d ';')
  key_path=$(grep -m1 'ssl_certificate_key ' "$NGINX_SITE_PATH" | awk '{print $2}' | tr -d ';')
  domain=$(grep -m1 'server_name ' "$NGINX_SITE_PATH" | awk '{print $2}' | tr -d ';')
  [[ -n "$cert_path" && -n "$key_path" && -n "$domain" ]] || {
    log "warning: cannot patch nginx for ntfy (missing cert/domain in $NGINX_SITE_PATH)"
    return 0
  }
  log "Adding ntfy HTTPS server on port ${ntfy_port} to $NGINX_SITE_PATH"
  cat >>"$NGINX_SITE_PATH" <<EOF

server {
    listen ${ntfy_port} ssl;
    listen [::]:${ntfy_port} ssl;
    server_name ${domain};

    ssl_certificate ${cert_path};
    ssl_certificate_key ${key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:8093/;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_redirect off;
        proxy_set_header Host \$http_host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 3m;
        proxy_send_timeout 3m;
        proxy_read_timeout 3m;
        client_max_body_size 0;
    }
}
EOF
}

ensure_nginx_connection_upgrade_map() {
  [[ -f "$NGINX_SITE_PATH" ]] || return 0
  if grep -q 'connection_upgrade' "$NGINX_SITE_PATH" 2>/dev/null; then
    return 0
  fi
  log "Adding nginx WebSocket map to $NGINX_SITE_PATH"
  local tmp="${NGINX_SITE_PATH}.tmp.$$"
  cat >"$tmp" <<'EOF'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

EOF
  cat "$NGINX_SITE_PATH" >>"$tmp"
  mv -f -- "$tmp" "$NGINX_SITE_PATH"
}

upgrade_nginx_ntfy_websocket() {
  local ntfy_port="$1"
  if grep -A20 "listen ${ntfy_port} ssl" "$NGINX_SITE_PATH" 2>/dev/null | grep -q 'proxy_set_header Upgrade'; then
    return 0
  fi
  log "Upgrading ntfy nginx block (port ${ntfy_port}) for WebSocket support"
  python3 - <<'PY' "$NGINX_SITE_PATH" "$ntfy_port"
import re, sys
from pathlib import Path
path, port = Path(sys.argv[1]), sys.argv[2]
text = path.read_text(encoding="utf-8")
block = """
    location / {
        proxy_pass http://127.0.0.1:8093/;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_redirect off;
        proxy_set_header Host $http_host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 3m;
        proxy_send_timeout 3m;
        proxy_read_timeout 3m;
        client_max_body_size 0;
    }"""
pat = re.compile(
    rf"(server\s*\{{\s*listen\s+{re.escape(port)}\s+ssl;.*?)(location\s+/\s*\{{.*?\n\s*\}})",
    re.S,
)
m = pat.search(text)
if not m:
    raise SystemExit(0)
new_text = pat.sub(rf"\1{block}", text, count=1)
path.write_text(new_text, encoding="utf-8")
PY
}

sync_notifications_server_url() {
  local server_url="$1"
  python3 - <<'PY' "$NOTIFY_JSON" "$server_url"
import json, sys
from pathlib import Path
p, url = Path(sys.argv[1]), sys.argv[2].rstrip("/")
if not p.exists():
    raise SystemExit(0)
try:
    d = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
if not isinstance(d, dict):
    raise SystemExit(0)
d["server_url"] = url
p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

enable_ntfy_service() {
  systemctl daemon-reload
  systemctl enable ntfy.service >/dev/null 2>&1 || systemctl enable ntfy >/dev/null 2>&1 || true
  systemctl restart ntfy.service 2>/dev/null || systemctl restart ntfy 2>/dev/null || die "failed to restart ntfy"
}

main() {
  [[ ${EUID:-0} -eq 0 ]] || die "run as root"
  read_env_from_webui
  [[ -n "${AWG_UI_DOMAIN:-}" ]] || die "AWG_UI_DOMAIN is required (set in $CFG_DIR/webui.env)"
  ensure_ntfy_package
  load_or_create_notifications_json "$AWG_UI_DOMAIN" "$AWG_UI_MASK_PORT"
  write_ntfy_server_yml "$AWG_NTFY_SERVER_URL" "$AWG_NTFY_TOPIC" "$AWG_NTFY_TOKEN" "$AWG_NTFY_PUBLISHER_PASS"
  sync_notifications_server_url "$AWG_NTFY_SERVER_URL"
  patch_nginx_ntfy_server
  if [[ -f "$NGINX_SITE_PATH" ]] && command -v nginx >/dev/null 2>&1; then
    nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
  fi
  enable_ntfy_service
  log "ntfy ready at $AWG_NTFY_SERVER_URL (topic=$AWG_NTFY_TOPIC)"
}

main "$@"

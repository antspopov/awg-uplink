#!/usr/bin/env bash
set -euo pipefail

CFG_DIR="${AWG_WEBUI_CFG_DIR:-/etc/awg-uplink-webui}"
ENV_FILE="$CFG_DIR/webui.env"
MTPROTO_CONFIG="/opt/mtproto-proxy/config.toml"
MTPROTO_PORT="${MTPROTO_PORT:-443}"
MASK_PORT="${MTPROTO_MASK_PORT:-5000}"
MTPROTO_MASK_PORT_ADDED=0

log() { echo "[awg-mtproto-install] $*"; }
die() { echo "[awg-mtproto-install] ERROR: $*" >&2; exit 1; }

run_mtbuddy_clean() {
  env -i \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME="/root" \
    TERM="${TERM:-xterm}" \
    LANG="${LANG:-C.UTF-8}" \
    mtbuddy "$@"
}

ZAPRET_DIR="/opt/zapret"
NFQWS_SERVICE="nfqws-mtproto"

require_root() {
  [[ ${EUID:-0} -eq 0 ]] || die "run as root"
}

read_env_value() {
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  awk -F= -v k="$key" '$1==k {print $2}' "$ENV_FILE" | tail -n1 | sed -e 's/^"//' -e 's/"$//'
}

detect_domain() {
  local domain
  domain="$(read_env_value AWG_UI_DOMAIN)"
  [[ -n "$domain" ]] || die "AWG_UI_DOMAIN is not set in $ENV_FILE; run awg-webui-bootstrap first"
  echo "$domain"
}

ensure_mtbuddy() {
  if command -v mtbuddy >/dev/null 2>&1; then
    return 0
  fi
  log "mtbuddy not found; installing via official bootstrap..."
  curl -fsSL "https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh" | bash
  command -v mtbuddy >/dev/null 2>&1 || die "mtbuddy install failed"
}

ensure_build_toolchain() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi
  log "Ensuring C build toolchain is present..."
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential gcc g++ make libc6-dev cpp gcc-13 cpp-13 >/dev/null
}

fix_cc_runtime() {
  local smoke_src="/tmp/awg-cc-smoke.c"
  local smoke_bin="/tmp/awg-cc-smoke"
  printf 'int main(void){return 0;}\n' >"$smoke_src"

  # Force cc to use GCC, not an accidental broken alternative.
  ln -sf "$(command -v gcc)" /usr/bin/cc

  if cc "$smoke_src" -o "$smoke_bin" >/dev/null 2>&1; then
    rm -f "$smoke_src" "$smoke_bin"
    return 0
  fi

  log "cc smoke-test failed, repairing gcc/cpp packages..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall gcc cpp gcc-13 cpp-13 libgcc-13-dev >/dev/null
  ln -sf "$(command -v gcc)" /usr/bin/cc

  cc "$smoke_src" -o "$smoke_bin" >/dev/null 2>&1 || die "cc toolchain still broken (cc1 unavailable)"
  rm -f "$smoke_src" "$smoke_bin"
}

prebuild_nfqws_if_needed() {
  log "Preflight: running mtbuddy setup nfqws before install..."
  run_mtbuddy_clean setup nfqws || true
  if [[ -x "$ZAPRET_DIR/nfq/nfqws" ]]; then
    log "nfqws binary is already present after preflight."
    return 0
  fi

  log "mtbuddy setup nfqws failed in preflight; building zapret/nfqws manually..."
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential git \
    libnetfilter-queue-dev libnfnetlink-dev libcap-dev iptables libmnl-dev zlib1g-dev >/dev/null

  rm -rf "$ZAPRET_DIR"
  git clone --depth 1 https://github.com/bol-van/zapret.git "$ZAPRET_DIR" >/dev/null 2>&1
  env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" HOME="/root" \
    bash -lc "cd \"$ZAPRET_DIR/nfq\" && make clean >/dev/null 2>&1 || true; make" >/tmp/awg-nfqws-build.log 2>&1 \
    || { cat /tmp/awg-nfqws-build.log >&2; die "manual nfqws build failed"; }
  [[ -x "$ZAPRET_DIR/nfq/nfqws" ]] || die "nfqws binary missing after manual build"
  log "nfqws binary prebuilt successfully; mtbuddy install will configure it."
}

install_mtproto_no_masking() {
  local domain="$1"
  log "Installing mtproto-proxy without masking (mtbuddy configures nfqws)..."
  run_mtbuddy_clean install --port "$MTPROTO_PORT" --domain "$domain" --no-masking --yes
}

configure_nfqws_with_mtbuddy() {
  log "Applying nfqws configuration via mtbuddy after install..."
  run_mtbuddy_clean setup nfqws || true
  systemctl is-active --quiet "$NFQWS_SERVICE" || die "$NFQWS_SERVICE service is not active after mtbuddy setup nfqws"
  [[ -x "$ZAPRET_DIR/nfq/nfqws" ]] || die "nfqws binary is missing after mtbuddy setup nfqws"
}

ensure_mtproto_service_user() {
  if ! getent group mtproto >/dev/null 2>&1; then
    log "Creating missing system group: mtproto"
    groupadd --system mtproto
  fi
  if ! id mtproto >/dev/null 2>&1; then
    log "Creating missing system user: mtproto"
    useradd --system --gid mtproto --home-dir /opt/mtproto-proxy --shell /usr/sbin/nologin mtproto
  fi
  if [[ -d /opt/mtproto-proxy ]]; then
    chown -R mtproto:mtproto /opt/mtproto-proxy || true
  fi
}

ensure_mtproto_netadmin_capability() {
  local dropin_dir="/etc/systemd/system/mtproto-proxy.service.d"
  local dropin_file="${dropin_dir}/90-awg-uplink-capabilities.conf"
  log "Ensuring mtproto-proxy has CAP_NET_ADMIN for SO_MARK policy routing..."
  mkdir -p "$dropin_dir"
  cat >"$dropin_file" <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
EOF
  systemctl daemon-reload
}

upsert_censorship_config() {
  local domain="$1"
  [[ -f "$MTPROTO_CONFIG" ]] || die "missing $MTPROTO_CONFIG after mtbuddy install"
  local before_has_mask_port="0"
  python3 - "$MTPROTO_CONFIG" <<'PY' >/tmp/awg-mtproto-maskport-before.txt
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
has = False
if "[censorship]" in text:
    start = text.index("[censorship]")
    rest = text[start:]
    m = re.search(r"\n\[[^\n]+\]", rest[1:])
    end = start + (m.start() + 1 if m else len(rest))
    section = text[start:end]
    has = bool(re.search(r"(?m)^\s*mask_port\s*=", section))
print("1" if has else "0")
PY
  before_has_mask_port="$(tr -cd '01' </tmp/awg-mtproto-maskport-before.txt || true)"
  [[ -n "$before_has_mask_port" ]] || before_has_mask_port="0"

  python3 - "$MTPROTO_CONFIG" "$domain" "$MASK_PORT" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
domain = sys.argv[2]
mask_port = sys.argv[3]
text = path.read_text(encoding="utf-8")

if "[censorship]" not in text:
    text += "\n[censorship]\n"

start = text.index("[censorship]")
rest = text[start:]
m = re.search(r"\n\[[^\n]+\]", rest[1:])
end = start + (m.start() + 1 if m else len(rest))
section = text[start:end]

def replace_or_add(section_text: str, key: str, value: str) -> str:
    pattern = re.compile(rf"(?m)^(\s*{re.escape(key)}\s*=\s*).*$")
    if pattern.search(section_text):
        return pattern.sub(rf"\g<1>{value}", section_text)
    if not section_text.endswith("\n"):
        section_text += "\n"
    return section_text + f"{key} = {value}\n"

section = replace_or_add(section, "mask", "true")
section = replace_or_add(section, "mask_port", mask_port)
section = replace_or_add(section, "tls_domain", f"\"{domain}\"")
section = replace_or_add(section, "drs", "true")

path.write_text(text[:start] + section + text[end:], encoding="utf-8")
PY
  rm -f /tmp/awg-mtproto-maskport-before.txt || true
  if [[ "$before_has_mask_port" == "0" ]]; then
    MTPROTO_MASK_PORT_ADDED=1
    log "mask_port was missing and has been added to [censorship]; restart required."
  fi
}

validate_or_repair_mtproto_toml() {
  [[ -f "$MTPROTO_CONFIG" ]] || {
    log "warning: missing $MTPROTO_CONFIG for validation"
    return 0
  }
  python3 - "$MTPROTO_CONFIG" <<'PY'
import re
import sys
import tomllib
from pathlib import Path

cfg = Path(sys.argv[1])
text = cfg.read_text(encoding="utf-8")

def ok_toml(s: str) -> bool:
    try:
        tomllib.loads(s)
        return True
    except Exception:
        return False

if ok_toml(text):
    print("[awg-mtproto-install] TOML validation: OK")
    raise SystemExit(0)

print("[awg-mtproto-install] warning: config.toml is invalid, attempting auto-repair...")

lines = text.splitlines()
out = []
in_censorship = False
dropped = []

for idx, raw in enumerate(lines, start=1):
    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        in_censorship = (s == "[censorship]")
        out.append(raw)
        continue
    if not in_censorship:
        out.append(raw)
        continue
    if s == "" or s.startswith("#") or "=" in s:
        out.append(raw)
        continue
    dropped.append((idx, raw))

repaired = "\n".join(out).rstrip() + "\n"
if ok_toml(repaired):
    cfg.write_text(repaired, encoding="utf-8")
    for n, line in dropped:
        print(f"[awg-mtproto-install] repaired: removed invalid [censorship] line {n}: {line!r}")
    print("[awg-mtproto-install] auto-repair complete; TOML is valid")
    raise SystemExit(0)

print("[awg-mtproto-install] warning: auto-repair could not fully validate TOML; keeping current file")
raise SystemExit(0)
PY
}

enable_mtproto_dashboard() {
  log "Enabling mtproto dashboard..."
  run_mtbuddy_clean setup dashboard
}

enable_mtproto_recovery() {
  local recovery_timer="${MTPROTO_RECOVERY_TIMER:-mtproto-mask-health.timer}"
  log "Enabling mtproto recovery..."
  run_mtbuddy_clean setup recovery || log "warning: mtbuddy setup recovery failed"
  local detected_timer=""
  for unit in "$recovery_timer" mtproto-mask-health.timer mtproto-proxy-recovery.timer; do
    if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | awk '{print $1}' | awk -v u="$unit" '$0==u{found=1} END{exit(found?0:1)}'; then
      detected_timer="$unit"
      break
    fi
  done
  if [[ -n "$detected_timer" ]]; then
    systemctl enable "$detected_timer" >/dev/null 2>&1 || true
    systemctl start "$detected_timer" >/dev/null 2>&1 || true
  else
    log "warning: recovery timer is not installed (checked: $recovery_timer, mtproto-mask-health.timer, mtproto-proxy-recovery.timer)"
  fi
}

restart_mtproto_service() {
  # Full restart is required after install:
  # - systemd capability drop-ins (CAP_NET_ADMIN/SO_MARK) are applied only on restart
  # - mtbuddy stages can rewrite config/runtime bits that are not safely hot-reloaded
  log "Restarting mtproto-proxy to apply install-time changes..."
  systemctl restart mtproto-proxy
}

main() {
  require_root
  local domain
  domain="$(detect_domain)"
  MASK_PORT="$(read_env_value AWG_UI_MASK_PORT)"
  MASK_PORT="${MASK_PORT:-5000}"

  ensure_mtbuddy
  ensure_build_toolchain
  fix_cc_runtime
  prebuild_nfqws_if_needed
  install_mtproto_no_masking "$domain"
  ensure_mtproto_service_user
  configure_nfqws_with_mtbuddy
  ensure_mtproto_netadmin_capability
  enable_mtproto_recovery
  enable_mtproto_dashboard
  # Some mtbuddy setup subcommands can rewrite config.toml sections.
  # Re-apply censorship keys at the very end to force local masking target.
  upsert_censorship_config "$domain"
  validate_or_repair_mtproto_toml
  if [[ "$MTPROTO_MASK_PORT_ADDED" == "1" ]]; then
    log "Restarting mtproto-proxy due to newly added mask_port..."
  fi
  restart_mtproto_service

  log "mtproto.zig installation completed."
  log "Domain: $domain"
  log "Masking port in mtproto config: ${MASK_PORT}"
  log "Config: $MTPROTO_CONFIG"
}

main "$@"

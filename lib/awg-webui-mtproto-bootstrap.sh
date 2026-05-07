#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# MTProto (mtproto.zig / mtbuddy) для awg-webui-bootstrap: установка/обновление прокси и embedded dashboard.
# После install включается drs в [censorship]. public_ip и middle_proxy_nat_ip — позже из веб-интерфейса.
set -euo pipefail

WITH_MTPROTO_PROXY=${WITH_MTPROTO_PROXY:-1}
MTPROTO_BOOTSTRAP_URL=${MTPROTO_BOOTSTRAP_URL:-https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh}
MTPROTO_PORT=${MTPROTO_PORT:-443}
MTPROTO_DOMAIN=${MTPROTO_DOMAIN:-wb.ru}
MTPROTO_USER=${MTPROTO_USER:-user}
MTPROTO_SECRET=${MTPROTO_SECRET:-}
MTPROTO_NO_DPI=${MTPROTO_NO_DPI:-0}
MTPROTO_MIDDLE_PROXY=${MTPROTO_MIDDLE_PROXY:-0}
MTPROTO_DRS=${MTPROTO_DRS:-1}
MTPROTO_DASHBOARD=${MTPROTO_DASHBOARD:-1}
MTPROTO_DASHBOARD_MONITOR_ADDR=${MTPROTO_DASHBOARD_MONITOR_ADDR:-127.0.0.1}
MTPROTO_DASHBOARD_MONITOR_PORT=${MTPROTO_DASHBOARD_MONITOR_PORT:-61208}

die() { echo "[awg-webui-mtproto] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-webui-mtproto] $*"; }

[[ -n "${MTPROTO_DOMAIN// }" ]] || die "MTPROTO_DOMAIN пуст — укажите домен TLS-маскировки (tls_domain)"

remove_legacy_mtproto_tunnel_artifacts() {
	# Ранние версии bootstrap ставили policy-routing tunnel; больше не нужны при default route через Amnezia.
	local legacy=/etc/systemd/system/mtproto-proxy.service.d/10-awg-uplink.conf
	if [[ -f $legacy ]]; then
		rm -f -- "$legacy"
		log "Удалён устаревший drop-in $legacy"
	fi
	rm -f -- /usr/local/sbin/awg-uplink-mtproto-routes.sh 2>/dev/null || true
	systemctl daemon-reload 2>/dev/null || true
}

patch_mtproto_drs() {
	[[ ${MTPROTO_DRS:-1} -eq 1 ]] || return 0
	local cfg=/opt/mtproto-proxy/config.toml
	[[ -f $cfg ]] || die "нет $cfg"
	command -v python3 >/dev/null 2>&1 || die "нужен python3 для drs в $cfg"
	python3 - "$cfg" <<'PY'
import re, sys

path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
drs_re = re.compile(r"^\s*drs\s*=")
if any(drs_re.match(ln) for ln in lines):
    out = [
        re.sub(r"^\s*drs\s*=.*$", "drs = true", ln) if drs_re.match(ln) else ln
        for ln in lines
    ]
else:
    out = []
    inserted = False
    for ln in lines:
        out.append(ln)
        if ln.strip() == "[censorship]" and not inserted:
            out.append("drs = true")
            inserted = True
    if not inserted:
        if out and out[-1].strip() != "":
            out.append("")
        out.append("[censorship]")
        out.append("drs = true")

open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
	log "MTProto: в config.toml включён drs = true ([censorship])"
}

# mtbuddy вызывает groupadd/useradd; если groupadd падает (редкий NSS, обрезанный PATH, нестандартный root),
# заранее создаём те же системные id — тогда установщик видит существующую группу/пользователя.
ensure_mtproto_system_ids() {
	if getent group mtproto >/dev/null 2>&1; then
		:
	elif command -v groupadd >/dev/null 2>&1; then
		groupadd --system mtproto \
			|| die "не удалось создать системную группу mtproto (groupadd --system). Проверьте /etc/group, свободное место и что контейнер не в read-only без слоя для /etc."
	elif command -v addgroup >/dev/null 2>&1; then
		addgroup -S mtproto || die "не удалось addgroup -S mtproto"
	else
		die "нет groupadd/addgroup — установите shadow/passwd или создайте группу mtproto вручную"
	fi

	if getent passwd mtproto >/dev/null 2>&1; then
		return 0
	fi
	if command -v useradd >/dev/null 2>&1; then
		if useradd --system --gid mtproto --home /nonexistent --shell /usr/sbin/nologin --no-create-home mtproto 2>/dev/null; then
			log "MTProto: создан системный пользователь mtproto"
			return 0
		fi
		if useradd --system --gid mtproto --shell /sbin/nologin --no-create-home --home-dir /nonexistent mtproto 2>/dev/null; then
			log "MTProto: создан системный пользователь mtproto"
			return 0
		fi
		if useradd -r -g mtproto -d /nonexistent -s /sbin/nologin -M mtproto 2>/dev/null; then
			log "MTProto: создан системный пользователь mtproto"
			return 0
		fi
		die "не удалось создать пользователя mtproto (useradd). Установите пакет passwd/shadow."
	elif command -v adduser >/dev/null 2>&1; then
		adduser -S -G mtproto -H -h /nonexistent -s /sbin/nologin mtproto \
			|| die "не удалось adduser mtproto"
	else
		die "нет useradd/adduser"
	fi
}

run_mtbuddy_install() {
	command -v curl >/dev/null 2>&1 || die "нужен curl для загрузки mtbuddy"
	ensure_mtproto_system_ids
	if ! command -v minisign >/dev/null 2>&1; then
		log "MTProto: устанавливаю minisign для проверки подписи релизов mtbuddy…"
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq
		apt-get install -y minisign || die "не удалось установить minisign (или используйте MTPROTO_INSECURE=1 на свой риск)"
	fi
	local -a args=(install --yes --port "$MTPROTO_PORT" --domain "$MTPROTO_DOMAIN" --user "$MTPROTO_USER")
	[[ -n ${MTPROTO_SECRET:-} ]] && args+=(--secret "$MTPROTO_SECRET")
	[[ ${MTPROTO_NO_DPI:-0} -eq 1 ]] && args+=(--no-dpi)
	[[ ${MTPROTO_MIDDLE_PROXY:-0} -eq 1 ]] && args+=(--middle-proxy)
	log "MTProto: mtbuddy ${args[*]} (bootstrap: ${MTPROTO_BOOTSTRAP_URL})"
	curl -fsSL "${MTPROTO_BOOTSTRAP_URL}" | bash -s -- "${args[@]}" \
		|| die "mtbuddy install не удался — https://github.com/sleep3r/mtproto.zig"
	command -v mtbuddy >/dev/null 2>&1 || die "mtbuddy не в PATH после установки"
}

setup_mtproto_dashboard() {
	[[ ${WITH_MTPROTO_PROXY:-0} -eq 1 ]] || return 0
	[[ ${MTPROTO_DASHBOARD:-1} -eq 1 ]] || return 0
	log "MTProto: mtbuddy setup dashboard …"
	mtbuddy setup dashboard || die "mtbuddy setup dashboard не удался — см. journalctl и https://github.com/sleep3r/mtproto.zig"
	log "MTProto: веб-dashboard на 127.0.0.1:${MTPROTO_DASHBOARD_MONITOR_PORT:-61208} — при необходимости: ssh -L ${MTPROTO_DASHBOARD_MONITOR_PORT:-61208}:localhost:${MTPROTO_DASHBOARD_MONITOR_PORT:-61208} root@<сервер>"
}


setup_mtproto_proxy() {
	remove_legacy_mtproto_tunnel_artifacts
	run_mtbuddy_install
	patch_mtproto_drs
	chown mtproto:mtproto /opt/mtproto-proxy/config.toml 2>/dev/null || true
	systemctl enable mtproto-proxy.service 2>/dev/null || true
	systemctl restart mtproto-proxy.service \
		|| die "mtproto-proxy не запустился: journalctl -u mtproto-proxy -n 50"
	setup_mtproto_dashboard
	log "MTProto: исходящий трафик к DC — default route хоста (см. [upstream] в /opt/mtproto-proxy/config.toml)"
	log "MTProto: systemctl status mtproto-proxy; конфиг: /opt/mtproto-proxy/config.toml"
}

main() {
	[[ ${EUID:-0} -eq 0 ]] || die "нужен root: sudo $0"
	setup_mtproto_proxy
}

main "$@"

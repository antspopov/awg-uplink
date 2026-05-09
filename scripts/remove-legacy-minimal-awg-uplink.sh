#!/usr/bin/env bash
# Удаляет артефакты ветки minimal-without-geo-routing-and-webui (awg-uplink-bootstrap.sh):
# split-юниты, policy-hook в /etc/amnezia/amneziawg/, drop-in awg-quick, nginx-сайт дашборда MTProto из старого bootstrap.
#
# НЕ удаляет: пакет amneziawg, /opt/mtproto-proxy (если MTProto ставили) — только явные файлы старого сценария.
# Перед переходом на awg-webui-bootstrap.sh сделайте бэкап сервера.
#
# Использование:
#   sudo ./scripts/remove-legacy-minimal-awg-uplink.sh
#   sudo ./scripts/remove-legacy-minimal-awg-uplink.sh --no-strip-wg-conf   # не трогать PostUp/PostDown в awg-uplink.conf (правка вручную)

set -euo pipefail

CANON_STEM=awg-uplink
WG_CONF=/etc/amnezia/amneziawg/${CANON_STEM}.conf
STRIP_WG_CONF=1

usage() {
	sed -n '1,20p' "$0" | tail -n +2
	exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h | --help) usage 0 ;;
		--no-strip-wg-conf) STRIP_WG_CONF=0 ;;
		*) usage 1 ;;
	esac
	shift
done

if [[ ${EUID:-1} -ne 0 ]]; then
	echo "Запускайте от root: sudo $0" >&2
	exit 1
fi

cat <<'EOF' >&2

╔══════════════════════════════════════════════════════════════════════════╗
║  ВНИМАНИЕ: удаление артефактов старой ветки minimal (awg-uplink-bootstrap) ║
║  Операция НЕОБРАТИМА в смысле конфигов: файлы будут удалены с диска.       ║
║  Рекомендуется снимок/бэкап и консольный доступ к серверу.                ║
╚══════════════════════════════════════════════════════════════════════════╝

Будет удалено (если существует):
  • systemd: awg-uplink-split@*, unit-шаблон, каталог drop-in awg-quick@${CANON_STEM}.service.d
  • /usr/local/sbin/awg-uplink-split-main.sh
  • /etc/amnezia/amneziawg/awg-uplink-policy.{sh,env}, awg-eth0-policy.*
  • /etc/awg-uplink-split.env и /etc/amnezia/amneziawg/awg-uplink-split.env
  • nginx: сайт/snippet/htpasswd дашборда MTProto из старого bootstrap
  • /etc/systemd/system/mtproto-proxy.service.d/10-awg-uplink.conf

EOF

if [[ "$STRIP_WG_CONF" -eq 1 ]]; then
	cat <<EOF >&2
Дополнительно для ${WG_CONF}:
  • создаётся резервная копия *.bak.<время>
  • из секции [Interface] удаляются строки PostUp/PostDown, связанные с awg-uplink-policy (старый hook)

Чтобы оставить awg-uplink.conf без изменений: $0 --no-strip-wg-conf

EOF
else
	echo "Режим --no-strip-wg-conf: файл ${WG_CONF} не изменяется — удалите PostUp/PostDown с policy вручную перед перезапуском туннеля." >&2
fi

read -r -p "Введите точную фразу DELETE-MINIMAL-AWG-UPLINK для продолжения: " confirm
if [[ "$confirm" != "DELETE-MINIMAL-AWG-UPLINK" ]]; then
	echo "Отменено." >&2
	exit 1
fi

log() { echo "[remove-legacy-minimal] $*"; }

strip_wg_conf() {
	[[ -f "$WG_CONF" ]] || {
		log "нет $WG_CONF — пропуск очистки PostUp/PostDown"
		return 0
	}
	local bak="${WG_CONF}.bak.$(date +%Y%m%d%H%M%S)"
	cp -a -- "$WG_CONF" "$bak"
	log "резервная копия: $bak"
	local tmp="${WG_CONF}.strip.$$"
	awk '
	/^\[Interface\]/ { in_iface=1; print; next }
	/^\[/ { in_iface=0; print; next }
	in_iface && /^PostUp[[:space:]]*=/ {
		if (index($0, "awg-uplink-policy") || index($0, "awg-eth0-policy") || index($0, "awg-docker-mark")) next
		print; next
	}
	in_iface && /^PostDown[[:space:]]*=/ {
		if (index($0, "awg-uplink-policy") || index($0, "awg-eth0-policy") || index($0, "awg-docker-mark")) next
		print; next
	}
	{ print }
	' "$WG_CONF" >"$tmp"
	chmod --reference="$WG_CONF" "$tmp" 2>/dev/null || chmod 600 "$tmp"
	mv -f -- "$tmp" "$WG_CONF"
	log "очищены PostUp/PostDown со ссылками на policy-hook в $WG_CONF"
}

disable_split_units() {
	local u
	while read -r u _; do
		[[ -n "$u" ]] || continue
		log "отключаю $u"
		systemctl disable --now "$u" 2>/dev/null || true
	done < <(systemctl list-units --type=service --all --no-legend 'awg-uplink-split@*' 2>/dev/null || true)
	while read -r u _; do
		[[ -n "$u" ]] || continue
		[[ "$u" == awg-uplink-split@* ]] || continue
		systemctl disable --now "$u" 2>/dev/null || true
	done < <(systemctl list-unit-files --no-legend 2>/dev/null | awk '$1 ~ /^awg-uplink-split@/ {print $1}' || true)
}

log "остановка и отключение awg-uplink-split@…"
disable_split_units

log "удаление unit-шаблона awg-uplink-split@.service"
rm -f -- "/etc/systemd/system/awg-uplink-split@.service"

log "удаление /usr/local/sbin/awg-uplink-split-main.sh"
rm -f -- "/usr/local/sbin/awg-uplink-split-main.sh"

log "удаление drop-in awg-quick@${CANON_STEM}.service.d"
rm -rf -- "/etc/systemd/system/awg-quick@${CANON_STEM}.service.d"

log "удаление policy-hook в ${WG_CONF%/*}"
rm -f -- \
	"/etc/amnezia/amneziawg/awg-uplink-policy.sh" \
	"/etc/amnezia/amneziawg/awg-uplink-policy.env" \
	"/etc/amnezia/amneziawg/awg-eth0-policy.sh" \
	"/etc/amnezia/amneziawg/awg-eth0-policy.env"

log "удаление split-env"
rm -f -- "/etc/awg-uplink-split.env" "/etc/amnezia/amneziawg/awg-uplink-split.env"

log "удаление nginx-артефактов дашборда MTProto (minimal bootstrap)"
rm -f -- "/etc/nginx/sites-enabled/awg-uplink-mtproto-dashboard"
rm -f -- "/etc/nginx/sites-available/awg-uplink-mtproto-dashboard"
rm -f -- "/etc/nginx/snippets/awg-uplink-mtproto-dashboard-locations.conf"
rm -f -- "/etc/nginx/snippets/awg-uplink-mtproto-dashboard-forward.inc"
rm -f -- "/etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard"
rm -f -- "/root/.awg-uplink-mtproto-dashboard.password"

log "удаление legacy drop-in mtproto-proxy"
rm -f -- "/etc/systemd/system/mtproto-proxy.service.d/10-awg-uplink.conf"
if [[ -d /etc/systemd/system/mtproto-proxy.service.d ]]; then
	rmdir --ignore-fail-on-non-empty /etc/systemd/system/mtproto-proxy.service.d 2>/dev/null || true
fi

rm -f -- "/usr/local/sbin/awg-uplink-mtproto-routes.sh" 2>/dev/null || true

if [[ "$STRIP_WG_CONF" -eq 1 ]]; then
	strip_wg_conf
fi

systemctl daemon-reload

if systemctl is-active --quiet nginx 2>/dev/null; then
	if nginx -t 2>/dev/null; then
		systemctl reload nginx && log "nginx reload OK" || log "nginx reload пропущен (ошибка)"
	else
		log "nginx -t не прошёл — reload не выполнялся; проверьте конфиг вручную"
	fi
fi

cat <<'EOF' >&2

Готово. Дальше:
  1) При необходимости: systemctl restart awg-quick@awg-uplink
  2) Установите новую версию: sudo ./awg-webui-bootstrap.sh
  3) Если не использовали --no-strip-wg-conf — проверьте awg-uplink.conf и резервную копию *.bak.*

EOF

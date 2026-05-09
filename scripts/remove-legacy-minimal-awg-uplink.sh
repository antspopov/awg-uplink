#!/usr/bin/env bash
# Полная очистка старой установки (ветка minimal: awg-uplink-bootstrap.sh) и смешанных
# остатков Web UI / MTProto, чтобы затем поднять всё заново через awg-webui-bootstrap.sh.
#
# Бэкапы пишутся в каталог под текущим рабочим каталогом ($PWD), например:
#   cd /root/awg-uplink && sudo ./scripts/remove-legacy-minimal-awg-uplink.sh
# → ./awg-uplink-legacy-uninstall-YYYYMMDD-HHMMSS/
#
# Переменная REMOVE_AWG_LEGACY_BACKUP_DIR переопределяет путь (абсолютный).
#
# Использование:
#   cd /path/to/awg-uplink && sudo ./scripts/remove-legacy-minimal-awg-uplink.sh
#   sudo ./scripts/remove-legacy-minimal-awg-uplink.sh --keep-wg-conf-on-disk
#       # не удалять awg-uplink.conf с диска после очистки Post/Pre Up/Down (копии всё равно в бэкап-каталоге)

set -euo pipefail

CANON_STEM=awg-uplink
WG_CONF=/etc/amnezia/amneziawg/${CANON_STEM}.conf
REMOVE_WG_CONF_FILE=1

usage() {
	sed -n '2,40p' "$0"
	exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h | --help) usage 0 ;;
		--keep-wg-conf-on-disk) REMOVE_WG_CONF_FILE=0 ;;
		*) usage 1 ;;
	esac
	shift
done

if [[ ${EUID:-1} -ne 0 ]]; then
	echo "Запускайте от root: sudo $0" >&2
	exit 1
fi

BACKUP_DIR="${REMOVE_AWG_LEGACY_BACKUP_DIR:-${PWD}/awg-uplink-legacy-uninstall-$(date +%Y%m%d-%H%M%S)}"

cat <<EOF >&2

╔══════════════════════════════════════════════════════════════════════════╗
║  ВНИМАНИЕ: полная деинсталляция awg-uplink / MTProto / проектного nginx   ║
║  Операция НЕОБРАТИМА: сервисы останавливаются, файлы и каталоги удаляются. ║
║  Консольный доступ и снимок ВМ обязательны.                               ║
╚══════════════════════════════════════════════════════════════════════════╝

Каталог бэкапов (создаётся): ${BACKUP_DIR}

Будет сделано:
  • Остановка и отключение awg-uplink-split@* (split routing), удаление юнита и split-main.sh
  • Остановка и отключение awg-quick@${CANON_STEM} (туннель AmneziaWG)
  • Бэкап awg-uplink.conf (оригинал + очищенный от Post/Pre Up/Down с policy-hook) → в каталог бэкапов;
    по умолчанию файл ${WG_CONF} с диска удаляется после копий
  • Полное удаление MTProto: архив /opt/mtproto-proxy, бэкап отдельно config.toml при наличии;
    отключение mtproto-proxy, nfqws-mtproto, известных таймеров; unit-файлы из /etc/systemd/system
  • Удаление drop-in awg-quick@…, policy-hook в /etc/amnezia/amneziawg/, split-env
  • Nginx: сайты/snippet/htpasswd minimal-дашборда; сайт awg-uplink-webui; при отсутствии default — symlink на sites-available/default;
    каталог /etc/ssl/awg-uplink-webui (самоподписанные сертификаты мастера Web UI)
  • Если есть Web UI стека main: бэкап и удаление /etc/awg-uplink-webui, /var/lib/awg-uplink-webui, /opt/awg-uplink;
    отключение awg-uplink-webui, awg-webui-ifaces, geo/dns/firewall юнитов проекта (файлы в /etc/systemd/system)

После скрипта в README: выполните **полный перезагрузку ОС** (reboot), чтобы сбросить nft-таблицы и зависшие маршруты.

EOF

if [[ "$REMOVE_WG_CONF_FILE" -eq 0 ]]; then
	echo "Режим --keep-wg-conf-on-disk: после бэкапа и очистки Post/Pre Up/Down файл ${WG_CONF} остаётся на месте (очищенный)." >&2
else
	echo "По умолчанию: после бэкапа файл ${WG_CONF} удаляется с диска." >&2
fi

if [[ "${AWG_UNINSTALL_NONINTERACTIVE:-}" == 1 ]]; then
	echo "[remove-legacy-minimal] AWG_UNINSTALL_NONINTERACTIVE=1 — пропуск ввода DELETE-MINIMAL-AWG-UPLINK." >&2
else
	read -r -p "Введите точную фразу DELETE-MINIMAL-AWG-UPLINK для продолжения: " confirm
	if [[ "$confirm" != "DELETE-MINIMAL-AWG-UPLINK" ]]; then
		echo "Отменено." >&2
		exit 1
	fi
fi

mkdir -p -- "$BACKUP_DIR"
chmod 700 -- "$BACKUP_DIR"
echo "$BACKUP_DIR" >"${BACKUP_DIR}/BACKUP_LOCATION.txt"

log() { echo "[remove-legacy-minimal] $*"; }
log "BACKUP_DIR=$BACKUP_DIR"

strip_policy_hooks_awk='function pl(s) {
  return (index(s,"awg-uplink-policy") || index(s,"awg-eth0-policy") || index(s,"awg-docker-mark"))
}
/^\[Interface\]/ { in_iface=1; print; next }
/^\[/ { in_iface=0; print; next }
in_iface && /^(PostUp|PreUp|PostDown|PreDown)[[:space:]]*=/ {
  if (pl($0)) next
  print; next
}
{ print }'

backup_and_strip_wg_conf() {
	[[ -f "$WG_CONF" ]] || {
		log "нет $WG_CONF — пропуск"
		return 0
	}
	cp -a -- "$WG_CONF" "${BACKUP_DIR}/awg-uplink.conf.orig"
	log "скопирован оригинал → ${BACKUP_DIR}/awg-uplink.conf.orig"
	awk "$strip_policy_hooks_awk" "$WG_CONF" >"${BACKUP_DIR}/awg-uplink.conf.stripped"
	log "очищенная копия → ${BACKUP_DIR}/awg-uplink.conf.stripped"
	if [[ "$REMOVE_WG_CONF_FILE" -eq 1 ]]; then
		rm -f -- "$WG_CONF"
		log "удалён с диска: $WG_CONF"
	else
		local tmp="${WG_CONF}.strip.$$"
		awk "$strip_policy_hooks_awk" "$WG_CONF" >"$tmp"
		chmod --reference="$WG_CONF" "$tmp" 2>/dev/null || chmod 600 "$tmp"
		mv -f -- "$tmp" "$WG_CONF"
		log "записан очищенный конфиг в $WG_CONF"
	fi
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

disable_project_systemd_units() {
	# Останавливаем всё, что могло быть поставлено main-веткой или вручную из /etc/systemd/system.
	local u
	while read -r u _; do
		[[ -n "$u" ]] || continue
		if [[ "$u" =~ ^(awg-uplink|awg-webui|mtproto|nfqws) ]]; then
			systemctl disable --now "$u" 2>/dev/null || true
		elif [[ "$u" == dnscrypt-proxy.service || "$u" == dnscrypt-proxy.socket ]] && [[ -f "/etc/systemd/system/$u" ]]; then
			systemctl disable --now "$u" 2>/dev/null || true
		fi
	done < <(systemctl list-unit-files --no-legend 2>/dev/null || true)
}

remove_project_unit_files() {
	shopt -s nullglob
	local f
	for f in \
		/etc/systemd/system/awg-uplink-split@.service \
		/etc/systemd/system/awg-uplink-webui.service \
		/etc/systemd/system/awg-webui-ifaces.service \
		/etc/systemd/system/awg-uplink-geo-ip-refresh.service \
		/etc/systemd/system/awg-uplink-geo-ip-refresh.timer \
		/etc/systemd/system/awg-uplink-geo-domain-refresh.service \
		/etc/systemd/system/awg-uplink-geo-domain-refresh.timer \
		/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.service \
		/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.timer \
		/etc/systemd/system/awg-uplink-dns-refresh.service \
		/etc/systemd/system/awg-uplink-dns-refresh.timer \
		/etc/systemd/system/awg-uplink-amnezia-dns-watch.service \
		/etc/systemd/system/awg-uplink-dns-transport-lock.service \
		/etc/systemd/system/awg-uplink-firewall.service \
		/etc/systemd/system/mtproto-proxy.service \
		/etc/systemd/system/nfqws-mtproto.service \
		/etc/systemd/system/dnscrypt-proxy.service; do
		[[ -e $f ]] || continue
		rm -f -- "$f"
		log "удалён unit: $f"
	done
	for f in /etc/systemd/system/mtproto*.timer /etc/systemd/system/mtproto*.service /etc/systemd/system/nfqws*.service; do
		[[ -e $f ]] || continue
		rm -f -- "$f"
		log "удалён unit: $f"
	done
	shopt -u nullglob
	rm -rf -- \
		"/etc/systemd/system/awg-quick@${CANON_STEM}.service.d" \
		"/etc/systemd/system/mtproto-proxy.service.d" \
		"/etc/systemd/system/dnscrypt-proxy.socket.d"
}

log "split routing: остановка awg-uplink-split@…"
disable_split_units
rm -f -- "/etc/systemd/system/awg-uplink-split@.service"
rm -f -- "/usr/local/sbin/awg-uplink-split-main.sh"

log "остановка туннеля awg-quick@${CANON_STEM}.service"
systemctl disable --now "awg-quick@${CANON_STEM}.service" 2>/dev/null || true

log "остановка MTProto / nfqws (известные имена)"
for u in mtproto-proxy.service nfqws-mtproto.service; do
	systemctl disable --now "$u" 2>/dev/null || true
done
for u in mtproto-mask-health.timer mtproto-proxy-recovery.timer mtproto-mask-health.service; do
	systemctl disable --now "$u" 2>/dev/null || true
done

log "остановка прочих юнитов проекта (webui, geo, dns, firewall…)"
disable_project_systemd_units

log "бэкап и удаление MTProto (/opt/mtproto-proxy)"
if [[ -f /opt/mtproto-proxy/config.toml ]]; then
	cp -a -- "/opt/mtproto-proxy/config.toml" "${BACKUP_DIR}/mtproto-config.toml.orig"
	log "скопирован ${BACKUP_DIR}/mtproto-config.toml.orig"
fi
if [[ -d /opt/mtproto-proxy ]]; then
	tar -czf "${BACKUP_DIR}/mtproto-proxy-opt.tar.gz" -C /opt mtproto-proxy
	log "архив каталога → ${BACKUP_DIR}/mtproto-proxy-opt.tar.gz"
	rm -rf -- /opt/mtproto-proxy
	log "удалён /opt/mtproto-proxy"
fi

log "бэкап и очистка awg-uplink.conf (Post/Pre Up/Down с policy)"
backup_and_strip_wg_conf

log "удаление policy-hook и split-env"
rm -f -- \
	"/etc/amnezia/amneziawg/awg-uplink-policy.sh" \
	"/etc/amnezia/amneziawg/awg-uplink-policy.env" \
	"/etc/amnezia/amneziawg/awg-eth0-policy.sh" \
	"/etc/amnezia/amneziawg/awg-eth0-policy.env"
rm -f -- "/etc/awg-uplink-split.env" "/etc/amnezia/amneziawg/awg-uplink-split.env"

log "бэкап и удаление конфигов Web UI (если есть)"
if [[ -d /etc/awg-uplink-webui ]]; then
	tar -czf "${BACKUP_DIR}/etc-awg-uplink-webui.tar.gz" -C /etc awg-uplink-webui
	rm -rf -- /etc/awg-uplink-webui
	log "удалён /etc/awg-uplink-webui"
fi
if [[ -d /var/lib/awg-uplink-webui ]]; then
	tar -czf "${BACKUP_DIR}/var-lib-awg-uplink-webui.tar.gz" -C /var/lib awg-uplink-webui
	rm -rf -- /var/lib/awg-uplink-webui
	log "удалён /var/lib/awg-uplink-webui"
fi
if [[ -d /opt/awg-uplink ]]; then
	tar -czf "${BACKUP_DIR}/opt-awg-uplink.tar.gz" -C /opt awg-uplink
	rm -rf -- /opt/awg-uplink
	log "удалён /opt/awg-uplink"
fi

log "удаление unit-файлов из /etc/systemd/system (проект + mtproto)"
remove_project_unit_files

rm -f -- "/usr/local/sbin/awg-uplink-mtproto-routes.sh" 2>/dev/null || true

log "nginx: убрать сайты и сниппеты проекта"
rm -f -- \
	"/etc/nginx/sites-enabled/awg-uplink-mtproto-dashboard" \
	"/etc/nginx/sites-available/awg-uplink-mtproto-dashboard" \
	"/etc/nginx/sites-enabled/awg-uplink-webui.conf" \
	"/etc/nginx/sites-available/awg-uplink-webui.conf" \
	"/etc/nginx/snippets/awg-uplink-mtproto-dashboard-locations.conf" \
	"/etc/nginx/snippets/awg-uplink-mtproto-dashboard-forward.inc" \
	"/etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard" \
	"/root/.awg-uplink-mtproto-dashboard.password"
rm -rf -- "/etc/ssl/awg-uplink-webui"

if [[ ! -e /etc/nginx/sites-enabled/default ]] && [[ -f /etc/nginx/sites-available/default ]]; then
	ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
	log "включён дефолтный сайт: sites-enabled/default → sites-available/default"
fi

systemctl daemon-reload

if systemctl is-active --quiet nginx 2>/dev/null; then
	if nginx -t 2>/dev/null; then
		systemctl reload nginx && log "nginx reload OK" || log "nginx reload пропущен"
	else
		log "nginx -t не прошёл — проверьте конфиг; при необходимости: apt-get install --reinstall nginx-common"
	fi
fi

cat <<EOF >&2

Готово. Бэкапы: ${BACKUP_DIR}

Обязательно:
  1) sudo reboot   — полная перезагрузка, чтобы очистить nft-таблицы и поднять сеть «с нуля».
  2) После reboot: cd в каталог репозитория и sudo ./awg-webui-bootstrap.sh

При проблемах с nginx: восстановите дефолтные конфиги пакета (зависит от дистрибутива), например переустановка nginx или копирование sites-available/default.

EOF

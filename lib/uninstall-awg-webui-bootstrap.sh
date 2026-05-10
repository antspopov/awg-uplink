#!/usr/bin/env bash
# Удаляет всё, что ставит awg-webui-bootstrap.sh (текущая ветка main): юниты, конфиги,
# /opt/awg-uplink, MTProto в /opt, nginx-сайт Web UI, самоподписанные сертификаты, сниппеты dnsmasq/resolved.
# Затем снимает пакеты, которые bootstrap ставит через apt (amneziawg, amneziawg-tools — отдельный .deb в PPA),
# и при необходимости
# удаляет DKMS-модуль amneziawg и бинарники awg/awg-quick из исходной сборки.
# Не трогает артефакты ветки minimal (split, policy-hook).
#
# Бэкапы: каталог $PWD/awg-webui-bootstrap-uninstall-ГГГГММДД-ЧЧММСС/ или REMOVE_AWG_WEBUI_UNINSTALL_BACKUP_DIR

set -euo pipefail

APP_DIR=${AWG_WEBUI_APP_DIR:-/opt/awg-uplink/webui}
APP_ROOT=$(dirname "$APP_DIR")
CFG_DIR=${AWG_WEBUI_CFG_DIR:-/etc/awg-uplink-webui}
CANON_STEM=awg-uplink
WG_CONF=/etc/amnezia/amneziawg/${CANON_STEM}.conf
SELF_SIGNED_CERT_DIR="/etc/ssl/awg-uplink-webui"
NGINX_SITE_PATH="/etc/nginx/sites-available/awg-uplink-webui.conf"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/awg-uplink-webui.conf"
AMNEZIA_APT_LIST=/etc/apt/sources.list.d/amnezia-ppa.list

WEBUI_SERVICE=awg-uplink-webui.service
IFACE_SERVICE=awg-webui-ifaces.service

log() { echo "[uninstall-awg-webui-bootstrap] $*"; }
die() { echo "[uninstall-awg-webui-bootstrap] ERROR: $*" >&2; exit 1; }

usage() {
	cat <<'EOF'
Usage: lib/uninstall-awg-webui-bootstrap.sh

Обычно из корня репозитория:
  cd /path/to/awg-uplink && sudo ./awg-webui-bootstrap.sh --uninstall

Переменные окружения (как у bootstrap): AWG_WEBUI_APP_DIR, AWG_WEBUI_CFG_DIR
Переменная REMOVE_AWG_WEBUI_UNINSTALL_BACKUP_DIR — абсолютный путь каталога бэкапов.
EOF
	exit "${1:-0}"
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage 0
[[ ${EUID:-1} -eq 0 ]] || die "run as root"

BACKUP_DIR="${REMOVE_AWG_WEBUI_UNINSTALL_BACKUP_DIR:-${PWD}/awg-webui-bootstrap-uninstall-$(date +%Y%m%d-%H%M%S)}"

cat <<EOF >&2

╔══════════════════════════════════════════════════════════════════════════╗
║  ВНИМАНИЕ: полное удаление стека AWG Web UI bootstrap                    ║
║  Остановятся сервисы, удалятся конфиги, /opt/awg-uplink, MTProto, nginx.   ║
║  Будут сняты пакеты: nginx, dnsmasq, dnscrypt-proxy, nftables, ufw, certbot, ║
║  amneziawg и др. (см. список в скрипте) — это может сломать чужие сервисы. ║
╚══════════════════════════════════════════════════════════════════════════╝

Каталог бэкапов: ${BACKUP_DIR}

EOF

read -r -p "Введите DELETE-AWG-WEBUI-BOOTSTRAP для продолжения: " confirm
if [[ "$confirm" != "DELETE-AWG-WEBUI-BOOTSTRAP" ]]; then
	echo "Отменено." >&2
	exit 1
fi

mkdir -p -- "$BACKUP_DIR"
chmod 700 -- "$BACKUP_DIR"
echo "$BACKUP_DIR" >"${BACKUP_DIR}/BACKUP_LOCATION.txt"
log "BACKUP_DIR=$BACKUP_DIR"

read_ui_domain_for_certbot() {
	local f="$CFG_DIR/webui.env"
	[[ -f "$f" ]] || return 0
	grep -E '^[[:space:]]*AWG_UI_DOMAIN=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "'\"" | tr -d '[:space:]'
}

disable_matching_units() {
	local u
	while read -r u _; do
		[[ -n "$u" ]] || continue
		if [[ "$u" =~ ^(awg-uplink|awg-webui|mtproto|nfqws) ]]; then
			systemctl disable --now "$u" 2>/dev/null || true
		elif [[ "$u" == dnscrypt-proxy.service || "$u" == dnscrypt-proxy.socket ]] && [[ -f "/etc/systemd/system/$u" ]]; then
			systemctl disable --now "$u" 2>/dev/null || true
		fi
	done < <(systemctl list-unit-files --no-legend 2>/dev/null || true)
	systemctl disable --now "awg-quick@${CANON_STEM}.service" 2>/dev/null || true
}

remove_unit_files() {
	shopt -s nullglob
	local f
	for f in \
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
		log "удалён $f"
	done
	for f in /etc/systemd/system/mtproto*.timer /etc/systemd/system/mtproto*.service /etc/systemd/system/nfqws*.service; do
		[[ -e $f ]] || continue
		rm -f -- "$f"
		log "удалён $f"
	done
	shopt -u nullglob
	rm -rf -- \
		"/etc/systemd/system/awg-quick@${CANON_STEM}.service.d" \
		"/etc/systemd/system/mtproto-proxy.service.d" \
		"/etc/systemd/system/dnscrypt-proxy.socket.d"
}

log "остановка systemd-юнитов…"
disable_matching_units

log "modprobe -r amneziawg (если загружен)"
modprobe -r amneziawg 2>/dev/null || true

log "DKMS: удаление модуля amneziawg (если есть)"
if command -v dkms >/dev/null 2>&1; then
	while IFS= read -r line; do
		[[ "$line" =~ ^amneziawg/([^,]+), ]] || continue
		ver="${BASH_REMATCH[1]// /}"
		[[ -n "$ver" ]] || continue
		dkms remove -m amneziawg -v "$ver" --all --force 2>/dev/null || true
	done < <(dkms status 2>/dev/null | grep '^amneziawg/' || true)
fi

log "бэкап конфигов и данных…"
if [[ -d $CFG_DIR ]]; then
	tar -czf "${BACKUP_DIR}/etc-awg-uplink-webui.tar.gz" -C /etc "$(basename "$CFG_DIR")"
fi
if [[ -d /var/lib/awg-uplink-webui ]]; then
	tar -czf "${BACKUP_DIR}/var-lib-awg-uplink-webui.tar.gz" -C /var/lib awg-uplink-webui
fi
if [[ -d /opt/awg-uplink ]]; then
	tar -czf "${BACKUP_DIR}/opt-awg-uplink.tar.gz" -C /opt awg-uplink
fi
if [[ -d /opt/mtproto-proxy ]]; then
	tar -czf "${BACKUP_DIR}/mtproto-proxy-opt.tar.gz" -C /opt mtproto-proxy
	[[ -f /opt/mtproto-proxy/config.toml ]] && cp -a /opt/mtproto-proxy/config.toml "${BACKUP_DIR}/mtproto-config.toml.orig"
fi
if [[ -f $WG_CONF ]]; then
	cp -a -- "$WG_CONF" "${BACKUP_DIR}/awg-uplink.conf.orig"
fi

LE_DOMAIN=$(read_ui_domain_for_certbot)
if [[ -n "$LE_DOMAIN" ]] && command -v certbot >/dev/null 2>&1; then
	log "certbot delete (если есть сертификат для $LE_DOMAIN)"
	certbot delete --cert-name "$LE_DOMAIN" --non-interactive 2>/dev/null || true
fi

log "снятие правил файрвола панели (UFW, метка awg-web-ui-fw) и legacy nft awg_webui_fw…"
if [[ -x /usr/local/sbin/awg-uplink-firewall-apply.py ]]; then
	AWG_FW_ENABLED=0 AWG_WEBUI_CFG_DIR="$CFG_DIR" python3 /usr/local/sbin/awg-uplink-firewall-apply.py 2>/dev/null || true
fi

log "удаление каталогов приложения и MTProto"
rm -rf -- /opt/mtproto-proxy /opt/awg-uplink "$CFG_DIR" /var/lib/awg-uplink-webui
rm -f -- "$WG_CONF"

log "удаление unit-файлов"
remove_unit_files

log "удаление /usr/local/sbin (скрипты bootstrap)"
rm -f -- \
	/usr/local/sbin/awg-webui-iface-routing-apply.sh \
	/usr/local/sbin/awg-uplink-geo-ip-refresh.py \
	/usr/local/sbin/awg-uplink-geo-domain-refresh.py \
	/usr/local/sbin/awg-uplink-dns-refresh.py \
	/usr/local/sbin/awg-uplink-amnezia-dns-watch.py \
	/usr/local/sbin/awg-uplink-dns-transport-lock.py \
	/usr/local/sbin/awg-uplink-firewall-apply.py \
	/usr/local/sbin/awg-mtproto-install.sh

log "nginx: сайт Web UI и самоподписанные сертификаты"
rm -f -- "$NGINX_SITE_LINK" "$NGINX_SITE_PATH"
rm -rf -- "$SELF_SIGNED_CERT_DIR"
if [[ ! -e /etc/nginx/sites-enabled/default ]] && [[ -f /etc/nginx/sites-available/default ]]; then
	ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
	log "включён sites-enabled/default"
fi

log "dnsmasq / systemd-resolved: сниппеты bootstrap"
rm -f -- /etc/dnsmasq.d/zzz-awg-uplink-base.conf /etc/dnsmasq.d/awg-uplink-base.conf
rm -f -- /etc/systemd/resolved.conf.d/awg-uplink-dns.conf

log "прочие каталоги /var/lib/awg-uplink (geo-domain, quarantine dnsmasq)"
rm -rf -- /var/lib/awg-uplink/geo-domain /var/lib/awg-uplink/dnsmasq-package-snippets
rmdir --ignore-fail-on-non-empty /var/lib/awg-uplink 2>/dev/null || true

rm -f -- /run/awg-webui-ifaces.state 2>/dev/null || true

log "бинарники awg/awg-quick из исходной сборки (если не из пакета)"
for bin in /usr/bin/awg /usr/bin/awg-quick; do
	if [[ -e "$bin" ]] && ! dpkg -S "$bin" &>/dev/null; then
		rm -f -- "$bin"
		log "удалён $bin"
	fi
done

rm -rf -- /usr/src/amneziawg-* 2>/dev/null || true

systemctl daemon-reload

if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
	systemctl restart systemd-resolved || true
fi

if systemctl is-active --quiet nginx 2>/dev/null; then
	nginx -t 2>/dev/null && systemctl reload nginx || log "nginx reload пропущен (проверьте nginx -t)"
fi

if command -v apt-get >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	log "apt: удаление PPA Amnezia (Ubuntu) или списка (Debian)"
	if [[ -f /etc/os-release ]]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		case "${ID:-}" in
			ubuntu|pop)
				if command -v add-apt-repository >/dev/null 2>&1; then
					add-apt-repository -y --remove ppa:amnezia/ppa 2>/dev/null || true
				fi
				;;
		esac
	fi
	rm -f -- "$AMNEZIA_APT_LIST"
	apt-get update -qq || true

	# Точное совпадение с пакетами из awg-webui-bootstrap.sh (ensure_amneziawg / основной apt-get install).
	PKGS=(
		amneziawg
		amneziawg-tools
		python3-certbot-nginx
		certbot
		python3
		iproute2
		netplan.io
		nftables
		ufw
		dnsmasq
		dnscrypt-proxy
		curl
		minisign
		openssl
		nginx
		build-essential
		gcc
		g++
		make
		libc6-dev
	)
	# Зависимости исходной сборки amneziawg (если ставились)
	PKGS+=(git dkms pkg-config libmnl-dev libelf-dev libssl-dev debhelper dh-python)
	# Транзитивно для PPA Ubuntu
	PKGS+=(software-properties-common gnupg2)

	log "apt-get remove --purge (пакеты bootstrap)…"
	if ! apt-get remove --purge -y "${PKGS[@]}"; then
		log "warning: часть пакетов не удалена (зависимости или уже сняты)"
	fi
	apt-get autoremove -y >/dev/null 2>&1 || true
fi

cat <<EOF >&2

Готово. Бэкапы: ${BACKUP_DIR}

Рекомендуется: sudo reboot — сброс nft-таблиц и маршрутов.

EOF

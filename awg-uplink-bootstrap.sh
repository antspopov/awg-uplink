#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# AmneziaWG + uplink (awg-quick@awg-uplink), опционально MTProto (mtbuddy / mtproto.zig).
# Нужен запущенный контейнер Amnezia в Docker; root. Подробности: --help
set -euo pipefail

SPLIT_ROUTING_WIZARD=${SPLIT_ROUTING_WIZARD:-0}

# Пустой / не заданный AMNEZIA_DOCKER_NAMES = искать контейнеры по AMNEZIA_DOCKER_NAME_PATTERN (ERE).
AMNEZIA_DOCKER_NAME_PATTERN=${AMNEZIA_DOCKER_NAME_PATTERN:-^amnezia-awg}
AMNEZIA_APT_LIST=/etc/apt/sources.list.d/amnezia-ppa.list
CANON_STEM=awg-uplink
AMNEZIAWG_FROM_SOURCE=${AMNEZIAWG_FROM_SOURCE:-0}
AMNEZIAWG_REINSTALL=${AMNEZIAWG_REINSTALL:-0}
AMNEZIAWG_SRC_CACHE=${AMNEZIAWG_SRC_CACHE:-/var/cache/awg-uplink-amneziawg}
AMNEZIAWG_KERNEL_REPO=${AMNEZIAWG_KERNEL_REPO:-https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git}
AMNEZIAWG_TOOLS_REPO=${AMNEZIAWG_TOOLS_REPO:-https://github.com/amnezia-vpn/amneziawg-tools.git}

WITH_MTPROTO_PROXY=${WITH_MTPROTO_PROXY:-0}
MTPROTO_BOOTSTRAP_URL=${MTPROTO_BOOTSTRAP_URL:-https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh}
MTPROTO_PORT=${MTPROTO_PORT:-443}
MTPROTO_DOMAIN=${MTPROTO_DOMAIN:-wb.ru}
MTPROTO_USER=${MTPROTO_USER:-user}
MTPROTO_SECRET=${MTPROTO_SECRET:-}
MTPROTO_PUBLIC_IP=${MTPROTO_PUBLIC_IP:-}
MTPROTO_MIDDLE_PROXY_NAT_IP=${MTPROTO_MIDDLE_PROXY_NAT_IP:-}
MTPROTO_EGRESS_IP_URL=${MTPROTO_EGRESS_IP_URL:-}
MTPROTO_NO_DPI=${MTPROTO_NO_DPI:-0}
MTPROTO_MIDDLE_PROXY=${MTPROTO_MIDDLE_PROXY:-0}
# [censorship] drs (Dynamic Record Sizing); по умолчанию включаем в config.toml после mtbuddy.
MTPROTO_DRS=${MTPROTO_DRS:-1}
MTPROTO_DASHBOARD=${MTPROTO_DASHBOARD:-1}
MTPROTO_DASHBOARD_NGINX=${MTPROTO_DASHBOARD_NGINX:-1}
# Пусто = взять mask_port из /opt/mtproto-proxy/config.toml (обычно 8443). Перекрытие: --mtproto-dashboard-nginx-port / MTPROTO_DASHBOARD_NGINX_MASK_PORT
MTPROTO_DASHBOARD_NGINX_MASK_PORT=${MTPROTO_DASHBOARD_NGINX_MASK_PORT:-${MTPROTO_DASHBOARD_NGINX_PORT:-}}
MTPROTO_DASHBOARD_USER=${MTPROTO_DASHBOARD_USER:-admin}
MTPROTO_DASHBOARD_PASSWORD=${MTPROTO_DASHBOARD_PASSWORD:-}
MTPROTO_DASHBOARD_MONITOR_ADDR=${MTPROTO_DASHBOARD_MONITOR_ADDR:-127.0.0.1}
MTPROTO_DASHBOARD_MONITOR_PORT=${MTPROTO_DASHBOARD_MONITOR_PORT:-61208}

# Итоговое сообщение (заполняется при mtproto/nginx)
SUMMARY_MT_TG_LINES=""
SUMMARY_DASHBOARD_URL=""
SUMMARY_DASHBOARD_USER=""
SUMMARY_DASHBOARD_PASSWORD=""

die() { echo "[awg-uplink] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-uplink] $*"; }
warn() { echo "[awg-uplink] WARN: $*" >&2; }

usage() {
	local ex=${1:-1}
	cat >&2 <<EOF
Использование: $0 [опции] /путь/к/exported.conf

Общее
  Запуск от root. Исходный .conf только читается.
  Docker: контейнер Amnezia — по умолчанию любое имя, подходящее под \$AMNEZIA_DOCKER_NAME_PATTERN (ERE, по умолчанию ^amnezia-awg: amnezia-awg, amnezia-awg2, …).
  Если задан непустой \$AMNEZIA_DOCKER_NAMES (через пробел), проверяются только эти точные имена.

  --split-routing-wizard  После inject: интерактивный мастер split-routing (ingress для клиентов / egress для исходящего трафика и unit awg-uplink-split@IFACE). См. lib/awg-uplink-split-wizard.sh --help

AmneziaWG (интерфейс ${CANON_STEM}, unit awg-quick@${CANON_STEM})
  --amneziawg-from-source   Сборка amneziawg (DKMS) + amneziawg-tools из Git, без PPA.
  --amneziawg-reinstall     Переустановка amneziawg (apt --reinstall или пересборка DKMS).
  По умолчанию: пакет amneziawg из репозитория (Ubuntu PPA / Debian Launchpad).

MTProto (mtbuddy / mtproto.zig, только с --with-mtproto-proxy)
  --with-mtproto-proxy      Установка прокси; исходящий трафик к DC — маршрутизация хоста ([upstream] в config.toml).
  --mtproto-port N          Порт прослушивания (по умолчанию 443).
  --mtproto-domain HOST     tls_domain для маскировки при install (по умолчанию wb.ru).
  --mtproto-user NAME       Пользователь в [access.users] (по умолчанию user).
  --mtproto-secret HEX      32 hex; иначе генерирует mtbuddy.
  --mtproto-public-ip ADDR  [server] public_ip; иначе авто: при AWG_SPLIT_ENABLE=1 — AWG_INGRESS_IPV4 из split-env, иначе IPv4 с uplink (не awg/wg/tun/amnN). Влияет на tg:// и на MP при IPv4.
  --mtproto-middle-proxy-nat-ip ADDR  [server] middle_proxy_nat_ip (только IPv4); иначе curl по default route
                            (ipify/ifconfig.me; первый URL — MTPROTO_EGRESS_IP_URL). Обычно «exit» за awg-uplink, ≠ public_ip.
  --mtproto-no-dpi          mtbuddy install --no-dpi (без nginx/nf/tcpmss).
  --mtproto-middle-proxy    mtbuddy install --middle-proxy.
  --mtproto-no-drs          Не выставлять в config.toml drs = true ([censorship]; по умолчанию включаем).

Дашборд MTProto и nginx (только при --with-mtproto-proxy)
  --mtproto-no-dashboard    Не вызывать mtbuddy setup dashboard.
  --mtproto-no-dashboard-nginx  Не добавлять location /dashboard/ в nginx-маску.
  --mtproto-dashboard-user U       Basic Auth (по умолчанию admin).
  --mtproto-dashboard-password P   Basic Auth; иначе пароль в /root/.awg-uplink-mtproto-dashboard.password при первом создании.
  --mtproto-dashboard-nginx-port N  Перекрыть [censorship] mask_port для поиска vhost (часто 8443).
  --mtproto-dashboard-nginx-site PATH  Явный путь к .conf nginx с listen mask_port.

Переменные окружения (дублируют опции)
  AmneziaWG:  AMNEZIAWG_FROM_SOURCE, AMNEZIAWG_REINSTALL, AMNEZIAWG_KERNEL_REPO, AMNEZIAWG_TOOLS_REPO,
              AMNEZIAWG_SRC_CACHE, AMNEZIAWG_KERNEL_SOURCE
  MTProto:    WITH_MTPROTO_PROXY=1, MTPROTO_BOOTSTRAP_URL, MTPROTO_PORT, MTPROTO_DOMAIN, MTPROTO_USER, MTPROTO_SECRET,
              MTPROTO_PUBLIC_IP, MTPROTO_MIDDLE_PROXY_NAT_IP, MTPROTO_EGRESS_IP_URL,
              MTPROTO_NO_DPI=1, MTPROTO_MIDDLE_PROXY=1, MTPROTO_DRS=0 — не включать drs в [censorship],
              MTPROTO_DASHBOARD=0
  Дашборд:   MTPROTO_DASHBOARD_NGINX=0, MTPROTO_DASHBOARD_NGINX_MASK_PORT, MTPROTO_DASHBOARD_NGINX_SITE,
              MTPROTO_DASHBOARD_USER, MTPROTO_DASHBOARD_PASSWORD, MTPROTO_DASHBOARD_MONITOR_ADDR, MTPROTO_DASHBOARD_MONITOR_PORT
  Docker:    AMNEZIA_DOCKER_NAME_PATTERN (ERE имени контейнера), AMNEZIA_DOCKER_NAMES — явный список имён (перекрывает шаблон); см. lib/awg-inject-uplink-policy.sh --help

Шаги скрипта
  1) Проверка Docker Amnezia
  2) Установка amneziawg (apt или из исходников)
  3) lib/awg-inject-uplink-policy.sh → ${CANON_STEM}.conf и policy
  4) systemctl enable --now awg-quick@${CANON_STEM}
  5) При --with-mtproto-proxy: mtbuddy, public_ip, middle_proxy_nat_ip, drs в [censorship] (если не отключено), снятие старых tunnel-артефактов,
     дашборд (если включён), nginx /dashboard/ (если дашборд и nginx и MTPROTO_DASHBOARD_NGINX не выключены)

Подсказки: при use_middle_proxy=false MiddleProxy для медиа/DC203 всё ещё возможен (force_media_middle_proxy в config.toml upstream).
EOF
	exit "$ex"
}

POSITIONAL=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	-h | --help) usage 0 ;;
	--amneziawg-from-source) AMNEZIAWG_FROM_SOURCE=1 ;;
	--amneziawg-reinstall) AMNEZIAWG_REINSTALL=1 ;;
	--split-routing-wizard) SPLIT_ROUTING_WIZARD=1 ;;
	--with-mtproto-proxy) WITH_MTPROTO_PROXY=1 ;;
	--mtproto-no-dpi) MTPROTO_NO_DPI=1 ;;
	--mtproto-middle-proxy) MTPROTO_MIDDLE_PROXY=1 ;;
	--mtproto-no-drs) MTPROTO_DRS=0 ;;
	--mtproto-no-dashboard) MTPROTO_DASHBOARD=0 ;;
	--mtproto-no-dashboard-nginx) MTPROTO_DASHBOARD_NGINX=0 ;;
	--mtproto-dashboard-user)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_DASHBOARD_USER=$2
		shift 2
		continue
		;;
	--mtproto-dashboard-password)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_DASHBOARD_PASSWORD=$2
		shift 2
		continue
		;;
	--mtproto-dashboard-nginx-port)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_DASHBOARD_NGINX_MASK_PORT=$2
		shift 2
		continue
		;;
	--mtproto-dashboard-nginx-site)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_DASHBOARD_NGINX_SITE=$2
		shift 2
		continue
		;;
	--mtproto-port)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_PORT=$2
		shift 2
		continue
		;;
	--mtproto-domain)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_DOMAIN=$2
		shift 2
		continue
		;;
	--mtproto-user)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_USER=$2
		shift 2
		continue
		;;
	--mtproto-secret)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_SECRET=$2
		shift 2
		continue
		;;
	--mtproto-public-ip)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_PUBLIC_IP=$2
		shift 2
		continue
		;;
	--mtproto-middle-proxy-nat-ip)
		[[ -n ${2-} ]] || die "ожидалось значение после $1"
		MTPROTO_MIDDLE_PROXY_NAT_IP=$2
		shift 2
		continue
		;;
	--)
		shift
		POSITIONAL+=("$@")
		break
		;;
	-*)
		die "неизвестная опция: $1 (см. --help)"
		;;
	*)
		POSITIONAL+=("$1")
		;;
	esac
	shift
done

[[ ${#POSITIONAL[@]} -eq 1 ]] || usage
INPUT=$(readlink -f "${POSITIONAL[0]}" 2>/dev/null || echo "${POSITIONAL[0]}")
[[ -f $INPUT ]] || die "нет файла: $INPUT"

[[ ${EUID:-0} -eq 0 ]] || die "нужны права root: sudo $0 \"$INPUT\""

ROOTDIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
INJECT="$ROOTDIR/lib/awg-inject-uplink-policy.sh"
[[ -f $INJECT ]] || die "нет $INJECT"

banner_need_amnezia_app() {
	cat >&2 <<'EOF'

================================================================================
  Сервер AmneziaVPN в Docker не обнаружен (нет запущенного контейнера с
  ожидаемым именем).

  Сначала настройте VPN-сервер через приложение AmneziaVPN: подключитесь к
  этому хосту по SSH и выполните развёртывание из приложения, либо убедитесь,
  что контейнер с AmneziaWG уже создан и запущен (docker ps).

  После того как сервер в Docker будет в статусе Up, снова запустите этот скрипт.

  По умолчанию ищется имя по шаблону ^amnezia-awg (amnezia-awg, amnezia-awg2, …). Свои имена:
    AMNEZIA_DOCKER_NAMES="имя1 имя2" sudo ./awg-uplink-bootstrap.sh …
  Свой шаблон: AMNEZIA_DOCKER_NAME_PATTERN='^my-amnezia-'

  Проверка вручную: docker ps --format '{{.Names}}'
================================================================================

EOF
}

docker_amnezia_server_running() {
	local n line pat=${AMNEZIA_DOCKER_NAME_PATTERN:-^amnezia-awg}
	command -v docker >/dev/null 2>&1 || return 1
	if ! docker info >/dev/null 2>&1; then
		warn "Docker недоступен (демон не запущен или нет прав). Проверьте: systemctl status docker"
		return 1
	fi
	if [[ -n ${AMNEZIA_DOCKER_NAMES:-} ]] && [[ -n ${AMNEZIA_DOCKER_NAMES// } ]]; then
		for n in $AMNEZIA_DOCKER_NAMES; do
			[[ -n $n ]] || continue
			if docker ps --format '{{.Names}}' 2>/dev/null | grep -Fxq "$n"; then
				return 0
			fi
		done
		return 1
	fi
	while IFS= read -r line; do
		[[ -n $line ]] || continue
		[[ $line =~ $pat ]] && return 0
	done < <(docker ps --format '{{.Names}}' 2>/dev/null)
	return 1
}

require_docker_amnezia() {
	if docker_amnezia_server_running; then
		return 0
	fi
	banner_need_amnezia_app
	exit 2
}

awg_quick_present() {
	command -v awg-quick >/dev/null 2>&1
}

stop_awg_uplink_for_module_change() {
	if systemctl is-active --quiet "awg-quick@${CANON_STEM}.service" 2>/dev/null; then
		log "Останавливаю awg-quick@${CANON_STEM} перед сменой модуля amneziawg…"
		systemctl stop "awg-quick@${CANON_STEM}.service" || true
	fi
	if lsmod 2>/dev/null | grep -q '^amneziawg'; then
		modprobe -r amneziawg 2>/dev/null || true
	fi
}

read_amneziawg_dkms_version() {
	local srcdir=$1
	[[ -f $srcdir/dkms.conf ]] || die "нет $srcdir/dkms.conf в клоне ядра AmneziaWG"
	sed -n 's/^PACKAGE_VERSION="\([^"]*\)".*/\1/p' "$srcdir/dkms.conf"
}

purge_apt_amneziawg_if_installed() {
	local p
	for p in amneziawg amneziawg-dkms; do
		if dpkg -s "$p" >/dev/null 2>&1; then
			log "Удаляю пакет $p (конфликт с установкой из исходников)…"
			DEBIAN_FRONTEND=noninteractive apt-get purge -y "$p" || die "не удалось удалить $p"
		fi
	done
}

sync_git_shallow() {
	local url=$1 dest=$2
	if [[ ${AMNEZIAWG_REINSTALL:-0} -eq 1 ]] && [[ -d $dest ]]; then
		rm -rf "$dest"
	fi
	if [[ ! -d $dest/.git ]]; then
		git clone --depth 1 "$url" "$dest" || die "git clone не удался: $url"
	else
		git -C "$dest" pull --ff-only 2>/dev/null || true
	fi
}

ensure_amneziawg_from_source() {
	if [[ ${AMNEZIAWG_REINSTALL:-0} -eq 0 ]] && awg_quick_present; then
		log "awg-quick уже в PATH — сборка из исходников не выполняется (нужна переустановка: --amneziawg-reinstall)."
		return 0
	fi

	[[ -f /etc/os-release ]] || die "нет /etc/os-release"
	# shellcheck disable=1091
	. /etc/os-release
	export DEBIAN_FRONTEND=noninteractive

	case "${ID:-}" in
	ubuntu | pop | debian | devuan | raspbian) ;;
	*)
		die "дистрибутив «${ID:-unknown}» — автоматическую сборку amneziawg из исходников не делаем. Используйте пакет вручную или другой дистрибутив."
		;;
	esac

	stop_awg_uplink_for_module_change
	purge_apt_amneziawg_if_installed

	apt-get update -qq
	apt-get install -y ca-certificates git dkms build-essential pkg-config \
		"linux-headers-$(uname -r)" libelf-dev || die "не удалось установить зависимости сборки"

	mkdir -p "$AMNEZIAWG_SRC_CACHE"
	local kroot troot ksrc dver
	kroot="$AMNEZIAWG_SRC_CACHE/amneziawg-linux-kernel-module"
	troot="$AMNEZIAWG_SRC_CACHE/amneziawg-tools"

	sync_git_shallow "$AMNEZIAWG_KERNEL_REPO" "$kroot"
	sync_git_shallow "$AMNEZIAWG_TOOLS_REPO" "$troot"

	ksrc="$kroot/src"
	[[ -d $ksrc ]] || die "ожидался каталог $ksrc"
	dver=$(read_amneziawg_dkms_version "$ksrc")

	local mod_id
	while IFS= read -r mod_id; do
		[[ -n $mod_id ]] || continue
		dkms remove "$mod_id" --all --force 2>/dev/null || true
	done < <(dkms status 2>/dev/null | awk -F', ' '/^amneziawg\// {print $1}' || true)
	rm -rf /usr/src/amneziawg-* 2>/dev/null || true

	if [[ -n ${AMNEZIAWG_KERNEL_SOURCE:-} ]]; then
		[[ -d $AMNEZIAWG_KERNEL_SOURCE ]] || die "AMNEZIAWG_KERNEL_SOURCE не каталог: $AMNEZIAWG_KERNEL_SOURCE"
		ln -sfn "$AMNEZIAWG_KERNEL_SOURCE" "$ksrc/kernel"
	fi

	(
		cd "$ksrc"
		make dkms-install || die "make dkms-install в $ksrc не удался"
	)
	dkms add -m amneziawg -v "$dver" || die "dkms add amneziawg/$dver"
	dkms build -m amneziawg -v "$dver" \
		|| die "dkms build не удался (ядро $(uname -r)). При необходимости задайте AMNEZIAWG_KERNEL_SOURCE — см. README https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)"
	dkms install -m amneziawg -v "$dver" || die "dkms install amneziawg/$dver"

	(
		cd "$troot/src"
		[[ -f Makefile ]] || die "нет $troot/src/Makefile"
		make clean 2>/dev/null || true
		make WITH_BASHCOMPLETION=yes WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes \
			|| die "сборка amneziawg-tools не удалась"
		make WITH_BASHCOMPLETION=yes WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes install \
			|| die "установка amneziawg-tools не удалась"
	)

	depmod -a 2>/dev/null || true
	modprobe amneziawg 2>/dev/null || true

	awg_quick_present || die "после сборки из исходников awg-quick не найден в PATH"
	log "AmneziaWG: DKMS $dver и amneziawg-tools установлены из исходников."
}

add_amnezia_apt_debian() {
	if grep -rq 'launchpadcontent.net/amnezia/ppa' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
		return 0
	fi
	apt-get install -y gnupg2 ca-certificates "linux-headers-$(uname -r)" 2>/dev/null || apt-get install -y gnupg2 ca-certificates
	# Как в README amneziawg-linux-kernel-module; apt-key устарел, но распространён в инструкциях Amnezia.
	apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828 2>/dev/null \
		|| die "не удалось импортировать ключ PPA Amnezia (57290828); проверьте сеть и gpg"
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
	if awg_quick_present && [[ ${AMNEZIAWG_REINSTALL:-0} -ne 1 ]]; then
		log "awg-quick уже в PATH — установка пакета amneziawg не требуется."
		return 0
	fi

	if [[ ${AMNEZIAWG_REINSTALL:-0} -eq 1 ]] && awg_quick_present; then
		stop_awg_uplink_for_module_change
	fi

	[[ -f /etc/os-release ]] || die "нет /etc/os-release"
	# shellcheck disable=1091
	. /etc/os-release
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y ca-certificates curl

	case "${ID:-}" in
	ubuntu | pop)
		add_amnezia_apt_ubuntu
		;;
	debian | devuan | raspbian)
		apt-get install -y software-properties-common 2>/dev/null || true
		add_amnezia_apt_debian
		;;
	*)
		die "дистрибутив «${ID:-unknown}» — автоматическую установку amneziawg не делаем. Установите amneziawg вручную (см. https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) и повторите скрипт."
		;;
	esac

	apt-get update -qq
	if [[ ${AMNEZIAWG_REINSTALL:-0} -eq 1 ]] && dpkg -s amneziawg >/dev/null 2>&1; then
		apt-get install -y --reinstall amneziawg
	else
		apt-get install -y amneziawg
	fi

	awg_quick_present || die "после установки amneziawg не найден awg-quick в PATH (проверьте dpkg -l amneziawg)"
	log "Пакет amneziawg установлен."
}

ensure_amneziawg_dispatch() {
	if [[ ${AMNEZIAWG_FROM_SOURCE:-0} -eq 1 ]]; then
		ensure_amneziawg_from_source
	else
		ensure_amneziawg
	fi
}

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

# Путь к split-env — как в lib/awg-uplink-split-main.sh
awg_uplink_split_env_path() {
	local p=${AWG_UPLINK_SPLIT_ENV:-/etc/awg-uplink-split.env}
	if [[ ! -f $p && -z ${AWG_UPLINK_SPLIT_ENV:-} && -f /etc/amnezia/amneziawg/awg-uplink-split.env ]]; then
		p=/etc/amnezia/amneziawg/awg-uplink-split.env
	fi
	echo "$p"
}

# Ingress для MTProto public_ip / URL дашборда, только если split-routing включён в split-env.
split_routing_ingress_ipv4_if_enabled() {
	local f
	f=$(awg_uplink_split_env_path)
	[[ -f $f ]] || return 1
	local AWG_SPLIT_ENABLE AWG_INGRESS_IPV4
	# shellcheck disable=1090
	set -a
	. "$f"
	set +a
	[[ ${AWG_SPLIT_ENABLE:-0} -eq 1 && -n ${AWG_INGRESS_IPV4:-} ]] || return 1
	echo "$AWG_INGRESS_IPV4"
}

# Авто public_ip / хост дашборда: при split — ingress; иначе прежний detect_mtproto_public_ipv4.
resolve_mtproto_public_ipv4_auto() {
	local pub
	pub=$(split_routing_ingress_ipv4_if_enabled) || true
	[[ -n ${pub:-} ]] && { echo "$pub"; return 0; }
	detect_mtproto_public_ipv4
}

# IPv4 «с земли»: default-маршрут не через awg/wg/tun/… иначе первый поднятый eth/ens/enp с global scope.
detect_mtproto_public_ipv4() {
	local line dev ip
	while IFS= read -r line; do
		[[ $line == default* ]] || continue
		[[ $line =~ dev[[:space:]]+([^[:space:]]+) ]] || continue
		dev="${BASH_REMATCH[1]}"
		[[ $dev =~ ^amn[0-9]+$ ]] && continue
		case "$dev" in
		awg* | wg* | tun* | tap* | vb* | sit* | gre* | ipip* | lo | docker0) continue ;;
		esac
		if [[ $line =~ [[:space:]]src[[:space:]]+([0-9.]+) ]]; then
			echo "${BASH_REMATCH[1]}"
			return 0
		fi
		ip=$(ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk 'NR==1 { gsub(/\/.*/, "", $4); print $4; exit }')
		[[ -n ${ip:-} ]] && echo "$ip" && return 0
	done < <(ip -4 route show default 2>/dev/null || true)
	while IFS= read -r dev; do
		[[ -e "/sys/class/net/$dev" ]] || continue
		ip=$(ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk 'NR==1 { gsub(/\/.*/, "", $4); print $4; exit }')
		[[ -n ${ip:-} ]] && echo "$ip" && return 0
	done < <(ip -o link show up 2>/dev/null | awk -F': ' '$2 ~ /^(eth|ens|enp|eno|enx)/ { sub(/@.*/, "", $2); print $2 }')
	return 1
}

# Публичный IPv4, который видят внешние сервисы при исходящем запросе с хоста (тот же default route, что у curl).
# Если default через awg-uplink — это «exit» за туннелем; public_ip при этом часто берётся с eth без туннеля.
detect_mtproto_egress_public_ipv4() {
	command -v curl >/dev/null 2>&1 || return 1
	command -v python3 >/dev/null 2>&1 || return 1
	local -a urls=()
	[[ -n ${MTPROTO_EGRESS_IP_URL:-} ]] && urls+=("$MTPROTO_EGRESS_IP_URL")
	urls+=(
		https://api4.ipify.org
		https://ipv4.icanhazip.com
		https://v4.ident.me
		https://ifconfig.me/ip
	)
	local url raw
	for url in "${urls[@]}"; do
		[[ -n $url ]] || continue
		raw=$(curl -4 -fsS --max-time 18 "$url" 2>/dev/null | tr -d '\r\n\t ' | head -c 45) || true
		[[ -z $raw ]] && continue
		if printf '%s' "$raw" | python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.stdin.read().strip())" >/dev/null 2>&1; then
			echo "$raw"
			return 0
		fi
	done
	return 1
}

mtproto_public_ip_is_rfc1918() {
	[[ $1 =~ ^10\. ]] && return 0
	[[ $1 =~ ^192\.168\. ]] && return 0
	[[ $1 =~ ^127\. ]] && return 0
	[[ $1 =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
	return 1
}

patch_mtproto_public_ip() {
	local pub=${MTPROTO_PUBLIC_IP:-}
	if [[ -z $pub ]]; then
		pub=$(resolve_mtproto_public_ipv4_auto) || true
	fi
	[[ -n $pub ]] || {
		warn "Не удалось определить IPv4 для [server] public_ip в mtproto; задайте MTPROTO_PUBLIC_IP или --mtproto-public-ip"
		return 0
	}
	if mtproto_public_ip_is_rfc1918 "$pub"; then
		warn "public_ip=$pub — частный (RFC1918/loopback); для MiddleProxy см. [server].middle_proxy_nat_ip в документации mtproto.zig (--help)"
	fi
	local cfg=/opt/mtproto-proxy/config.toml
	[[ -f $cfg ]] || die "нет $cfg"
	command -v python3 >/dev/null 2>&1 || die "нужен python3 для public_ip в $cfg"
	python3 - "$cfg" "$pub" <<'PY'
import re, sys

path, pub = sys.argv[1], sys.argv[2].strip()
lines = open(path, encoding="utf-8").read().splitlines()
out = []
if any(re.match(r"^\s*public_ip\s*=", ln) for ln in lines):
    out = [
        re.sub(r"^\s*public_ip\s*=.*$", f'public_ip = "{pub}"', ln)
        if re.match(r"^\s*public_ip\s*=", ln)
        else ln
        for ln in lines
    ]
else:
    new_out = []
    inserted = False
    for ln in lines:
        new_out.append(ln)
        if ln.strip() == "[server]" and not inserted:
            new_out.append(f'public_ip = "{pub}"')
            inserted = True
    out = new_out

open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
	log "MTProto: в config.toml задан public_ip=$pub (см. --help про force_media_middle_proxy / DC203)"
}

mtproto_ipv4_literal_ok() {
	[[ -n ${1:-} ]] || return 1
	command -v python3 >/dev/null 2>&1 || return 1
	python3 - "$1" <<'PY'
import ipaddress, sys

ipaddress.IPv4Address(sys.argv[1])
PY
}

patch_mtproto_middle_proxy_nat_ip() {
	local nat=${MTPROTO_MIDDLE_PROXY_NAT_IP:-}
	if [[ -z $nat ]]; then
		nat=$(detect_mtproto_egress_public_ipv4) || true
	fi
	[[ -n $nat ]] || {
		warn "Не удалось получить IPv4 для middle_proxy_nat_ip (curl); задайте MTPROTO_MIDDLE_PROXY_NAT_IP или MTPROTO_EGRESS_IP_URL"
		return 0
	}
	if ! mtproto_ipv4_literal_ok "$nat"; then
		warn "middle_proxy_nat_ip — только IPv4-литерал; пропускаю: $nat"
		return 0
	fi
	if mtproto_public_ip_is_rfc1918 "$nat"; then
		warn "middle_proxy_nat_ip=$nat — частный RFC1918; для клиентов снаружи обычно нужен публичный WAN"
	fi
	local cfg=/opt/mtproto-proxy/config.toml
	[[ -f $cfg ]] || die "нет $cfg"
	command -v python3 >/dev/null 2>&1 || die "нужен python3 для middle_proxy_nat_ip в $cfg"
	python3 - "$cfg" "$nat" <<'PY'
import re, sys

path, val = sys.argv[1], sys.argv[2].strip()
key = "middle_proxy_nat_ip"
lines = open(path, encoding="utf-8").read().splitlines()
pat = re.compile(rf"^\s*{re.escape(key)}\s*=")
if any(pat.match(ln) for ln in lines):
    out = [
        re.sub(rf"^\s*{re.escape(key)}\s*=.*$", f'{key} = "{val}"', ln) if pat.match(ln) else ln
        for ln in lines
    ]
else:
    out = list(lines)
    insert_at = None
    for i, ln in enumerate(out):
        if re.match(r"^\s*public_ip\s*=", ln):
            insert_at = i + 1
            break
    if insert_at is None:
        for i, ln in enumerate(out):
            if ln.strip() == "[server]":
                insert_at = i + 1
                break
    if insert_at is not None:
        out.insert(insert_at, f'{key} = "{val}"')
    else:
        out.append(f'{key} = "{val}"')

open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
	log "MTProto: в config.toml задан middle_proxy_nat_ip=$nat"
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

run_mtbuddy_install() {
	command -v curl >/dev/null 2>&1 || die "нужен curl для загрузки mtbuddy"
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

read_mtproto_mask_port() {
	local cfg=/opt/mtproto-proxy/config.toml
	[[ -n ${MTPROTO_DASHBOARD_NGINX_MASK_PORT:-} ]] && echo "$MTPROTO_DASHBOARD_NGINX_MASK_PORT" && return 0
	[[ -f $cfg ]] || {
		echo "8443"
		return 0
	}
	python3 - "$cfg" <<'PY'
import re, sys

path = sys.argv[1]
port = 8443
try:
	for ln in open(path, encoding="utf-8", errors="replace"):
		s = ln.split("#")[0].strip()
		m = re.match(r"mask_port\s*=\s*(\d+)", s)
		if m:
			port = int(m.group(1))
except OSError:
	pass
print(port)
PY
}

ensure_mtproto_dashboard_htpasswd() {
	[[ ${WITH_MTPROTO_PROXY:-0} -eq 1 ]] || return 0
	local f=/etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard
	local user=${MTPROTO_DASHBOARD_USER:-admin}
	local pw sec hash
	sec=/root/.awg-uplink-mtproto-dashboard.password
	if [[ -n ${MTPROTO_DASHBOARD_PASSWORD:-} ]]; then
		pw=$MTPROTO_DASHBOARD_PASSWORD
	elif [[ -s $f ]]; then
		return 0
	else
		pw=$(openssl rand -base64 18 2>/dev/null || openssl rand -hex 16)
		umask 077
		printf '%s\n' "$pw" >"$sec" || die "не удалось записать $sec"
		log "Пароль Basic Auth для дашборда записан в $sec (600); смените после первого входа при необходимости"
	fi
	command -v openssl >/dev/null 2>&1 || die "нужен openssl для Basic Auth дашборда (nginx)"
	hash=$(openssl passwd -apr1 "$pw") || die "openssl passwd -apr1 не удался"
	printf '%s:%s\n' "$user" "$hash" >"${f}.tmp"
	mv -f -- "${f}.tmp" "$f"
	chmod 640 "$f"
	chown root:www-data "$f" 2>/dev/null || chown root:root "$f"
}

setup_mtproto_dashboard_nginx() {
	[[ ${WITH_MTPROTO_PROXY:-0} -eq 1 ]] || return 0
	[[ ${MTPROTO_DASHBOARD:-1} -eq 1 ]] || return 0
	[[ ${MTPROTO_DASHBOARD_NGINX:-1} -eq 1 ]] || return 0
	command -v nginx >/dev/null 2>&1 || {
		warn "nginx не установлен — reverse proxy /dashboard/ пропущен (часто при --mtproto-no-dpi)"
		return 0
	}
	local mask addr mport snippet up legacy_avail legacy_site
	legacy_avail=/etc/nginx/sites-available/awg-uplink-mtproto-dashboard
	legacy_site=/etc/nginx/sites-enabled/awg-uplink-mtproto-dashboard
	if [[ -L $legacy_site || -f $legacy_site ]]; then
		rm -f -- "$legacy_site"
	fi
	[[ -f $legacy_avail ]] && rm -f -- "$legacy_avail"
	mask=$(read_mtproto_mask_port)
	[[ -n ${mask:-} ]] || mask=8443
	addr=${MTPROTO_DASHBOARD_MONITOR_ADDR:-127.0.0.1}
	mport=${MTPROTO_DASHBOARD_MONITOR_PORT:-61208}
	pub_port=${MTPROTO_PORT:-443}
	local fwd_proto=https
	[[ "$pub_port" == "80" ]] && fwd_proto=http
	local dash_redirect_line
	case "$pub_port" in
	443) dash_redirect_line='	return 308 https://$host/dashboard/;' ;;
	80) dash_redirect_line='	return 308 http://$host/dashboard/;' ;;
	*) dash_redirect_line="	return 308 https://\\\$host:${pub_port}/dashboard/;" ;;
	esac
	snippet=/etc/nginx/snippets/awg-uplink-mtproto-dashboard-locations.conf
	local fwd_inc=/etc/nginx/snippets/awg-uplink-mtproto-dashboard-forward.inc
	mkdir -p /etc/nginx/snippets
	ensure_mtproto_dashboard_htpasswd
	cat >"$fwd_inc" <<EOF
# awg-uplink: прокси к embedded dashboard (публичный порт ${pub_port}, маска ${mask})
proxy_set_header Host ${addr}:${mport};
proxy_set_header X-Real-IP \$remote_addr;
proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto ${fwd_proto};
proxy_set_header X-Forwarded-Port ${pub_port};
proxy_set_header X-Forwarded-Host \$host;
proxy_redirect ~^https?://(?:[^/:]+:${mask}|127\.0\.0\.1:${mport})(/.*)\$ https://\$host\$1;
EOF
	cat >"$snippet" <<EOF
# awg-uplink: locations для mtproto dashboard (include из nginx-маски, mask_port=${mask})
location ~* ^/(?:style\.css|app\.js|logo\.svg|favicon\.ico|robots\.txt)$ {
	auth_basic "mtproto dashboard";
	auth_basic_user_file /etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard;
	proxy_http_version 1.1;
	include ${fwd_inc};
	proxy_pass http://${addr}:${mport};
	proxy_read_timeout 3600s;
	proxy_send_timeout 3600s;
}
location ~* ^/(?:chunk-[^/]+\.js|index-[^/]+\.js|vendor-[^/]+\.js)$ {
	auth_basic "mtproto dashboard";
	auth_basic_user_file /etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard;
	proxy_http_version 1.1;
	include ${fwd_inc};
	proxy_pass http://${addr}:${mport};
	proxy_read_timeout 3600s;
	proxy_send_timeout 3600s;
}
location ^~ /api/ {
	auth_basic "mtproto dashboard";
	auth_basic_user_file /etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard;
	proxy_http_version 1.1;
	include ${fwd_inc};
	proxy_buffering off;
	proxy_request_buffering off;
	client_max_body_size 32m;
	proxy_connect_timeout 75s;
	proxy_pass http://${addr}:${mport};
	proxy_read_timeout 3600s;
	proxy_send_timeout 3600s;
}
location ^~ /ws/ {
	auth_basic "mtproto dashboard";
	auth_basic_user_file /etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard;
	proxy_http_version 1.1;
	include ${fwd_inc};
	proxy_set_header Upgrade \$http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_pass http://${addr}:${mport};
	proxy_read_timeout 86400s;
	proxy_send_timeout 86400s;
}
location = /dashboard {
${dash_redirect_line}
}
location /dashboard/ {
	auth_basic "mtproto dashboard";
	auth_basic_user_file /etc/nginx/.htpasswd-awg-uplink-mtproto-dashboard;
	proxy_http_version 1.1;
	include ${fwd_inc};
	proxy_set_header Upgrade \$http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_pass http://${addr}:${mport}/;
	proxy_read_timeout 3600s;
	proxy_send_timeout 3600s;
}
EOF
	command -v python3 >/dev/null 2>&1 || die "нужен python3 для вставки include в nginx-маску"
	set +e
	py_out=$(python3 - "$mask" "${MTPROTO_DASHBOARD_NGINX_SITE:-}" <<'PY'
import pathlib, re, sys

mask_port = int(sys.argv[1])
explicit = (sys.argv[2] or "").strip()
marker = "# awg-uplink: mtproto dashboard (awg-uplink-bootstrap)"
include_line = "include /etc/nginx/snippets/awg-uplink-mtproto-dashboard-locations.conf;"


def listen_line_matches(line: str, port: int) -> bool:
	if re.search(rf"listen\s+[^\n#;]*:{port}\b", line):
		return True
	if re.search(rf"^\s*listen\s+{port}\s*;", line):
		return True
	return False


def find_nginx_site_files():
	out = []
	for base in (pathlib.Path("/etc/nginx/sites-enabled"), pathlib.Path("/etc/nginx/conf.d")):
		if not base.is_dir():
			continue
		for p in sorted(base.iterdir()):
			if p.is_file() and not p.name.startswith("."):
				out.append(p.resolve())
	return out


def pick_target(port: int):
	if explicit:
		p = pathlib.Path(explicit).resolve()
		return p if p.is_file() else None
	for p in find_nginx_site_files():
		try:
			t = p.read_text(encoding="utf-8", errors="replace")
		except OSError:
			continue
		if listen_line_matches(t, port):
			return p
	return None


def inject(path: pathlib.Path, port: int) -> bool:
	text = path.read_text(encoding="utf-8", errors="replace")
	if include_line in text:
		return False
	lines = text.splitlines(keepends=True)
	idx = None
	for i, ln in enumerate(lines):
		if listen_line_matches(ln, port):
			idx = i
			break
	if idx is None:
		raise SystemExit(f"в {path} нет listen на порт {port}")
	m = re.match(r"^(\s*)", lines[idx])
	ind = m.group(1) if m else "\t"
	block = f"{ind}{marker}\n{ind}{include_line}\n"
	lines.insert(idx + 1, block)
	path.write_text("".join(lines), encoding="utf-8")
	return True


def main():
	path = pick_target(mask_port)
	if path is None:
		print(
			f"не найден vhost nginx с listen на mask_port={mask_port} "
			"(проверьте [censorship] mask_port в /opt/mtproto-proxy/config.toml или задайте MTPROTO_DASHBOARD_NGINX_SITE=/path/to/site.conf)",
			file=sys.stderr,
		)
		sys.exit(2)
	changed = inject(path, mask_port)
	print(str(path))
	sys.exit(0 if changed else 3)


main()
PY
	)
	inj_rc=$?
	set -e
	if [[ $inj_rc -eq 2 ]]; then
		warn "Не удалось вставить /dashboard/ в nginx-маску (см. stderr выше)"
		return 0
	fi
	[[ $inj_rc -eq 0 || $inj_rc -eq 3 ]] || die "вставка include в nginx: неожиданный код $inj_rc"
	nginx -t || die "nginx -t не прошёл после правки $py_out"
	if systemctl is-active --quiet nginx 2>/dev/null; then
		systemctl reload nginx || die "systemctl reload nginx не удался"
	else
		systemctl enable nginx 2>/dev/null || true
		systemctl start nginx || die "systemctl start nginx не удался"
	fi
	up=$(resolve_mtproto_public_ipv4_auto || true)
	[[ -n ${up:-} ]] || up="<публичный-IPv4-сервера>"
	SUMMARY_DASHBOARD_URL="https://${up}:${pub_port}/dashboard/"
	SUMMARY_DASHBOARD_USER=${MTPROTO_DASHBOARD_USER:-admin}
	if [[ -n ${MTPROTO_DASHBOARD_PASSWORD:-} ]]; then
		SUMMARY_DASHBOARD_PASSWORD=$MTPROTO_DASHBOARD_PASSWORD
	elif [[ -r /root/.awg-uplink-mtproto-dashboard.password ]]; then
		SUMMARY_DASHBOARD_PASSWORD=$(tr -d '\r\n' </root/.awg-uplink-mtproto-dashboard.password)
	else
		SUMMARY_DASHBOARD_PASSWORD="(см. /root/.awg-uplink-mtproto-dashboard.password или задайте MTPROTO_DASHBOARD_PASSWORD)"
	fi
	log "Дашборд MTProto: ${SUMMARY_DASHBOARD_URL} (Basic Auth; nginx mask_port=${mask}, vhost: $py_out)"
}

setup_mtproto_proxy() {
	remove_legacy_mtproto_tunnel_artifacts
	run_mtbuddy_install
	patch_mtproto_public_ip
	patch_mtproto_middle_proxy_nat_ip
	patch_mtproto_drs
	chown mtproto:mtproto /opt/mtproto-proxy/config.toml 2>/dev/null || true
	systemctl enable mtproto-proxy.service 2>/dev/null || true
	systemctl restart mtproto-proxy.service \
		|| die "mtproto-proxy не запустился: journalctl -u mtproto-proxy -n 50"
	setup_mtproto_dashboard
	setup_mtproto_dashboard_nginx
	fill_mtproto_summary_links
	log "MTProto: исходящий трафик к DC — default route хоста (см. [upstream] в /opt/mtproto-proxy/config.toml)"
	log "MTProto: systemctl status mtproto-proxy; конфиг: /opt/mtproto-proxy/config.toml"
}

# Ссылки tg:// и t.me по README mtproto.zig: secret=ee<32hex><tls_domain_hex>
fill_mtproto_summary_links() {
	[[ ${WITH_MTPROTO_PROXY:-0} -eq 1 ]] || return 0
	local cfg=/opt/mtproto-proxy/config.toml
	[[ -f $cfg ]] || return 0
	command -v python3 >/dev/null 2>&1 || return 0
	local out
	out=$(python3 - "$cfg" "${MTPROTO_USER:-user}" <<'PY'
import re, sys

path, primary = sys.argv[1], sys.argv[2]
try:
    raw_lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
except OSError:
    sys.exit(0)

section = ""
pub_ip, port, tls_domain = None, "443", "wb.ru"
users = {}

for raw in raw_lines:
    ln = raw.split("#", 1)[0].strip()
    if not ln:
        continue
    if ln.startswith("[") and ln.endswith("]"):
        section = ln.strip().lower()
        continue
    if "=" not in ln:
        continue
    key, _, rest = ln.partition("=")
    key = key.strip()
    val = rest.strip()
    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1]
    elif val.startswith("'") and val.endswith("'"):
        val = val[1:-1]
    if section == "[server]":
        if key == "port" and val.isdigit():
            port = val
        elif key == "public_ip":
            pub_ip = val
    elif section == "[censorship]":
        if key == "tls_domain":
            tls_domain = val
    elif section == "[access.users]":
        if re.fullmatch(r"[0-9a-fA-F]{32}", val):
            users[key] = val.lower()

if not pub_ip or not users:
    sys.exit(0)

dom_hex = tls_domain.encode("utf-8").hex()
ordered = []
if primary in users:
    ordered.append((primary, users[primary]))
for k, v in sorted(users.items()):
    if k == primary:
        continue
    ordered.append((k, v))

lines = []
for uname, sec_hex in ordered:
    ee = "ee" + sec_hex + dom_hex
    tg = f"tg://proxy?server={pub_ip}&port={port}&secret={ee}"
    https = f"https://t.me/proxy?server={pub_ip}&port={port}&secret={ee}"
    lines.append(f"  Пользователь «{uname}»:")
    lines.append(f"    {tg}")
    lines.append(f"    {https}")
print("\n".join(lines))
PY
)
	[[ -n ${out// } ]] && SUMMARY_MT_TG_LINES=$out
}

print_bootstrap_summary() {
	log ""
	log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	log "Итог: awg-uplink — awg-quick@${CANON_STEM} активен"
	if [[ ${WITH_MTPROTO_PROXY:-0} -eq 1 ]]; then
		log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		log "MTProto — ссылки для Telegram (tg:// и t.me):"
		if [[ -n ${SUMMARY_MT_TG_LINES:-} ]]; then
			printf '%s\n' "$SUMMARY_MT_TG_LINES"
		else
			log "  (нет ссылок: в config.toml нужны public_ip и [access.users] с 32 hex)"
		fi
		if [[ -n ${SUMMARY_DASHBOARD_URL:-} ]]; then
			log ""
			log "MTProto — дашборд по HTTPS (nginx, Basic Auth):"
			log "  URL:      ${SUMMARY_DASHBOARD_URL}"
			log "  Логин:    ${SUMMARY_DASHBOARD_USER:-}"
			log "  Пароль:   ${SUMMARY_DASHBOARD_PASSWORD:-}"
		fi
	else
		log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	fi
	log ""
}

main() {
	log "Шаг 1/4: проверка Docker (Amnezia)…"
	require_docker_amnezia
	log "Шаг 2/4: AmneziaWG…"
	ensure_amneziawg_dispatch
	export AMNEZIA_DOCKER_NAME_PATTERN="${AMNEZIA_DOCKER_NAME_PATTERN:-^amnezia-awg}"
	if [[ -v AMNEZIA_DOCKER_NAMES ]]; then
		export AMNEZIA_DOCKER_NAMES
	else
		unset AMNEZIA_DOCKER_NAMES 2>/dev/null || true
	fi
	log "Шаг 3/4: inject uplink policy…"
	bash -- "$INJECT" "$INPUT"
	if [[ ${SPLIT_ROUTING_WIZARD:-0} -eq 1 ]]; then
		log "Мастер split-routing (ingress/egress)…"
		bash -- "$ROOTDIR/lib/awg-uplink-split-wizard.sh" || die "мастер split-routing завершился с ошибкой"
	fi
	systemctl daemon-reload
	systemctl enable "awg-quick@${CANON_STEM}.service"
	systemctl restart "awg-quick@${CANON_STEM}.service"
	systemctl --no-pager --full status "awg-quick@${CANON_STEM}.service" || true
	log "Шаг 4/4: awg-quick@${CANON_STEM} включён и перезапущен."
	if [[ ${WITH_MTPROTO_PROXY:-0} -eq 1 ]]; then
		log "Дополнительно: MTProto (mtbuddy)…"
		setup_mtproto_proxy
		systemctl --no-pager --full status mtproto-proxy.service || true
	fi
	print_bootstrap_summary
}

main

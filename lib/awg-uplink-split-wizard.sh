#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Интерактивная настройка split-routing (не только Amnezia): ingress / egress, unit awg-uplink-split@IFACE.
# Конфиг по умолчанию: /etc/awg-uplink-split.env (общесистемный, не в каталоге amnezia).

set -euo pipefail

SPLIT_ENV=${AWG_UPLINK_SPLIT_ENV:-/etc/awg-uplink-split.env}
ROOTDIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)
UNIT_SRC="$ROOTDIR/systemd/awg-uplink-split@.service"
MAIN_SRC="$ROOTDIR/lib/awg-uplink-split-main.sh"
MAIN_DST=/usr/local/sbin/awg-uplink-split-main.sh

die() { echo "[awg-split-wizard] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-split-wizard] $*"; }
warn() { echo "[awg-split-wizard] WARN: $*" >&2; }

usage() {
	local ex=${1:-1}
	cat >&2 <<EOF
Использование: $0

  Интерактивно (нужен TTY): список IPv4 на интерфейсах (кроме awg/wg/tun), выбор ingress для
  правила policy (from IP → table uplink) и egress для default route с src=.

  Запуск от root. После завершения (файл настроек, см. AWG_UPLINK_SPLIT_ENV):
    $SPLIT_ENV
    systemctl enable --now awg-uplink-split@<интерфейс>.service

  Повторный запуск перезапишет $SPLIT_ENV и обновит unit.

Из bootstrap:
  sudo ./awg-uplink-bootstrap.sh --split-routing-wizard /path/to/exported.conf
EOF
	exit "$ex"
}

case "${1:-}" in -h | --help) usage 0 ;; esac

[[ ${EUID:-0} -eq 0 ]] || die "нужен root"
[[ -t 0 ]] || die "нужен интерактивный терминал (TTY); запустите: sudo $0"

[[ -f $MAIN_SRC ]] || die "нет $MAIN_SRC"
[[ -f $UNIT_SRC ]] || die "нет $UNIT_SRC"

is_awg_family() {
	[[ $1 =~ ^amn[0-9]+$ ]] && return 0
	case "$1" in
	awg* | wg* | tun* | tap* | vb* | sit* | gre* | ipip* | docker0) return 0 ;;
	esac
	return 1
}

collect_addrs() {
	local dev ip pfx
	declare -gA ADDR_DEV=()
	declare -ga ADDR_LIST=()
	while read -r dev ip; do
		[[ -n $dev && -n $ip ]] || continue
		is_awg_family "$dev" && continue
		pfx=${ip%%/*}
		[[ $pfx =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || continue
		ADDR_DEV["$pfx"]=$dev
	done < <(ip -4 -o addr show scope global 2>/dev/null | awk '
	$2 ~ /^(awg|wg|tun|tap|vb|sit|gre|ipip|docker0|amn[0-9]+)/ { next }
	$3 != "inet" { next }
	{
		ip = $4
		sub(/\/.*/, "", ip)
		if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $2, ip
	}')
	mapfile -t ADDR_LIST < <(printf '%s\n' "${!ADDR_DEV[@]}" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
}

# Подсказка шлюза: та же подсеть, последний октет = 1 (как типичный LAN gateway).
default_gw_from_ip() {
	local host_ip=$1 head
	head=${host_ip%.*}
	[[ $head == "$host_ip" ]] && echo "" && return
	echo "${head}.1"
}

pick_from_list() {
	local title=$1
	local -n arr=$2
	local i n=${#arr[@]}
	local choice
	[[ $n -gt 0 ]] || die "нет адресов для выбора"
	echo "" >&2
	echo "=== $title ===" >&2
	for ((i = 0; i < n; i++)); do
		printf '  %d) %s (dev %s)\n' "$((i + 1))" "${arr[i]}" "${ADDR_DEV[${arr[i]}]:-?}" >&2
	done
	while true; do
		read -r -p "Номер [1-$n]: " choice >&2 || true
		[[ -n $choice ]] || continue
		[[ $choice =~ ^[0-9]+$ ]] || continue
		((choice >= 1 && choice <= n)) || continue
		echo "${arr[choice - 1]}"
		return 0
	done
}

ask_gw() {
	local label=$1 suggested=$2
	local g
	read -r -p "$label [Enter = $suggested, «-» = без шлюза]: " g || true
	if [[ ${g:-} == "-" ]]; then
		echo ""
	elif [[ -n ${g:-} ]]; then
		echo "$g"
	else
		echo "$suggested"
	fi
}

collect_addrs
[[ ${#ADDR_LIST[@]} -gt 0 ]] || die "не найдено ни одного глобального IPv4 (кроме awg/wg/tun/…)"

INGRESS=$(pick_from_list "Адрес, на который клиенты подключаются (WireGuard / публичный)" ADDR_LIST)
ING_DEV=${ADDR_DEV[$INGRESS]}

EGRESS=$(pick_from_list "Адрес, с которого должен уходить трафик сервера и uplink (другой адрес или тот же)" ADDR_LIST)
EG_DEV=${ADDR_DEV[$EGRESS]}

SG_ING=$(default_gw_from_ip "$INGRESS")
SG_EG=$(default_gw_from_ip "$EGRESS")
ING_GW=$(ask_gw "Шлюз для маршрутизации, связанной с ingress ($INGRESS)" "${SG_ING:-}")
EG_GW=$(ask_gw "Шлюз для default route (egress, $EGRESS)" "${SG_EG:-}")

read -r -p "Интерфейс для systemd (запуск apply при поднятии линка) [${EG_DEV}]: " BIND_IF || true
BIND_IF=${BIND_IF:-$EG_DEV}
[[ -n $BIND_IF ]] || die "пустой интерфейс"

install -m755 "$MAIN_SRC" "$MAIN_DST"
install -m644 "$UNIT_SRC" "/etc/systemd/system/awg-uplink-split@.service"

umask 077
{
	echo "# Сгенерировано awg-uplink-split-wizard.sh — не правьте формат вручную без необходимости"
	echo "AWG_SPLIT_ENABLE=1"
	printf 'AWG_INGRESS_IPV4=%q\n' "$INGRESS"
	printf 'AWG_INGRESS_DEV=%q\n' "$ING_DEV"
	printf 'AWG_INGRESS_GW=%q\n' "$ING_GW"
	printf 'AWG_EGRESS_IPV4=%q\n' "$EGRESS"
	printf 'AWG_EGRESS_DEV=%q\n' "$EG_DEV"
	printf 'AWG_EGRESS_GW=%q\n' "$EG_GW"
	echo "AWG_EGRESS_METRIC=100"
	printf 'AWG_SPLIT_BIND_IFACE=%q\n' "$BIND_IF"
} >"$SPLIT_ENV.tmp.$$"
mv -f -- "$SPLIT_ENV.tmp.$$" "$SPLIT_ENV"

systemctl enable "awg-uplink-split@${BIND_IF}.service" 2>/dev/null || true
# RemainAfterExit=yes: повторный start не вызывает ExecStart — нужен restart, чтобы применить новый split.env
systemctl daemon-reload
systemctl restart "awg-uplink-split@${BIND_IF}.service" || warn "awg-uplink-split@${BIND_IF} не перезапустился — проверьте: systemctl status awg-uplink-split@${BIND_IF}"

log "Записано: $SPLIT_ENV"
log "Unit: awg-uplink-split@${BIND_IF}.service (apply main default с src=$EGRESS)"
if systemctl is-enabled --quiet awg-quick@awg-uplink.service 2>/dev/null \
	|| systemctl is-active --quiet awg-quick@awg-uplink.service 2>/dev/null; then
	systemctl restart awg-quick@awg-uplink.service \
		|| warn "не удалось перезапустить awg-quick@awg-uplink — systemctl status awg-quick@awg-uplink"
fi

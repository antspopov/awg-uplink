#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Main table: default IPv4 route с src=AWG_EGRESS_IPV4 (исходящий трафик сервера с выбранного адреса).
# Читает /etc/awg-uplink-split.env (или AWG_UPLINK_SPLIT_ENV). Вызывается systemd awg-uplink-split@IFACE или вручную.

set -euo pipefail

SPLIT_ENV=${AWG_UPLINK_SPLIT_ENV:-/etc/awg-uplink-split.env}
if [[ ! -f $SPLIT_ENV && -z ${AWG_UPLINK_SPLIT_ENV:-} && -f /etc/amnezia/amneziawg/awg-uplink-split.env ]]; then
	SPLIT_ENV=/etc/amnezia/amneziawg/awg-uplink-split.env
fi
STATE=/run/awg-uplink-split-main.state

die() { echo "[awg-split-main] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-split-main] $*"; }

usage() {
	cat >&2 <<EOF
Использование: $0 apply | remove

  apply  — заменить default IPv4 на dev \$AWG_EGRESS_DEV с шлюзом \$AWG_EGRESS_GW и src=\$AWG_EGRESS_IPV4
  remove — восстановить сохранённый default (из state)

Конфиг: $SPLIT_ENV (см. lib/awg-uplink-split-wizard.sh)
EOF
	exit 1
}

[[ $# -eq 1 ]] || usage
ACTION=$1

[[ -f $SPLIT_ENV ]] || {
	log "нет $SPLIT_ENV — нечего делать"
	exit 0
}
# shellcheck disable=1090
set -a
. "$SPLIT_ENV"
set +a

[[ ${AWG_SPLIT_ENABLE:-0} -eq 1 ]] || {
	log "AWG_SPLIT_ENABLE не 1 — пропуск"
	exit 0
}
[[ -n ${AWG_EGRESS_DEV:-} && -n ${AWG_EGRESS_IPV4:-} ]] || die "нужны AWG_EGRESS_DEV и AWG_EGRESS_IPV4 в $SPLIT_ENV"

apply() {
	local old
	[[ -e $STATE ]] && die "уже применено (есть $STATE); сначала: $0 remove"
	old=$(ip -4 route show default dev "$AWG_EGRESS_DEV" 2>/dev/null | head -1 || true)
	[[ -n $old ]] || old=$(ip -4 route show default 2>/dev/null | head -1 || true)
	printf '%s\n' "$old" >"$STATE.tmp.$$"
	mv -f -- "$STATE.tmp.$$" "$STATE"
	while ip -4 route del default dev "$AWG_EGRESS_DEV" 2>/dev/null; do true; done
	if [[ -n ${AWG_EGRESS_GW:-} ]]; then
		ip -4 route replace default via "$AWG_EGRESS_GW" dev "$AWG_EGRESS_DEV" src "$AWG_EGRESS_IPV4" metric "${AWG_EGRESS_METRIC:-100}"
	else
		ip -4 route replace default dev "$AWG_EGRESS_DEV" src "$AWG_EGRESS_IPV4" metric "${AWG_EGRESS_METRIC:-100}"
	fi
	log "main: default через $AWG_EGRESS_DEV src=$AWG_EGRESS_IPV4 (было: $(tr -d '\n' <"$STATE"))"
}

remove() {
	[[ -f $STATE ]] || return 0
	local old
	old=$(tr -d '\r\n' <"$STATE")
	rm -f -- "$STATE"
	while ip -4 route del default dev "$AWG_EGRESS_DEV" 2>/dev/null; do true; done
	if [[ -n $old ]]; then
		# shellcheck disable=2086
		ip -4 route replace $old 2>/dev/null || true
	fi
	log "main: default восстановлен (если возможно): $old"
}

case "$ACTION" in
apply) apply ;;
remove) remove ;;
*) usage ;;
esac

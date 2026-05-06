#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Selective geo-routing:
# - при включении переводит main default на egress;
# - только dst из geo-списка получают fwmark и идут через awg-uplink (таблица AWG_GEO_TABLE).

set -euo pipefail

ENV_FILE=${AWG_GEO_ENV_FILE:-/etc/awg-uplink-geo-routing.env}
STATE_FILE=${AWG_GEO_STATE_FILE:-/run/awg-uplink-geo-routing.state}
die() { echo "[awg-geo-routing] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-geo-routing] $*"; }
warn() { echo "[awg-geo-routing] WARN: $*" >&2; }

require_bin() { command -v "$1" >/dev/null 2>&1 || die "нужна команда: $1"; }

load_env() {
	[[ -f $ENV_FILE ]] || die "нет $ENV_FILE"
	# shellcheck disable=1090
	set -a
	. "$ENV_FILE"
	set +a
	GEO_ENABLED=${AWG_GEO_ROUTING_ENABLE:-0}
	AWG_IFACE=${AWG_GEO_AWG_IFACE:-awg-uplink}
	MARK_HEX=${AWG_GEO_MARK_HEX:-0x77a3}
	MARK_DEC=${AWG_GEO_MARK_DEC:-30627}
	RULE_PRIO=${AWG_GEO_RULE_PRIO:-77}
	TABLE_ID=${AWG_GEO_TABLE:-207}
	NFT_TABLE=${AWG_GEO_NFT_TABLE:-awg_geo_routing}
	NFT_SET=${AWG_GEO_NFT_SET:-geo_targets}
	LIST_FILE=${AWG_GEO_LIST_FILE:-/var/lib/awg-uplink/geo-routing/allyouneed.lst}
	MANUAL_LIST_FILE=${AWG_GEO_MANUAL_LIST_FILE:-/etc/awg-uplink-geo-routing.manual.lst}
	# Обход wg-quick catch-all rules (lookup 51820) в geo-режиме: после policy rule 100, но до 32764/32765.
	MAIN_BYPASS_PRIO=${AWG_GEO_MAIN_BYPASS_PRIO:-101}
	POLICY_ENV=${AWG_GEO_POLICY_ENV:-/etc/amnezia/amneziawg/awg-uplink-policy.env}
	UPLINK_TABLE=${AWG_GEO_UPLINK_TABLE:-}
	if [[ -z $UPLINK_TABLE && -f $POLICY_ENV ]]; then
		# shellcheck disable=1090
		set -a
		. "$POLICY_ENV"
		set +a
		UPLINK_TABLE=${TABLE:-200}
	fi
	UPLINK_TABLE=${UPLINK_TABLE:-200}
}

main_default_line() {
	ip -4 route show default 2>/dev/null | awk 'NR==1 { print; exit }'
}

awg_iface_ready() {
	ip link show dev "$AWG_IFACE" >/dev/null 2>&1 || return 1
	local st
	st=$(ip -o link show dev "$AWG_IFACE" 2>/dev/null | awk '{print $9}' || true)
	[[ $st == "UP" || $st == "UNKNOWN" ]]
}

build_nft_from_list() {
	local tmp=$1 first=1 cidr
	{
		echo "table ip $NFT_TABLE {"
		echo "  set $NFT_SET {"
		echo "    type ipv4_addr"
		echo "    flags interval"
		echo "    elements = {"
		{
			[[ -f $LIST_FILE ]] && cat -- "$LIST_FILE"
			[[ -f $MANUAL_LIST_FILE ]] && cat -- "$MANUAL_LIST_FILE"
		} | awk '
			{
				line=$0
				sub(/#.*/, "", line)
				gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
				if (line == "") next
				if (line !~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[12][0-9]|3[0-2])$/) next
				if (!seen[line]++) print line
			}
		' | while IFS= read -r cidr; do
			[[ -n $cidr ]] || continue
			if [[ $first -eq 1 ]]; then
				printf "      %s\n" "$cidr"
				first=0
			else
				printf "      , %s\n" "$cidr"
			fi
		done
		echo "    }"
		echo "  }"
		echo "  chain out_mark {"
		echo "    type route hook output priority mangle; policy accept;"
		echo "    oifname != \"$AWG_IFACE\" ip daddr @$NFT_SET meta mark set $MARK_HEX"
		echo "  }"
		echo "  chain pre_mark {"
		echo "    type filter hook prerouting priority mangle; policy accept;"
		echo "    iifname != \"$AWG_IFACE\" ip daddr @$NFT_SET meta mark set $MARK_HEX"
		echo "  }"
		echo "}"
	} >"$tmp"
}

replace_main_default() {
	local route=$1 line
	[[ -n $route ]] || die "пустой default route для main"
	while IFS= read -r line; do
		[[ -n $line ]] || continue
		# shellcheck disable=SC2086
		ip -4 route del $line 2>/dev/null || true
	done < <(ip -4 route show default 2>/dev/null)
	# shellcheck disable=SC2086
	ip -4 route add $route
}

egress_default_from_uplink_table() {
	ip -4 route show table "$UPLINK_TABLE" default 2>/dev/null | awk 'NR==1 { print; exit }'
}

cmd_base_up() {
	require_bin ip
	require_bin nft
	load_env
	[[ ${GEO_ENABLED:-0} -eq 1 ]] || {
		log "AWG_GEO_ROUTING_ENABLE не 1 — пропуск"
		return 0
	}
	local main_before egress_default
	awg_iface_ready || die "интерфейс $AWG_IFACE не готов (поднимите awg-quick@$AWG_IFACE)"
	main_before=$(main_default_line || true)
	[[ -n $main_before ]] || die "в main нет default route"
	egress_default=$(egress_default_from_uplink_table || true)
	[[ -n $egress_default ]] || die "нет default route в table $UPLINK_TABLE (ожидался egress из awg-uplink-policy)"
	if grep -Eq "(^| )dev[[:space:]]+${AWG_IFACE}([[:space:]]|$)" <<<"$egress_default"; then
		die "table $UPLINK_TABLE содержит default через $AWG_IFACE, нужен egress-default"
	fi

	if [[ ! -f $STATE_FILE ]]; then
		local tmp
		tmp=$(mktemp)
		{
			printf 'MAIN_DEFAULT_BEFORE=%q\n' "$main_before"
		} >"$tmp"
		mv -f -- "$tmp" "$STATE_FILE"
	fi

	replace_main_default "$egress_default"

	ip -4 route replace default dev "$AWG_IFACE" table "$TABLE_ID"
	ip rule del fwmark "$MARK_DEC" table "$TABLE_ID" priority "$RULE_PRIO" 2>/dev/null || true
	ip rule add fwmark "$MARK_DEC" table "$TABLE_ID" priority "$RULE_PRIO"
	ip rule del priority "$MAIN_BYPASS_PRIO" 2>/dev/null || true
	ip rule add priority "$MAIN_BYPASS_PRIO" table main

	log "base-up: main default -> egress (из table $UPLINK_TABLE); mark/rule готовы"
}

cmd_apply_list() {
	require_bin nft
	load_env
	[[ ${GEO_ENABLED:-0} -eq 1 ]] || {
		log "AWG_GEO_ROUTING_ENABLE не 1 — пропуск"
		return 0
	}
	if [[ ! -s $LIST_FILE && ! -s $MANUAL_LIST_FILE ]]; then
		warn "нет списков префиксов ($LIST_FILE и $MANUAL_LIST_FILE) — apply-list пропущен"
		return 0
	fi
	local nft_tmp

	nft_tmp=$(mktemp)
	build_nft_from_list "$nft_tmp"
	nft delete table ip "$NFT_TABLE" 2>/dev/null || true
	nft -f "$nft_tmp"
	rm -f -- "$nft_tmp"
	log "apply-list: nft set обновлён (base: $LIST_FILE, manual: $MANUAL_LIST_FILE)"
}

cmd_up() {
	cmd_base_up
	cmd_apply_list
	log "включено: main default -> egress; dst из списка -> $AWG_IFACE"
}

cmd_down() {
	require_bin ip
	require_bin nft
	# down должен срабатывать даже при AWG_GEO_ROUTING_ENABLE=0,
	# чтобы снять ранее применённые правила/таблицы.
	load_env
	ip rule del fwmark "$MARK_DEC" table "$TABLE_ID" priority "$RULE_PRIO" 2>/dev/null || true
	ip rule del priority "$MAIN_BYPASS_PRIO" 2>/dev/null || true
	ip -4 route flush table "$TABLE_ID" 2>/dev/null || true
	nft delete table ip "$NFT_TABLE" 2>/dev/null || true
	if [[ -f $STATE_FILE ]]; then
		# shellcheck disable=1090
		. "$STATE_FILE"
		if [[ -n ${MAIN_DEFAULT_BEFORE:-} ]]; then
			replace_main_default "$MAIN_DEFAULT_BEFORE" || warn "не удалось восстановить main default"
		fi
		rm -f -- "$STATE_FILE"
	fi
	log "выключено: mark/rule/table/nft сняты"
}

usage() {
	cat >&2 <<EOF
Использование: $0 up | down | base-up | apply-list
EOF
	exit 1
}

case "${1:-}" in
up) cmd_up ;;
base-up) cmd_base_up ;;
apply-list) cmd_apply_list ;;
down) cmd_down ;;
*) usage ;;
esac


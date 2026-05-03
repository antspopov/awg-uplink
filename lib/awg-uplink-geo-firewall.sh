#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# nft: маркировка трафика к dst ∈ staging ∪ route → fwmark → table uplink (как awg-uplink-policy).
# Вызывается PostUp/PostDown awg-quick (см. awg-uplink-geo-install.sh).

set -euo pipefail

POLICY_ENV=${AWG_GEO_POLICY_ENV:-/etc/amnezia/amneziawg/awg-uplink-policy.env}
GEO_ENV=${AWG_GEO_ENV:-/etc/awg-uplink-geo.env}
ROT=/usr/local/sbin/awg-uplink-geo-ipset-rotate.sh
NFT_TABLE=awg_uplink_geo

die() { echo "[awg-geo-fw] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-geo-fw] $*"; }

load_policy() {
	[[ -f $POLICY_ENV ]] || die "нет $POLICY_ENV"
	# shellcheck disable=1090
	set -a
	. "$POLICY_ENV"
	set +a
	TABLE=${TABLE:-200}
	DOCKER_BR=${DOCKER_MARK_IN:-docker0}
}

load_geo() {
	[[ -f $GEO_ENV ]] || die "нет $GEO_ENV"
	# shellcheck disable=1090
	set -a
	. "$GEO_ENV"
	set +a
	STAGING=${AWG_GEO_IPSET_STAGING:-awg_geo_staging}
	ROUTE=${AWG_GEO_IPSET_ROUTE:-awg_geo_route}
	GEO_DEC=${AWG_GEO_FWMARK_DEC:-30595}
	GEO_HEX=${AWG_GEO_FWMARK_HEX:-0x7783}
	GEO_PRIO=${AWG_GEO_RULE_PRIO:-83}
	NFT_TABLE=${AWG_GEO_NFT_TABLE:-awg_uplink_geo}
}

cmd_down() {
	local t=200 dec=30595 prio=83 tab=${AWG_GEO_NFT_TABLE:-awg_uplink_geo}
	command -v nft >/dev/null 2>&1 || return 0
	[[ -f $GEO_ENV ]] && {
		# shellcheck disable=1090
		set -a
		. "$GEO_ENV"
		set +a
		dec=${AWG_GEO_FWMARK_DEC:-30595}
		prio=${AWG_GEO_RULE_PRIO:-83}
		tab=${AWG_GEO_NFT_TABLE:-awg_uplink_geo}
	}
	if [[ -f $POLICY_ENV ]]; then
		# shellcheck disable=1090
		set -a
		. "$POLICY_ENV"
		set +a
		t=${TABLE:-200}
	fi
	ip rule del fwmark "$dec" table "$t" priority "$prio" 2>/dev/null || true
	nft delete table ip "$tab" 2>/dev/null || true
	log "снято: table ip $tab, ip rule fwmark $dec → table $t"
}

cmd_up() {
	command -v nft >/dev/null 2>&1 || die "нужен nftables (nft)"
	command -v ipset >/dev/null 2>&1 || die "нужен ipset"
	[[ -f $GEO_ENV ]] || die "нет $GEO_ENV"
	# shellcheck disable=1090
	set -a
	. "$GEO_ENV"
	set +a
	[[ ${AWG_GEO_ENABLE:-0} -eq 1 ]] || {
		log "AWG_GEO_ENABLE не 1 — пропуск"
		return 0
	}
	load_policy
	load_geo
	[[ -x $ROT ]] && AWG_GEO_IPSET_STAGING=$STAGING AWG_GEO_IPSET_ROUTE=$ROUTE AWG_GEO_IPSET_MAXELEM=${AWG_GEO_IPSET_MAXELEM:-262144} "$ROT" init

	cmd_down

	nft add table ip "$NFT_TABLE"
	# forward: из Docker (и др. bridge) к dst в geo — в uplink
	nft add chain ip "$NFT_TABLE" forward '{ type filter hook forward priority -25; policy accept; }'
	nft add rule ip "$NFT_TABLE" forward iifname "$DOCKER_BR" ip daddr @"$STAGING" meta mark set "$GEO_HEX"
	nft add rule ip "$NFT_TABLE" forward iifname "$DOCKER_BR" ip daddr @"$ROUTE" meta mark set "$GEO_HEX"
	# output: маркировка до FIB (route hook; при ошибке — filter output на старых nft)
	if ! nft add chain ip "$NFT_TABLE" out_rt '{ type route hook output priority -150; policy accept; }' 2>/dev/null; then
		nft add chain ip "$NFT_TABLE" out_rt '{ type filter hook output priority -25; policy accept; }'
	fi
	nft add rule ip "$NFT_TABLE" out_rt ip daddr @"$STAGING" meta mark set "$GEO_HEX"
	nft add rule ip "$NFT_TABLE" out_rt ip daddr @"$ROUTE" meta mark set "$GEO_HEX"

	ip rule del fwmark "$GEO_DEC" table "$TABLE" priority "$GEO_PRIO" 2>/dev/null || true
	ip rule add fwmark "$GEO_DEC" table "$TABLE" priority "$GEO_PRIO"
	log "nft ip $NFT_TABLE: mark $GEO_HEX → table $TABLE prio $GEO_PRIO (sets $STAGING + $ROUTE, iif $DOCKER_BR)"
}

usage() {
	cat >&2 <<EOF
Использование: $0 up | down

  Переменные: AWG_GEO_ENV, AWG_GEO_POLICY_ENV, AWG_GEO_NFT_TABLE
EOF
	exit 1
}

case "${1:-}" in
up) cmd_up ;;
down) cmd_down ;;
*) usage ;;
esac

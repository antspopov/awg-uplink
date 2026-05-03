#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# nft: перехват DNS (udp/tcp 53) из подсетей Docker → localhost:dnsmasq;
# маркировка forward/output к dst ∈ staging ∪ route → fwmark → table uplink (как awg-uplink-policy).
# Подсети: lib/awg-uplink-geo-docker-subnets.sh (логика как to_main bypass).

set -euo pipefail

POLICY_ENV=${AWG_GEO_POLICY_ENV:-/etc/amnezia/amneziawg/awg-uplink-policy.env}
GEO_ENV=${AWG_GEO_ENV:-/etc/awg-uplink-geo.env}
ROT=/usr/local/sbin/awg-uplink-geo-ipset-rotate.sh
SUBNET_SH=${AWG_GEO_DOCKER_SUBNETS:-/usr/local/lib/awg-uplink/awg-uplink-geo-docker-subnets.sh}
NFT_TABLE=awg_uplink_geo

die() { echo "[awg-geo-fw] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-geo-fw] $*"; }
warn() { echo "[awg-geo-fw] WARN: $*" >&2; }

load_policy() {
	[[ -f $POLICY_ENV ]] || die "нет $POLICY_ENV"
	# shellcheck disable=1090
	set -a
	. "$POLICY_ENV"
	set +a
	TABLE=${TABLE:-200}
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

docker_bridge_ifaces() {
	ip -4 route show table main 2>/dev/null | awk '$2 == "dev" && ($3 ~ /^docker0$/ || $3 ~ /^br-/ || $3 ~ /^amn[0-9]+$/) { print $3 }' | sort -u
}

route_localnet_set() {
	local v=$1 dev
	while IFS= read -r dev; do
		[[ -n $dev ]] || continue
		[[ -e "/sys/class/net/$dev" ]] || continue
		sysctl -q "net.ipv4.conf.${dev}.route_localnet=$v" 2>/dev/null || true
	done < <(docker_bridge_ifaces)
}

collect_docker_cidrs() {
	local out=""
	if [[ -x $SUBNET_SH ]]; then
		out=$(AWG_GEO_POLICY_ENV="$POLICY_ENV" "$SUBNET_SH" 2>/dev/null || true)
	fi
	echo -n "$out"
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
	route_localnet_set 0
	log "снято: table ip $tab, ip rule fwmark $dec → table $t, route_localnet=0 на docker bridge"
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

	local cidrs elem c
	cidrs=$(collect_docker_cidrs)
	elem=""
	for c in $cidrs; do
		[[ -n $c ]] || continue
		[[ -n $elem ]] && elem+=", "
		elem+="$c"
	done

	nft add table ip "$NFT_TABLE"

	if [[ -n $elem ]]; then
		nft add set ip "$NFT_TABLE" docker_nets "{ type ipv4_addr; flags interval; elements = { $elem }; }"
		nft add chain ip "$NFT_TABLE" nat_pre '{ type nat hook prerouting priority -150; policy accept; }'
		nft add rule ip "$NFT_TABLE" nat_pre ip saddr @docker_nets udp dport 53 redirect to :53
		nft add rule ip "$NFT_TABLE" nat_pre ip saddr @docker_nets tcp dport 53 redirect to :53
		log "nat prerouting: DNS из docker-подсетей → localhost:53 ($cidrs)"
		route_localnet_set 1
	else
		warn "подсети Docker пусты ($SUBNET_SH) — нет nat DNS redirect; проверьте docker и awg-uplink-policy.env"
	fi

	if [[ -n $elem ]]; then
		nft add chain ip "$NFT_TABLE" forward '{ type filter hook forward priority -25; policy accept; }'
		nft add rule ip "$NFT_TABLE" forward ip saddr @docker_nets ip daddr @"$STAGING" meta mark set "$GEO_HEX"
		nft add rule ip "$NFT_TABLE" forward ip saddr @docker_nets ip daddr @"$ROUTE" meta mark set "$GEO_HEX"
	else
		warn "нет docker CIDR — цепочка forward geo-mark не создаётся (только output на хосте)"
	fi

	if ! nft add chain ip "$NFT_TABLE" out_rt '{ type route hook output priority -150; policy accept; }' 2>/dev/null; then
		nft add chain ip "$NFT_TABLE" out_rt '{ type filter hook output priority -25; policy accept; }'
	fi
	nft add rule ip "$NFT_TABLE" out_rt ip daddr @"$STAGING" meta mark set "$GEO_HEX"
	nft add rule ip "$NFT_TABLE" out_rt ip daddr @"$ROUTE" meta mark set "$GEO_HEX"

	ip rule del fwmark "$GEO_DEC" table "$TABLE" priority "$GEO_PRIO" 2>/dev/null || true
	ip rule add fwmark "$GEO_DEC" table "$TABLE" priority "$GEO_PRIO"
	log "nft ip $NFT_TABLE: mark $GEO_HEX → table $TABLE prio $GEO_PRIO (geo ipset $STAGING + $ROUTE)"
}

usage() {
	cat >&2 <<EOF
Использование: $0 up | down

  Переменные: AWG_GEO_ENV, AWG_GEO_POLICY_ENV, AWG_GEO_DOCKER_SUBNETS (скрипт списка CIDR), AWG_GEO_NFT_TABLE
EOF
	exit 1
}

case "${1:-}" in
up) cmd_up ;;
down) cmd_down ;;
*) usage ;;
esac

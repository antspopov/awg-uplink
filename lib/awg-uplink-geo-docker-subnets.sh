#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Список приватных IPv4 CIDR Docker (как detect_to_main_cidrs_auto в awg-uplink-policy.sh):
# сети контейнеров Amnezia + dev docker0/br-*/amn* из main + EXTRA_CIDRS.
# Вывод: одна строка, CIDR через пробел (для dnsmasq listen / nft).
#
# Переменные: AWG_GEO_POLICY_ENV — путь к awg-uplink-policy.env (подхватывает AMNEZIA_*, EXTRA_CIDRS).

set -euo pipefail

POLICY_ENV=${AWG_GEO_POLICY_ENV:-/etc/amnezia/amneziawg/awg-uplink-policy.env}
if [[ -f $POLICY_ENV ]]; then
	# shellcheck disable=1090
	set -a
	. "$POLICY_ENV"
	set +a
fi

cidr_list_add() {
	local b="$1" a="$2" x
	[[ -z $a ]] && {
		echo "$b"
		return
	}
	for x in $b; do
		[[ $x == "$a" ]] && {
			echo "$b"
			return
		}
	done
	if [[ -z $b ]]; then
		echo "$a"
	else
		echo "$b $a"
	fi
}

is_private_ipv4_cidr() {
	local p=$1
	[[ $p =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || return 1
	[[ $p =~ ^127\. ]] && return 1
	[[ $p =~ ^10\. ]] && return 0
	[[ $p =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
	[[ $p =~ ^192\.168\. ]] && return 0
	[[ $p =~ ^100\.(6[4-9]|7[0-9]|8[0-9]|9[0-9]|1[01][0-9]|12[0-7])\. ]] && return 0
	return 1
}

detect_docker_cidrs() {
	local out="" d cid net t s c dev pat
	if command -v docker >/dev/null 2>&1; then
		if [[ -n ${AMNEZIA_DOCKER_NAMES:-} ]] && [[ -n ${AMNEZIA_DOCKER_NAMES// } ]]; then
			for d in $AMNEZIA_DOCKER_NAMES; do
				[[ -n $d ]] || continue
				cid=$(docker inspect "$d" -f '{{.Id}}' 2>/dev/null) || continue
				[[ -n ${cid:-} ]] || continue
				while read -r net; do
					[[ -n $net ]] || continue
					while read -r t; do
						[[ -n $t ]] || continue
						is_private_ipv4_cidr "$t" || continue
						out=$(cidr_list_add "$out" "$t")
					done < <(docker network inspect "$net" -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null)
				done < <(docker inspect "$cid" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' 2>/dev/null)
			done
		else
			pat=${AMNEZIA_DOCKER_NAME_PATTERN:-^amnezia-awg}
			while IFS= read -r d; do
				[[ -n $d ]] || continue
				[[ $d =~ $pat ]] || continue
				cid=$(docker inspect "$d" -f '{{.Id}}' 2>/dev/null) || continue
				[[ -n ${cid:-} ]] || continue
				while read -r net; do
					[[ -n $net ]] || continue
					while read -r t; do
						[[ -n $t ]] || continue
						is_private_ipv4_cidr "$t" || continue
						out=$(cidr_list_add "$out" "$t")
					done < <(docker network inspect "$net" -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null)
				done < <(docker inspect "$cid" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' 2>/dev/null)
			done < <(docker ps --format '{{.Names}}' 2>/dev/null)
		fi
	fi
	while read -r c dev _; do
		[[ -n $c && -n $dev ]] || continue
		[[ $c =~ ^[0-9.]+/[0-9]+$ ]] || continue
		[[ $dev =~ ^(docker0|br-[a-f0-9]+|amn[0-9]+)$ ]] || continue
		is_private_ipv4_cidr "$c" || continue
		out=$(cidr_list_add "$out" "$c")
	done < <(ip -4 route show table main 2>/dev/null | awk '$2=="dev" && ($3 ~ /^docker0$/ || $3 ~ /^br-/ || $3 ~ /^amn[0-9]+$/) { print $1, $3 }')
	for s in ${EXTRA_CIDRS:-}; do
		[[ -n $s ]] || continue
		is_private_ipv4_cidr "$s" || continue
		out=$(cidr_list_add "$out" "$s")
	done
	echo -n "$out"
}

detect_docker_cidrs

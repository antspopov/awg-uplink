#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# PostUp/PostDown awg-quick: policy routing, Docker fwmark, bypass to main для ответов к клиентам VPN.
# Параметры: awg-uplink-policy.env рядом с .conf. Вызов: awg-uplink-policy.sh postup|postdown /path/to/awg-uplink.conf

set -euo pipefail

# Маркировка ответов: nft prerouting mangle+5 (после wg-quick), иначе конфликт с iptables-nft.
NFT_PUBUDP_TABLE=${NFT_PUBUDP_TABLE:-awg_uplink_pubudp}
NFT_PUBUDP_CHAIN=${NFT_PUBUDP_CHAIN:-prerouting}
MARK_TAG_BASE='awg-uplink-pubudp'
STATE_DIR=/run

die() { echo "[awg-policy] ERROR: $*" >&2; exit 1; }
warn() { echo "[awg-policy] WARN: $*" >&2; }
log() { echo "[awg-policy] $*"; }

usage() {
	cat >&2 <<EOF
Использование: $0 postup|postdown /path/to/awg-uplink.conf

  postup   — policy routing, опционально mangle/fwmark для ответов Docker VPN
  postdown — снятие правил (состояние в $STATE_DIR)

Конфиг рядом с .conf: awg-uplink-policy.env (см. lib/awg-inject-uplink-policy.sh --help)
EOF
	exit 1
}

[[ $# -ge 2 ]] || usage
ACTION=$1
WGCONF=$(readlink -f "$2" 2>/dev/null || echo "$2")
[[ -f $WGCONF ]] || die "нет файла: $WGCONF"

POL_DIR=$(dirname "$WGCONF")
ENVF="$POL_DIR/awg-uplink-policy.env"
[[ -f $ENVF ]] || ENVF="$POL_DIR/awg-eth0-policy.env"
[[ -f $ENVF ]] || die "нет awg-uplink-policy.env — сначала: lib/awg-inject-uplink-policy.sh /путь/к/исходному.conf (из корня репозитория)"

# shellcheck disable=1090
set -a
. "$ENVF"
set +a

IFACE_KEY=$(basename "$WGCONF" .conf)
[[ -n $IFACE_KEY ]] || die "не удалось имя интерфейса из $WGCONF"
STATE="$STATE_DIR/awg-uplink-policy.${IFACE_KEY}.state"
MARK_TAG="${MARK_TAG_BASE}-${IFACE_KEY}"

TABLE=${TABLE:-200}
PRIORITY=${PRIORITY:-100}
RP_LOOSE=${RP_LOOSE:-2}
RP_RESTORE=${RP_RESTORE:-1}
FWMARK_DEC=${FWMARK_DEC:-30596}
FWMARK_HEX=${FWMARK_HEX:-0x7784}
FW_RULE_PRIO=$((PRIORITY - 15))
DOCKER_MARK_AUTO=${DOCKER_MARK_AUTO:-0}
DOCKER_MARK_IN=${DOCKER_MARK_IN:-}
DOCKER_FORCE_PORT=${DOCKER_FORCE_PORT:-}
NETWORK_BOOT_WAIT_SEC=${NETWORK_BOOT_WAIT_SEC:-120}
NETWORK_BOOT_POLL_SEC=${NETWORK_BOOT_POLL_SEC:-2}
DOCKER_BOOT_WAIT_SEC=${DOCKER_BOOT_WAIT_SEC:-120}
DOCKER_BOOT_POLL_SEC=${DOCKER_BOOT_POLL_SEC:-2}
# Ручной override (пробелом); иначе awg-uplink-policy.sh сам находит подсети (docker + main-table link-маршруты + EXTRA_CIDRS).
TO_MAIN_CIDRS=${TO_MAIN_CIDRS:-}
AMNEZIA_DOCKER_NAME_PATTERN=${AMNEZIA_DOCKER_NAME_PATTERN:-^amnezia-awg}
AMNEZIA_DOCKER_NAMES=${AMNEZIA_DOCKER_NAMES:-}
# Список CIDR, для которых реально добавлены ip rules (для postdown)
TO_MAIN_APPLIED=""

wait_for_default_route() {
	local max=$NETWORK_BOOT_WAIT_SEC step=$NETWORK_BOOT_POLL_SEC e=0
	while [[ $e -lt $max ]]; do
		if ip -4 route show default 2>/dev/null | grep -q '^default '; then
			return 0
		fi
		sleep "$step"
		e=$((e + step))
	done
	die "postup: нет IPv4 default route за ${max}s (проверьте network-online / DHCP)"
}

# При boot awg-quick@ часто стартует раньше Docker: DNAT в nat ещё нет — ждём появления порта.
wait_for_docker_udp_port() {
	local br=$1 max=$DOCKER_BOOT_WAIT_SEC step=$DOCKER_BOOT_POLL_SEC e=0 d
	while [[ $e -lt $max ]]; do
		d=$(detect_dport_nat "$br" || true)
		[[ -n $d ]] && {
			echo "$d"
			return 0
		}
		d=$(detect_dport_docker || true)
		[[ -n $d ]] && {
			echo "$d"
			return 0
		}
		[[ -n ${DOCKER_FORCE_PORT:-} ]] && {
			echo "$DOCKER_FORCE_PORT"
			return 0
		}
		sleep "$step"
		e=$((e + step))
	done
	return 1
}

write_state() {
	{
		echo "DEV=$DEV"
		echo "GW=$GW"
		echo "SRC=$SRC"
		echo "LINK=$LINK"
		echo "TABLE=$TABLE"
		echo "PRIORITY=$PRIORITY"
		echo "RP_RESTORE=$RP_RESTORE"
		echo "DOCKER_ACTIVE=$DOCKER_ACTIVE"
		echo "DOCKER_BR=$DOCKER_BR"
		echo "DOCKER_DPORT=$DOCKER_DPORT"
		echo "FW_RULE_PRIO=$FW_RULE_PRIO"
		echo "FWMARK_DEC=$FWMARK_DEC"
		echo "FWMARK_HEX=$FWMARK_HEX"
		printf 'EXTRA_CIDRS=%q\n' "${EXTRA_CIDRS:-}"
		printf 'TO_MAIN_APPLIED=%q\n' "${TO_MAIN_APPLIED:-}"
	} >"$STATE.tmp.$$"
	mv -f -- "$STATE.tmp.$$" "$STATE"
}

detect_ipv4_default() {
	local line
	DEV=""
	GW=""
	SRC=""
	LINK=""
	if [[ -n ${AWG_DEFAULT_IFACE:-} ]]; then
		line=$(ip -4 route show default dev "$AWG_DEFAULT_IFACE" 2>/dev/null | awk '/^default / { print; exit }' || true)
	fi
	if [[ -z ${line:-} ]]; then
		line=$(ip -4 route show default 2>/dev/null | awk '/^default / { print; exit }' || true)
	fi
	[[ -n $line ]] || die "не найден IPv4 default route"
	if [[ $line =~ dev[[:space:]]+([^[:space:]]+) ]]; then
		DEV="${BASH_REMATCH[1]}"
	fi
	if [[ $line =~ via[[:space:]]+([0-9.]+) ]]; then
		GW="${BASH_REMATCH[1]}"
	else
		GW=""
	fi
	[[ -n $DEV ]] || die "не удалось разобрать интерфейс из: $line"
	if [[ $line =~ [[:space:]]src[[:space:]]+([0-9.]+) ]]; then
		SRC="${BASH_REMATCH[1]}"
	else
		SRC=$(ip -4 -o addr show dev "$DEV" scope global 2>/dev/null | awk 'NR==1 { gsub(/\/.*/, "", $4); print $4; exit }')
	fi
	[[ -n $SRC ]] || die "не удалось определить IPv4 на $DEV"
	LINK=$(ip -4 route show dev "$DEV" scope link 2>/dev/null | awk '/proto kernel/ { print $1; exit }' || true)
	if [[ -z $LINK ]]; then
		LINK=$(ip -4 route show dev "$DEV" scope link 2>/dev/null | awk 'NR==1 { print $1; exit }' || true)
	fi
}

bridge_prefix() {
	local br="$1" ip
	ip=$(ip -4 -o addr show "$br" 2>/dev/null | awk 'NR==1 { gsub(/\/.*/, "", $4); print $4; exit }') || true
	[[ -n $ip ]] || return 1
	local a b c
	IFS=. read -r a b c _ <<<"$ip"
	printf '%s.%s.%s.' "$a" "$b" "$c"
}

detect_docker_br_iface() {
	local line br i
	while read -r line; do
		[[ $line == *"-A DOCKER"* ]] || continue
		[[ $line == *"-p udp"* ]] || continue
		[[ $line == *"DNAT"* ]] || continue
		read -r -a toks <<<"$line"
		for ((i = 0; i < ${#toks[@]} - 2; i++)); do
			if [[ ${toks[i]} == '!' && ${toks[i + 1]} == '-i' ]]; then
				br=${toks[i + 2]}
				if [[ -n $br ]] && ip link show "$br" &>/dev/null; then
					echo "$br"
					return 0
				fi
			fi
		done
	done < <(iptables-save -t nat 2>/dev/null || true)
	echo amn0
}

detect_dport_nat() {
	local br_if="$1" pfx d t
	pfx=$(bridge_prefix "$br_if") || return 1
	while read -r line; do
		[[ $line == *"-A DOCKER"* ]] || continue
		[[ $line == *"-p udp"* ]] || continue
		[[ $line == *"DNAT"* ]] || continue
		[[ $line == *"--dport"* ]] || continue
		d=''
		t=''
		read -r -a toks <<<"$line"
		local i
		for ((i = 0; i < ${#toks[@]}; i++)); do
			if [[ ${toks[i]} == '--dport' ]]; then
				d=${toks[i + 1]}
			fi
			if [[ ${toks[i]} == 'to-destination' ]]; then
				t=${toks[i + 1]}
				t=${t%%:*}
			fi
		done
		[[ -n $d && -n $t ]] || continue
		if [[ $t == "$pfx"* ]]; then
			echo "$d"
			return 0
		fi
	done < <(iptables-save -t nat 2>/dev/null || true)
	return 1
}

nft_pubudp_teardown() {
	command -v nft >/dev/null 2>&1 || return 0
	nft delete table ip "$NFT_PUBUDP_TABLE" 2>/dev/null || true
}

nft_pubudp_setup() {
	local br=$1 port=$2
	command -v nft >/dev/null 2>&1 || die "нужен nft для маркировки Docker-UDP (после wg-quick premangle); установите nftables"
	nft delete table ip "$NFT_PUBUDP_TABLE" 2>/dev/null || true
	nft add table ip "$NFT_PUBUDP_TABLE"
	# mangle+5: строго после chain premangle wg-quick (priority mangle), иначе ct mark затирает fwmark.
	nft add chain ip "$NFT_PUBUDP_TABLE" "$NFT_PUBUDP_CHAIN" \
		'{ type filter hook prerouting priority mangle + 5; policy accept; }'
	nft add rule ip "$NFT_PUBUDP_TABLE" "$NFT_PUBUDP_CHAIN" \
		iifname "$br" udp sport "$port" meta mark set "$FWMARK_HEX" comment "$MARK_TAG"
}

detect_dport_docker() {
	command -v docker >/dev/null 2>&1 || return 1
	local line hostp
	while read -r line; do
		hostp=$(sed -n 's/.*0\.0\.0\.0:\([0-9][0-9]*\)->[0-9][0-9]*\/udp.*/\1/p' <<<"$line")
		[[ -n $hostp ]] && echo "$hostp" && return 0
	done < <(docker ps --no-trunc --format '{{.Ports}}' 2>/dev/null || true)
	return 1
}

docker_setup() {
	DOCKER_ACTIVE=0
	DOCKER_BR=''
	DOCKER_DPORT=''
	[[ $DOCKER_MARK_AUTO -eq 1 || -n $DOCKER_FORCE_PORT ]] || return 0
	if [[ -z ${DOCKER_MARK_IN:-} ]]; then
		DOCKER_MARK_IN=$(detect_docker_br_iface)
	fi
	DOCKER_BR=$DOCKER_MARK_IN
	if [[ $DOCKER_MARK_AUTO -eq 1 ]]; then
		DOCKER_DPORT=$(wait_for_docker_udp_port "$DOCKER_BR" || true)
		[[ -n $DOCKER_DPORT ]] || DOCKER_DPORT=$DOCKER_FORCE_PORT
	else
		DOCKER_DPORT=$DOCKER_FORCE_PORT
	fi
	[[ -n $DOCKER_DPORT ]] || die "docker: не удалось определить UDP-порт (bridge $DOCKER_BR); задайте DOCKER_FORCE_PORT в awg-uplink-policy.env"
	local oldtag="awg-uplink-dockerudp-${IFACE_KEY}"
	while iptables -t mangle -D PREROUTING -i "$DOCKER_BR" -p udp -m conntrack --ctstate ESTABLISHED,RELATED \
		-m conntrack --ctorigdstport "$DOCKER_DPORT" -m comment --comment "$oldtag" \
		-j MARK --set-xmark "${FWMARK_HEX}/0xffffffff" 2>/dev/null; do true; done
	# Снять устаревшее правило iptables-nft (v2), если осталось — конфликтует по смыслу с nft v3.
	while iptables -t mangle -D PREROUTING -i "$DOCKER_BR" -p udp -m udp --sport "$DOCKER_DPORT" -m comment --comment "$MARK_TAG" \
		-j MARK --set-xmark "${FWMARK_HEX}/0xffffffff" 2>/dev/null; do true; done
	DOCKER_ACTIVE=1
	nft_pubudp_setup "$DOCKER_BR" "$DOCKER_DPORT"
	ip rule del fwmark "$FWMARK_DEC" table "$TABLE" priority "$FW_RULE_PRIO" 2>/dev/null || true
	ip rule add fwmark "$FWMARK_DEC" table "$TABLE" priority "$FW_RULE_PRIO"
}

docker_teardown() {
	[[ ${DOCKER_ACTIVE:-0} -eq 1 ]] || return 0
	ip rule del fwmark "$FWMARK_DEC" table "$TABLE" priority "$FW_RULE_PRIO" 2>/dev/null || true
	nft_pubudp_teardown
	[[ -n ${DOCKER_DPORT:-} ]] || return 0
	while iptables -t mangle -D PREROUTING -i "$DOCKER_BR" -p udp -m udp --sport "$DOCKER_DPORT" -m comment --comment "$MARK_TAG" \
		-j MARK --set-xmark "${FWMARK_HEX}/0xffffffff" 2>/dev/null; do true; done
}

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

# RFC1918 + CGNAT carrier-grade 100.64/10; без loopback.
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

# Подсети, куда ответы с публичного SRC должны идти через table main (клиенты Amnezia в Docker, bridge-маршруты).
detect_to_main_cidrs_auto() {
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

# Ответы с SRC (публичный IPv4 на eth0) к пулу клиентов Amnezia — иначе правило «from SRC → table uplink»
# отправляет их в таблицу без маршрута к VPN (mtproto к публичному IP ломается при включённом VPN у клиента).
to_main_bypass_setup() {
	local c p=$((PRIORITY - 35)) list
	if [[ -n ${TO_MAIN_CIDRS:-} ]]; then
		list=$TO_MAIN_CIDRS
	else
		list=$(detect_to_main_cidrs_auto)
	fi
	TO_MAIN_APPLIED=$list
	[[ -n $list ]] || {
		warn "to_main bypass: подсети не найдены; при необходимости задайте TO_MAIN_CIDRS в awg-uplink-policy.env"
		return 0
	}
	log "to_main bypass (from $SRC → main): $list"
	for c in $list; do
		[[ -n $c ]] || continue
		ip rule del from "$SRC" to "$c" table main priority "$p" 2>/dev/null || true
		ip rule add from "$SRC" to "$c" table main priority "$p"
		p=$((p + 1))
	done
}

to_main_bypass_teardown() {
	local c p=$((PRIORITY - 35))
	[[ -n ${TO_MAIN_APPLIED:-} ]] || return 0
	for c in $TO_MAIN_APPLIED; do
		[[ -n $c ]] || continue
		ip rule del from "$SRC" to "$c" table main priority "$p" 2>/dev/null || true
		p=$((p + 1))
	done
}

do_postup() {
	DOCKER_ACTIVE=0
	DOCKER_BR=''
	DOCKER_DPORT=''
	wait_for_default_route
	detect_ipv4_default
	if [[ -n $GW ]]; then
		ip route replace default via "$GW" dev "$DEV" table "$TABLE"
	else
		ip route replace default dev "$DEV" table "$TABLE"
	fi
	if [[ -n $LINK && $LINK =~ ^[0-9.]+/[0-9]+$ ]]; then
		ip route replace "$LINK" dev "$DEV" table "$TABLE"
	fi
	local_p=$((PRIORITY - 5))
	if [[ -n ${EXTRA_CIDRS:-} ]]; then
		local c
		for c in $EXTRA_CIDRS; do
			ip rule add from "$c" table "$TABLE" priority "$local_p"
			local_p=$((local_p - 1))
		done
	fi
	docker_setup
	to_main_bypass_setup
	ip rule del from "$SRC" table "$TABLE" priority "$PRIORITY" 2>/dev/null || true
	ip rule add from "$SRC" table "$TABLE" priority "$PRIORITY"
	sysctl -q "net.ipv4.conf.${DEV}.rp_filter=$RP_LOOSE"
	write_state
}

do_postdown() {
	[[ -f $STATE ]] || {
		warn "нет $STATE — пропуск postdown"
		return 0
	}
	# shellcheck disable=1090
	. "$STATE"
	ip rule del from "$SRC" table "$TABLE" priority "$PRIORITY" 2>/dev/null || true
	to_main_bypass_teardown
	docker_teardown
	if [[ -n ${EXTRA_CIDRS:-} ]]; then
		local c local_p=$((PRIORITY - 5))
		for c in $EXTRA_CIDRS; do
			ip rule del from "$c" table "$TABLE" priority "$local_p" 2>/dev/null || true
			local_p=$((local_p - 1))
		done
	fi
	if [[ -n $LINK && $LINK =~ ^[0-9.]+/[0-9]+$ ]]; then
		ip route del "$LINK" dev "$DEV" table "$TABLE" 2>/dev/null || true
	fi
	if [[ -n $GW ]]; then
		ip route del default via "$GW" dev "$DEV" table "$TABLE" 2>/dev/null || true
	else
		ip route del default dev "$DEV" table "$TABLE" 2>/dev/null || true
	fi
	sysctl -q "net.ipv4.conf.${DEV}.rp_filter=$RP_RESTORE"
	rm -f "$STATE"
}

case "$ACTION" in
postup) do_postup ;;
postdown) do_postdown ;;
*) usage ;;
esac

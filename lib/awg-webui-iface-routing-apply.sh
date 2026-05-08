#!/usr/bin/env bash
set -euo pipefail

CFG_ENV="${AWG_WEBUI_IFACE_ENV:-/etc/awg-uplink-webui/interfaces.env}"
STATE_FILE="/run/awg-webui-ifaces.state"
INGRESS_NAT_COMMENT="awg-webui-tunnel-ingress-docker-snat"
# nft mangle после wg-quick, fwmark для ответов Docker-VPN через uplink-table.
NFT_PUBUDP_TABLE=${NFT_PUBUDP_TABLE:-awg_webui_pubudp}
NFT_PUBUDP_CHAIN=${NFT_PUBUDP_CHAIN:-prerouting}
DOCKER_MARK_TUNNEL_PRIO=${DOCKER_MARK_TUNNEL_PRIO:-71}
DOCKER_SRC_PRIO_AFTER_MARK=${DOCKER_SRC_PRIO_AFTER_MARK:-73}
DOCKER_FWMARK_DEC=${DOCKER_FWMARK_DEC:-30596}
DOCKER_FWMARK_HEX=${DOCKER_FWMARK_HEX:-0x7784}
MTPROTO_FWMARK_DEC=${MTPROTO_FWMARK_DEC:-200}
MTPROTO_FWMARK_PRIO=${MTPROTO_FWMARK_PRIO:-200}
MTPROTO_ROUTE_TABLE=${MTPROTO_ROUTE_TABLE:-200}

log() { echo "[awg-webui-iface] $*"; }

usage() {
  echo "Usage: $0 apply|remove" >&2
  exit 1
}

link_for_dev() {
  local d=$1 lk
  lk=$(ip -4 route show dev "$d" scope link 2>/dev/null | awk '/proto kernel/ { print $1; exit }' || true)
  [[ -n $lk ]] || lk=$(ip -4 route show dev "$d" scope link 2>/dev/null | awk 'NR==1 { print $1; exit }' || true)
  echo "$lk"
}

# В main могут остаться несколько default (awg-uplink metric 0 и eth metric 100); тогда «ещё» побеждает туннель.
flush_default_via_dev() {
  local d=$1
  [[ -n "${d:-}" ]] || return 0
  while ip -4 route del default dev "$d" 2>/dev/null; do true; done
}

# После apply store: при остановке сервиса восстанавливать прямой egress, а не default с awg-uplink.
canonical_egress_default_line() {
  if [[ -n "${EGRESS_GW:-}" ]]; then
    echo "default via ${EGRESS_GW} dev ${EGRESS_DEV} src ${EGRESS_IP} metric ${EGRESS_METRIC:-100}"
  else
    echo "default dev ${EGRESS_DEV} src ${EGRESS_IP} metric ${EGRESS_METRIC:-100}"
  fi
}

first_ipv4_for_dev() {
  local d=$1
  ip -4 -o addr show dev "$d" 2>/dev/null | awk '{print $4}' | awk -F/ 'NR==1 {print $1}'
}

rp_filter_read() {
  local d=$1
  [[ -n "$d" && -r "/proc/sys/net/ipv4/conf/${d}/rp_filter" ]] || {
    echo ""
    return 0
  }
  cat "/proc/sys/net/ipv4/conf/${d}/rp_filter"
}

# Default route через туннель ломает strict RPF для DNAT Docker (используем loose rp_filter=2).
rp_filter_tunnel_prepare() {
  RP_RESTORE_EGRESS_VAL=""
  RP_RESTORE_INGRESS_VAL=""
  RP_INGRESS_RESTORE_DEV=""
  RP_RESTORE_EGRESS_VAL=$(rp_filter_read "$EGRESS_DEV")
  sysctl -q "net.ipv4.conf.${EGRESS_DEV}.rp_filter=2" 2>/dev/null || true
  if [[ -n "${INGRESS_DEV:-}" && "${INGRESS_DEV}" != "${EGRESS_DEV}" ]]; then
    RP_INGRESS_RESTORE_DEV="${INGRESS_DEV}"
    RP_RESTORE_INGRESS_VAL=$(rp_filter_read "${INGRESS_DEV}")
    sysctl -q "net.ipv4.conf.${INGRESS_DEV}.rp_filter=2" 2>/dev/null || true
  fi
}

rp_filter_restore_saved() {
  local edev=$1 egress_val=$2 idev=$3 ingress_val=$4
  [[ -n "$edev" && -n "$egress_val" ]] && sysctl -q "net.ipv4.conf.${edev}.rp_filter=${egress_val}" 2>/dev/null || true
  [[ -n "$idev" && -n "$ingress_val" ]] && sysctl -q "net.ipv4.conf.${idev}.rp_filter=${ingress_val}" 2>/dev/null || true
}

cidr_list_add() {
  local base="$1" add="$2" x
  [[ -z "$add" ]] && {
    echo "$base"
    return
  }
  for x in $base; do
    [[ "$x" == "$add" ]] && {
      echo "$base"
      return
    }
  done
  if [[ -z "$base" ]]; then
    echo "$add"
  else
    echo "$base $add"
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

detect_to_main_cidrs() {
  local egress_dev=$1 ingress_dev=$2 out="" cidr dev
  while read -r cidr dev _; do
    [[ -n "${cidr:-}" && -n "${dev:-}" ]] || continue
    [[ "$cidr" =~ ^[0-9.]+/[0-9]+$ ]] || continue
    is_private_ipv4_cidr "$cidr" || continue
    [[ "$dev" == "lo" || "$dev" == "awg-uplink" || "$dev" == "$egress_dev" || "$dev" == "$ingress_dev" ]] && continue
    # Universal criteria: Linux bridge devices (docker/br/custom), plus common docker-style names.
    if [[ -d "/sys/class/net/${dev}/bridge" || "$dev" =~ ^(docker0|br-.*|amn[0-9]+)$ ]]; then
      out=$(cidr_list_add "$out" "$cidr")
    fi
  done < <(ip -4 route show table main 2>/dev/null | awk '$2=="dev" { print $1, $3 }')
  echo -n "$out"
}

# Lines: "cidr<TAB>dev" — bridge subnets from main table (excluding egress/ingress).
detect_docker_bridge_subnet_lines() {
  local egress_dev=$1 ingress_dev=$2 cidr dev
  while read -r cidr dev _; do
    [[ -n "${cidr:-}" && -n "${dev:-}" ]] || continue
    [[ "$cidr" =~ ^[0-9.]+/[0-9]+$ ]] || continue
    is_private_ipv4_cidr "$cidr" || continue
    [[ "$dev" == "lo" || "$dev" == "awg-uplink" || "$dev" == "$egress_dev" || "$dev" == "$ingress_dev" ]] && continue
    if [[ -d "/sys/class/net/${dev}/bridge" || "$dev" =~ ^(docker0|br-.*|amn[0-9]+)$ ]]; then
      printf '%s\t%s\n' "$cidr" "$dev"
    fi
  done < <(ip -4 route show table main 2>/dev/null | awk '$2=="dev" { print $1, $3 }')
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

detect_dport_docker() {
  command -v docker >/dev/null 2>&1 || return 1
  local line hostp
  while read -r line; do
    hostp=$(sed -n 's/.*0\.0\.0\.0:\([0-9][0-9]*\)->[0-9][0-9]*\/udp.*/\1/p' <<<"$line")
    [[ -n $hostp ]] && echo "$hostp" && return 0
  done < <(docker ps --no-trunc --format '{{.Ports}}' 2>/dev/null || true)
  return 1
}

wait_for_docker_udp_port() {
  local br=$1 max=${DOCKER_BOOT_WAIT_SEC:-120} step=${DOCKER_BOOT_POLL_SEC:-2} e=0 d
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
    [[ -n "${DOCKER_FORCE_PORT:-}" ]] && {
      echo "$DOCKER_FORCE_PORT"
      return 0
    }
    sleep "$step"
    e=$((e + step))
  done
  return 1
}

nft_pubudp_teardown() {
  command -v nft >/dev/null 2>&1 || return 0
  nft delete table ip "$NFT_PUBUDP_TABLE" 2>/dev/null || true
}

nft_pubudp_setup() {
  local br=$1 port=$2 mark_hex=$3
  command -v nft >/dev/null 2>&1 || {
    log "nft not installed; omit docker udp mark (answers may mis-route in tunnel)"
    return 1
  }
  nft delete table ip "$NFT_PUBUDP_TABLE" 2>/dev/null || true
  nft add table ip "$NFT_PUBUDP_TABLE"
  nft add chain ip "$NFT_PUBUDP_TABLE" "$NFT_PUBUDP_CHAIN" \
    '{ type filter hook prerouting priority mangle + 5; policy accept; }'
  nft add rule ip "$NFT_PUBUDP_TABLE" "$NFT_PUBUDP_CHAIN" \
    iifname "$br" udp sport "$port" meta mark set "$mark_hex" comment "awg-webui-dockerudp"
}

# fwmark → uplink table must be before \"from <docker CIDR>\" rules.
setup_docker_udp_fwmark_tunnel() {
  local uplink_tab=$1 mark_dec=$2 prio=$3
  [[ -n "${DOCKER_MARK_BR:-}" && -n "${DOCKER_MARK_DPORT:-}" ]] || return 0
  ip rule del fwmark "$mark_dec" table "$uplink_tab" priority "$prio" 2>/dev/null || true
  ip rule add fwmark "$mark_dec" table "$uplink_tab" priority "$prio"
}

# Tunnel mode:
# - Connected routes в таблицу egress (202) для fwmark→202 (ответы с published UDP WG).
# - Те же connected routes в tun table (203) чтобы DNAT forward (src=клиент, dst=контейнер) при lookup 203 доходил до bridge.
# - ip rule from <cidr> → policy_tab: в туннельном режиме это TUN_TABLE (203), default = awg-uplink (интернет VPN-клиентов).
#   Исключение: пакеты с nft mark (udp sport listen) идут раньше по prio в table 202 — ответы наружу без туннеля.
setup_docker_bridge_source_uplink() {
  local route_tab=$1 prio_start=$2 egress_dev=$3 ingress_dev=$4 extra_route_tab=${5:-} policy_tab=${6:-}
  local prio=$prio_start cidr brdev
  DOCKER_SRC_CIDRS_ORDERED=""
  DOCKER_SRC_PRIO_START=$prio_start
  [[ -n "${policy_tab:-}" ]] || policy_tab="$route_tab"
  while IFS=$'\t' read -r cidr brdev; do
    [[ -n "${cidr:-}" && -n "${brdev:-}" ]] || continue
    ip -4 route replace "$cidr" dev "$brdev" table "$route_tab"
    [[ -n "${extra_route_tab:-}" ]] && ip -4 route replace "$cidr" dev "$brdev" table "$extra_route_tab"
    ip rule del from "$cidr" table "$policy_tab" priority "$prio" 2>/dev/null || true
    ip rule add from "$cidr" table "$policy_tab" priority "$prio"
    DOCKER_SRC_CIDRS_ORDERED="${DOCKER_SRC_CIDRS_ORDERED} ${cidr}"
    prio=$((prio + 1))
  done < <(detect_docker_bridge_subnet_lines "$egress_dev" "${ingress_dev:-$egress_dev}")
}

teardown_docker_bridge_source_uplink() {
  local route_tab=$1 policy_tab=$2 prio_start=$3 cidrs="$4" extra_route_tab=${5:-}
  [[ -z "${cidrs:-}" ]] && return 0
  local prio=$prio_start cidr
  for cidr in $cidrs; do
    [[ -n "${cidr:-}" ]] || continue
    ip rule del from "$cidr" table "$policy_tab" priority "$prio" 2>/dev/null || true
    ip -4 route del "$cidr" table "$route_tab" 2>/dev/null || true
    [[ -n "${extra_route_tab:-}" ]] && ip -4 route del "$cidr" table "$extra_route_tab" 2>/dev/null || true
    prio=$((prio + 1))
  done
}

setup_bridge_connected_routes_for_table() {
  local table_id=$1 egress_dev=$2 ingress_dev=$3 cidr brdev
  [[ -n "${table_id:-}" ]] || return 0
  while IFS=$'\t' read -r cidr brdev; do
    [[ -n "${cidr:-}" && -n "${brdev:-}" ]] || continue
    ip -4 route replace "$cidr" dev "$brdev" table "$table_id"
  done < <(detect_docker_bridge_subnet_lines "$egress_dev" "${ingress_dev:-$egress_dev}")
}

teardown_bridge_connected_routes_for_table() {
  local table_id=$1 cidrs="$2" cidr
  [[ -n "${table_id:-}" && -n "${cidrs:-}" ]] || return 0
  for cidr in $cidrs; do
    [[ -n "${cidr:-}" ]] || continue
    ip -4 route del "$cidr" table "$table_id" 2>/dev/null || true
  done
}

setup_to_main_bypass() {
  local src_ips="$1" cidrs="$2" prio_base="${3:-60}" src cidr prio
  [[ -n "$src_ips" && -n "$cidrs" ]] || return 0
  for src in $src_ips; do
    [[ -n "$src" ]] || continue
    prio=$prio_base
    for cidr in $cidrs; do
      [[ -n "$cidr" ]] || continue
      ip rule del from "$src/32" to "$cidr" table main priority "$prio" 2>/dev/null || true
      ip rule add from "$src/32" to "$cidr" table main priority "$prio"
      prio=$((prio + 1))
    done
  done
}

teardown_to_main_bypass() {
  local src_ips="$1" cidrs="$2" prio_base="${3:-60}" src cidr prio
  [[ -n "$src_ips" && -n "$cidrs" ]] || return 0
  for src in $src_ips; do
    [[ -n "$src" ]] || continue
    prio=$prio_base
    for cidr in $cidrs; do
      [[ -n "$cidr" ]] || continue
      ip rule del from "$src/32" to "$cidr" table main priority "$prio" 2>/dev/null || true
      prio=$((prio + 1))
    done
  done
}

# mtproto.zig upstream=tunnel uses SO_MARK=200; route marked sockets via table 200.
setup_mtproto_fwmark_policy() {
  local mode=${1:-egress}
  case "$mode" in
    tunnel|egress|direct) ;;
    *) mode="egress" ;;
  esac
  local awg_src=""
  ip rule del fwmark "$MTPROTO_FWMARK_DEC" table "$MTPROTO_ROUTE_TABLE" priority "$MTPROTO_FWMARK_PRIO" 2>/dev/null || true
  ip route del default table "$MTPROTO_ROUTE_TABLE" 2>/dev/null || true

  if [[ "$mode" == "tunnel" ]] && ip link show dev awg-uplink 2>/dev/null | grep -q 'UP'; then
    awg_src="$(first_ipv4_for_dev awg-uplink || true)"
    if [[ -n "$awg_src" ]]; then
      ip -4 route replace default dev awg-uplink src "$awg_src" table "$MTPROTO_ROUTE_TABLE"
    else
      ip -4 route replace default dev awg-uplink table "$MTPROTO_ROUTE_TABLE"
    fi
  else
    if [[ -n "${EGRESS_GW:-}" ]]; then
      ip -4 route replace default via "$EGRESS_GW" dev "$EGRESS_DEV" src "$EGRESS_IP" table "$MTPROTO_ROUTE_TABLE"
    else
      ip -4 route replace default dev "$EGRESS_DEV" src "$EGRESS_IP" table "$MTPROTO_ROUTE_TABLE"
    fi
  fi
  ip rule add fwmark "$MTPROTO_FWMARK_DEC" table "$MTPROTO_ROUTE_TABLE" priority "$MTPROTO_FWMARK_PRIO"
}

# Ответы на published UDP WG: nft mark → lookup 202 → MASQUERADE с egress/ingress.
# Остальной трафик с bridge: from cidr → lookup 203 (туннель). SNAT по ctdst для split ingress см. ниже.
setup_ingress_docker_snat() {
  local ing=$1 cidrs=$2 c
  [[ -n "$ing" && -n "$cidrs" ]] || return 0
  command -v iptables >/dev/null 2>&1 || {
    log "iptables not found; skip ingress docker SNAT"
    return 0
  }
  for c in $cidrs; do
    [[ -n "$c" ]] || continue
    iptables -t nat -C POSTROUTING -m conntrack --ctorigdst "${ing}/32" -s "$c" ! -d "$c" -j SNAT --to-source "$ing" -m comment --comment "$INGRESS_NAT_COMMENT" 2>/dev/null && continue
    iptables -t nat -I POSTROUTING 1 -m conntrack --ctorigdst "${ing}/32" -s "$c" ! -d "$c" -j SNAT --to-source "$ing" -m comment --comment "$INGRESS_NAT_COMMENT" 2>/dev/null || true
  done
}

teardown_ingress_docker_snat() {
  local ing=$1 cidrs=$2 c
  [[ -n "$ing" && -n "$cidrs" ]] || return 0
  command -v iptables >/dev/null 2>&1 || return 0
  for c in $cidrs; do
    [[ -n "$c" ]] || continue
    while iptables -t nat -D POSTROUTING -m conntrack --ctorigdst "${ing}/32" -s "$c" ! -d "$c" -j SNAT --to-source "$ing" -m comment --comment "$INGRESS_NAT_COMMENT" 2>/dev/null; do true; done
  done
}

save_state() {
  local old_default=$1
  local tmp="${STATE_FILE}.tmp.$$"
  {
    printf 'OLD_DEFAULT=%q\n' "$old_default"
    printf 'EGRESS_DEV=%q\n' "${EGRESS_DEV:-}"
    printf 'INGRESS_ENABLED=%q\n' "${INGRESS_ENABLED:-0}"
    printf 'INGRESS_IP=%q\n' "${INGRESS_IP:-}"
    printf 'INGRESS_TABLE=%q\n' "${INGRESS_TABLE:-201}"
    printf 'INGRESS_RULE_PRIO=%q\n' "${INGRESS_RULE_PRIO:-81}"
    printf 'EGRESS_IP=%q\n' "${EGRESS_IP:-}"
    printf 'EGRESS_GW=%q\n' "${EGRESS_GW:-}"
    printf 'EGRESS_TABLE=%q\n' "${EGRESS_TABLE:-202}"
    printf 'EGRESS_RULE_PRIO=%q\n' "${EGRESS_RULE_PRIO:-80}"
    printf 'INGRESS_RULE_PRIO=%q\n' "${INGRESS_RULE_PRIO:-81}"
    printf 'ROUTE_MODE=%q\n' "${ROUTE_MODE:-egress}"
    printf 'TUN_TABLE=%q\n' "203"
    printf 'TUN_RULE_PRIO=%q\n' "90"
    printf 'TUN_ENDPOINTS=%q\n' "${TUN_ENDPOINTS:-}"
    printf 'BYPASS_CIDRS=%q\n' "${BYPASS_CIDRS:-}"
    printf 'BYPASS_SRCS=%q\n' "${BYPASS_SRCS:-}"
    printf 'BYPASS_PRIO_BASE=%q\n' "${BYPASS_PRIO_BASE:-60}"
    printf 'DOCKER_SRC_CIDRS_ORDERED=%q\n' "${DOCKER_SRC_CIDRS_ORDERED:-}"
    printf 'DOCKER_SRC_PRIO_START=%q\n' "${DOCKER_SRC_PRIO_START:-72}"
    printf 'RP_RESTORE_EGRESS_VAL=%q\n' "${RP_RESTORE_EGRESS_VAL:-}"
    printf 'RP_RESTORE_INGRESS_VAL=%q\n' "${RP_RESTORE_INGRESS_VAL:-}"
    printf 'RP_INGRESS_RESTORE_DEV=%q\n' "${RP_INGRESS_RESTORE_DEV:-}"
    printf 'INGRESS_DOCKER_SNAT_CIDRS=%q\n' "${INGRESS_DOCKER_SNAT_CIDRS:-}"
    printf 'INGRESS_LOCAL_CIDRS=%q\n' "${INGRESS_LOCAL_CIDRS:-}"
    printf 'DOCKER_TUNNEL_MARK_DEC=%q\n' "${DOCKER_TUNNEL_MARK_DEC:-}"
    printf 'DOCKER_TUNNEL_MARK_PRIO=%q\n' "${DOCKER_TUNNEL_MARK_PRIO:-}"
    printf 'DOCKER_TUNNEL_NFT_ACTIVE=%q\n' "${DOCKER_TUNNEL_NFT_ACTIVE:-0}"
    printf 'DOCKER_POLICY_RULE_TABLE=%q\n' "${DOCKER_POLICY_RULE_TABLE:-}"
  } >"$tmp"
  mv -f -- "$tmp" "$STATE_FILE"
}

remove_rules() {
  # shellcheck disable=SC1090
  [[ -f $STATE_FILE ]] && . "$STATE_FILE"
  local idev="${INGRESS_IP:-}"
  local itab="${INGRESS_TABLE:-201}"
  local iprio="${INGRESS_RULE_PRIO:-81}"
  local edev="${EGRESS_DEV:-}"
  local eip="${EGRESS_IP:-}"
  local etab="${EGRESS_TABLE:-202}"
  local eprio="${EGRESS_RULE_PRIO:-80}"
  local tendpoints="${TUN_ENDPOINTS:-}"
  local ttab="${TUN_TABLE:-203}"
  local tprio="${TUN_RULE_PRIO:-90}"
  local bypass_cidrs="${BYPASS_CIDRS:-}"
  local bypass_srcs="${BYPASS_SRCS:-}"
  local bypass_prio_base="${BYPASS_PRIO_BASE:-60}"
  local dock_cidrs="${DOCKER_SRC_CIDRS_ORDERED:-}"
  local dock_prio="${DOCKER_SRC_PRIO_START:-72}"
  local docker_policy_tab="${DOCKER_POLICY_RULE_TABLE:-$etab}"
  local ing_snat_cidrs="${INGRESS_DOCKER_SNAT_CIDRS:-}"
  local ingress_local_cidrs="${INGRESS_LOCAL_CIDRS:-}"
  local tun_mark_prio="${DOCKER_TUNNEL_MARK_PRIO:-}"
  local tun_mark_dec="${DOCKER_TUNNEL_MARK_DEC:-}"
  local tun_nft="${DOCKER_TUNNEL_NFT_ACTIVE:-0}"
  local mt_mark_dec="${MTPROTO_FWMARK_DEC:-200}"
  local mt_mark_prio="${MTPROTO_FWMARK_PRIO:-200}"
  local mt_table="${MTPROTO_ROUTE_TABLE:-200}"
  rp_filter_restore_saved "$edev" "${RP_RESTORE_EGRESS_VAL:-}" "${RP_INGRESS_RESTORE_DEV:-}" "${RP_RESTORE_INGRESS_VAL:-}"
  if [[ "${tun_nft}" == "1" && -n "${tun_mark_prio}" && -n "${tun_mark_dec}" ]]; then
    ip rule del fwmark "$tun_mark_dec" table "${EGRESS_TABLE:-202}" priority "$tun_mark_prio" 2>/dev/null || true
  fi
  nft_pubudp_teardown
  teardown_ingress_docker_snat "${INGRESS_IP:-}" "$ing_snat_cidrs"
  teardown_docker_bridge_source_uplink "$etab" "$docker_policy_tab" "$dock_prio" "$dock_cidrs" "$ttab"
  teardown_bridge_connected_routes_for_table "$itab" "$ingress_local_cidrs"
  [[ -n $idev ]] && ip rule del from "$idev/32" table "$itab" priority "$iprio" 2>/dev/null || true
  [[ -n $eip ]] && ip rule del from "$eip/32" table "$etab" priority "$eprio" 2>/dev/null || true
  ip rule del fwmark "$mt_mark_dec" table "$mt_table" priority "$mt_mark_prio" 2>/dev/null || true
  ip route del default table "$mt_table" 2>/dev/null || true
  teardown_to_main_bypass "$bypass_srcs" "$bypass_cidrs" "$bypass_prio_base"
  ip rule del table "$ttab" priority "$tprio" 2>/dev/null || true
  ip route del default table "$itab" 2>/dev/null || true
  ip route del default table "$etab" 2>/dev/null || true
  ip route del default table "$ttab" 2>/dev/null || true
  if [[ -n $edev ]]; then
    local ilink
    ilink=$(link_for_dev "$edev" || true)
    [[ -n $ilink ]] && ip route del "$ilink" table "$itab" 2>/dev/null || true
    [[ -n $ilink ]] && ip route del "$ilink" table "$etab" 2>/dev/null || true
    [[ -n $ilink ]] && ip route del "$ilink" table "$ttab" 2>/dev/null || true
  fi
  if [[ -n "$tendpoints" ]]; then
    for ep in $tendpoints; do
      ip route del "$ep/32" 2>/dev/null || true
    done
  fi
}

restore_default() {
  [[ -f $STATE_FILE ]] || return 0
  # shellcheck disable=SC1090
  . "$STATE_FILE"
  [[ -n ${OLD_DEFAULT:-} ]] || return 0
  flush_default_via_dev awg-uplink
  # shellcheck disable=SC2086
  ip -4 route replace $OLD_DEFAULT 2>/dev/null || true
}

apply_cfg() {
  [[ -f $CFG_ENV ]] || { log "no config env: $CFG_ENV"; exit 0; }
  # shellcheck disable=SC1090
  . "$CFG_ENV"
  [[ "${ENABLE:-0}" == "1" ]] || { log "disabled in config"; exit 0; }
  [[ -n "${EGRESS_DEV:-}" && -n "${EGRESS_IP:-}" ]] || { log "missing egress fields"; exit 1; }
  ROUTE_MODE="${ROUTE_MODE:-egress}"
  EGRESS_TABLE=202
  EGRESS_RULE_PRIO=80
  INGRESS_RULE_PRIO=81
  local TUN_TABLE=203
  local TUN_RULE_PRIO=90

  local old_default=""
  # Clear defaults on egress dev to avoid duplicated default routes.
  while ip -4 route del default dev "$EGRESS_DEV" 2>/dev/null; do true; done

  remove_rules

  local elink
  elink=$(link_for_dev "$EGRESS_DEV" || true)
  TUN_ENDPOINTS=""
  BYPASS_CIDRS=""
  BYPASS_SRCS=""
  BYPASS_PRIO_BASE=60
  INGRESS_DOCKER_SNAT_CIDRS=""
  INGRESS_LOCAL_CIDRS=""
  DOCKER_POLICY_RULE_TABLE=""

  if [[ "$ROUTE_MODE" == "tunnel" ]]; then
    # Bootstrapping / fresh install: apply egress+ingress split even if tunnel is not ready yet.
    if ! ip link show dev awg-uplink 2>/dev/null | grep -q ',UP,'; then
      log "awg-uplink not present or not UP — applying egress split instead of tunnel"
      ROUTE_MODE=egress
    fi
  fi

  if [[ "$ROUTE_MODE" == "tunnel" ]]; then
    local awg_src
    awg_src="$(first_ipv4_for_dev awg-uplink || true)"
    # Keep route to tunnel endpoint(s) over physical uplink.
    while read -r _ ep; do
      [[ -z "${ep:-}" || "$ep" == "(none)" ]] && continue
      ep="${ep%:*}"
      if [[ "$ep" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TUN_ENDPOINTS="${TUN_ENDPOINTS} ${ep}"
      fi
    done < <(awg show awg-uplink endpoints 2>/dev/null || true)
    TUN_ENDPOINTS="$(echo "$TUN_ENDPOINTS" | xargs -n1 2>/dev/null | sort -u | xargs 2>/dev/null || true)"
    if [[ -n "$TUN_ENDPOINTS" ]]; then
      for ep in $TUN_ENDPOINTS; do
        if [[ -n "${EGRESS_GW:-}" ]]; then
          ip -4 route replace "$ep/32" via "$EGRESS_GW" dev "$EGRESS_DEV"
          ip -4 route replace "$ep/32" via "$EGRESS_GW" dev "$EGRESS_DEV" table "$TUN_TABLE"
        else
          ip -4 route replace "$ep/32" dev "$EGRESS_DEV"
          ip -4 route replace "$ep/32" dev "$EGRESS_DEV" table "$TUN_TABLE"
        fi
      done
    fi
    # Default for whole system -> tunnel.
    while ip -4 route del default dev awg-uplink 2>/dev/null; do true; done
    if [[ -n "$awg_src" ]]; then
      ip -4 route replace default dev awg-uplink src "$awg_src"
    else
      ip -4 route replace default dev awg-uplink
    fi
    rp_filter_tunnel_prepare

    # Keep replies from public egress/ingress IPs through physical uplinks.
    if [[ -n "${EGRESS_GW:-}" ]]; then
      ip -4 route replace default via "$EGRESS_GW" dev "$EGRESS_DEV" src "$EGRESS_IP" table "$EGRESS_TABLE"
    else
      ip -4 route replace default dev "$EGRESS_DEV" src "$EGRESS_IP" table "$EGRESS_TABLE"
    fi
    [[ -n $elink ]] && ip -4 route replace "$elink" dev "$EGRESS_DEV" table "$EGRESS_TABLE"
    ip -4 rule add from "$EGRESS_IP/32" table "$EGRESS_TABLE" priority "$EGRESS_RULE_PRIO"
    BYPASS_SRCS="$EGRESS_IP"

    # Keep non-selected inbound interfaces routed to tunnel table explicitly.
    if [[ -n "$awg_src" ]]; then
      ip -4 route replace default dev awg-uplink src "$awg_src" table "$TUN_TABLE"
    else
      ip -4 route replace default dev awg-uplink table "$TUN_TABLE"
    fi
    [[ -n $elink ]] && ip -4 route replace "$elink" dev "$EGRESS_DEV" table "$TUN_TABLE"
    # Docker / bridge: nft mark + fwmark правило ПЕРЕД from <CIDR> (иначе mark не влияет).
    DOCKER_TUNNEL_MARK_DEC=""
    DOCKER_TUNNEL_MARK_PRIO=""
    DOCKER_TUNNEL_NFT_ACTIVE=0
    DOCKER_MARK_BR="${DOCKER_MARK_IN:-}"
    [[ -z "${DOCKER_MARK_BR:-}" ]] && DOCKER_MARK_BR="$(detect_docker_br_iface)"
    DOCKER_MARK_DPORT=""
    if [[ -n "${DOCKER_FORCE_PORT:-}" ]]; then
      DOCKER_MARK_DPORT="${DOCKER_FORCE_PORT}"
    else
      DOCKER_MARK_DPORT="$(wait_for_docker_udp_port "$DOCKER_MARK_BR" || true)"
    fi
    if [[ -n "$DOCKER_MARK_DPORT" ]]; then
      if nft_pubudp_setup "$DOCKER_MARK_BR" "$DOCKER_MARK_DPORT" "$DOCKER_FWMARK_HEX"; then
        setup_docker_udp_fwmark_tunnel "$EGRESS_TABLE" "$DOCKER_FWMARK_DEC" "$DOCKER_MARK_TUNNEL_PRIO"
        DOCKER_TUNNEL_MARK_DEC="$DOCKER_FWMARK_DEC"
        DOCKER_TUNNEL_MARK_PRIO="$DOCKER_MARK_TUNNEL_PRIO"
        DOCKER_TUNNEL_NFT_ACTIVE=1
        log "docker-udp nft mark + fwmark prio ${DOCKER_MARK_TUNNEL_PRIO} (${DOCKER_MARK_BR}, sport=${DOCKER_MARK_DPORT})"
      fi
    else
      log "tunnel: could not detect published Docker UDP port (set DOCKER_FORCE_PORT in interfaces.env)"
    fi
    # Forwarded traffic uses private src before SNAT → must not hit catch-all tunnel rule (prio 90).
    DOCKER_POLICY_RULE_TABLE="$TUN_TABLE"
    DOCKER_SRC_CIDRS_ORDERED=""
    DOCKER_SRC_PRIO_START="${DOCKER_SRC_PRIO_AFTER_MARK}"
    setup_docker_bridge_source_uplink "$EGRESS_TABLE" "$DOCKER_SRC_PRIO_START" "$EGRESS_DEV" "${INGRESS_DEV:-$EGRESS_DEV}" "$TUN_TABLE" "$DOCKER_POLICY_RULE_TABLE"
    # Replies from source INGRESS_IP use table 201; include Docker/Amnezia bridge routes there too.
    if [[ "${INGRESS_ENABLED:-0}" == "1" && -n "${INGRESS_IP:-}" ]]; then
      setup_bridge_connected_routes_for_table "${INGRESS_TABLE:-201}" "$EGRESS_DEV" "${INGRESS_DEV:-$EGRESS_DEV}"
    fi
    ip -4 rule add table "$TUN_TABLE" priority "$TUN_RULE_PRIO"
  else
    # Egress mode: whole system default -> egress.
    flush_default_via_dev awg-uplink
    if [[ -n "${EGRESS_GW:-}" ]]; then
      ip -4 route replace default via "$EGRESS_GW" dev "$EGRESS_DEV" src "$EGRESS_IP" metric "${EGRESS_METRIC:-100}"
    else
      ip -4 route replace default dev "$EGRESS_DEV" src "$EGRESS_IP" metric "${EGRESS_METRIC:-100}"
    fi
  fi

  if [[ "${INGRESS_ENABLED:-0}" == "1" && -n "${INGRESS_IP:-}" ]]; then
    local itab="${INGRESS_TABLE:-201}"
    local iprio="81"
    local ilink
    ilink=$(link_for_dev "${INGRESS_DEV:-$EGRESS_DEV}" || true)
    if [[ -n "${INGRESS_GW:-}" ]]; then
      ip -4 route replace default via "$INGRESS_GW" dev "${INGRESS_DEV:-$EGRESS_DEV}" src "$INGRESS_IP" table "$itab"
    else
      ip -4 route replace default dev "${INGRESS_DEV:-$EGRESS_DEV}" src "$INGRESS_IP" table "$itab"
    fi
    [[ -n $ilink ]] && ip -4 route replace "$ilink" dev "${INGRESS_DEV:-$EGRESS_DEV}" table "$itab"
    INGRESS_LOCAL_CIDRS="$(detect_to_main_cidrs "$EGRESS_DEV" "${INGRESS_DEV:-$EGRESS_DEV}")"
    setup_bridge_connected_routes_for_table "$itab" "$EGRESS_DEV" "${INGRESS_DEV:-$EGRESS_DEV}"
    ip -4 rule del from "$INGRESS_IP/32" table "$itab" priority "$iprio" 2>/dev/null || true
    ip -4 rule add from "$INGRESS_IP/32" table "$itab" priority "$iprio"
    if [[ "$ROUTE_MODE" == "tunnel" ]]; then
      BYPASS_SRCS="$BYPASS_SRCS $INGRESS_IP"
    fi
  fi

  if [[ "$ROUTE_MODE" == "tunnel" ]]; then
    BYPASS_SRCS="$(echo "$BYPASS_SRCS" | xargs -n1 2>/dev/null | sort -u | xargs 2>/dev/null || true)"
    BYPASS_CIDRS="$(detect_to_main_cidrs "$EGRESS_DEV" "${INGRESS_DEV:-$EGRESS_DEV}")"
    setup_to_main_bypass "$BYPASS_SRCS" "$BYPASS_CIDRS" "$BYPASS_PRIO_BASE"
    if [[ -n "$BYPASS_CIDRS" ]]; then
      log "to-main bypass enabled for $BYPASS_CIDRS"
    else
      log "to-main bypass: no docker/bridge private subnets detected"
    fi
    if [[ "${INGRESS_ENABLED:-0}" == "1" && -n "${INGRESS_IP:-}" && "${INGRESS_IP}" != "${EGRESS_IP}" && -n "${DOCKER_SRC_CIDRS_ORDERED:-}" ]]; then
      INGRESS_DOCKER_SNAT_CIDRS="$DOCKER_SRC_CIDRS_ORDERED"
      setup_ingress_docker_snat "$INGRESS_IP" "$DOCKER_SRC_CIDRS_ORDERED"
      log "ingress docker SNAT (${INGRESS_IP}) for cidrs: ${DOCKER_SRC_CIDRS_ORDERED}"
    fi
  fi
  # Сохраняем восстановление после stop/remove: канонический default по eth, не «случайная» строка после туннеля.
  old_default="$(canonical_egress_default_line)"
  local mtproto_mode="${MTPROTO_OUTBOUND_MODE:-$ROUTE_MODE}"
  setup_mtproto_fwmark_policy "$mtproto_mode"
  save_state "$old_default"

  log "applied: mode=${ROUTE_MODE}, egress=${EGRESS_DEV}/${EGRESS_IP}, ingress_enabled=${INGRESS_ENABLED:-0}"
}

remove_cfg() {
  remove_rules
  restore_default
  rm -f -- "$STATE_FILE"
  log "removed rules and restored default route"
}

[[ $# -eq 1 ]] || usage
case "$1" in
  apply) apply_cfg ;;
  remove) remove_cfg ;;
  *) usage ;;
esac


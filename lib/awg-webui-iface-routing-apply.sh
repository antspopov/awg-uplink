#!/usr/bin/env bash
set -euo pipefail

CFG_ENV="${AWG_WEBUI_IFACE_ENV:-/etc/awg-uplink-webui/interfaces.env}"
STATE_FILE="/run/awg-webui-ifaces.state"

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

first_ipv4_for_dev() {
  local d=$1
  ip -4 -o addr show dev "$d" 2>/dev/null | awk '{print $4}' | awk -F/ 'NR==1 {print $1}'
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

# Tunnel mode before rule \"from all lookup 203\": traffic sourced from Docker bridge subnets must use uplink table
# (default via eth0), not the catch-all tunnel table. Also copy link routes into uplink table so intra-bridge still works.
setup_docker_bridge_source_uplink() {
  local uplink_tab=$1 prio_start=$2 egress_dev=$3 ingress_dev=$4
  local prio=$prio_start cidr brdev
  DOCKER_SRC_CIDRS_ORDERED=""
  DOCKER_SRC_PRIO_START=$prio_start
  while IFS=$'\t' read -r cidr brdev; do
    [[ -n "${cidr:-}" && -n "${brdev:-}" ]] || continue
    ip -4 route replace "$cidr" dev "$brdev" table "$uplink_tab"
    ip rule del from "$cidr" table "$uplink_tab" priority "$prio" 2>/dev/null || true
    ip rule add from "$cidr" table "$uplink_tab" priority "$prio"
    DOCKER_SRC_CIDRS_ORDERED="${DOCKER_SRC_CIDRS_ORDERED} ${cidr}"
    prio=$((prio + 1))
  done < <(detect_docker_bridge_subnet_lines "$egress_dev" "${ingress_dev:-$egress_dev}")
}

teardown_docker_bridge_source_uplink() {
  local uplink_tab=$1 prio_start=$2 cidrs="$3"
  [[ -z "${cidrs:-}" ]] && return 0
  local prio=$prio_start cidr
  for cidr in $cidrs; do
    [[ -n "${cidr:-}" ]] || continue
    ip rule del from "$cidr" table "$uplink_tab" priority "$prio" 2>/dev/null || true
    ip -4 route del "$cidr" table "$uplink_tab" 2>/dev/null || true
    prio=$((prio + 1))
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
  teardown_docker_bridge_source_uplink "$etab" "$dock_prio" "$dock_cidrs"
  [[ -n $idev ]] && ip rule del from "$idev/32" table "$itab" priority "$iprio" 2>/dev/null || true
  [[ -n $eip ]] && ip rule del from "$eip/32" table "$etab" priority "$eprio" 2>/dev/null || true
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

  local old_default
  old_default=$(ip -4 route show default 2>/dev/null | awk 'NR==1 { print; exit }' || true)
  # Clear defaults on egress dev to avoid duplicated default routes.
  while ip -4 route del default dev "$EGRESS_DEV" 2>/dev/null; do true; done

  remove_rules

  local elink
  elink=$(link_for_dev "$EGRESS_DEV" || true)
  TUN_ENDPOINTS=""
  BYPASS_CIDRS=""
  BYPASS_SRCS=""
  BYPASS_PRIO_BASE=60

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
    # Docker / bridge: forwarded traffic uses private src before SNAT → must not hit catch-all tunnel rule (prio 90).
    DOCKER_SRC_CIDRS_ORDERED=""
    DOCKER_SRC_PRIO_START=72
    setup_docker_bridge_source_uplink "$EGRESS_TABLE" "$DOCKER_SRC_PRIO_START" "$EGRESS_DEV" "${INGRESS_DEV:-$EGRESS_DEV}"
    ip -4 rule add table "$TUN_TABLE" priority "$TUN_RULE_PRIO"
  else
    # Egress mode: whole system default -> egress.
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
  fi
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


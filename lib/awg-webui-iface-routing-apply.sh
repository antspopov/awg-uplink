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
  [[ -n $idev ]] && ip rule del from "$idev/32" table "$itab" priority "$iprio" 2>/dev/null || true
  [[ -n $eip ]] && ip rule del from "$eip/32" table "$etab" priority "$eprio" 2>/dev/null || true
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

  if [[ "$ROUTE_MODE" == "tunnel" ]]; then
    ip -4 link show dev awg-uplink >/dev/null 2>&1 || { log "awg-uplink is missing for tunnel mode"; exit 1; }
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

    # Keep non-selected inbound interfaces routed to tunnel table explicitly.
    if [[ -n "$awg_src" ]]; then
      ip -4 route replace default dev awg-uplink src "$awg_src" table "$TUN_TABLE"
    else
      ip -4 route replace default dev awg-uplink table "$TUN_TABLE"
    fi
    [[ -n $elink ]] && ip -4 route replace "$elink" dev "$EGRESS_DEV" table "$TUN_TABLE"
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


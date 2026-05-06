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

save_state() {
  local old_default=$1
  local tmp="${STATE_FILE}.tmp.$$"
  {
    printf 'OLD_DEFAULT=%q\n' "$old_default"
    printf 'EGRESS_DEV=%q\n' "${EGRESS_DEV:-}"
    printf 'INGRESS_ENABLED=%q\n' "${INGRESS_ENABLED:-0}"
    printf 'INGRESS_IP=%q\n' "${INGRESS_IP:-}"
    printf 'INGRESS_TABLE=%q\n' "${INGRESS_TABLE:-201}"
    printf 'INGRESS_RULE_PRIO=%q\n' "${INGRESS_RULE_PRIO:-110}"
  } >"$tmp"
  mv -f -- "$tmp" "$STATE_FILE"
}

remove_rules() {
  # shellcheck disable=SC1090
  [[ -f $STATE_FILE ]] && . "$STATE_FILE"
  local idev="${INGRESS_IP:-}"
  local itab="${INGRESS_TABLE:-201}"
  local iprio="${INGRESS_RULE_PRIO:-110}"
  local edev="${EGRESS_DEV:-}"
  [[ -n $idev ]] && ip rule del from "$idev/32" table "$itab" priority "$iprio" 2>/dev/null || true
  ip route del default table "$itab" 2>/dev/null || true
  if [[ -n $edev ]]; then
    local ilink
    ilink=$(link_for_dev "$edev" || true)
    [[ -n $ilink ]] && ip route del "$ilink" table "$itab" 2>/dev/null || true
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

  local old_default
  old_default=$(ip -4 route show default 2>/dev/null | awk 'NR==1 { print; exit }' || true)
  save_state "$old_default"

  # Clear defaults on egress dev to avoid duplicated default routes.
  while ip -4 route del default dev "$EGRESS_DEV" 2>/dev/null; do true; done

  if [[ -n "${EGRESS_GW:-}" ]]; then
    ip -4 route replace default via "$EGRESS_GW" dev "$EGRESS_DEV" src "$EGRESS_IP" metric "${EGRESS_METRIC:-100}"
  else
    ip -4 route replace default dev "$EGRESS_DEV" src "$EGRESS_IP" metric "${EGRESS_METRIC:-100}"
  fi

  remove_rules

  if [[ "${INGRESS_ENABLED:-0}" == "1" && -n "${INGRESS_IP:-}" ]]; then
    local itab="${INGRESS_TABLE:-201}"
    local iprio="${INGRESS_RULE_PRIO:-110}"
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

  log "applied: egress=${EGRESS_DEV}/${EGRESS_IP}, ingress_enabled=${INGRESS_ENABLED:-0}"
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


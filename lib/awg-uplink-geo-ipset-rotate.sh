#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Два ipset для geo-DNS: dnsmasq пишет только в STAGING; раз в сутки — снимок в ROUTE,
# затем очистка STAGING (протухшие IP уходят, dnsmasq снова наполняет staging).
#
# Важно для nft: пока staging снова не наполнен, совпадения могут быть только в ROUTE;
# после начала дня — в STAGING появляются новые IP. Правила nft должны проверять
# ОБА множества (логическое ИЛИ), иначе новые резолвы до следующей ротации не попадут в geo.

set -euo pipefail

STAGING=${AWG_GEO_IPSET_STAGING:-awg_geo_staging}
ROUTE=${AWG_GEO_IPSET_ROUTE:-awg_geo_route}
MAXELEM=${AWG_GEO_IPSET_MAXELEM:-262144}

die() { echo "[awg-geo-ipset] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-geo-ipset] $*"; }

usage() {
	cat >&2 <<EOF
Использование: $0 init | rotate | status

  init    — создать ipset $STAGING и $ROUTE (hash:ip, inet), если ещё нет
  rotate  — ipset flush $ROUTE; перенести все элементы из $STAGING в $ROUTE; ipset flush $STAGING
  status  — кратко: число элементов в каждом set

Переменные: AWG_GEO_IPSET_STAGING, AWG_GEO_IPSET_ROUTE, AWG_GEO_IPSET_MAXELEM
EOF
	exit 1
}

[[ $# -eq 1 ]] || usage
command -v ipset >/dev/null 2>&1 || die "нужен ipset (пакет ipset)"

cmd_init() {
	ipset create "$STAGING" hash:ip family inet hashsize 4096 maxelem "$MAXELEM" -exist
	ipset create "$ROUTE" hash:ip family inet hashsize 4096 maxelem "$MAXELEM" -exist
	log "sets: $STAGING, $ROUTE (maxelem=$MAXELEM)"
}

count_members() {
	local n
	n=$(ipset list "$1" 2>/dev/null | awk '
		/^Members:/ { m = 1; next }
		m && /^[[:space:]]*$/ { exit }
		m && NF { c++ }
		END { print c+0 }
	')
	echo "${n:-0}"
}

cmd_status() {
	local a b
	a=$(count_members "$STAGING")
	b=$(count_members "$ROUTE")
	log "members: $STAGING=$a $ROUTE=$b"
}

cmd_rotate() {
	ipset list "$STAGING" >/dev/null 2>&1 || die "нет ipset $STAGING — сначала: $0 init"
	ipset list "$ROUTE" >/dev/null 2>&1 || die "нет ipset $ROUTE — сначала: $0 init"

	ipset flush "$ROUTE"
	tmp=$(mktemp)
	ipset save "$STAGING" 2>/dev/null | awk -v s="$STAGING" -v d="$ROUTE" '$1 == "add" && $2 == s { $2 = d; print }' >"$tmp"
	if [[ -s $tmp ]]; then
		ipset restore -exist <"$tmp" || die "ipset restore из $STAGING не удался"
	fi
	rm -f -- "$tmp"
	ipset flush "$STAGING"
	log "rotate: $STAGING → $ROUTE (staging очищен)"
}

case "$1" in
init) cmd_init ;;
rotate) cmd_rotate ;;
status) cmd_status ;;
-h | --help) usage ;;
*) usage ;;
esac

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Устанавливает отдельный модуль selective geo-routing (по списку префиксов).

set -euo pipefail

[[ ${EUID:-0} -eq 0 ]] || {
	echo "[awg-geo-install] нужен root" >&2
	exit 1
}

ROOTDIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)
CANON_CONF=${AWG_GEO_WG_CONF:-/etc/amnezia/amneziawg/awg-uplink.conf}
ENV_FILE=/etc/awg-uplink-geo-routing.env
MANUAL_LIST_FILE=/etc/awg-uplink-geo-routing.manual.lst

FETCH_SRC="$ROOTDIR/lib/awg-uplink-geo-routing-fetch.sh"
ROUTE_SRC="$ROOTDIR/lib/awg-uplink-geo-routing.sh"
POSTUP_SRC="$ROOTDIR/lib/awg-uplink-geo-routing-postup.sh"
POSTDOWN_SRC="$ROOTDIR/lib/awg-uplink-geo-routing-postdown.sh"
CONTAINS_SRC="$ROOTDIR/lib/awg-uplink-geo-routing-contains.sh"
FETCH_DST=/usr/local/sbin/awg-uplink-geo-routing-fetch.sh
ROUTE_DST=/usr/local/sbin/awg-uplink-geo-routing.sh
POSTUP_DST=/usr/local/sbin/awg-uplink-geo-routing-postup.sh
POSTDOWN_DST=/usr/local/sbin/awg-uplink-geo-routing-postdown.sh
CONTAINS_DST=/usr/local/sbin/awg-uplink-geo-routing-contains.sh

UNIT_SVC_SRC="$ROOTDIR/systemd/awg-uplink-geo-routing-refresh.service"
UNIT_TMR_SRC="$ROOTDIR/systemd/awg-uplink-geo-routing-refresh.timer"
UNIT_SVC_DST=/etc/systemd/system/awg-uplink-geo-routing-refresh.service
UNIT_TMR_DST=/etc/systemd/system/awg-uplink-geo-routing-refresh.timer

die() { echo "[awg-geo-install] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-geo-install] $*"; }
warn() { echo "[awg-geo-install] WARN: $*" >&2; }

merge_geo_hooks() {
	[[ -f $CANON_CONF ]] || {
		log "нет $CANON_CONF — пропуск merge PostUp/PostDown"
		return 0
	}
	grep -q 'awg-uplink-geo-routing-postup' "$CANON_CONF" 2>/dev/null && return 0
	local tmp
	tmp=$(mktemp)
	awk -v up="$POSTUP_DST" -v dn="$POSTDOWN_DST" '
	BEGIN { iface = 0 }
	/^\[Interface\]/ { iface = 1; print; next }
	/^\[/ { iface = 0; print; next }
	iface && /^PostUp[[:space:]]*=/ {
		line = $0
		sub(/^PostUp[[:space:]]*=[[:space:]]*/, "", line)
		print "PostUp = " line " && " up
		next
	}
	iface && /^PostDown[[:space:]]*=/ {
		line = $0
		sub(/^PostDown[[:space:]]*=[[:space:]]*/, "", line)
		print "PostDown = " dn " && " line
		next
	}
	{ print }
	' "$CANON_CONF" >"$tmp"
	mv -f -- "$tmp" "$CANON_CONF"
	log "PostUp/PostDown дополнены geo-routing хуками"
}

write_env() {
	[[ -f $ENV_FILE ]] && {
		log "сохраняю существующий $ENV_FILE"
		return 0
	}
	cat >"$ENV_FILE" <<'EOF'
# selective geo-routing: default route -> egress, только список -> awg-uplink
AWG_GEO_ROUTING_ENABLE=1
AWG_GEO_AWG_IFACE=awg-uplink
AWG_GEO_LIST_URL=https://antifilter.download/list/allyouneed.lst
AWG_GEO_LIST_FILE=/var/lib/awg-uplink/geo-routing/allyouneed.lst
AWG_GEO_MANUAL_LIST_FILE=/etc/awg-uplink-geo-routing.manual.lst
AWG_GEO_TABLE=207
AWG_GEO_RULE_PRIO=77
AWG_GEO_MARK_HEX=0x77a3
AWG_GEO_MARK_DEC=30627
AWG_GEO_MAIN_BYPASS_PRIO=101
AWG_GEO_NFT_TABLE=awg_geo_routing
AWG_GEO_NFT_SET=geo_targets
EOF
	chmod 644 "$ENV_FILE"
}

write_manual_list_template() {
	[[ -f $MANUAL_LIST_FILE ]] && return 0
	cat >"$MANUAL_LIST_FILE" <<'EOF'
# Ручной список CIDR для тестов/добавок к allyouneed.lst
# Формат: один IPv4 CIDR в строке, комментарии через #
# Пример:
# 1.1.1.1/32
# 8.8.8.0/24
EOF
	chmod 644 "$MANUAL_LIST_FILE"
}

install_deps() {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y ca-certificates curl nftables
}

install_files() {
	install -m755 "$FETCH_SRC" "$FETCH_DST"
	install -m755 "$ROUTE_SRC" "$ROUTE_DST"
	install -m755 "$POSTUP_SRC" "$POSTUP_DST"
	install -m755 "$POSTDOWN_SRC" "$POSTDOWN_DST"
	install -m755 "$CONTAINS_SRC" "$CONTAINS_DST"
	install -m644 "$UNIT_SVC_SRC" "$UNIT_SVC_DST"
	install -m644 "$UNIT_TMR_SRC" "$UNIT_TMR_DST"
}

main() {
	install_deps
	write_env
	write_manual_list_template
	install_files
	merge_geo_hooks
	systemctl daemon-reload
	systemctl enable --now awg-uplink-geo-routing-refresh.timer
	"$ROUTE_DST" down || true
	systemctl start --no-block awg-uplink-geo-routing-refresh.service >/dev/null 2>&1 || true
	log "готово: модуль установлен; refresh/fetch выполняется в фоне"
}

main "$@"


#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

ENV_FILE=${AWG_GEO_ENV_FILE:-/etc/awg-uplink-geo-routing.env}

die() { echo "[awg-geo-fetch] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-geo-fetch] $*"; }

require_bin() { command -v "$1" >/dev/null 2>&1 || die "нужна команда: $1"; }

load_env() {
	[[ -f $ENV_FILE ]] || die "нет $ENV_FILE"
	# shellcheck disable=1090
	set -a
	. "$ENV_FILE"
	set +a
	[[ ${AWG_GEO_ROUTING_ENABLE:-0} -eq 1 ]] || {
		log "AWG_GEO_ROUTING_ENABLE не 1 — пропуск"
		exit 0
	}
	LIST_URL=${AWG_GEO_LIST_URL:-https://antifilter.download/list/allyouneed.lst}
	LIST_FILE=${AWG_GEO_LIST_FILE:-/var/lib/awg-uplink/geo-routing/allyouneed.lst}
}

validate_list() {
	local file=$1 ok=0 line
	while IFS= read -r line; do
		line=${line%%#*}
		line=$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$line")
		[[ -z $line ]] && continue
		if [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
			ok=1
			continue
		fi
		die "некорректная строка в списке: $line"
	done <"$file"
	[[ $ok -eq 1 ]] || die "список пуст после фильтрации"
}

main() {
	require_bin curl
	load_env
	mkdir -p -- "$(dirname "$LIST_FILE")"
	local tmp
	tmp=$(mktemp)
	curl -fsSL --max-time "${AWG_GEO_FETCH_TIMEOUT_SEC:-40}" "$LIST_URL" -o "$tmp"
	validate_list "$tmp"
	mv -f -- "$tmp" "$LIST_FILE"
	log "обновлён список: $LIST_FILE"
}

main "$@"


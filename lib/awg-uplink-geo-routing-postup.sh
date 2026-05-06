#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail
ENV_FILE=${AWG_GEO_ENV_FILE:-/etc/awg-uplink-geo-routing.env}
[[ -f $ENV_FILE ]] || exit 0
# shellcheck disable=1090
set -a
. "$ENV_FILE"
set +a
if [[ ${AWG_GEO_ROUTING_ENABLE:-0} -ne 1 ]]; then
	/usr/local/sbin/awg-uplink-geo-routing.sh down >/dev/null 2>&1 || true
	exit 0
fi
LIST_FILE=${AWG_GEO_LIST_FILE:-/var/lib/awg-uplink/geo-routing/allyouneed.lst}

# Быстро и синхронно: только переключение default->egress + правила.
/usr/local/sbin/awg-uplink-geo-routing.sh base-up >/dev/null 2>&1 || true

# Не блокируем awg-quick PostUp: загрузка/обновление списка и apply-list выполняются в фоне сервисом.
if command -v systemctl >/dev/null 2>&1; then
	systemctl start --no-block awg-uplink-geo-routing-refresh.service >/dev/null 2>&1 || true
	exit 0
fi

# Fallback без systemd.
nohup /bin/sh -c '/usr/local/sbin/awg-uplink-geo-routing.sh apply-list || true; /usr/local/sbin/awg-uplink-geo-routing-fetch.sh && /usr/local/sbin/awg-uplink-geo-routing.sh apply-list' >/dev/null 2>&1 &
exit 0


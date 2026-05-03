#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# PostUp-цепочка awg-quick: после awg-uplink-policy (см. PostUp в awg-uplink.conf).

set -euo pipefail
GEO_ENV=${AWG_GEO_ENV:-/etc/awg-uplink-geo.env}
[[ -f $GEO_ENV ]] || exit 0
# shellcheck disable=1090
set -a
. "$GEO_ENV"
set +a
[[ ${AWG_GEO_ENABLE:-0} -eq 1 ]] || exit 0
exec /usr/local/sbin/awg-uplink-geo-firewall.sh up

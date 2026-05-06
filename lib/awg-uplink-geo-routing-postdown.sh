#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail
ENV_FILE=${AWG_GEO_ENV_FILE:-/etc/awg-uplink-geo-routing.env}
[[ -f $ENV_FILE ]] || exit 0
# shellcheck disable=1090
set -a
. "$ENV_FILE"
set +a
exec /usr/local/sbin/awg-uplink-geo-routing.sh down


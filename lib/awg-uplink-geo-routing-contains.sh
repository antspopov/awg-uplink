#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Проверка IP: входит ли в geo-списки (base + manual) с учётом CIDR.

set -euo pipefail

ENV_FILE=${AWG_GEO_ENV_FILE:-/etc/awg-uplink-geo-routing.env}

die() { echo "[awg-geo-contains] ERROR: $*" >&2; exit 2; }
usage() {
	cat >&2 <<'EOF'
Использование:
  awg-uplink-geo-routing-contains.sh <IPv4>

Коды выхода:
  0  IP найден в одном из CIDR
  1  IP не найден
  2  ошибка (невалидный IP/конфиг)
EOF
	exit 2
}

[[ $# -eq 1 ]] || usage
TARGET_IP=$1

LIST_FILE=/var/lib/awg-uplink/geo-routing/allyouneed.lst
MANUAL_LIST_FILE=/etc/awg-uplink-geo-routing.manual.lst
if [[ -f $ENV_FILE ]]; then
	# shellcheck disable=1090
	set -a
	. "$ENV_FILE"
	set +a
	LIST_FILE=${AWG_GEO_LIST_FILE:-$LIST_FILE}
	MANUAL_LIST_FILE=${AWG_GEO_MANUAL_LIST_FILE:-$MANUAL_LIST_FILE}
fi

python3 - "$TARGET_IP" "$LIST_FILE" "$MANUAL_LIST_FILE" <<'PY'
import ipaddress
import sys
from pathlib import Path

ip_raw = sys.argv[1].strip()
try:
    target = ipaddress.ip_address(ip_raw)
except ValueError:
    print(f"[awg-geo-contains] ERROR: invalid IPv4: {ip_raw}", file=sys.stderr)
    sys.exit(2)
if target.version != 4:
    print(f"[awg-geo-contains] ERROR: only IPv4 is supported: {ip_raw}", file=sys.stderr)
    sys.exit(2)

paths = [Path(p) for p in sys.argv[2:]]
seen = set()
for p in paths:
    if not p.is_file():
        continue
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line in seen:
            continue
        seen.add(line)
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        if target in net:
            print(f"MATCH {target} in {net} ({p})")
            sys.exit(0)

print(f"MISS {target}")
sys.exit(1)
PY


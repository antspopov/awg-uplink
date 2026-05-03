#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Установка ротации geo-ipset (скрипт + systemd timer). Остальной geo-стек — отдельно.

set -euo pipefail

[[ ${EUID:-0} -eq 0 ]] || { echo "нужен root" >&2; exit 1; }

ROOTDIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)
ROT_SRC="$ROOTDIR/lib/awg-uplink-geo-ipset-rotate.sh"
UNIT_SVC="$ROOTDIR/systemd/awg-uplink-geo-ipset-rotate.service"
UNIT_TMR="$ROOTDIR/systemd/awg-uplink-geo-ipset-rotate.timer"
ROT_DST=/usr/local/sbin/awg-uplink-geo-ipset-rotate.sh

[[ -f $ROT_SRC && -f $UNIT_SVC && -f $UNIT_TMR ]] || { echo "нет файлов в $ROOTDIR" >&2; exit 1; }

install -m755 "$ROT_SRC" "$ROT_DST"
install -m644 "$UNIT_SVC" /etc/systemd/system/awg-uplink-geo-ipset-rotate.service
install -m644 "$UNIT_TMR" /etc/systemd/system/awg-uplink-geo-ipset-rotate.timer

"$ROT_DST" init
systemctl daemon-reload
systemctl enable --now awg-uplink-geo-ipset-rotate.timer
echo "[awg-geo] установлено: $ROT_DST, timer awg-uplink-geo-ipset-rotate.timer"

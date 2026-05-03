#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Читает любой .conf → пишет /etc/amnezia/amneziawg/awg-uplink.conf, hook, .env, PostUp/PostDown.
# При записи: удаляются пустые Amnezia-поля I2=, I3=, …; из AllowedIPs убираются IPv6-адреса (::/0 и т.д.).
# Исходник не меняется. Полный цикл: ../awg-uplink-bootstrap.sh (см. --help).

set -euo pipefail

# Каноническое имя: отдельный интерфейс, не awg0.
CANON_DIR=/etc/amnezia/amneziawg
CANON_STEM=awg-uplink
CANON_CONF="$CANON_DIR/${CANON_STEM}.conf"

MARKER='awg-uplink-policy'
MARKER_DOWN='awg-uplink-policy-down'
TABLE=200
PRIORITY=100
RP_LOOSE=2
RP_RESTORE=1
DOCKER_FWMARK_DEC=30596
DOCKER_FWMARK_HEX=0x7784
DOCKER_MARK_AUTO=1
DOCKER_MARK_IN=""
DOCKER_MARK_UDP=""
INPUT=""

die() { echo "[awg-inject] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-inject] $*"; }

usage_short() {
	echo "Использование: $0 /путь/к/любому.conf" >&2
	echo "  Исходник только читается. Пишется: $CANON_CONF" >&2
	echo "  Полная установка из корня репозитория: ./awg-uplink-bootstrap.sh (см. его --help)" >&2
	echo "  (ключ -i, если указан, игнорируется)" >&2
}

usage_full() {
	usage_short
	cat >&2 <<EOF

Куда пишется
  Каталог: $CANON_DIR
  Интерфейс и unit: ${CANON_STEM}  →  systemctl enable --now awg-quick@${CANON_STEM}

awg-uplink-policy.env (ручная правка при необходимости)
  TABLE, PRIORITY, RP_LOOSE, RP_RESTORE, FWMARK_DEC, FWMARK_HEX
  DOCKER_MARK_AUTO=0 — без правил для Docker-VPN
  DOCKER_MARK_IN — bridge (пусто = авто через iptables nat)
  DOCKER_FORCE_PORT — запасной UDP, если авто не сработало
  EXTRA_CIDRS — CIDR через пробел в таблицу uplink
  AMNEZIA_DOCKER_NAME_PATTERN — ERE имени контейнера (по умолчанию ^amnezia-awg: amnezia-awg, amnezia-awg2, …)
  AMNEZIA_DOCKER_NAMES — если непусто: только эти имена (пробелом), шаблон не используется
  Split-routing: /etc/awg-uplink-split.env (мастер lib/awg-uplink-split-wizard.sh или bootstrap --split-routing-wizard; опционально AWG_UPLINK_SPLIT_ENV в awg-uplink-policy.env)
  Geo-DNS (опционально): bootstrap --with-geo-dns или lib/awg-uplink-geo-install.sh; подсети Docker — как to_main (скрипт geo-docker-subnets), без docker update
  TO_MAIN_CIDRS — вручную подменяет авто-список bypass в main
  AWG_DEFAULT_IFACE — явный интерфейс default route
  NETWORK_BOOT_WAIT_SEC / NETWORK_BOOT_POLL_SEC, DOCKER_BOOT_WAIT_SEC / DOCKER_BOOT_POLL_SEC

Миграция с awg0
  systemctl disable --now awg-quick@awg0

Полная установка (из корня репозитория)
  sudo ./awg-uplink-bootstrap.sh /путь/к/exported.conf
  sudo ./awg-uplink-bootstrap.sh --amneziawg-from-source …
  sudo ./awg-uplink-bootstrap.sh --with-mtproto-proxy …   # см. ./awg-uplink-bootstrap.sh --help

Только inject
  sudo ./lib/awg-inject-uplink-policy.sh /путь/к/exported.conf
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-h|--help) usage_full; exit 0 ;;
	-i|--in-place) shift ;;
	-*)
		die "неизвестная опция: $1 (нужен только путь к .conf; см. --help)"
		;;
	*)
		[[ -z $INPUT ]] || die "укажите один файл: лишний аргумент «$1»"
		INPUT=$1
		shift
		;;
	esac
done

[[ -n $INPUT ]] || {
	usage_short
	exit 1
}
[[ -f $INPUT ]] || die "нет файла: $INPUT"

SRCDIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
REPODIR=$(cd "$SRCDIR/.." && pwd)
BUNDLE="$SRCDIR/awg-uplink-policy.sh"
[[ -f $BUNDLE ]] || die "нет $BUNDLE"

mkdir -p -- "$CANON_DIR"
POL_DIR=$CANON_DIR
HOOK_DST="$POL_DIR/awg-uplink-policy.sh"
ENV_DST="$POL_DIR/awg-uplink-policy.env"
WGABS=$(readlink -f "$CANON_CONF" 2>/dev/null || echo "$CANON_CONF")

write_env() {
	local tmp="${ENV_DST}.tmp.$$"
	local existing_dock="" existing_pattern="" dock_out pattern_out
	if [[ -f $ENV_DST ]]; then
		existing_dock=$(sed -n 's/^AMNEZIA_DOCKER_NAMES=//p' "$ENV_DST" | tail -1 || true)
		existing_dock=${existing_dock#\"}
		existing_dock=${existing_dock%\"}
		existing_dock=${existing_dock#\'}
		existing_dock=${existing_dock%\'}
		existing_pattern=$(sed -n 's/^AMNEZIA_DOCKER_NAME_PATTERN=//p' "$ENV_DST" | tail -1 || true)
		existing_pattern=${existing_pattern#\"}
		existing_pattern=${existing_pattern%\"}
		existing_pattern=${existing_pattern#\'}
		existing_pattern=${existing_pattern%\'}
	fi
	if [[ -v AMNEZIA_DOCKER_NAMES ]]; then
		dock_out=$AMNEZIA_DOCKER_NAMES
	else
		dock_out=${existing_dock:-}
	fi
	if [[ -v AMNEZIA_DOCKER_NAME_PATTERN ]]; then
		pattern_out=$AMNEZIA_DOCKER_NAME_PATTERN
	else
		pattern_out=${existing_pattern:-^amnezia-awg}
	fi
	{
		echo "# Сгенерировано $0 — при смене настроек снова запустите этот скрипт или правьте вручную"
		echo "TABLE=$TABLE"
		echo "PRIORITY=$PRIORITY"
		echo "RP_LOOSE=$RP_LOOSE"
		echo "RP_RESTORE=$RP_RESTORE"
		echo "FWMARK_DEC=$DOCKER_FWMARK_DEC"
		echo "FWMARK_HEX=$DOCKER_FWMARK_HEX"
		echo "DOCKER_MARK_AUTO=$DOCKER_MARK_AUTO"
		printf 'DOCKER_MARK_IN=%q\n' "${DOCKER_MARK_IN:-}"
		printf 'DOCKER_FORCE_PORT=%q\n' "${DOCKER_MARK_UDP:-}"
		printf 'EXTRA_CIDRS=%q\n' ""
		printf 'AMNEZIA_DOCKER_NAME_PATTERN=%q\n' "${pattern_out}"
		printf 'AMNEZIA_DOCKER_NAMES=%q\n' "${dock_out}"
	} >"$tmp"
	mv -f -- "$tmp" "$ENV_DST"
}

rm -f -- "$POL_DIR/awg-eth0-policy.sh" "$POL_DIR/awg-eth0-policy.env"
cp -f -- "$BUNDLE" "$HOOK_DST"
chmod 755 "$HOOK_DST"
write_env

POSTUP=": \"${MARKER}\"; \"$HOOK_DST\" postup \"$WGABS\""
POSTDOWN=": \"${MARKER_DOWN}\"; \"$HOOK_DST\" postdown \"$WGABS\""

# Убирает пустые Amnezia-поля I2=, I3= (awg-quick ругается) и IPv6 из AllowedIPs.
sanitize_amnezia_conf() {
	awk '
	function trim(s) {
		sub(/^[[:space:]]+/, "", s)
		sub(/[[:space:]]+$/, "", s)
		return s
	}
	function empty_amnezia_i(l, eq, rest) {
		if (l !~ /^[[:space:]]*I[0-9]+[[:space:]]*=/) return 0
		eq = index(l, "=")
		if (eq == 0) return 0
		rest = substr(l, eq + 1)
		return (trim(rest) == "")
	}
	function strip_ipv6_allowedips(l, keylen, val, n, a, i, t, out, sep) {
		if (l !~ /^[[:space:]]*AllowedIPs[[:space:]]*=/) return l
		if (match(l, /^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*/)) {
			keylen = RLENGTH
			val = substr(l, keylen + 1)
		} else {
			return l
		}
		n = split(val, a, ",")
		out = ""
		sep = ""
		for (i = 1; i <= n; i++) {
			t = trim(a[i])
			if (t == "") continue
			if (index(t, ":") > 0) continue
			out = out sep t
			sep = ", "
		}
		if (out == "") out = "0.0.0.0/0"
		return substr(l, 1, keylen) out
	}
	{
		if (empty_amnezia_i($0)) next
		print strip_ipv6_allowedips($0)
	}
	'
}

process() {
	export AWG_POSTUP="$POSTUP" AWG_POSTDOWN="$POSTDOWN"
	awk -v marker="$MARKER" -v mdown="$MARKER_DOWN" '
	function is_our_post(s) {
		if (s !~ /^PostUp[[:space:]]*=/ && s !~ /^PostDown[[:space:]]*=/) return 0
		if (index(s, marker) > 0) return 1
		if (index(s, mdown) > 0) return 1
		if (index(s, "awg-uplink-policy.sh") > 0) return 1
		if (index(s, "awg-eth0-policy.sh") > 0) return 1
		if (index(s, "awg-docker-mark.sh") > 0) return 1
		if (index(s, "awg-eth0-policy") > 0) return 1
		return 0
	}
	BEGIN { in_iface = 0; inject_done = 0 }
	/^\[Interface\]/ {
		in_iface = 1
		print
		next
	}
	in_iface && is_our_post($0) {
		next
	}
	/^\[/ {
		if (in_iface && !inject_done) {
			print "PostUp = " ENVIRON["AWG_POSTUP"]
			print "PostDown = " ENVIRON["AWG_POSTDOWN"]
			inject_done = 1
		}
		in_iface = 0
		print
		next
	}
	{ print }
	END {
		if (in_iface && !inject_done) {
			print "PostUp = " ENVIRON["AWG_POSTUP"]
			print "PostDown = " ENVIRON["AWG_POSTDOWN"]
		}
	}
	'
}

tmp="${CANON_CONF}.tmp.$$"
cat -- "$INPUT" | sanitize_amnezia_conf | process >"$tmp"
chmod 600 "$tmp" 2>/dev/null || true
[[ -f $CANON_CONF ]] && chmod --reference="$CANON_CONF" "$tmp" 2>/dev/null || chmod 600 "$tmp"
mv -f -- "$tmp" "$CANON_CONF"

DROPIN_SRC="$REPODIR/systemd/awg-quick@${CANON_STEM}.service.d/override.conf"
if [[ -f $DROPIN_SRC ]] && command -v systemctl >/dev/null; then
	DI="/etc/systemd/system/awg-quick@${CANON_STEM}.service.d"
	mkdir -p "$DI"
	cp -f -- "$DROPIN_SRC" "$DI/override.conf"
	systemctl daemon-reload
	log "systemd drop-in: $DI/override.conf (daemon-reload выполнен). Туннель: systemctl enable --now awg-quick@${CANON_STEM}"
fi

log "Готово. Канон: $CANON_CONF, hook: $HOOK_DST, env: $ENV_DST"
log "Исходный файл не изменялся: $INPUT"

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Установка geo-DNS: systemd-resolved off, dnscrypt-proxy → dnsmasq (ipset staging),
# таймер ротации ipset, nft+ip rule (awg-uplink-geo-firewall), хуки PostUp/PostDown awg-uplink,
# docker update --dns на шлюз bridge (контейнеры Amnezia по шаблону из awg-uplink-policy.env).

set -euo pipefail

[[ ${EUID:-0} -eq 0 ]] || {
	echo "[awg-geo-install] нужен root" >&2
	exit 1
}

ROOTDIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)
CANON_CONF=${AWG_GEO_WG_CONF:-/etc/amnezia/amneziawg/awg-uplink.conf}
POLICY_ENV=${AWG_GEO_POLICY_ENV:-/etc/amnezia/amneziawg/awg-uplink-policy.env}
GEO_ENV=/etc/awg-uplink-geo.env
DOMAINS_CONF=/etc/awg-uplink-geo.domains.conf
DNSMASQ_SNIP=/etc/dnsmasq.d/zzz-awg-uplink-geo.conf
DNCRYPT_TOML=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
ROT_SRC="$ROOTDIR/lib/awg-uplink-geo-ipset-rotate.sh"
UNIT_ROT_SVC="$ROOTDIR/systemd/awg-uplink-geo-ipset-rotate.service"
UNIT_ROT_TMR="$ROOTDIR/systemd/awg-uplink-geo-ipset-rotate.timer"
ROT_DST=/usr/local/sbin/awg-uplink-geo-ipset-rotate.sh
FW_SRC="$ROOTDIR/lib/awg-uplink-geo-firewall.sh"
POSTUP_SRC="$ROOTDIR/lib/awg-uplink-geo-postup.sh"
POSTDOWN_SRC="$ROOTDIR/lib/awg-uplink-geo-postdown.sh"
FW_DST=/usr/local/sbin/awg-uplink-geo-firewall.sh
POSTUP_DST=/usr/local/sbin/awg-uplink-geo-postup.sh
POSTDOWN_DST=/usr/local/sbin/awg-uplink-geo-postdown.sh
GEO_UP=$POSTUP_DST
GEO_DOWN=$POSTDOWN_DST

die() { echo "[awg-geo-install] ERROR: $*" >&2; exit 1; }
log() { echo "[awg-geo-install] $*"; }
warn() { echo "[awg-geo-install] WARN: $*" >&2; }

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && {
	cat >&2 <<'EOF'
Использование: awg-uplink-geo-install.sh

  Устанавливает geo-DNS стек (root): пакеты, отключение systemd-resolved,
  dnscrypt-proxy (127.0.0.1:5354), dnsmasq (53 на 127.0.0.1 + docker0),
  /etc/awg-uplink-geo.env, домены → /etc/awg-uplink-geo.domains.conf,
  ipset + таймер ротации, nft/fwmark, PostUp/PostDown в awg-uplink.conf,
  docker update --dns <gateway bridge> для контейнеров по AMNEZIA_DOCKER_NAME_PATTERN.

  Переменные: AWG_GEO_WG_CONF, AWG_GEO_POLICY_ENV (пути к .conf и policy.env).
EOF
	exit 0
}

merge_geo_hooks() {
	[[ -f $CANON_CONF ]] || {
		warn "нет $CANON_CONF — хуки PostUp/PostDown не добавлены (сделайте inject и повторите)"
		return 0
	}
	if grep -q 'awg-uplink-geo-postup' "$CANON_CONF" 2>/dev/null; then
		log "PostUp уже содержит awg-uplink-geo — пропуск merge"
		return 0
	fi
	local tmp
	tmp=$(mktemp)
	awk -v up="$GEO_UP" -v dn="$GEO_DOWN" '
	BEGIN { iface = 0 }
	/^\[Interface\]/ { iface = 1; print; next }
	/^\[/ {
		iface = 0
		print
		next
	}
	iface && /^PostUp[[:space:]]*=/ {
		line = $0
		sub(/\r$/, "", line)
		if (index(line, "awg-uplink-geo-postup") > 0) { print line; next }
		sub(/^PostUp[[:space:]]*=[[:space:]]*/, "", line)
		print "PostUp = " line " && " up
		next
	}
	iface && /^PostDown[[:space:]]*=/ {
		line = $0
		sub(/\r$/, "", line)
		if (index(line, "awg-uplink-geo-postdown") > 0) { print line; next }
		sub(/^PostDown[[:space:]]*=[[:space:]]*/, "", line)
		print "PostDown = " dn " && " line
		next
	}
	{ print }
	' "$CANON_CONF" >"$tmp"
	mv -f -- "$tmp" "$CANON_CONF"
	log "обновлены PostUp/PostDown в $CANON_CONF"
}

disable_systemd_resolved() {
	if systemctl list-unit-files systemd-resolved.service &>/dev/null; then
		if systemctl is-enabled systemd-resolved &>/dev/null || systemctl is-active systemd-resolved &>/dev/null; then
			systemctl disable --now systemd-resolved 2>/dev/null || true
			log "systemd-resolved отключён (disable --now)"
		fi
	fi
	if [[ -L /etc/resolv.conf ]] && [[ $(readlink -f /etc/resolv.conf 2>/dev/null) == */systemd/resolve/* ]]; then
		rm -f -- /etc/resolv.conf
	fi
	if [[ ! -f /etc/resolv.conf ]] || ! grep -q '^nameserver[[:space:]]' /etc/resolv.conf 2>/dev/null; then
		printf 'nameserver 127.0.0.1\n' >/etc/resolv.conf
		log "/etc/resolv.conf → nameserver 127.0.0.1 (dnsmasq)"
	fi
}

patch_dnscrypt_listen() {
	[[ -f $DNCRYPT_TOML ]] || {
		warn "нет $DNCRYPT_TOML — пакет dnscrypt-proxy нестандартен; задайте listen вручную на 127.0.0.1:5354"
		return 0
	}
	if grep -qE "127\.0\.0\.1:5354" "$DNCRYPT_TOML" 2>/dev/null; then
		log "dnscrypt-proxy: listen уже 127.0.0.1:5354"
		return 0
	fi
	cp -a -- "$DNCRYPT_TOML" "${DNCRYPT_TOML}.awg-geo-bak.$(date +%s)" 2>/dev/null || true
	if grep -q '^listen_addresses' "$DNCRYPT_TOML"; then
		sed -i "s/^listen_addresses *=.*/listen_addresses = ['127.0.0.1:5354']/" "$DNCRYPT_TOML"
	else
		printf "\n# awg-uplink-geo\nlisten_addresses = ['127.0.0.1:5354']\n" >>"$DNCRYPT_TOML"
	fi
	log "dnscrypt-proxy: listen_addresses = 127.0.0.1:5354 ($DNCRYPT_TOML)"
}

write_geo_env() {
	[[ -f $GEO_ENV ]] && {
		log "сохраняю существующий $GEO_ENV (не перезаписываю)"
		return 0
	}
	cat >"$GEO_ENV" <<'ENVEOF'
# awg-uplink geo (см. lib/awg-uplink-geo-install.sh)
AWG_GEO_ENABLE=1
AWG_GEO_IPSET_STAGING=awg_geo_staging
AWG_GEO_IPSET_ROUTE=awg_geo_route
AWG_GEO_IPSET_MAXELEM=262144
AWG_GEO_FWMARK_DEC=30595
AWG_GEO_FWMARK_HEX=0x7783
AWG_GEO_RULE_PRIO=83
AWG_GEO_NFT_TABLE=awg_uplink_geo
ENVEOF
	chmod 644 "$GEO_ENV"
	log "создан $GEO_ENV"
}

write_domains_conf() {
	[[ -f $DOMAINS_CONF ]] && return 0
	cat >"$DOMAINS_CONF" <<'EOF'
# dnsmasq: домен → ipset staging (имя должно совпадать с AWG_GEO_IPSET_STAGING в /etc/awg-uplink-geo.env).
# Пример:
# ipset=/youtube.com/awg_geo_staging
# ipset=/googlevideo.com/awg_geo_staging
EOF
	chmod 644 "$DOMAINS_CONF"
	log "создан $DOMAINS_CONF — добавьте ipset=/домен/awg_geo_staging"
}

write_dnsmasq_snippet() {
	local docker0_ip
	docker0_ip=$(ip -4 -o addr show docker0 2>/dev/null | awk '$3=="inet" {gsub(/\/.*/,"",$4); print $4; exit}')
	{
		echo "# awg-uplink-geo (перегенерация: снова запустите lib/awg-uplink-geo-install.sh)"
		echo "bind-interfaces"
		echo "except-interface=lo"
		echo "listen-address=127.0.0.1"
		if [[ -n ${docker0_ip:-} ]]; then
			echo "listen-address=$docker0_ip"
			log "dnsmasq: listen docker0=$docker0_ip"
		else
			warn "нет IPv4 на docker0 — только 127.0.0.1; контейнеры без маршрута к нему не увидят DNS"
		fi
		echo "no-resolv"
		echo "no-poll"
		echo "server=127.0.0.1#5354"
		echo "cache-size=20000"
		echo "conf-file=$DOMAINS_CONF"
	} >"$DNSMASQ_SNIP"
	chmod 644 "$DNSMASQ_SNIP"
	log "записан $DNSMASQ_SNIP"
}

dnsmasq_systemd_dropin() {
	mkdir -p /etc/systemd/system/dnsmasq.service.d
	cat >/etc/systemd/system/dnsmasq.service.d/awg-uplink-geo.conf <<'EOF'
[Unit]
After=network-online.target dnscrypt-proxy.service
Wants=dnscrypt-proxy.service
EOF
	log "drop-in dnsmasq.service.d/awg-uplink-geo.conf"
}

install_packages() {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y dnsmasq dnscrypt-proxy ipset nftables
}

install_bins_and_units() {
	install -m755 "$ROT_SRC" "$ROT_DST"
	install -m644 "$UNIT_ROT_SVC" /etc/systemd/system/awg-uplink-geo-ipset-rotate.service
	install -m644 "$UNIT_ROT_TMR" /etc/systemd/system/awg-uplink-geo-ipset-rotate.timer
	install -m755 "$FW_SRC" "$FW_DST"
	install -m755 "$POSTUP_SRC" "$POSTUP_DST"
	install -m755 "$POSTDOWN_SRC" "$POSTDOWN_DST"
}

docker_set_dns_to_bridge_gateway() {
	command -v docker >/dev/null 2>&1 || {
		warn "docker не в PATH — пропуск docker update --dns"
		return 0
	}
	local gw pat
	gw=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null | tr -d '\r\n' || true)
	[[ -n $gw ]] || gw=172.17.0.1
	pat='^amnezia-awg'
	if [[ -f $POLICY_ENV ]]; then
		# shellcheck disable=1090
		set -a
		. "$POLICY_ENV"
		set +a
		pat=${AMNEZIA_DOCKER_NAME_PATTERN:-^amnezia-awg}
	fi
	local n
	while IFS= read -r n; do
		[[ -n $n ]] || continue
		[[ $n =~ $pat ]] || continue
		if docker update --dns "$gw" "$n" 2>/dev/null; then
			log "docker update --dns $gw $n"
		else
			warn "docker update --dns $gw $n не удался"
		fi
	done < <(docker ps --format '{{.Names}}' 2>/dev/null || true)
}

main() {
	log "пакеты: dnsmasq, dnscrypt-proxy, ipset, nftables"
	install_packages
	disable_systemd_resolved
	patch_dnscrypt_listen
	write_geo_env
	write_domains_conf
	write_dnsmasq_snippet
	dnsmasq_systemd_dropin
	install_bins_and_units
	"$ROT_DST" init
	systemctl daemon-reload
	systemctl enable --now dnscrypt-proxy.service 2>/dev/null || systemctl enable --now dnscrypt-proxy.socket 2>/dev/null || warn "dnscrypt-proxy unit не включён — проверьте systemctl list-units '*dnscrypt*'"
	systemctl enable --now awg-uplink-geo-ipset-rotate.timer
	systemctl enable dnsmasq.service 2>/dev/null || true
	systemctl restart dnscrypt-proxy.service 2>/dev/null || systemctl restart dnscrypt-proxy.socket 2>/dev/null || true
	systemctl restart dnsmasq.service || die "dnsmasq не стартует — journalctl -u dnsmasq"
	merge_geo_hooks
	docker_set_dns_to_bridge_gateway
	log "готово. Проверка: ss -lunp | grep -E ':53|:5354'; dig @127.0.0.1 example.com; $ROT_DST status"
}

main "$@"

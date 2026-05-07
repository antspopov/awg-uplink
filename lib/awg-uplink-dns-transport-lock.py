#!/usr/bin/env python3
"""nftables: при включённом dns_transport_lock в dns.json — DNAT UDP/TCP 53 → шлюз Docker,
блок TCP/UDP 853 (DoT), блок TCP/UDP 443 к известным публичным резолверам с DoH.

Подсеть/шлюз: docker network inspect по amnezia_dns_network из dns.json,
либо переопределение dns_transport_lock_subnet / dns_transport_lock_gateway (IPv4 CIDR и IPv4).

Таблицы: inet awg_uplink_dns_transport_lock, ip awg_uplink_dns_transport_nat [, ip6 …].
Удаление старых тестовых таблиц awg_amnezia_subnet_*."""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CFG_DIR = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
DNS_JSON = CFG_DIR / "dns.json"

TABLE_INET = "awg_uplink_dns_transport_lock"
TABLE_NAT4 = "awg_uplink_dns_transport_nat"
TABLE_NAT6 = "awg_uplink_dns_transport_nat6"

# Известные адреса публичных DNS с типовым DoH на 443 (IPv4). Неполный список anycast/CDN.
DOH_IPV4: frozenset[str] = frozenset(
    {
        # Cloudflare
        "1.1.1.1",
        "1.0.0.1",
        "1.1.1.2",
        "1.1.1.3",
        # Google
        "8.8.8.8",
        "8.8.4.4",
        # Quad9
        "9.9.9.9",
        "9.9.9.10",
        "9.9.9.11",
        "9.9.9.12",
        "149.112.112.112",
        "149.112.112.9",
        "149.112.112.10",
        "149.112.112.11",
        # OpenDNS / Cisco
        "208.67.222.222",
        "208.67.220.220",
        # AdGuard
        "94.140.14.14",
        "94.140.15.15",
        "94.140.14.15",
        "94.140.15.16",
        "176.103.130.130",
        "176.103.130.131",
        "176.103.130.132",
        "176.103.130.134",
        # CleanBrowsing
        "185.228.168.9",
        "185.228.169.9",
        "185.228.168.10",
        "185.228.169.11",
        "185.228.168.168",
        # DNS.SB
        "185.222.222.222",
        "45.11.45.11",
        # Alibaba / Tencent / DNSPod
        "223.5.5.5",
        "223.6.6.6",
        "119.29.29.29",
        "119.28.28.28",
        # Comodo
        "8.26.56.26",
        "8.20.247.20",
        # SafeDNS
        "195.46.39.39",
        "195.46.39.40",
        # Verisign
        "64.6.64.6",
        "64.6.65.6",
        # UncensoredDNS
        "91.239.100.100",
        "89.233.43.71",
        # DNSWatch
        "84.200.69.80",
        "84.200.70.40",
        # BlahDNS / LibreDNS / др.
        "159.69.198.101",
        "45.91.92.121",
        "88.198.92.222",
        # Control D
        "76.76.2.2",
        "76.76.10.10",
        "76.76.2.22",
        # Mullvad
        "194.242.2.2",
        "194.242.2.3",
        "194.242.2.4",
        # CIRA Canadian Shield
        "149.112.121.10",
        "149.112.121.30",
        # Freenom World
        "80.80.80.80",
        "80.80.81.81",
        # Switch CH
        "195.10.195.195",
        # Snopyta / Applied Privacy / dnswarden
        "95.216.155.133",
        "146.255.56.98",
        "88.198.91.90",
        # NextDNS (часть anycast-узлов)
        "45.90.28.231",
        "45.90.30.231",
        "217.146.22.163",
        # He.net
        "74.82.42.42",
        # Yandex (есть DoH)
        "77.88.8.8",
        "77.88.8.1",
        "77.88.8.2",
        "77.88.8.88",
        "5.45.225.25",
        # DNSlify
        "185.236.104.104",
        "185.236.105.105",
        # OpenNIC ADGuard через некоторые узлы — уже покрыто
    }
)

DOH_IPV6: frozenset[str] = frozenset(
    {
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2606:4700:4700::1112",
        "2606:4700:4700::1113",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2620:fe::fe",
        "2620:fe::11",
        "2620:fe::10",
        "2620:fe::9",
        "2620:119:35::35",
        "2620:119:53::53",
        "2a10:50c0::ad1:ff",
        "2a10:50c0::ad2:ff",
        "2a10:50c0::bad1:ff",
        "2a10:50c0::bad2:ff",
        "2a0d:2a00:1::2",
        "2a0d:2a00:2::2",
        "2606:1a40::1",
        "2606:1a40::2",
        "2001:1608:10:25::1c04:b12f",
        "2001:1608:10:25::9249:d69e",
        "2a01:4f8:c17:ec19::1",
    }
)


def run(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def load_dns_cfg() -> dict:
    if not DNS_JSON.exists():
        return {}
    try:
        o = json.loads(DNS_JSON.read_text(encoding="utf-8"))
        return o if isinstance(o, dict) else {}
    except Exception:
        return {}


def nft_delete_table(family: str, name: str) -> None:
    run(["nft", "delete", "table", family, name])


def delete_legacy_and_own() -> None:
    for fam, name in (
        ("inet", "awg_amnezia_subnet_block"),
        ("ip", "awg_amnezia_subnet_nat"),
        ("inet", TABLE_INET),
        ("ip", TABLE_NAT4),
        ("ip6", TABLE_NAT6),
    ):
        nft_delete_table(fam, name)


def docker_ipam(network: str) -> tuple[str | None, str | None, str | None, str | None]:
    """IPv4 subnet, IPv4 gw, IPv6 subnet, IPv6 gw."""
    p = run(
        ["docker", "network", "inspect", network, "--format", "{{json .IPAM.Config}}"],
        check=False,
    )
    if p.returncode != 0 or not (p.stdout or "").strip():
        return None, None, None, None
    try:
        cfg = json.loads(p.stdout.strip())
    except json.JSONDecodeError:
        return None, None, None, None
    if not isinstance(cfg, list):
        return None, None, None, None
    sub4 = gw4 = sub6 = gw6 = None
    for block in cfg:
        if not isinstance(block, dict):
            continue
        sn = str(block.get("Subnet") or "").strip()
        gw = str(block.get("Gateway") or "").strip()
        if not sn:
            continue
        try:
            net = ipaddress.ip_network(sn, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            if sub4 is None:
                sub4 = str(net)
                gw4 = gw or gw4
        elif net.version == 6:
            if sub6 is None:
                sub6 = str(net)
                gw6 = gw or gw6
    return sub4, gw4, sub6, gw6


def resolve_subnet_gateway(cfg: dict) -> tuple[str, str, str | None, str | None]:
    over_sub = str(cfg.get("dns_transport_lock_subnet") or "").strip()
    over_gw = str(cfg.get("dns_transport_lock_gateway") or "").strip()
    if over_sub and over_gw:
        net4 = ipaddress.ip_network(over_sub, strict=False)
        if net4.version != 4:
            raise ValueError("dns_transport_lock_subnet must be IPv4 CIDR")
        ipaddress.ip_address(over_gw)
        return str(net4), over_gw, None, None
    else:
        net = str(cfg.get("amnezia_dns_network") or "amnezia-dns-net").strip() or "amnezia-dns-net"
        sub4, gw4, sub6, gw6 = docker_ipam(net)
        if not sub4 or not gw4:
            raise ValueError(f"не удалось получить IPv4 subnet/gateway для Docker-сети «{net}»")
        net4 = ipaddress.ip_network(sub4, strict=False)
        ipaddress.ip_address(gw4)
        if sub6 and gw6:
            try:
                ipaddress.ip_network(sub6, strict=False)
                ipaddress.ip_address(gw6)
            except ValueError:
                sub6, gw6 = None, None
        else:
            sub6, gw6 = None, None
        return str(net4), gw4, sub6, gw6


def nft_escape_set_elem(ip: str) -> str:
    return ip


def build_nft(
    sub4: str,
    gw4: str,
    sub6: str | None,
    gw6: str | None,
) -> str:
    lines: list[str] = [
        f"table ip {TABLE_NAT4} {{",
        "  chain prerouting {",
        "    type nat hook prerouting priority -125; policy accept;",
        f"    ip saddr {sub4} tcp dport 53 ip daddr != {gw4} counter dnat ip to {gw4}:53",
        f"    ip saddr {sub4} udp dport 53 ip daddr != {gw4} counter dnat ip to {gw4}:53",
        "  }",
        "}",
        "",
        f"table inet {TABLE_INET} {{",
        "  set doh4 {",
        "    type ipv4_addr",
        "    flags interval",
        "    elements = {",
    ]
    elems4 = sorted(DOH_IPV4)
    lines.append("      " + ", ".join(nft_escape_set_elem(x) for x in elems4))
    lines.extend(["    }", "  }", ""])

    if sub6 and gw6:
        lines.extend(
            [
                "  set doh6 {",
                "    type ipv6_addr",
                "    flags interval",
                "    elements = {",
            ]
        )
        elems6 = sorted(DOH_IPV6)
        lines.append("      " + ", ".join(nft_escape_set_elem(x) for x in elems6))
        lines.extend(["    }", "  }", ""])

    lines.extend(
        [
            "  chain forward {",
            "    type filter hook forward priority -50; policy accept;",
            f"    ip saddr {sub4} tcp dport 853 counter drop",
            f"    ip saddr {sub4} udp dport 853 counter drop",
            f"    ip saddr {sub4} tcp dport 443 ip daddr @doh4 counter drop",
            f"    ip saddr {sub4} udp dport 443 ip daddr @doh4 counter drop",
        ]
    )
    if sub6 and gw6:
        lines.extend(
            [
                f"    ip6 saddr {sub6} tcp dport 853 counter drop",
                f"    ip6 saddr {sub6} udp dport 853 counter drop",
                f"    ip6 saddr {sub6} tcp dport 443 ip6 daddr @doh6 counter drop",
                f"    ip6 saddr {sub6} udp dport 443 ip6 daddr @doh6 counter drop",
            ]
        )
    lines.extend(
        [
            "  }",
            "",
            "  chain input {",
            "    type filter hook input priority -50; policy accept;",
            f"    ip saddr {sub4} tcp dport 853 counter drop",
            f"    ip saddr {sub4} udp dport 853 counter drop",
            f"    ip saddr {sub4} tcp dport 443 ip daddr @doh4 counter drop",
            f"    ip saddr {sub4} udp dport 443 ip daddr @doh4 counter drop",
        ]
    )
    if sub6 and gw6:
        lines.extend(
            [
                f"    ip6 saddr {sub6} tcp dport 853 counter drop",
                f"    ip6 saddr {sub6} udp dport 853 counter drop",
                f"    ip6 saddr {sub6} tcp dport 443 ip6 daddr @doh6 counter drop",
                f"    ip6 saddr {sub6} udp dport 443 ip6 daddr @doh6 counter drop",
            ]
        )
    lines.extend(["  }", "}"])

    if sub6 and gw6:
        lines.extend(
            [
                "",
                f"table ip6 {TABLE_NAT6} {{",
                "  chain prerouting {",
                "    type nat hook prerouting priority -125; policy accept;",
                f"    ip6 saddr {sub6} tcp dport 53 ip6 daddr != {gw6} counter dnat ip6 to [{gw6}]:53",
                f"    ip6 saddr {sub6} udp dport 53 ip6 daddr != {gw6} counter dnat ip6 to [{gw6}]:53",
                "  }",
                "}",
            ]
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    cfg = load_dns_cfg()
    enabled = bool(cfg.get("dns_transport_lock_enabled"))

    delete_legacy_and_own()

    if not enabled:
        return 0

    try:
        sub4, gw4, sub6, gw6 = resolve_subnet_gateway(cfg)
    except ValueError as e:
        print(f"awg-uplink-dns-transport-lock: {e}", file=sys.stderr)
        return 1

    body = build_nft(sub4, gw4, sub6, gw6)
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False, encoding="utf-8") as tmp:
        tmp.write(body)
        tmp_path = tmp.name
    try:
        p = run(["nft", "-f", tmp_path], check=False)
        if p.returncode != 0:
            err = (p.stderr or p.stdout or "").strip()
            print(f"awg-uplink-dns-transport-lock: nft failed: {err}", file=sys.stderr)
            return p.returncode or 1
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())

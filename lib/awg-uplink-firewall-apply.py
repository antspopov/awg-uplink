#!/usr/bin/env python3
"""Брандмауэр панели «интерфейсы»: nftables (по умолчанию) или UFW (удобнее смотреть `ufw status`).

Геороутинг / DNS-transport-lock и др. по-прежнему используют свои nft-таблицы — только таблица
inet awg_webui_fw или набор правил UFW с маркером awg-web-ui-fw.

Порты: interfaces.json → firewall (fallback — dns.json).
Бэкенд: interfaces.env AWG_FW_BACKEND=nft|ufw (пишет Web UI) или переменная окружения."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CFG = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
ENV_FILE = CFG / "interfaces.env"
IFACE_JSON = CFG / "interfaces.json"
DNS_JSON = CFG / "dns.json"
NFT_TABLE = "awg_webui_fw"
AWG_IFACE = os.environ.get("AWG_FW_AWG_IFACE", "awg-uplink").strip() or "awg-uplink"
UFW_MARKER = "awg-web-ui-fw"


def parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        out[k] = v
    return out


def nft_escape(name: str) -> str:
    return name.replace("\\", "\\\\").replace('"', '\\"')


def load_fw_ports() -> tuple[list[int], list[int]]:
    eg = [22]
    ing = [22, 443, 8080]
    fw = None
    if IFACE_JSON.exists():
        try:
            iface = json.loads(IFACE_JSON.read_text(encoding="utf-8"))
            fw = iface.get("firewall") if isinstance(iface.get("firewall"), dict) else None
        except Exception:
            fw = None
    if fw is None and DNS_JSON.exists():
        try:
            dns = json.loads(DNS_JSON.read_text(encoding="utf-8"))
            fw = dns.get("firewall") if isinstance(dns.get("firewall"), dict) else None
        except Exception:
            fw = None
    if isinstance(fw, dict):
        e = fw.get("egress_tcp_ports")
        i = fw.get("ingress_tcp_ports")
        try:
            if isinstance(e, list):
                eg = sorted({int(x) for x in e if str(x).isdigit() and 1 <= int(x) <= 65535}) or eg
            if isinstance(i, list):
                ing = sorted({int(x) for x in i if str(x).isdigit() and 1 <= int(x) <= 65535}) or ing
        except Exception:
            pass
    return eg, ing


def ufw_purge_marker() -> None:
    """Удаляет только правила с нашим comment (не трогает чужие правила UFW)."""
    if not shutil.which("ufw"):
        return
    for _ in range(256):
        proc = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True)
        out = proc.stdout or ""
        nums: list[int] = []
        for line in out.splitlines():
            if UFW_MARKER not in line:
                continue
            m = re.match(r"\s*\[\s*(\d+)\s*\]", line)
            if m:
                nums.append(int(m.group(1)))
        if not nums:
            break
        subprocess.run(["ufw", "--force", "delete", str(max(nums))], capture_output=True)


def ufw_is_active() -> bool:
    if not shutil.which("ufw"):
        return False
    proc = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    s = (proc.stdout or "").lower()
    return "status: active" in s


def ufw_add(rule_args: list[str]) -> bool:
    """rule_args: например ['allow', 'in', 'on', 'eth0', ...] — без префикса ufw."""
    proc = subprocess.run(["ufw", *rule_args], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"[awg-uplink-firewall] ufw {' '.join(rule_args)} failed: {proc.stderr or proc.stdout}\n")
        return False
    return True


def apply_nft(
    egress: str,
    ing_en: bool,
    ingress: str,
    eg_ports: list[int],
    ing_ports: list[int],
) -> None:
    ufw_purge_marker()
    subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], capture_output=True)
    if not egress:
        return

    lines = [
        f"table inet {NFT_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority 55; policy accept;",
        "    ct state established,related accept",
        "    iif lo accept",
        f'    iifname "{nft_escape(AWG_IFACE)}" ct state new counter drop',
    ]

    distinct_ingress = ing_en and ingress and ingress != egress
    union_fw_ports = bool(egress and ingress and ingress == egress)

    if distinct_ingress:
        eg_ps = ", ".join(str(p) for p in eg_ports)
        ing_ps = ", ".join(str(p) for p in ing_ports)
        lines.append(f'    iifname "{nft_escape(egress)}" tcp dport {{ {eg_ps} }} ct state new counter accept')
        lines.append(f'    iifname "{nft_escape(egress)}" ct state new counter drop')
        lines.append(f'    iifname "{nft_escape(ingress)}" tcp dport {{ {ing_ps} }} ct state new counter accept')
        lines.append(f'    iifname "{nft_escape(ingress)}" ct state new counter drop')
    else:
        if union_fw_ports:
            ports = sorted(set(eg_ports) | set(ing_ports))
        else:
            ports = eg_ports
        ps = ", ".join(str(p) for p in ports)
        lines.append(f'    iifname "{nft_escape(egress)}" tcp dport {{ {ps} }} ct state new counter accept')
        lines.append(f'    iifname "{nft_escape(egress)}" ct state new counter drop')

    lines.extend(["  }", "}"])
    nft_body = "\n".join(lines) + "\n"

    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False, encoding="utf-8") as tmp:
        tmp.write(nft_body)
        tmp_path = tmp.name
    try:
        subprocess.run(["nft", "-f", tmp_path], check=True)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def apply_ufw(
    egress: str,
    ing_en: bool,
    ingress: str,
    eg_ports: list[int],
    ing_ports: list[int],
) -> None:
    subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], capture_output=True)
    if not shutil.which("ufw"):
        sys.stderr.write("[awg-uplink-firewall] ufw не найден (apt install ufw); используется nft.\n")
        apply_nft(egress, ing_en, ingress, eg_ports, ing_ports)
        return
    if not ufw_is_active():
        sys.stderr.write(
            "[awg-uplink-firewall] AWG_FW_BACKEND=ufw, но UFW не активен (sudo ufw enable). Используется nft.\n"
        )
        apply_nft(egress, ing_en, ingress, eg_ports, ing_ports)
        return

    ufw_purge_marker()
    if not egress:
        return

    distinct_ingress = ing_en and ingress and ingress != egress
    union_fw_ports = bool(egress and ingress and ingress == egress)

    def allow_tcp_on(dev: str, ports: list[int]) -> None:
        if not ports:
            return
        ps = ",".join(str(p) for p in ports)
        ufw_add(
            [
                "allow",
                "in",
                "on",
                dev,
                "to",
                "any",
                "port",
                ps,
                "proto",
                "tcp",
                "comment",
                UFW_MARKER,
            ]
        )

    def deny_in_on(dev: str) -> None:
        ufw_add(["deny", "in", "on", dev, "comment", UFW_MARKER])

    # Сначала разрешения по TCP, затем запрет остального входящего на том же интерфейсе (как ct state new drop в nft).
    if distinct_ingress:
        allow_tcp_on(egress, eg_ports)
        deny_in_on(egress)
        allow_tcp_on(ingress, ing_ports)
        deny_in_on(ingress)
    else:
        if union_fw_ports:
            ports = sorted(set(eg_ports) | set(ing_ports))
        else:
            ports = eg_ports
        allow_tcp_on(egress, ports)
        deny_in_on(egress)

    deny_in_on(AWG_IFACE)


def main() -> None:
    os.environ.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env = parse_env(ENV_FILE)
    egress = env.get("EGRESS_DEV", "").strip()
    ing_en = env.get("INGRESS_ENABLED", "0").strip() == "1"
    ingress = env.get("INGRESS_DEV", "").strip()
    eg_ports, ing_ports = load_fw_ports()
    backend = (env.get("AWG_FW_BACKEND") or os.environ.get("AWG_FW_BACKEND") or "nft").strip().lower()
    if backend not in ("nft", "ufw"):
        backend = "nft"

    if backend == "ufw":
        apply_ufw(egress, ing_en, ingress, eg_ports, ing_ports)
    else:
        apply_nft(egress, ing_en, ingress, eg_ports, ing_ports)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""nftables: ограничить входящие на egress / ingress / awg-uplink; порты из interfaces.json (fallback — dns.json)."""
import json
import os
import subprocess
import tempfile
from pathlib import Path

CFG = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
ENV_FILE = CFG / "interfaces.env"
IFACE_JSON = CFG / "interfaces.json"
DNS_JSON = CFG / "dns.json"
NFT_TABLE = "awg_webui_fw"
AWG_IFACE = os.environ.get("AWG_FW_AWG_IFACE", "awg-uplink").strip() or "awg-uplink"


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
    # Обратная совместимость: порты раньше хранились в dns.json
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


def main():
    env = parse_env(ENV_FILE)
    egress = env.get("EGRESS_DEV", "").strip()
    ing_en = env.get("INGRESS_ENABLED", "0").strip() == "1"
    ingress = env.get("INGRESS_DEV", "").strip()
    eg_ports, ing_ports = load_fw_ports()

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
    # Один и тот же NIC: в interfaces.env при совпадении IP/интерфейса INGRESS_ENABLED=0, но INGRESS_DEV
    # всё равно может совпадать с EGRESS — порты ingress/egress из JSON объединяем.
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


if __name__ == "__main__":
    main()

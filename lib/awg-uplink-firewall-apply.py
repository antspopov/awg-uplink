#!/usr/bin/env python3
"""Файрвол панели «интерфейсы».

- Установлен **ufw**: при включённом переключателе панели — `ufw --force enable` и только правила с
  comment `awg-web-ui-fw` (остальные записи UFW не трогаем). На **egress**, **ingress** (если отдельный)
  и **awg-uplink** — входящий трафик: разрешённые TCP-порты панели, остальное deny; на **всех прочих**
  интерфейсах (docker/amn/veth и т.д.) — явный **allow in** на весь входящий, иначе при глобальном
  default deny UFW блокирует DNS и локальный трафик. При **выключенном** переключателе —
  снять помеченные правила, удалить таблицу `inet awg_webui_fw`, **`ufw --force disable`**.
- **Без пакета ufw** — те же ограничения через nftables (`inet awg_webui_fw`); переключатель «выкл»
  только снимает эту таблицу.

Порты 80, 443 и masking (AWG_UI_MASK_PORT, по умолчанию 5000) всегда открываются на ingress при split
или на egress, если ingress совпадает с egress.

Georouting / DNS-transport-lock — отдельные nft-таблицы.

Порты: interfaces.json → firewall (fallback — dns.json).
AWG_FW_ENABLED в interfaces.env (по умолчанию 1); переменные окружения перекрывают файл."""
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
WEBUI_ENV = CFG / "webui.env"
IFACE_JSON = CFG / "interfaces.json"
DNS_JSON = CFG / "dns.json"
NFT_TABLE = "awg_webui_fw"
AWG_IFACE = os.environ.get("AWG_FW_AWG_IFACE", "awg-uplink").strip() or "awg-uplink"
UFW_MARKER = "awg-web-ui-fw"
DEFAULT_MASK_PORT = 5000


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


def env_flag_true(key: str, env: dict, *, default: str = "1") -> bool:
    raw = (os.environ.get(key) or env.get(key, default) or default).strip().lower()
    return raw not in ("0", "false", "no", "off", "")


def load_mask_port() -> int:
    raw = (os.environ.get("AWG_UI_MASK_PORT") or "").strip()
    if not raw and WEBUI_ENV.exists():
        for line in WEBUI_ENV.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("AWG_UI_MASK_PORT="):
                raw = line.split("=", 1)[1].strip().strip('"').strip("'")
                break
    if raw:
        try:
            n = int(raw)
            if 1 <= n <= 65535:
                return n
        except ValueError:
            pass
    return DEFAULT_MASK_PORT


def reserved_tcp_ports() -> list[int]:
    return sorted({80, 443, load_mask_port()})


def effective_fw_ports(
    egress: str,
    ing_en: bool,
    ingress: str,
    eg_ports: list[int],
    ing_ports: list[int],
) -> tuple[list[int], list[int]]:
    """Порты для UFW/nft: reserved всегда на ingress (split) или на egress (egress=ingress)."""
    reserved = set(reserved_tcp_ports())
    distinct_ingress = bool(ing_en and ingress and ingress != egress)
    if distinct_ingress:
        return sorted(set(eg_ports)), sorted(set(ing_ports) | reserved)
    return sorted(set(eg_ports) | set(ing_ports) | reserved), sorted(set(ing_ports))


def load_fw_ports() -> tuple[list[int], list[int]]:
    eg = [22]
    ing = [22, 80, 443, load_mask_port()]
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


def nft_delete_table() -> None:
    subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], capture_output=True)


def nft_escape(name: str) -> str:
    return name.replace("\\", "\\\\").replace('"', '\\"')


def ufw_purge_marker() -> None:
    """Удаляет только правила с comment awg-web-ui-fw."""
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


def ufw_force_enable() -> bool:
    if not shutil.which("ufw"):
        return False
    if ufw_is_active():
        return True
    proc = subprocess.run(["ufw", "--force", "enable"], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"[awg-uplink-firewall] ufw --force enable failed: {proc.stderr or proc.stdout}\n")
        return False
    return True


def ufw_force_disable() -> None:
    if not shutil.which("ufw"):
        return
    subprocess.run(["ufw", "--force", "disable"], capture_output=True, text=True)


def ufw_add(rule_args: list[str]) -> bool:
    proc = subprocess.run(["ufw", *rule_args], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"[awg-uplink-firewall] ufw {' '.join(rule_args)} failed: {proc.stderr or proc.stdout}\n")
        return False
    return True


def load_tunnel_ifaces(env: dict[str, str]) -> list[str]:
    names: list[str] = []
    for key in ("TUNNEL_IFACE", "TUNNEL1_IFACE", "TUNNEL2_IFACE", "AWG_FW_AWG_IFACE"):
        v = (os.environ.get(key) or env.get(key, "") or "").strip()
        if v and v not in names:
            names.append(v)
    if AWG_IFACE not in names:
        names.append(AWG_IFACE)
    return names


def ufw_managed_input_ifaces(egress: str, distinct_ingress: bool, ingress: str, tunnel_ifaces: list[str]) -> set[str]:
    """Интерфейсы, на которых входящий трафик режем (остальные считаем «локальными» для UFW)."""
    s: set[str] = set(tunnel_ifaces)
    if egress:
        s.add(egress)
    if distinct_ingress and ingress:
        s.add(ingress)
    return {x for x in s if x}


def ufw_local_input_ifaces(managed: set[str]) -> list[str]:
    """Все интерфейсы кроме lo и managed — на них нужен allow in при глобальном UFW deny."""
    proc = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True, timeout=8)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return []
    try:
        items = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(items, list):
        return []
    out: set[str] = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        name = (it.get("ifname") or "").strip()
        if not name or name == "lo" or name in managed:
            continue
        out.add(name)
    return sorted(out)


def apply_nft(
    egress: str,
    ing_en: bool,
    ingress: str,
    eg_ports: list[int],
    ing_ports: list[int],
) -> None:
    """Если пакета ufw нет — ограничения через nft (отдельная таблица)."""
    if not shutil.which("nft"):
        sys.stderr.write("[awg-uplink-firewall] nft не найден — файрвол панели не применён.\n")
        return
    nft_delete_table()
    if not egress:
        return

    eg_ports, ing_ports = effective_fw_ports(egress, ing_en, ingress, eg_ports, ing_ports)

    lines = [
        f"table inet {NFT_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority 55; policy accept;",
        "    ct state established,related accept",
        "    iif lo accept",
    ]
    tunnel_ifaces = load_tunnel_ifaces(parse_env(ENV_FILE))
    for tun in tunnel_ifaces:
        lines.append(f'    iifname "{nft_escape(tun)}" ct state new counter drop')

    distinct_ingress = ing_en and ingress and ingress != egress

    if distinct_ingress:
        eg_ps = ", ".join(str(p) for p in eg_ports)
        ing_ps = ", ".join(str(p) for p in ing_ports)
        lines.append(f'    iifname "{nft_escape(egress)}" tcp dport {{ {eg_ps} }} ct state new counter accept')
        lines.append(f'    iifname "{nft_escape(egress)}" ct state new counter drop')
        lines.append(f'    iifname "{nft_escape(ingress)}" tcp dport {{ {ing_ps} }} ct state new counter accept')
        lines.append(f'    iifname "{nft_escape(ingress)}" ct state new counter drop')
    else:
        ps = ", ".join(str(p) for p in eg_ports)
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


def apply_ufw_panel(
    egress: str,
    ing_en: bool,
    ingress: str,
    eg_ports: list[int],
    ing_ports: list[int],
) -> None:
    if not egress:
        return

    eg_ports, ing_ports = effective_fw_ports(egress, ing_en, ingress, eg_ports, ing_ports)
    distinct_ingress = ing_en and ingress and ingress != egress

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

    def allow_all_in_on(dev: str) -> None:
        """Полный входящий на «локальный» интерфейс (docker bridge, veth и т.д.)."""
        ufw_add(["allow", "in", "on", dev, "comment", UFW_MARKER])

    tunnel_ifaces = load_tunnel_ifaces(parse_env(ENV_FILE))
    managed = ufw_managed_input_ifaces(egress, distinct_ingress, ingress, tunnel_ifaces)
    for loc in ufw_local_input_ifaces(managed):
        allow_all_in_on(loc)

    if distinct_ingress:
        allow_tcp_on(egress, eg_ports)
        deny_in_on(egress)
        allow_tcp_on(ingress, ing_ports)
        deny_in_on(ingress)
    else:
        allow_tcp_on(egress, eg_ports)
        deny_in_on(egress)

    for tun in tunnel_ifaces:
        deny_in_on(tun)


def main() -> None:
    os.environ.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env = parse_env(ENV_FILE)
    egress = env.get("EGRESS_DEV", "").strip()
    ing_en = env.get("INGRESS_ENABLED", "0").strip() == "1"
    ingress = env.get("INGRESS_DEV", "").strip()
    eg_ports, ing_ports = load_fw_ports()
    enabled = env_flag_true("AWG_FW_ENABLED", env, default="1")

    if not enabled:
        nft_delete_table()
        ufw_purge_marker()
        ufw_force_disable()
        return

    nft_delete_table()
    ufw_purge_marker()

    if not egress:
        sys.stderr.write(
            "[awg-uplink-firewall] EGRESS_DEV не задан — UFW/nft не применяются "
            "(сохраните настройки интерфейсов в панели).\n"
        )
        return

    eg_ports, ing_ports = effective_fw_ports(egress, ing_en, ingress, eg_ports, ing_ports)

    if shutil.which("ufw"):
        if not ufw_force_enable():
            sys.stderr.write("[awg-uplink-firewall] не удалось включить UFW — fallback на nftables.\n")
            apply_nft(egress, ing_en, ingress, eg_ports, ing_ports)
            return
        apply_ufw_panel(egress, ing_en, ingress, eg_ports, ing_ports)
    else:
        sys.stderr.write("[awg-uplink-firewall] пакет ufw не установлен — правила панели через nftables.\n")
        apply_nft(egress, ing_en, ingress, eg_ports, ing_ports)


if __name__ == "__main__":
    main()

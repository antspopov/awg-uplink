#!/usr/bin/env python3
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional


CFG_DIR = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
CIF_JSON = CFG_DIR / "interfaces.json"
GEO_JSON = CFG_DIR / "georouting.json"
CACHE_DIR = Path("/var/lib/awg-uplink/geo-ip")
NFT_TABLE = "awg_geo_ip"
NFT_NAT_TABLE = "awg_geo_snat"
NFT_SET = "geo_ip_targets"
NFT_EXCLUDE_SET = "geo_ip_exclude"
# Forward (Docker/VPN и пр.): только policy routing, без SNAT.
MARK_FWD_HEX = "0x77a4"
MARK_FWD_DEC = "30628"
# Локально сгенерированный трафик: после route hook ядро часто оставляет «чужой» ip saddr;
# SNAT на адрес туннеля только для этой метки (см. table awg_geo_snat).
MARK_LOCAL_HEX = "0x77a5"
MARK_LOCAL_DEC = "30629"
# Должен быть < правил «from <docker CIDR> lookup 203» (см. DOCKER_SRC_PRIO_AFTER_MARK≈73 в
# awg-webui-iface-routing-apply.sh), иначе транзит из Docker/VPN попадает в table 203 раньше fwmark.
RULE_PRIO = os.environ.get("AWG_GEO_IP_RULE_PRIO", "72").strip() or "72"
NAT_POST_PRIO = os.environ.get("AWG_GEO_IP_NAT_POST_PRIO", "99").strip() or "99"
LIST_TIMEOUT_SEC = int(os.environ.get("AWG_GEO_IP_FETCH_TIMEOUT_SEC", "40"))
AWG_IFACE = os.environ.get("AWG_GEO_IP_AWG_IFACE", "awg-uplink").strip() or "awg-uplink"
# Таблицы policy routing для fwmark (см. awg-webui-iface-routing-apply.sh EGRESS_TABLE / AWG_GEO).
TABLE_GEO_TUN = os.environ.get("AWG_GEO_IP_TABLE_TUN", "207").strip() or "207"
# Отдельная таблица для target=egress, чтобы не зависеть от системной table 202/правил iface (prio 90 -> 203).
TABLE_GEO_EGRESS = os.environ.get("AWG_GEO_IP_TABLE_EGRESS", "208").strip() or "208"


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "command failed").strip())
    return proc


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def normalize_cidrs(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$", line):
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def _maybe_flush_geo_policy_routing_tables() -> None:
    """Таблицы 207/208 общие для ip/domain — не flush пока включён хотя бы один режим."""
    iface = load_json(CIF_JSON)
    geo = load_json(GEO_JSON)
    route_mode = str(iface.get("route_mode", "egress")).strip().lower()
    if route_mode != "georouting":
        run(["ip", "-4", "route", "flush", "table", TABLE_GEO_TUN], check=False)
        run(["ip", "-4", "route", "flush", "table", TABLE_GEO_EGRESS], check=False)
        return
    if bool(geo.get("ipMode", False)) or bool(geo.get("domainMode", False)):
        return
    run(["ip", "-4", "route", "flush", "table", TABLE_GEO_TUN], check=False)
    run(["ip", "-4", "route", "flush", "table", TABLE_GEO_EGRESS], check=False)


def cleanup():
    for dec in (MARK_FWD_DEC, MARK_LOCAL_DEC):
        run(["ip", "rule", "del", "fwmark", dec, "priority", RULE_PRIO], check=False)
        run(["ip", "rule", "del", "fwmark", dec, "priority", "78"], check=False)
        run(["ip", "rule", "del", "fwmark", dec, "priority", "88"], check=False)
        while True:
            p = run(["ip", "rule", "del", "fwmark", dec], check=False)
            if p.returncode != 0:
                break
    run(["nft", "delete", "table", "ip", NFT_TABLE], check=False)
    run(["nft", "delete", "table", "ip", NFT_NAT_TABLE], check=False)
    _maybe_flush_geo_policy_routing_tables()


def _nft_escape_iface(name: str) -> str:
    return name.replace("\\", "\\\\").replace('"', '\\"')


def awg_tunnel_ipv4() -> Optional[str]:
    """Локальный IPv4 на интерфейсе туннеля (для SNAT локального geo-трафика)."""
    p = run(["ip", "-4", "addr", "show", "dev", AWG_IFACE], check=False)
    if p.returncode != 0:
        return None
    for raw in (p.stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("inet "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        addr = parts[1].split("/")[0].strip()
        if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", addr):
            return addr
    return None


def awg_endpoints_ipv4() -> list[str]:
    """Tunnel endpoint IPs must never be geo-marked, otherwise we can break the tunnel itself."""
    if not shutil.which("awg"):
        return []
    try:
        p = run(["awg", "show", AWG_IFACE, "endpoints"], check=False)
    except Exception:
        return []
    ips: list[str] = []
    for raw in (p.stdout or "").splitlines():
        parts = raw.strip().split()
        if len(parts) < 2:
            continue
        ep = parts[1].strip()
        if ep == "(none)":
            continue
        host = ep.split(":", 1)[0].strip().strip("[]")
        if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", host):
            ips.append(host)
    # unique
    return sorted(set(ips))


def first_ipv4_on_dev(dev: str) -> Optional[str]:
    p = run(["ip", "-4", "addr", "show", "dev", dev], check=False)
    if p.returncode != 0:
        return None
    for raw in (p.stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("inet "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if "scope" in parts and "global" not in parts and "site" not in parts:
            continue
        addr = parts[1].split("/")[0].strip()
        if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", addr):
            return addr
    return None


def link_scope_cidr_for_dev(dev: str) -> Optional[str]:
    """Connected subnet on dev (как link_for_dev в awg-webui-iface-routing-apply.sh)."""
    p = run(["ip", "-4", "route", "show", "dev", dev, "scope", "link"], check=False)
    if p.returncode != 0 or not (p.stdout or "").strip():
        return None
    for line in (p.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 1:
            continue
        if "proto" in line and "kernel" in line:
            return parts[0]
    parts = p.stdout.strip().splitlines()[0].split()
    return parts[0] if parts else None


def sync_geo_policy_table(table_id: str, iface_cfg: dict) -> None:
    """Заполняет таблицу для fwmark; иначе lookup «проваливается» дальше (напр. table 203 → туннель)."""
    if table_id == TABLE_GEO_TUN:
        run(["ip", "-4", "route", "replace", "default", "dev", AWG_IFACE, "table", TABLE_GEO_TUN], check=False)
        return
    if table_id != TABLE_GEO_EGRESS:
        return
    dev = str((iface_cfg or {}).get("egress_dev", "") or "eth0").strip() or "eth0"
    eip = str((iface_cfg or {}).get("egress_ip", "") or "").strip()
    gw = str((iface_cfg or {}).get("egress_gw", "") or "").strip()
    if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", eip):
        eip = first_ipv4_on_dev(dev) or ""
    if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", eip):
        return
    if gw and re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", gw):
        run(
            [
                "ip",
                "-4",
                "route",
                "replace",
                "default",
                "via",
                gw,
                "dev",
                dev,
                "src",
                eip,
                "table",
                TABLE_GEO_EGRESS,
            ],
            check=False,
        )
    else:
        run(
            ["ip", "-4", "route", "replace", "default", "dev", dev, "src", eip, "table", TABLE_GEO_EGRESS],
            check=False,
        )
    lk = link_scope_cidr_for_dev(dev)
    if lk and re.match(r"^[0-9./]+$", lk):
        run(["ip", "-4", "route", "replace", lk, "dev", dev, "table", TABLE_GEO_EGRESS], check=False)


def apply_nft(
    cidr_list: list[str],
    table_id: str,
    endpoint_ips: list[str],
    iface_cfg: dict,
    exclude_cidrs: list[str] | None = None,
):
    if not cidr_list:
        cleanup()
        return
    excl = [c for c in (exclude_cidrs or []) if c]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    nft_tmp = Path(tempfile.mkstemp(prefix="awg-geo-ip-", suffix=".nft")[1])
    try:
        lines = [
            f"table ip {NFT_TABLE} {{",
            f"  set {NFT_SET} {{",
            "    type ipv4_addr",
            "    flags interval",
            "    elements = {",
        ]
        for idx, cidr in enumerate(cidr_list):
            prefix = "      " if idx == 0 else "      , "
            lines.append(f"{prefix}{cidr}")
        lines.extend(["    }", "  }"])
        if excl:
            lines.extend(
                [
                    f"  set {NFT_EXCLUDE_SET} {{",
                    "    type ipv4_addr",
                    "    flags interval",
                    "    elements = {",
                ]
            )
            for idx, cidr in enumerate(excl):
                prefix = "      " if idx == 0 else "      , "
                lines.append(f"{prefix}{cidr}")
            lines.extend(["    }", "  }"])
        exclude_match = f" ip daddr != @{NFT_EXCLUDE_SET}" if excl else ""
        daddr_ne = (" " + " ".join([f"ip daddr != {ip}" for ip in endpoint_ips])) if endpoint_ips else ""
        # Локально сгенерированный трафик: chain type route + output перевыполняет FIB после meta mark.
        # Для target=tunnel: не трогаем пакеты, у которых уже выбран oif=awg-uplink (уже «правильный» путь).
        # Для target=egress: базовый default часто awg-uplink, первый lookup даёт oif=awg-uplink — без метки
        # пакет останется в туннеле; поэтому для egress метим по daddr, не смотря на oif.
        oif_guard = f'oifname != "{_nft_escape_iface(AWG_IFACE)}" ' if table_id == TABLE_GEO_TUN else ""
        out_rule = (
            f"    {oif_guard}ip daddr @{NFT_SET}{exclude_match}"
            + daddr_ne
            + f" counter meta mark set {MARK_LOCAL_HEX}"
        )
        # Транзит из Docker/VPN: пакет часто приходит с iif = veth*, а не с bridge (amn0/docker0).
        # Маркируем весь форвард с «внутренних» интерфейсов: всё, что не uplink и не lo.
        egress_dev = str((iface_cfg or {}).get("egress_dev", "") or "eth0").strip() or "eth0"
        ingress_dev = str((iface_cfg or {}).get("ingress_dev", "") or "").strip()
        pre_iface = [
            f'iifname != "{_nft_escape_iface(egress_dev)}"',
            'iifname != "lo"',
        ]
        if ingress_dev and ingress_dev != egress_dev:
            pre_iface.append(f'iifname != "{_nft_escape_iface(ingress_dev)}"')
        # Транзит VPN-клиентов: prerouting+mangle до первого fib lookup для forward.
        pre_rule = (
            "    " + " ".join(pre_iface) + " "
            "fib daddr type != local "
            f"ip daddr @{NFT_SET}{exclude_match}"
            + daddr_ne
            + f" counter meta mark set {MARK_FWD_HEX}"
        )
        lines.extend(
            [
                "  chain out_mark {",
                "    type route hook output priority mangle; policy accept;",
                out_rule,
                "  }",
                "  chain pre_geo {",
                "    type filter hook prerouting priority mangle; policy accept;",
                pre_rule,
                "  }",
                "}",
            ]
        )
        tunnel_ip = awg_tunnel_ipv4() if table_id == TABLE_GEO_TUN else None
        if tunnel_ip:
            lines.extend(
                [
                    f"table ip {NFT_NAT_TABLE} {{",
                    "  chain postroute {",
                    f"    type nat hook postrouting priority {NAT_POST_PRIO}; policy accept;",
                    f'    meta mark {MARK_LOCAL_HEX} oifname "{_nft_escape_iface(AWG_IFACE)}" snat to {tunnel_ip}',
                    "  }",
                    "}",
                ]
            )
        elif table_id == TABLE_GEO_EGRESS:
            # После route hook выбор table 208 может дать oif=eth0, а ip saddr всё ещё с туннеля (10.8.x);
            # без SNAT ответы теряются — как для туннельного таргета, только подмена на egress.
            edev = str((iface_cfg or {}).get("egress_dev", "") or "eth0").strip() or "eth0"
            eip = str((iface_cfg or {}).get("egress_ip", "") or "").strip()
            if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", eip):
                eip = first_ipv4_on_dev(edev) or ""
            if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", eip):
                lines.extend(
                    [
                        f"table ip {NFT_NAT_TABLE} {{",
                        "  chain postroute {",
                        f"    type nat hook postrouting priority {NAT_POST_PRIO}; policy accept;",
                        f'    meta mark {MARK_LOCAL_HEX} oifname "{_nft_escape_iface(edev)}" snat to {eip}',
                        "  }",
                        "}",
                    ]
                )
        nft_tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        run(["nft", "delete", "table", "ip", NFT_TABLE], check=False)
        run(["nft", "delete", "table", "ip", NFT_NAT_TABLE], check=False)
        run(["nft", "-f", str(nft_tmp)], check=True)
        # Убрать старые записи с prio 78/88 после смены дефолтного RULE_PRIO.
        for _prio in ("78", "88"):
            for _dec in (MARK_FWD_DEC, MARK_LOCAL_DEC):
                while True:
                    p = run(["ip", "rule", "del", "fwmark", _dec, "priority", _prio], check=False)
                    if p.returncode != 0:
                        break
        run(["ip", "rule", "del", "fwmark", MARK_FWD_DEC, "priority", RULE_PRIO], check=False)
        run(["ip", "rule", "del", "fwmark", MARK_LOCAL_DEC, "priority", RULE_PRIO], check=False)
        run(["ip", "rule", "add", "fwmark", MARK_FWD_DEC, "table", table_id, "priority", RULE_PRIO], check=True)
        run(["ip", "rule", "add", "fwmark", MARK_LOCAL_DEC, "table", table_id, "priority", RULE_PRIO], check=True)
    finally:
        try:
            nft_tmp.unlink(missing_ok=True)
        except Exception:
            pass


def cache_name(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:20] + ".lst"


def fetch_to_cache(url: str, target: Path):
    req = urllib.request.Request(url, headers={"User-Agent": "awg-uplink-geo-ip/1.0"})
    with urllib.request.urlopen(req, timeout=LIST_TIMEOUT_SEC) as r:
        data = r.read().decode("utf-8", errors="replace")
    cidrs = normalize_cidrs(data)
    if not cidrs:
        raise RuntimeError("empty or invalid list")
    target.write_text("\n".join(cidrs) + "\n", encoding="utf-8")


def main():
    if not shutil.which("nft") or not shutil.which("ip"):
        raise SystemExit("ip/nft is required")
    iface_cfg = load_json(CIF_JSON)
    geo = load_json(GEO_JSON)
    route_mode = str(iface_cfg.get("route_mode", "egress")).strip().lower()
    geo = geo if isinstance(geo, dict) else {}
    ip_mode = bool(geo.get("ipMode", False))
    if route_mode != "georouting" or not ip_mode:
        cleanup()
        return

    target = str(geo.get("target", "tunnel")).strip().lower()
    # target=tunnel → отдельная table (по умолчанию 207); target=egress → отдельная table (по умолчанию 208).
    # Изолируем geo от базовых таблиц iface (202/203), чтобы порядок чужих ip rule не ломал выбор пути.
    table_id = TABLE_GEO_TUN if target == "tunnel" else TABLE_GEO_EGRESS
    sync_geo_policy_table(table_id, iface_cfg)

    endpoint_ips = awg_endpoints_ipv4()

    ready = geo.get("readyLinks", {}) if isinstance(geo.get("readyLinks", {}), dict) else {}
    ready_ip = ready.get("ip", []) if isinstance(ready.get("ip", []), list) else []
    include_text = str((geo.get("lists", {}) or {}).get("ipInclude", ""))
    include_cidrs = normalize_cidrs(include_text)
    exclude_text = str((geo.get("lists", {}) or {}).get("ipExclude", ""))
    exclude_cidrs = normalize_cidrs(exclude_text)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    all_cidrs: list[str] = []
    seen: set[str] = set()

    for entry in ready_ip:
        if not isinstance(entry, dict):
            continue
        if entry.get("enabled", True) is False:
            continue
        url = str(entry.get("url", "")).strip()
        if not url:
            continue
        cfile = CACHE_DIR / cache_name(url)
        if cfile.exists():
            for cidr in normalize_cidrs(cfile.read_text(encoding="utf-8")):
                if cidr not in seen:
                    seen.add(cidr)
                    all_cidrs.append(cidr)

    for cidr in include_cidrs:
        if cidr not in seen:
            seen.add(cidr)
            all_cidrs.append(cidr)
    apply_nft(all_cidrs, table_id, endpoint_ips, iface_cfg, exclude_cidrs)

    changed = False
    for entry in ready_ip:
        if not isinstance(entry, dict):
            continue
        if entry.get("enabled", True) is False:
            continue
        url = str(entry.get("url", "")).strip()
        if not url:
            continue
        cfile = CACHE_DIR / cache_name(url)
        try:
            fetch_to_cache(url, cfile)
            entry["status"] = "OK"
            changed = True
        except Exception:
            entry["status"] = "с ошибкой"
            changed = True

    all_cidrs = []
    seen = set()
    for entry in ready_ip:
        if not isinstance(entry, dict):
            continue
        if entry.get("enabled", True) is False:
            continue
        url = str(entry.get("url", "")).strip()
        if not url:
            continue
        cfile = CACHE_DIR / cache_name(url)
        if not cfile.exists():
            continue
        for cidr in normalize_cidrs(cfile.read_text(encoding="utf-8")):
            if cidr not in seen:
                seen.add(cidr)
                all_cidrs.append(cidr)
    for cidr in include_cidrs:
        if cidr not in seen:
            seen.add(cidr)
            all_cidrs.append(cidr)
    apply_nft(all_cidrs, table_id, endpoint_ips, iface_cfg, exclude_cidrs)

    if changed:
        geo_ready = geo.setdefault("readyLinks", {})
        geo_ready["ip"] = ready_ip
        write_json(GEO_JSON, geo)


if __name__ == "__main__":
    main()

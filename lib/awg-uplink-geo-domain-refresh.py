#!/usr/bin/env python3
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Optional


CFG_DIR = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
CIF_JSON = CFG_DIR / "interfaces.json"
GEO_JSON = CFG_DIR / "georouting.json"
CACHE_DIR = Path("/var/lib/awg-uplink/geo-domain")
# JSON list of nft interval strings; used only when ip awg_geo_domain is created empty (e.g. after reboot).
GEO_DOMAIN_SET_SNAPSHOT = CACHE_DIR / "geo_domain_targets.snapshot.json"
NFT_TABLE = "awg_geo_domain"
NFT_NAT_TABLE = "awg_geo_domain_snat"
NFT_SET = "geo_domain_targets"
NFT_TABLE_BACKUP = "awg_geo_domain_backup"
NFT_SET_BACKUP = "geo_domain_targets_backup"
NFT_ROTATE_ELEM_CHUNK = max(32, int(os.environ.get("AWG_GEO_DOMAIN_ROTATE_ELEM_CHUNK", "400")))
# Свои fwmark, не пересекаются с geo-ip (0x77a4/0x77a5), иначе cleanup одного сервиса
# снимает ip rule другого.
MARK_FWD_HEX = "0x77a6"
MARK_FWD_DEC = "30630"
MARK_LOCAL_HEX = "0x77a7"
MARK_LOCAL_DEC = "30631"
RULE_PRIO = os.environ.get("AWG_GEO_DOMAIN_RULE_PRIO", "72").strip() or "72"
NAT_POST_PRIO = os.environ.get("AWG_GEO_DOMAIN_NAT_POST_PRIO", "99").strip() or "99"
LIST_TIMEOUT_SEC = int(os.environ.get("AWG_GEO_DOMAIN_FETCH_TIMEOUT_SEC", "40"))
AWG_IFACE = os.environ.get("AWG_GEO_DOMAIN_AWG_IFACE", "awg-uplink").strip() or "awg-uplink"
TABLE_GEO_TUN = os.environ.get("AWG_GEO_DOMAIN_TABLE_TUN", "207").strip() or "207"
TABLE_GEO_EGRESS = os.environ.get("AWG_GEO_DOMAIN_TABLE_EGRESS", "208").strip() or "208"
DNSMASQ_GEO_NFTSET = Path("/etc/dnsmasq.d/awg-uplink-geo-domain-nftset.conf")


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


def _nft_escape_iface(name: str) -> str:
    return name.replace("\\", "\\\\").replace('"', '\\"')


def awg_tunnel_ipv4() -> Optional[str]:
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
            ["ip", "-4", "route", "replace", "default", "via", gw, "dev", dev, "src", eip, "table", TABLE_GEO_EGRESS],
            check=False,
        )
    else:
        run(["ip", "-4", "route", "replace", "default", "dev", dev, "src", eip, "table", TABLE_GEO_EGRESS], check=False)
    lk = link_scope_cidr_for_dev(dev)
    if lk and re.match(r"^[0-9./]+$", lk):
        run(["ip", "-4", "route", "replace", lk, "dev", dev, "table", TABLE_GEO_EGRESS], check=False)


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
    remove_dnsmasq_geo_conf()
    restart_dnsmasq()
    for dec in (MARK_FWD_DEC, MARK_LOCAL_DEC):
        run(["ip", "rule", "del", "fwmark", dec, "priority", RULE_PRIO], check=False)
        run(["ip", "rule", "del", "fwmark", dec, "priority", "78"], check=False)
        run(["ip", "rule", "del", "fwmark", dec, "priority", "88"], check=False)
        while True:
            p = run(["ip", "rule", "del", "fwmark", dec], check=False)
            if p.returncode != 0:
                break
    run(["nft", "delete", "table", "ip", NFT_NAT_TABLE], check=False)
    _maybe_flush_geo_policy_routing_tables()


def restart_dnsmasq() -> None:
    subprocess.run(["systemctl", "restart", "dnsmasq"], check=False)


def remove_dnsmasq_geo_conf() -> None:
    try:
        DNSMASQ_GEO_NFTSET.unlink(missing_ok=True)
    except OSError:
        pass


def apply_or_update_nft(table_id: str, endpoint_ips: list[str], iface_cfg: dict):
    """Создаёт таблицу/цепочки при первом запуске; иначе только обновляет правила цепочек.
    Набор {NFT_SET} не очищаем и таблицу ip не удаляем — очистка набора только через --rotate-nft."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    main_exists = run(["nft", "list", "table", "ip", NFT_TABLE], check=False).returncode == 0
    created_new_main_table = not main_exists

    daddr_ne = (" " + " ".join([f"ip daddr != {ip}" for ip in endpoint_ips])) if endpoint_ips else ""
    oif_guard = f'oifname != "{_nft_escape_iface(AWG_IFACE)}" ' if table_id == TABLE_GEO_TUN else ""
    out_rule_embed = f"    {oif_guard}ip daddr @{NFT_SET}" + daddr_ne + f" counter meta mark set {MARK_LOCAL_HEX}"
    egress_dev = str((iface_cfg or {}).get("egress_dev", "") or "eth0").strip() or "eth0"
    ingress_dev = str((iface_cfg or {}).get("ingress_dev", "") or "").strip()
    pre_iface = [
        f'iifname != "{_nft_escape_iface(egress_dev)}"',
        'iifname != "lo"',
    ]
    if ingress_dev and ingress_dev != egress_dev:
        pre_iface.append(f'iifname != "{_nft_escape_iface(ingress_dev)}"')
    pre_rule_embed = (
        "    " + " ".join(pre_iface) + " " + "fib daddr type != local " + f"ip daddr @{NFT_SET}" + daddr_ne
        + f" counter meta mark set {MARK_FWD_HEX}"
    )
    rule_out = " ".join(out_rule_embed.split())
    rule_pre = " ".join(pre_rule_embed.split())

    nat_lines: list[str] = []
    tunnel_ip = awg_tunnel_ipv4() if table_id == TABLE_GEO_TUN else None
    if tunnel_ip:
        nat_lines = [
            f"table ip {NFT_NAT_TABLE} {{",
            "  chain postroute {",
            f"    type nat hook postrouting priority {NAT_POST_PRIO}; policy accept;",
            f'    meta mark {MARK_LOCAL_HEX} oifname "{_nft_escape_iface(AWG_IFACE)}" snat to {tunnel_ip}',
            "  }",
            "}",
        ]
    elif table_id == TABLE_GEO_EGRESS:
        edev = str((iface_cfg or {}).get("egress_dev", "") or "eth0").strip() or "eth0"
        eip = str((iface_cfg or {}).get("egress_ip", "") or "").strip()
        if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", eip):
            eip = first_ipv4_on_dev(edev) or ""
        if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", eip):
            nat_lines = [
                f"table ip {NFT_NAT_TABLE} {{",
                "  chain postroute {",
                f"    type nat hook postrouting priority {NAT_POST_PRIO}; policy accept;",
                f'    meta mark {MARK_LOCAL_HEX} oifname "{_nft_escape_iface(edev)}" snat to {eip}',
                "  }",
                "}",
            ]

    nft_tmp = Path(tempfile.mkstemp(prefix="awg-geo-domain-", suffix=".nft")[1])
    try:
        blob_lines: list[str] = []
        if not main_exists:
            blob_lines = [
                f"table ip {NFT_TABLE} {{",
                f"  set {NFT_SET} {{",
                "    type ipv4_addr",
                "    flags interval",
                "  }",
                "  chain out_mark {",
                "    type route hook output priority mangle; policy accept;",
                out_rule_embed,
                "  }",
                "  chain pre_geo {",
                "    type filter hook prerouting priority mangle; policy accept;",
                pre_rule_embed,
                "  }",
                "}",
            ]
            blob_lines.extend(nat_lines)
        else:
            blob_lines = [
                f"flush chain ip {NFT_TABLE} out_mark",
                f"flush chain ip {NFT_TABLE} pre_geo",
                f"add rule ip {NFT_TABLE} out_mark {rule_out}",
                f"add rule ip {NFT_TABLE} pre_geo {rule_pre}",
            ]
            blob_lines.extend(nat_lines)

        run(["nft", "delete", "table", "ip", NFT_NAT_TABLE], check=False)
        nft_tmp.write_text("\n".join(blob_lines) + "\n", encoding="utf-8")
        run(["nft", "-f", str(nft_tmp)], check=True)
        ensure_backup_table()
        if created_new_main_table:
            restore_geo_domain_set_snapshot()
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


def _elem_json_to_nft_interval(el: Any) -> Optional[str]:
    if isinstance(el, str):
        return el.strip()
    if isinstance(el, dict) and "prefix" in el:
        p = el["prefix"]
        if isinstance(p, dict):
            addr = p.get("addr")
            ln = p.get("len")
            try:
                plen = int(ln) if ln is not None else None
            except (TypeError, ValueError):
                plen = None
            if isinstance(addr, str) and plen is not None:
                return f"{addr}/{plen}"
    return None


def list_interval_set_elements(table: str, set_name: str) -> list[str]:
    p = run(["nft", "-j", "list", "set", "ip", table, set_name], check=False)
    if p.returncode != 0:
        return []
    try:
        root = json.loads(p.stdout or "{}")
    except Exception:
        return []
    out: list[str] = []
    for item in root.get("nftables", []):
        s = item.get("set")
        if not isinstance(s, dict):
            continue
        for el in s.get("elem") or []:
            nft = _elem_json_to_nft_interval(el)
            if nft:
                out.append(nft)
    return out


def ensure_backup_table() -> None:
    p = run(["nft", "list", "table", "ip", NFT_TABLE_BACKUP], check=False)
    if p.returncode == 0:
        return
    nft_tmp = Path(tempfile.mkstemp(prefix="awg-geo-domain-backup-", suffix=".nft")[1])
    try:
        nft_tmp.write_text(
            "\n".join(
                [
                    f"table ip {NFT_TABLE_BACKUP} {{",
                    f"  set {NFT_SET_BACKUP} {{",
                    "    type ipv4_addr",
                    "    flags interval",
                    "  }",
                    "}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        run(["nft", "-f", str(nft_tmp)], check=True)
    finally:
        try:
            nft_tmp.unlink(missing_ok=True)
        except Exception:
            pass


def _nft_add_elements_chunked(table: str, set_name: str, elems: list[str]) -> None:
    for i in range(0, len(elems), NFT_ROTATE_ELEM_CHUNK):
        chunk = elems[i : i + NFT_ROTATE_ELEM_CHUNK]
        blob = ", ".join(chunk)
        line = f"add element ip {table} {set_name} {{ {blob} }}\n"
        nft_tmp = Path(tempfile.mkstemp(prefix="awg-geo-domain-add-", suffix=".nft")[1])
        try:
            nft_tmp.write_text(line, encoding="utf-8")
            run(["nft", "-f", str(nft_tmp)], check=True)
        finally:
            try:
                nft_tmp.unlink(missing_ok=True)
            except Exception:
                pass


def _valid_geo_set_interval(elem: str) -> bool:
    """Allow only IPv4 prefixes for nft set elements (no hostnames / injection)."""
    s = (elem or "").strip()
    if not s or len(s) > 64:
        return False
    rest = s
    if "/" in s:
        rest, pls = s.split("/", 1)
        try:
            plen = int(pls)
            if plen < 0 or plen > 32:
                return False
        except ValueError:
            return False
    parts = rest.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
    return True


def restore_geo_domain_set_snapshot() -> None:
    """Reload set elements from disk after apply_or_update_nft created an empty table (post-reboot)."""
    p = GEO_DOMAIN_SET_SNAPSHOT
    if not p.is_file():
        return
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(raw, list):
        return
    elems: list[str] = []
    seen: set[str] = set()
    for x in raw:
        if not isinstance(x, str):
            continue
        s = x.strip()
        if not _valid_geo_set_interval(s):
            continue
        if s in seen:
            continue
        seen.add(s)
        elems.append(s)
    if not elems:
        return
    _nft_add_elements_chunked(NFT_TABLE, NFT_SET, elems)


def persist_geo_domain_set_snapshot() -> None:
    """Write current nft set elements to disk when non-empty (skip if empty to keep last snapshot)."""
    if run(["nft", "list", "table", "ip", NFT_TABLE], check=False).returncode != 0:
        return
    elems = list_interval_set_elements(NFT_TABLE, NFT_SET)
    if not elems:
        return
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    body = json.dumps(sorted(elems), ensure_ascii=False, indent=2) + "\n"
    tmp = GEO_DOMAIN_SET_SNAPSHOT.with_suffix(GEO_DOMAIN_SET_SNAPSHOT.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(body, encoding="utf-8")
    os.replace(tmp, GEO_DOMAIN_SET_SNAPSHOT)


def rotate_nft_sets_to_backup() -> None:
    """Плановая ротация: только этот путь очищает основной set (после копии в backup)."""
    if run(["nft", "list", "table", "ip", NFT_TABLE], check=False).returncode != 0:
        return
    ensure_backup_table()
    run(["nft", "flush", "set", "ip", NFT_TABLE_BACKUP, NFT_SET_BACKUP], check=False)
    elems = list_interval_set_elements(NFT_TABLE, NFT_SET)
    if elems:
        _nft_add_elements_chunked(NFT_TABLE_BACKUP, NFT_SET_BACKUP, elems)
    run(["nft", "flush", "set", "ip", NFT_TABLE, NFT_SET], check=False)


def normalize_domains(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip().lower().rstrip(".")
        if not line:
            continue
        if line.startswith("*."):
            line = line[2:]
        if not re.match(r"^(?=.{1,253}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$", line):
            continue
        if "." not in line or ".." in line:
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def cache_name(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:20] + ".lst"


def fetch_to_cache(url: str, target: Path):
    req = urllib.request.Request(url, headers={"User-Agent": "awg-uplink-geo-domain/1.0"})
    with urllib.request.urlopen(req, timeout=LIST_TIMEOUT_SEC) as r:
        data = r.read().decode("utf-8", errors="replace")
    domains = normalize_domains(data)
    if not domains:
        raise RuntimeError("empty or invalid list")
    target.write_text("\n".join(domains) + "\n", encoding="utf-8")


def write_dnsmasq_geo_conf(domains: list[str]) -> None:
    lines = [
        "# Generated by awg-uplink-geo-domain-refresh.py — nftset → ip " + NFT_TABLE + " / " + NFT_SET,
    ]
    for d in domains:
        lines.append(f"nftset=/{d}/4#ip#{NFT_TABLE}#{NFT_SET}")
    DNSMASQ_GEO_NFTSET.parent.mkdir(parents=True, exist_ok=True)
    tmp = DNSMASQ_GEO_NFTSET.with_suffix(DNSMASQ_GEO_NFTSET.suffix + f".tmp.{os.getpid()}")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, DNSMASQ_GEO_NFTSET)


def collect_domains(ready_domain: list, include_domains: list[str], exclude_set: set[str]) -> list[str]:
    all_domains: list[str] = []
    seen: set[str] = set()
    for entry in ready_domain:
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
        for dom in normalize_domains(cfile.read_text(encoding="utf-8")):
            if dom in exclude_set or dom in seen:
                continue
            seen.add(dom)
            all_domains.append(dom)
    for dom in include_domains:
        if dom in exclude_set or dom in seen:
            continue
        seen.add(dom)
        all_domains.append(dom)
    return all_domains


def main():
    if not shutil.which("nft") or not shutil.which("ip"):
        raise SystemExit("ip/nft is required")
    iface_cfg = load_json(CIF_JSON)
    geo = load_json(GEO_JSON)
    route_mode = str(iface_cfg.get("route_mode", "egress")).strip().lower()
    geo = geo if isinstance(geo, dict) else {}
    domain_mode = bool(geo.get("domainMode", False))
    if route_mode != "georouting" or not domain_mode:
        cleanup()
        return

    target = str(geo.get("target", "tunnel")).strip().lower()
    table_id = TABLE_GEO_TUN if target == "tunnel" else TABLE_GEO_EGRESS
    sync_geo_policy_table(table_id, iface_cfg)
    endpoint_ips = awg_endpoints_ipv4()
    apply_or_update_nft(table_id, endpoint_ips, iface_cfg)

    ready = geo.get("readyLinks", {}) if isinstance(geo.get("readyLinks", {}), dict) else {}
    ready_domain = ready.get("domain", []) if isinstance(ready.get("domain", []), list) else []
    include_text = str((geo.get("lists", {}) or {}).get("domainInclude", ""))
    exclude_text = str((geo.get("lists", {}) or {}).get("domainExclude", ""))
    include_domains = normalize_domains(include_text)
    exclude_set = set(normalize_domains(exclude_text))

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    changed = False
    for entry in ready_domain:
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

    all_domains = collect_domains(ready_domain, include_domains, exclude_set)
    write_dnsmasq_geo_conf(all_domains)
    restart_dnsmasq()

    if changed:
        geo_ready = geo.setdefault("readyLinks", {})
        geo_ready["domain"] = ready_domain
        write_json(GEO_JSON, geo)

    persist_geo_domain_set_snapshot()


if __name__ == "__main__":
    if "--rotate-nft" in sys.argv:
        if not shutil.which("nft"):
            raise SystemExit("nft is required")
        rotate_nft_sets_to_backup()
    else:
        main()

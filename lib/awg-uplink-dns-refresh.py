#!/usr/bin/env python3
"""Генерация dnsmasq/dnscrypt-proxy из dns.json + georouting.json; списки доменов для dnscrypt."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

CFG_DIR = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
DNS_JSON = CFG_DIR / "dns.json"
GEO_JSON = CFG_DIR / "georouting.json"
CACHE_DIR = Path("/var/lib/awg-uplink/geo-domain")
STATE_DIR = Path("/var/lib/awg-uplink")
DNSCRYPT_PORT = int(os.environ.get("AWG_DNS_DNSCRYPT_PORT", "5354"))
DNSCRYPT_ADDR = os.environ.get("AWG_DNS_DNSCRYPT_ADDR", "127.0.0.1").strip() or "127.0.0.1"

DNSMASQ_UPSTREAM = Path("/etc/dnsmasq.d/awg-uplink-upstream.conf")
DNSMASQ_DOMAINS = Path("/etc/dnsmasq.d/awg-uplink-dnscrypt-domains.conf")
DNSCRYPT_CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "").strip() or "command failed")
    return p


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        o = json.loads(path.read_text(encoding="utf-8"))
        return o if isinstance(o, dict) else {}
    except Exception:
        return {}


def write_atomic(path: Path, text: str, mode: int = 0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def normalize_dns_servers(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # IPv4 or hostname for dnsmasq server=
        if not re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", line) and not re.match(
            r"^(\d{1,3}\.){3}\d{1,3}$", line
        ):
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def normalize_dnscrypt_names(items) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in items or []:
        s = str(x).strip()
        if not s or not re.match(r"^[a-zA-Z0-9_.-]+$", s):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


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


def domains_from_ready_cache(url: str) -> list[str]:
    p = CACHE_DIR / cache_name(url)
    if not p.exists():
        return []
    return normalize_domains(p.read_text(encoding="utf-8"))


def collect_dnscrypt_domains(geo: dict) -> list[str]:
    """protected ready — всегда; остальные ready — при domainMode+enabled; include и exclude при domainMode."""
    geo = geo if isinstance(geo, dict) else {}
    domain_mode = bool(geo.get("domainMode", False))
    lists = geo.get("lists", {}) if isinstance(geo.get("lists", {}), dict) else {}
    exclude_text = str(lists.get("domainExclude", ""))
    exclude = set(normalize_domains(exclude_text)) if domain_mode else set()

    ready = geo.get("readyLinks", {}) if isinstance(geo.get("readyLinks", {}), dict) else {}
    entries = ready.get("domain", []) if isinstance(ready.get("domain", []), list) else []

    seen: set[str] = set()
    out: list[str] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url", "")).strip()
        if not url:
            continue
        protected = bool(entry.get("protected", False))
        enabled = entry.get("enabled", True) is not False
        if protected:
            take = True
        elif domain_mode and enabled:
            take = True
        else:
            continue
        for dom in domains_from_ready_cache(url):
            if domain_mode and dom in exclude:
                continue
            if dom in seen:
                continue
            seen.add(dom)
            out.append(dom)

    if domain_mode:
        for dom in normalize_domains(str(lists.get("domainInclude", ""))):
            if dom in exclude or dom in seen:
                continue
            seen.add(dom)
            out.append(dom)

    return out


def default_dns_cfg() -> dict:
    return {
        "upstream_servers": ["77.88.8.8", "77.88.8.1"],
        "dnscrypt_server_names": ["cloudflare", "google"],
        "domains_list_updated_at": None,
        "amnezia_dns_watch_enabled": True,
        "amnezia_dns_container": "amnezia-dns",
        "amnezia_dns_network": "amnezia-dns-net",
        "amnezia_dns_forward_ip": "",
        "dns_transport_lock_enabled": False,
    }


def _coerce_dns_bool(val, default: bool = False) -> bool:
    """Как в webui/server.py — не использовать bool(\"false\")."""
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return bool(int(val))
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ("true", "1", "yes", "on"):
            return True
        if s in ("false", "0", "no", "off", ""):
            return False
    return default


def normalize_dns_cfg(raw: dict) -> dict:
    d = default_dns_cfg()
    up = raw.get("upstream_servers")
    if isinstance(up, list):
        d["upstream_servers"] = normalize_dns_servers("\n".join(str(x) for x in up))
    elif isinstance(up, str):
        d["upstream_servers"] = normalize_dns_servers(up)
    dc = raw.get("dnscrypt_server_names")
    if isinstance(dc, list):
        d["dnscrypt_server_names"] = normalize_dnscrypt_names(dc)
    elif isinstance(dc, str):
        lines = [ln.strip() for ln in dc.splitlines() if ln.strip()]
        d["dnscrypt_server_names"] = normalize_dnscrypt_names(lines)
    ts = raw.get("domains_list_updated_at")
    if ts is not None:
        try:
            d["domains_list_updated_at"] = int(ts)
        except Exception:
            d["domains_list_updated_at"] = None
    d["amnezia_dns_watch_enabled"] = _coerce_dns_bool(raw.get("amnezia_dns_watch_enabled"), True)
    ctn = raw.get("amnezia_dns_container")
    if isinstance(ctn, str) and ctn.strip():
        d["amnezia_dns_container"] = ctn.strip()
    net = raw.get("amnezia_dns_network")
    if isinstance(net, str) and net.strip():
        d["amnezia_dns_network"] = net.strip()
    fwd = raw.get("amnezia_dns_forward_ip")
    if isinstance(fwd, str):
        d["amnezia_dns_forward_ip"] = fwd.strip()
    d["dns_transport_lock_enabled"] = _coerce_dns_bool(raw.get("dns_transport_lock_enabled"), False)
    return d


MINISIGN_PUBLIC_RESOLVERS_V3 = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"


def render_dnscrypt_toml(server_names: list[str]) -> str:
    sn = json.dumps(server_names, ensure_ascii=False)
    listen = json.dumps([f"{DNSCRYPT_ADDR}:{DNSCRYPT_PORT}"])
    mk = MINISIGN_PUBLIC_RESOLVERS_V3
    return (
        "# Generated by awg-uplink-dns-refresh.py — do not edit by hand.\n"
        f"# Слушает {DNSCRYPT_ADDR}:{DNSCRYPT_PORT} (без привилегий для порта < 1024). systemd socket для dnscrypt отключён.\n"
        f"listen_addresses = {listen}\n"
        f"server_names = {sn}\n"
        "max_clients = 500\n"
        "ipv4_servers = true\n"
        "ipv6_servers = false\n"
        "dnscrypt_servers = true\n"
        "doh_servers = true\n"
        "require_dnssec = false\n"
        "ignore_system_dns = true\n"
        "fallback_resolvers = ['9.9.9.9:53', '8.8.8.8:53']\n"
        "\n"
        "[sources]\n"
        "  [sources.'public-resolvers']\n"
        "  urls = [\n"
        "    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',\n"
        "    'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',\n"
        "    'https://ipv6.download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',\n"
        "    'https://download.dnscrypt.net/resolvers-list/v3/public-resolvers.md'\n"
        "  ]\n"
        "  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'\n"
        f"  minisign_key = '{mk}'\n"
        "\n"
        "  [sources.'relays']\n"
        "  urls = [\n"
        "    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',\n"
        "    'https://download.dnscrypt.info/resolvers-list/v3/relays.md',\n"
        "    'https://ipv6.download.dnscrypt.info/resolvers-list/v3/relays.md',\n"
        "    'https://download.dnscrypt.net/resolvers-list/v3/relays.md'\n"
        "  ]\n"
        "  cache_file = '/var/cache/dnscrypt-proxy/relays.md'\n"
        f"  minisign_key = '{mk}'\n"
    )


def render_dnsmasq_upstream(servers: list[str]) -> str:
    lines = ["# Generated by awg-uplink-dns-refresh.py", "no-resolv"]
    for s in servers:
        lines.append(f"server={s}")
    return "\n".join(lines) + "\n"


def render_dnsmasq_domains(domains: list[str]) -> str:
    lines = [
        "# Generated by awg-uplink-dns-refresh.py — домены через dnscrypt-proxy",
        f"# forwards to {DNSCRYPT_ADDR}#{DNSCRYPT_PORT}",
    ]
    fwd = f"{DNSCRYPT_ADDR}#{DNSCRYPT_PORT}"
    for d in domains:
        lines.append(f"server=/{d}/{fwd}")
    return "\n".join(lines) + "\n"


def reload_services():
    subprocess.run(["systemctl", "restart", "dnscrypt-proxy"], check=False)
    subprocess.run(["systemctl", "restart", "dnsmasq"], check=False)


def main():
    if not shutil.which("dnsmasq"):
        raise SystemExit("dnsmasq not installed")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    Path("/var/cache/dnscrypt-proxy").mkdir(parents=True, exist_ok=True)
    if not DNS_JSON.exists():
        write_atomic(DNS_JSON, json.dumps(default_dns_cfg(), ensure_ascii=False, indent=2) + "\n", 0o600)
    raw = load_json(DNS_JSON)
    cfg = normalize_dns_cfg(raw)
    geo = load_json(GEO_JSON)

    domains = collect_dnscrypt_domains(geo)
    upstream = cfg["upstream_servers"] or default_dns_cfg()["upstream_servers"]
    dc_names = cfg["dnscrypt_server_names"] or default_dns_cfg()["dnscrypt_server_names"]

    write_atomic(DNSMASQ_UPSTREAM, render_dnsmasq_upstream(upstream), 0o644)
    write_atomic(DNSMASQ_DOMAINS, render_dnsmasq_domains(domains), 0o644)

    DNSCRYPT_CONF.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(DNSCRYPT_CONF, render_dnscrypt_toml(dc_names), 0o644)

    cfg["domains_list_updated_at"] = int(time.time())
    write_atomic(DNS_JSON, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", 0o600)

    reload_services()

    fw_py = Path("/usr/local/sbin/awg-uplink-firewall-apply.py")
    if fw_py.exists():
        subprocess.run(["python3", str(fw_py)], check=False)


if __name__ == "__main__":
    main()

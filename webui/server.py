#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import posixpath
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import time
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def _require_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise SystemExit(f"Missing required env: {name}")
    return v


def _normalize_base_path(p: str) -> str:
    p = (p or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    if not p.endswith("/"):
        p = p + "/"
    return p


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "y")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _json_bytes(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")


def _run(cmd: list[str], timeout: float = 2.5) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return default


def _write_text(path: str, data: str):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)


def _sanitize_tunnel_config(cfg_text: str) -> str:
    lines = cfg_text.splitlines()
    out: list[str] = []
    in_iface = False
    saw_iface = False
    table_written = False
    table_pending = False

    def flush_table_if_needed():
        nonlocal table_pending, table_written
        if table_pending and not table_written:
            out.append("Table = off")
            table_written = True
            table_pending = False

    for raw in lines:
        line = raw.rstrip("\r\n")
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            flush_table_if_needed()
            sec = s[1:-1].strip().lower()
            in_iface = sec == "interface"
            if in_iface:
                saw_iface = True
                table_written = False
                table_pending = True
            out.append(line)
            continue

        if in_iface:
            # Remove DNS lines and all routing hooks for this stage.
            if re.match(r"^\s*DNS\s*=", line):
                continue
            if re.match(r"^\s*PostUp\s*=", line) or re.match(r"^\s*PostDown\s*=", line):
                continue
            # Remove empty Amnezia I* keys.
            m_i = re.match(r"^\s*I[0-9]+\s*=\s*(.*)$", line)
            if m_i and not m_i.group(1).strip():
                continue
            # Force table off and avoid duplicates.
            if re.match(r"^\s*Table\s*=", line):
                if not table_written:
                    out.append("Table = off")
                    table_written = True
                table_pending = False
                continue

        if re.match(r"^\s*AllowedIPs\s*=", line):
            pfx = re.match(r"^(\s*AllowedIPs\s*=\s*)(.*)$", line)
            if pfx:
                vals = [x.strip() for x in pfx.group(2).split(",")]
                vals = [x for x in vals if x and ":" not in x]
                if not vals:
                    vals = ["0.0.0.0/0"]
                line = pfx.group(1) + ", ".join(vals)

        # Insert Table=off before first non-empty key inside [Interface] if missing.
        if in_iface and table_pending and s and not s.startswith("#"):
            out.append("Table = off")
            table_written = True
            table_pending = False
        out.append(line)

    flush_table_if_needed()
    if not saw_iface:
        raise ValueError("invalid config: [Interface] section not found")
    return "\n".join(out).rstrip() + "\n"


def _validate_tunnel_config(cfg_text: str) -> tuple[bool, str]:
    try:
        sanitized = _sanitize_tunnel_config(cfg_text)
    except Exception as e:
        return False, str(e)

    if "[Interface]" not in sanitized:
        return False, "missing [Interface] section"
    if not re.search(r"^\s*PrivateKey\s*=\s*\S+", sanitized, flags=re.M):
        return False, "missing Interface.PrivateKey"
    if not re.search(r"^\s*\[Peer\]\s*$", sanitized, flags=re.M):
        return False, "missing [Peer] section"
    if not re.search(r"^\s*PublicKey\s*=\s*\S+", sanitized, flags=re.M):
        return False, "missing Peer.PublicKey"

    # Validate private key format via awg pubkey when available.
    m = re.search(r"^\s*PrivateKey\s*=\s*(\S+)\s*$", sanitized, flags=re.M)
    if m and shutil.which("awg"):
        key = m.group(1).strip()
        p = subprocess.run(
            ["awg", "pubkey"],
            input=f"{key}\n",
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if p.returncode != 0:
            return False, f"invalid PrivateKey: {(p.stderr or p.stdout).strip()}"
    return True, ""


def _ip_in_subnet(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def _guess_gateway_from_cidr(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses <= 2:
            return ""
        return str(next(net.hosts()))
    except Exception:
        return ""


def _mkdir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def _parse_simple_toml(text: str) -> dict:
    data: dict = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            data.setdefault(section, {})
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip()
        val = v.strip()
        if "#" in val:
            val = val.split("#", 1)[0].strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            parsed = val[1:-1]
        elif val.lower() in ("true", "false"):
            parsed = val.lower() == "true"
        else:
            try:
                parsed = int(val)
            except Exception:
                try:
                    parsed = float(val)
                except Exception:
                    parsed = val
        sec = data.setdefault(section, {})
        if isinstance(sec, dict):
            sec[key] = parsed
    return data


def _extract_access_users(cfg_text: str) -> dict[str, str]:
    parsed = _parse_simple_toml(cfg_text)
    sec = parsed.get("access.users", {})
    if not isinstance(sec, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in sec.items():
        out[str(k)] = str(v)
    return out


def _extract_disabled_users(cfg_text: str) -> dict[str, str]:
    parsed = _parse_simple_toml(cfg_text)
    sec = parsed.get("access.disabled_users", {})
    if not isinstance(sec, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in sec.items():
        out[str(k)] = str(v)
    return out


def _replace_named_section(cfg_text: str, section_name: str, values: dict[str, str]) -> str:
    lines = cfg_text.splitlines()
    start = -1
    end = len(lines)
    for i, line in enumerate(lines):
        if line.strip() == f"[{section_name}]":
            start = i
            break
    if start != -1:
        for j in range(start + 1, len(lines)):
            s = lines[j].strip()
            if s.startswith("[") and s.endswith("]"):
                end = j
                break
        before = lines[:start]
        after = lines[end:]
    else:
        before = lines[:]
        after = []

    section_lines = [f"[{section_name}]"]
    for name in sorted(values.keys()):
        section_lines.append(f'{name} = "{values[name]}"')

    merged = before
    if merged and merged[-1].strip():
        merged.append("")
    merged.extend(section_lines)
    if after:
        if merged and merged[-1].strip():
            merged.append("")
        merged.extend(after)
    return "\n".join(merged).rstrip() + "\n"


def _replace_access_users_section(cfg_text: str, users: dict[str, str]) -> str:
    return _replace_named_section(cfg_text, "access.users", users)


def _replace_disabled_users_section(cfg_text: str, users: dict[str, str]) -> str:
    return _replace_named_section(cfg_text, "access.disabled_users", users)


def _toml_remove_upstream_tree(text: str) -> str:
    """Drop [upstream] and every [upstream.*] subsection (socks5/http/tunnel/…)."""
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        stripped = lines[i].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            sec = stripped[1:-1].strip()
            if sec == "upstream" or sec.startswith("upstream."):
                i += 1
                while i < n:
                    s2 = lines[i].strip()
                    if s2.startswith("[") and s2.endswith("]"):
                        break
                    i += 1
                continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def _toml_insert_before_section(text: str, before_section: str, block: str) -> str:
    lines = text.splitlines()
    anchor = f"[{before_section}]"
    block_lines = [ln for ln in block.strip().splitlines()]
    if not block_lines:
        return text
    for i, line in enumerate(lines):
        if line.strip() == anchor:
            new_lines = lines[:i] + block_lines + [""] + lines[i:]
            return "\n".join(new_lines).rstrip() + "\n"
    sep = "" if text.endswith("\n") or not text.strip() else "\n"
    return text.rstrip() + sep + "\n".join(block_lines) + "\n"


def _patch_mtproto_upstream_cfg(cfg_text: str, mode: str, egress_dev: str, tunnel_iface: str) -> str:
    """mtproto.zig [upstream]: direct | tunnel+interface (egress или тунельный интерфейс)."""
    m = str(mode or "").strip().lower()
    cleaned = _toml_remove_upstream_tree(cfg_text)
    if m == "direct":
        block = '[upstream]\ntype = "direct"'
    else:
        iface = (
            str(egress_dev or "").strip()
            if m == "egress"
            else (str(tunnel_iface or "").strip() or "awg-uplink")
        )
        block = f'[upstream]\ntype = "tunnel"\n\n[upstream.tunnel]\ninterface = "{iface}"'
    for anchor in ("censorship", "access.users", "monitor", "metrics"):
        if f"[{anchor}]" in cleaned:
            return _toml_insert_before_section(cleaned, anchor, block)
    sep = "\n" if cleaned.strip() else ""
    return cleaned.rstrip() + sep + block + "\n"


def _iface_split_active(iface: dict) -> bool:
    egress_dev = str(iface.get("egress_dev", "")).strip()
    egress_ip = str(iface.get("egress_ip", "")).strip()
    ingress_dev = str(iface.get("ingress_dev", "")).strip()
    ingress_ip = str(iface.get("ingress_ip", "")).strip()
    return bool(ingress_ip and ingress_dev and (ingress_ip != egress_ip or ingress_dev != egress_dev))


def _mtproto_public_ip_from_iface(iface: dict) -> str:
    """Публичный адрес для ссылок: ingress при split, иначе egress (egress = ingress)."""
    egress_ip = str(iface.get("egress_ip", "")).strip()
    ingress_ip = str(iface.get("ingress_ip", "")).strip()
    if not _iface_split_active(iface):
        return egress_ip
    return ingress_ip


def _mtproto_middle_nat_from_iface(iface: dict) -> str:
    return str(iface.get("egress_ip", "")).strip()


def _ipv4_literal_ok(s: str) -> bool:
    try:
        ipaddress.IPv4Address(str(s).strip())
        return True
    except Exception:
        return False


def _infer_mtproto_outbound_mode(parsed: dict, iface: dict) -> str:
    up = parsed.get("upstream", {})
    if not isinstance(up, dict):
        return "direct"
    typ = str(up.get("type", "auto") or "auto").strip().lower()
    if typ == "direct":
        return "direct"
    if typ != "tunnel":
        return "direct"
    tun = parsed.get("upstream.tunnel", {})
    if not isinstance(tun, dict):
        return "tunnel"
    ifname = str(tun.get("interface", "") or "").strip()
    egress_dev = str(iface.get("egress_dev", "")).strip()
    ingress_dev = str(iface.get("ingress_dev", "")).strip()
    if egress_dev and ifname == egress_dev:
        return "egress"
    if ifname == ingress_dev or ifname == "awg-uplink":
        return "tunnel"
    return "tunnel"


def _effective_mtproto_outbound_mode(prefs: dict, cfg_text: str, iface: dict) -> str:
    raw = str(prefs.get("outbound_mode", "")).strip().lower()
    if raw in ("direct", "egress", "tunnel"):
        return raw
    leg = str(prefs.get("upstream_target", "")).strip().lower()
    if leg == "tunnel":
        return "tunnel"
    if leg == "egress":
        return "direct"
    if cfg_text.strip():
        return _infer_mtproto_outbound_mode(_parse_simple_toml(cfg_text), iface)
    return "direct"


def _toml_merge_keys_in_section(cfg_text: str, section: str, string_values: dict[str, str]) -> str:
    """Задать строковые ключи в [section]; пустое значение — ключ не трогаем."""
    sec_header = f"[{section}]"
    lines = cfg_text.splitlines()
    start = -1
    end = len(lines)
    for i, line in enumerate(lines):
        if line.strip() == sec_header:
            start = i
            break
    to_set = {k: v.strip() for k, v in string_values.items() if str(v).strip()}
    if not to_set:
        return cfg_text if cfg_text.endswith("\n") else (cfg_text + "\n")

    def fmt_line(key: str, val: str) -> str:
        return f'{key} = "{val}"'

    if start == -1:
        block = [sec_header] + [fmt_line(k, v) for k, v in sorted(to_set.items())]
        sep = "\n" if cfg_text.strip() and not cfg_text.endswith("\n") else "\n"
        base = cfg_text.rstrip()
        return base + sep + "\n".join(block) + "\n"

    for j in range(start + 1, len(lines)):
        s = lines[j].strip()
        if s.startswith("[") and s.endswith("]"):
            end = j
            break

    sec_body = lines[start + 1 : end]
    replaced = {k: False for k in to_set}
    key_patterns = {k: re.compile(rf"^\s*{re.escape(k)}\s*=") for k in to_set}
    new_body: list[str] = []
    for line in sec_body:
        raw_key = line.split("#", 1)[0].strip()
        hit = None
        for k, rx in key_patterns.items():
            if raw_key and rx.match(raw_key):
                hit = k
                break
        if hit is not None:
            new_body.append(fmt_line(hit, to_set[hit]))
            replaced[hit] = True
        else:
            new_body.append(line)
    for k in sorted(to_set.keys()):
        if not replaced[k]:
            new_body.append(fmt_line(k, to_set[k]))
    out = lines[:start] + [sec_header] + new_body + lines[end:]
    return "\n".join(out).rstrip() + "\n"


class WebUIHandler(SimpleHTTPRequestHandler):
    server_version = "awg-uplink-webui/0.2"

    def __init__(self, *args, directory=None, username="", password="", **kwargs):
        self._username = username
        self._password = password
        self._base_path = kwargs.pop("base_path")
        self._auth_enabled = kwargs.pop("auth_enabled")
        self._realm = kwargs.pop("realm")
        self._secret = kwargs.pop("secret")
        self._sessions = kwargs.pop("sessions")
        self._nonces = kwargs.pop("nonces")
        super().__init__(*args, directory=directory, **kwargs)

    def _strip_base(self, path: str) -> str | None:
        if not path.startswith(self._base_path):
            return None
        out = path[len(self._base_path) - 1 :]
        if not out.startswith("/"):
            out = "/" + out
        return out

    def _set_cookie(self, token: str, max_age_sec: int = 12 * 3600):
        p = self._base_path
        self.send_header(
            "Set-Cookie",
            f"AWGSESS={token}; Max-Age={max_age_sec}; Path={p}; HttpOnly; SameSite=Lax",
        )

    def _clear_cookie(self):
        p = self._base_path
        self.send_header("Set-Cookie", f"AWGSESS=; Max-Age=0; Path={p}; HttpOnly; SameSite=Lax")

    def _read_cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie", "")
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        for p in parts:
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            if k == name:
                return v
        return None

    def _session_user(self) -> str | None:
        tok = self._read_cookie("AWGSESS")
        if not tok:
            return None
        s = self._sessions.get(tok)
        if not s:
            return None
        if s["exp"] < time.time():
            self._sessions.pop(tok, None)
            return None
        return s["u"]

    def _require_session(self) -> bool:
        if not self._auth_enabled:
            return True
        # allow login assets + auth endpoints without session
        p = self.path.split("?", 1)[0]
        sp = self._strip_base(p)
        if sp is None:
            return False
        if (
            sp in ("/login.html", "/login.js", "/styles.css", "/config.js")
            or sp.startswith("/login")
            or sp.startswith("/api/auth/")
        ):
            return True
        return self._session_user() is not None

    def _send_text(self, code: int, text: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write((text + "\n").encode("utf-8"))

    def _send_json(self, code: int, obj):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(_json_bytes(obj))

    def _read_json_body(self) -> dict:
        n = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(n) if n > 0 else b"{}"
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _new_nonce(self) -> str:
        nonce = secrets.token_hex(16)
        self._nonces[nonce] = time.time() + 120.0
        return nonce

    def _nonce_valid(self, nonce: str) -> bool:
        exp = self._nonces.get(nonce)
        if not exp:
            return False
        if exp < time.time():
            self._nonces.pop(nonce, None)
            return False
        return True

    def _verify_digest_login(self, body: dict) -> bool:
        # Minimal RFC7616-like flow for our own JSON challenge-response.
        username = str(body.get("username", ""))
        nonce = str(body.get("nonce", ""))
        realm = str(body.get("realm", ""))
        qop = str(body.get("qop", ""))
        algorithm = str(body.get("algorithm", ""))
        nc = str(body.get("nc", ""))
        cnonce = str(body.get("cnonce", ""))
        uri = str(body.get("uri", ""))
        method = str(body.get("method", ""))
        response = str(body.get("response", ""))

        if username != self._username:
            return False
        if realm != self._realm or qop != "auth" or algorithm != "SHA-256":
            return False
        if not self._nonce_valid(nonce):
            return False
        if not (nc and cnonce and uri and method and response):
            return False

        ha1 = _sha256_hex(f"{username}:{realm}:{self._password}")
        ha2 = _sha256_hex(f"{method}:{uri}")
        expected = _sha256_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        return hmac.compare_digest(expected, response)

    def _default_iface_firewall(self) -> dict:
        return {"egress_tcp_ports": [22], "ingress_tcp_ports": [22, 443, 8080]}

    def _iface_firewall_for_response(self, cfg: dict) -> dict:
        base = self._default_iface_firewall()
        fw = cfg.get("firewall") if isinstance(cfg.get("firewall"), dict) else {}
        eg = fw.get("egress_tcp_ports")
        ing = fw.get("ingress_tcp_ports")
        out = dict(base)
        if isinstance(eg, list) and eg and all(isinstance(x, int) and 1 <= x <= 65535 for x in eg):
            out["egress_tcp_ports"] = sorted(set(eg))
        if isinstance(ing, list) and ing and all(isinstance(x, int) and 1 <= x <= 65535 for x in ing):
            out["ingress_tcp_ports"] = sorted(set(ing))
        return out

    def _merge_iface_firewall_save(self, prev: dict, fw_body) -> dict:
        cur = self._iface_firewall_for_response(prev if isinstance(prev, dict) else {})
        if not isinstance(fw_body, dict):
            return cur
        eg = self._parse_dns_tcp_ports(fw_body.get("egress_tcp_ports"))
        ing = self._parse_dns_tcp_ports(fw_body.get("ingress_tcp_ports"))
        if eg is not None:
            cur["egress_tcp_ports"] = eg
        if ing is not None:
            cur["ingress_tcp_ports"] = ing
        return cur

    def _webui_cfg_dir(self) -> str:
        return os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui")

    def _webui_iface_json(self) -> str:
        return str(Path(self._webui_cfg_dir()) / "interfaces.json")

    def _webui_iface_env(self) -> str:
        return str(Path(self._webui_cfg_dir()) / "interfaces.env")

    def _webui_geo_json(self) -> str:
        return str(Path(self._webui_cfg_dir()) / "georouting.json")

    def _webui_dns_json(self) -> str:
        return str(Path(self._webui_cfg_dir()) / "dns.json")

    def _default_dns_cfg(self) -> dict:
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

    def _read_amnezia_dns_watch_state(self) -> dict:
        p = Path("/var/lib/awg-uplink/amnezia-dns-watch.json")
        if not p.exists():
            return {}
        try:
            o = json.loads(p.read_text(encoding="utf-8"))
            return o if isinstance(o, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _coerce_dns_bool(val) -> bool:
        """Безопасное bool для dns.json / JSON API (избегаем bool('false') == True)."""
        if isinstance(val, bool):
            return val
        if val is None:
            return False
        if isinstance(val, (int, float)):
            return bool(int(val))
        if isinstance(val, str):
            s = val.strip().lower()
            if s in ("true", "1", "yes", "on"):
                return True
            if s in ("false", "0", "no", "off", ""):
                return False
        return False

    def _load_dns_config(self) -> dict:
        raw = _read_text(self._webui_dns_json(), "")
        if not raw.strip():
            return dict(self._default_dns_cfg())
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                return dict(self._default_dns_cfg())
            for key in ("amnezia_dns_watch_enabled", "dns_transport_lock_enabled"):
                if key in obj:
                    obj[key] = self._coerce_dns_bool(obj[key])
            return obj
        except Exception:
            return dict(self._default_dns_cfg())

    def _store_dns_config(self, cfg: dict):
        _mkdir(self._webui_cfg_dir())
        _write_text(self._webui_dns_json(), json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")

    def _service_is_active(self, unit: str) -> bool:
        rc, out, _ = _run(["systemctl", "is-active", unit], timeout=2.0)
        return rc == 0 and (out or "").strip() == "active"

    _MSG_AMNEZIA_DNS_MISSING = (
        "Отсутствует сервис AmneziaDNS — установите его на сервер из приложения AmneziaVPN."
    )

    def _docker_container_running(self, name: str) -> bool:
        n = (name or "").strip()
        if not n:
            return False
        rc, out, _ = _run(["docker", "inspect", "-f", "{{.State.Running}}", n], timeout=6.0)
        return rc == 0 and (out or "").strip().lower() == "true"

    def _iface_with_geo(self, iface: dict | None) -> dict:
        merged = dict(iface or {})
        merged["geo"] = self._load_geo_config()
        return merged

    def _sync_dns_amnezia_if_domain_routing(self, iface: dict | None) -> None:
        if not self._is_geo_domain_enabled(self._iface_with_geo(iface)):
            return
        dns = self._load_dns_config()
        base = self._default_dns_cfg()
        for k, v in base.items():
            dns.setdefault(k, v)
        dns["amnezia_dns_watch_enabled"] = True
        self._store_dns_config(dns)

    def _parse_dns_tcp_ports(self, val) -> list[int] | None:
        if val is None:
            return None
        if isinstance(val, list):
            out = []
            for x in val:
                try:
                    n = int(x)
                except Exception:
                    continue
                if 1 <= n <= 65535:
                    out.append(n)
            return sorted(set(out)) if out else None
        if isinstance(val, str):
            parts = re.split(r"[\s,;]+", val.strip())
            out = []
            for p in parts:
                if not p:
                    continue
                try:
                    n = int(p)
                except Exception:
                    continue
                if 1 <= n <= 65535:
                    out.append(n)
            return sorted(set(out)) if out else None
        return None

    def _api_dns_config(self):
        cfg = dict(self._load_dns_config())
        cfg.pop("firewall", None)
        base = self._default_dns_cfg()
        for k, v in base.items():
            cfg.setdefault(k, v)
        ts = cfg.get("domains_list_updated_at")
        try:
            ts_int = int(ts) if ts is not None else None
        except Exception:
            ts_int = None
        st = self._read_amnezia_dns_watch_state()
        watch_svc = self._service_is_active("awg-uplink-amnezia-dns-watch.service")
        iface = self._load_iface_config()
        iwg = self._iface_with_geo(iface)
        domain_lock = self._is_geo_domain_enabled(iwg)
        container_name = str(cfg.get("amnezia_dns_container", "amnezia-dns") or "amnezia-dns").strip() or "amnezia-dns"
        container_present = self._docker_container_running(container_name)
        toggle_locked = (not container_present) or domain_lock
        if domain_lock:
            toggle_checked = True
        elif not container_present:
            toggle_checked = False
        else:
            toggle_checked = self._coerce_dns_bool(cfg.get("amnezia_dns_watch_enabled", True))
        detail_ui = str(st.get("detail", "") or "")
        if not container_present:
            detail_ui = self._MSG_AMNEZIA_DNS_MISSING
        tl_rc, _, _ = _run(["nft", "list", "table", "inet", "awg_uplink_dns_transport_lock"], timeout=2.0)
        return self._send_json(
            200,
            {
                "config": cfg,
                "dnsmasq_active": self._service_is_active("dnsmasq.service"),
                "dnscrypt_active": self._service_is_active("dnscrypt-proxy.service"),
                "domains_list_updated_at": ts_int,
                "config_dir": self._webui_cfg_dir(),
                "dns_transport_lock": {
                    "enabled": self._coerce_dns_bool(cfg.get("dns_transport_lock_enabled")),
                    "nft_active": tl_rc == 0,
                },
                "amnezia_dns_watch": {
                    "enabled": self._coerce_dns_bool(cfg.get("amnezia_dns_watch_enabled")),
                    "service_active": watch_svc,
                    "status": str(st.get("status", "") or "unknown"),
                    "detail": detail_ui,
                    "forward_ip": str(st.get("forward_ip", "") or ""),
                    "container": str(st.get("container", "") or ""),
                    "last_run_unix": st.get("last_run_unix"),
                    "last_patch_unix": st.get("last_patch_unix"),
                    "container_present": container_present,
                    "domain_routing_requires": domain_lock,
                    "toggle_locked": toggle_locked,
                    "toggle_checked": toggle_checked,
                },
            },
        )

    def _api_dns_save(self, body: dict):
        cfg = self._load_dns_config()
        base = self._default_dns_cfg()
        for k, v in base.items():
            cfg.setdefault(k, v)

        up = body.get("upstream_servers")
        if isinstance(up, str):
            cfg["upstream_servers"] = [ln.strip() for ln in up.splitlines() if ln.strip()]
        elif isinstance(up, list):
            cfg["upstream_servers"] = [str(x).strip() for x in up if str(x).strip()]

        dc = body.get("dnscrypt_server_names")
        if isinstance(dc, str):
            cfg["dnscrypt_server_names"] = [ln.strip() for ln in dc.splitlines() if ln.strip()]
        elif isinstance(dc, list):
            cfg["dnscrypt_server_names"] = [str(x).strip() for x in dc if str(x).strip()]

        iface = self._load_iface_config()
        iwg = self._iface_with_geo(iface)
        domain_lock = self._is_geo_domain_enabled(iwg)
        container_name = str(cfg.get("amnezia_dns_container", "amnezia-dns") or "amnezia-dns").strip() or "amnezia-dns"
        container_present = self._docker_container_running(container_name)
        if domain_lock:
            cfg["amnezia_dns_watch_enabled"] = True
        elif not container_present:
            cfg["amnezia_dns_watch_enabled"] = False
        else:
            if "amnezia_dns_watch_enabled" in body:
                cfg["amnezia_dns_watch_enabled"] = self._coerce_dns_bool(body.get("amnezia_dns_watch_enabled"))

        if "dns_transport_lock_enabled" in body:
            cfg["dns_transport_lock_enabled"] = self._coerce_dns_bool(body.get("dns_transport_lock_enabled"))

        cfg.pop("firewall", None)
        self._store_dns_config(cfg)
        _run(["systemctl", "daemon-reload"], timeout=3.0)
        _run(["systemctl", "enable", "awg-uplink-dns-refresh.timer"], timeout=3.0)
        _run(["systemctl", "start", "awg-uplink-dns-refresh.timer"], timeout=3.0)
        rc, out, err = _run(["systemctl", "start", "awg-uplink-dns-refresh.service"], timeout=180.0)
        if rc != 0:
            raise RuntimeError((err or out or "awg-uplink-dns-refresh.service failed").strip())
        _run(["systemctl", "enable", "awg-uplink-firewall.service"], timeout=3.0)
        _run(["systemctl", "start", "awg-uplink-firewall.service"], timeout=30.0)
        _run(["systemctl", "enable", "awg-uplink-dns-transport-lock.service"], timeout=3.0)
        _run(["systemctl", "restart", "awg-uplink-dns-transport-lock.service"], timeout=45.0)
        _run(["systemctl", "enable", "awg-uplink-amnezia-dns-watch.service"], timeout=3.0)
        _run(["systemctl", "restart", "awg-uplink-amnezia-dns-watch.service"], timeout=20.0)
        _run(
            ["python3", "/usr/local/sbin/awg-uplink-amnezia-dns-watch.py", "--once"],
            timeout=45.0,
        )
        return self._api_dns_config()

    def _normalize_geo_entry(self, item) -> dict:
        if isinstance(item, str):
            return {"url": item.strip(), "status": "ожидает проверки", "enabled": True, "protected": False}
        if not isinstance(item, dict):
            return {"url": "", "status": "ожидает проверки", "enabled": True, "protected": False}
        return {
            "url": str(item.get("url", "")).strip(),
            "status": str(item.get("status", "ожидает проверки") or "ожидает проверки"),
            "enabled": bool(item.get("enabled", True)),
            "protected": bool(item.get("protected", False)),
        }

    def _normalize_geo_cfg(self, raw) -> dict:
        geo = raw if isinstance(raw, dict) else {}
        ready = geo.get("readyLinks", {}) if isinstance(geo.get("readyLinks", {}), dict) else {}
        lists = geo.get("lists", {}) if isinstance(geo.get("lists", {}), dict) else {}
        target = str(geo.get("target", "tunnel") or "tunnel").strip().lower()
        if target not in ("tunnel", "egress"):
            target = "tunnel"
        return {
            "target": target,
            "ipMode": bool(geo.get("ipMode", False)),
            "domainMode": bool(geo.get("domainMode", False)),
            "readyLinks": {
                "ip": [self._normalize_geo_entry(x) for x in (ready.get("ip", []) if isinstance(ready.get("ip", []), list) else [])],
                "domain": [
                    self._normalize_geo_entry(x)
                    for x in (ready.get("domain", []) if isinstance(ready.get("domain", []), list) else [])
                ],
            },
            "lists": {
                "ipInclude": str(lists.get("ipInclude", "")),
                "ipExclude": str(lists.get("ipExclude", "")),
                "domainInclude": str(lists.get("domainInclude", "")),
                "domainExclude": str(lists.get("domainExclude", "")),
            },
        }

    def _netplan_path(self) -> str:
        explicit = os.environ.get("AWG_WEBUI_NETPLAN_PATH", "").strip()
        if explicit:
            return explicit
        d = Path("/etc/netplan")
        if not d.exists():
            return "/etc/netplan/50-cloud-init.yaml"
        candidates = sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml")))
        if not candidates:
            return "/etc/netplan/50-cloud-init.yaml"
        for c in candidates:
            if c.name == "50-cloud-init.yaml":
                return str(c)
        return str(candidates[0])

    def _validate_netplan_text(self, pth: str, cfg_text: str) -> tuple[bool, str]:
        path_obj = Path(pth)
        old_exists = path_obj.exists()
        old_text = _read_text(pth, "") if old_exists else ""
        data = cfg_text if cfg_text.endswith("\n") else (cfg_text + "\n")
        try:
            _mkdir(str(path_obj.parent))
            _write_text(pth, data)
            rc, out, err = _run(["netplan", "generate"], timeout=20.0)
            if rc != 0:
                return False, (err or out or "netplan generate failed").strip()
            return True, ""
        finally:
            try:
                if old_exists:
                    _write_text(pth, old_text if old_text.endswith("\n") else (old_text + "\n"))
                else:
                    if path_obj.exists():
                        path_obj.unlink()
            except Exception:
                pass

    def _repo_root(self) -> Path:
        # webui/server.py lives under <repo>/webui/server.py
        return Path(__file__).resolve().parent.parent

    def _runtime_src_root(self) -> Path:
        """Каталог с lib/ и systemd/ (после bootstrap — /opt/awg-uplink).

        Если webui запущен из другого пути, но полное дерево лежит в /opt/awg-uplink,
        берём оттуда же, что и awg-webui-iface-routing-apply в bootstrap."""
        candidates = (
            self._repo_root(),
            Path("/opt/awg-uplink"),
            Path("/root/awg-uplink"),
        )
        for base in candidates:
            try:
                b = base.resolve()
            except OSError:
                continue
            if not (b / "lib" / "awg-uplink-dns-refresh.py").exists():
                continue
            if not (b / "systemd" / "awg-uplink-dns-refresh.service").exists():
                continue
            return b
        return self._repo_root().resolve()

    def _iface_service_state(self) -> dict:
        name = "awg-webui-ifaces.service"
        rc_a, out_a, _ = _run(["systemctl", "is-active", name], timeout=1.5)
        rc_e, out_e, _ = _run(["systemctl", "is-enabled", name], timeout=1.5)
        active = (out_a or "").strip() if rc_a == 0 else "inactive"
        enabled = (out_e or "").strip() if rc_e == 0 else "disabled"
        return {"name": name, "active": active, "enabled": enabled, "ok": active == "active"}

    def _tunnel_iface_up(self) -> bool:
        """True if kernel device awg-uplink exists and has UP flag (L3 usable for tunnel routing)."""
        rc, out, _ = _run(["ip", "-j", "link", "show", "dev", "awg-uplink"], timeout=2.0)
        if rc != 0:
            return False
        try:
            items = json.loads(out)
            if not items:
                return False
            flags = items[0].get("flags", []) or []
            return "UP" in flags
        except Exception:
            return False

    def _load_iface_config(self) -> dict:
        raw = _read_text(self._webui_iface_json(), "")
        if not raw.strip():
            return {}
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                return {}
            return obj
        except Exception:
            return {}

    def _load_geo_config(self) -> dict:
        raw = _read_text(self._webui_geo_json(), "")
        if not raw.strip():
            return self._normalize_geo_cfg({})
        try:
            obj = json.loads(raw)
            return self._normalize_geo_cfg(obj)
        except Exception:
            return self._normalize_geo_cfg({})

    def _store_iface_config(self, cfg: dict):
        c = dict(cfg)
        c.pop("geo", None)
        _mkdir(self._webui_cfg_dir())
        _write_text(self._webui_iface_json(), json.dumps(c, ensure_ascii=False, indent=2) + "\n")

    def _store_geo_config(self, geo: dict):
        g = self._normalize_geo_cfg(geo)
        _mkdir(self._webui_cfg_dir())
        _write_text(self._webui_geo_json(), json.dumps(g, ensure_ascii=False, indent=2) + "\n")

    def _write_iface_env(self, cfg: dict):
        egress_dev = str(cfg.get("egress_dev", "")).strip()
        egress_ip = str(cfg.get("egress_ip", "")).strip()
        egress_gw = str(cfg.get("egress_gw", "")).strip()
        ingress_dev = str(cfg.get("ingress_dev", "")).strip()
        ingress_ip = str(cfg.get("ingress_ip", "")).strip()
        ingress_gw = str(cfg.get("ingress_gw", "")).strip()
        route_mode = str(cfg.get("route_mode", "egress") or "egress").strip().lower()
        if route_mode not in ("egress", "tunnel", "georouting"):
            route_mode = "egress"
        if route_mode == "georouting":
            geo = cfg.get("geo", {}) if isinstance(cfg.get("geo", {}), dict) else self._load_geo_config()
            target = str(geo.get("target", "tunnel") or "tunnel").strip().lower()
            # If geo routes "listed resources" to tunnel => base default must be egress.
            # If geo routes "listed resources" to egress => base default must be tunnel.
            apply_mode = "tunnel" if target == "egress" else "egress"
        else:
            apply_mode = route_mode

        ingress_enabled = bool(
            ingress_ip and ingress_dev and (ingress_ip != egress_ip or ingress_dev != egress_dev)
        )
        env = [
            "ENABLE=1",
            f"EGRESS_DEV={shlex.quote(egress_dev)}",
            f"EGRESS_IP={shlex.quote(egress_ip)}",
            f"EGRESS_GW={shlex.quote(egress_gw)}",
            "EGRESS_METRIC=100",
            f"INGRESS_ENABLED={'1' if ingress_enabled else '0'}",
            f"INGRESS_DEV={shlex.quote(ingress_dev)}",
            f"INGRESS_IP={shlex.quote(ingress_ip)}",
            f"INGRESS_GW={shlex.quote(ingress_gw)}",
            "INGRESS_TABLE=201",
            "INGRESS_RULE_PRIO=81",
            "EGRESS_TABLE=202",
            "EGRESS_RULE_PRIO=80",
            f"ROUTE_MODE={shlex.quote(apply_mode)}",
            "# Tunnel + Docker-VPN: optional knobs for awg-webui-iface-routing-apply.sh",
            "# DOCKER_FORCE_PORT=39983",
            "# DOCKER_MARK_IN=amn0",
            "",
        ]
        _mkdir(self._webui_cfg_dir())
        _write_text(self._webui_iface_env(), "\n".join(env))

    def _effective_base_route_mode(self, cfg: dict) -> str:
        route_mode = str(cfg.get("route_mode", "egress") or "egress").strip().lower()
        if route_mode not in ("egress", "tunnel", "georouting"):
            route_mode = "egress"
        if route_mode != "georouting":
            return route_mode
        geo = cfg.get("geo", {}) if isinstance(cfg.get("geo", {}), dict) else self._load_geo_config()
        target = str(geo.get("target", "tunnel") or "tunnel").strip().lower()
        # See _write_iface_env mapping.
        return "tunnel" if target == "egress" else "egress"

    def _is_geo_ip_enabled(self, cfg: dict) -> bool:
        if str(cfg.get("route_mode", "egress")).strip().lower() != "georouting":
            return False
        geo = cfg.get("geo", {}) if isinstance(cfg.get("geo", {}), dict) else self._load_geo_config()
        return bool(geo.get("ipMode", False))

    def _is_geo_domain_enabled(self, cfg: dict) -> bool:
        if str(cfg.get("route_mode", "egress")).strip().lower() != "georouting":
            return False
        geo = cfg.get("geo", {}) if isinstance(cfg.get("geo", {}), dict) else self._load_geo_config()
        return bool(geo.get("domainMode", False))

    def _install_iface_runtime(self):
        root = self._runtime_src_root()
        script_src = root / "lib" / "awg-webui-iface-routing-apply.sh"
        unit_src = root / "systemd" / "awg-webui-ifaces.service"
        script_dst = "/usr/local/sbin/awg-webui-iface-routing-apply.sh"
        unit_dst = "/etc/systemd/system/awg-webui-ifaces.service"
        if not script_src.exists() or not unit_src.exists():
            raise RuntimeError("webui routing runtime files are missing (lib/systemd)")
        shutil.copyfile(str(script_src), script_dst)
        os.chmod(script_dst, 0o755)
        shutil.copyfile(str(unit_src), unit_dst)
        geo_ip_script_src = str(root / "lib" / "awg-uplink-geo-ip-refresh.py")
        geo_ip_script_dst = "/usr/local/sbin/awg-uplink-geo-ip-refresh.py"
        geo_ip_service_src = str(root / "systemd" / "awg-uplink-geo-ip-refresh.service")
        geo_ip_timer_src = str(root / "systemd" / "awg-uplink-geo-ip-refresh.timer")
        if not Path(geo_ip_script_src).exists() or not Path(geo_ip_service_src).exists() or not Path(geo_ip_timer_src).exists():
            raise RuntimeError("geo-ip runtime files are missing (lib/systemd)")
        shutil.copyfile(geo_ip_script_src, geo_ip_script_dst)
        os.chmod(geo_ip_script_dst, 0o755)
        shutil.copyfile(geo_ip_service_src, "/etc/systemd/system/awg-uplink-geo-ip-refresh.service")
        shutil.copyfile(geo_ip_timer_src, "/etc/systemd/system/awg-uplink-geo-ip-refresh.timer")
        geo_domain_script_src = str(root / "lib" / "awg-uplink-geo-domain-refresh.py")
        geo_domain_script_dst = "/usr/local/sbin/awg-uplink-geo-domain-refresh.py"
        geo_domain_service_src = str(root / "systemd" / "awg-uplink-geo-domain-refresh.service")
        geo_domain_timer_src = str(root / "systemd" / "awg-uplink-geo-domain-refresh.timer")
        geo_domain_rotate_svc = str(root / "systemd" / "awg-uplink-geo-domain-nft-rotate.service")
        geo_domain_rotate_tmr = str(root / "systemd" / "awg-uplink-geo-domain-nft-rotate.timer")
        if (
            not Path(geo_domain_script_src).exists()
            or not Path(geo_domain_service_src).exists()
            or not Path(geo_domain_timer_src).exists()
            or not Path(geo_domain_rotate_svc).exists()
            or not Path(geo_domain_rotate_tmr).exists()
        ):
            raise RuntimeError("geo-domain runtime files are missing (lib/systemd)")
        shutil.copyfile(geo_domain_script_src, geo_domain_script_dst)
        os.chmod(geo_domain_script_dst, 0o755)
        shutil.copyfile(geo_domain_service_src, "/etc/systemd/system/awg-uplink-geo-domain-refresh.service")
        shutil.copyfile(geo_domain_timer_src, "/etc/systemd/system/awg-uplink-geo-domain-refresh.timer")
        shutil.copyfile(geo_domain_rotate_svc, "/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.service")
        shutil.copyfile(geo_domain_rotate_tmr, "/etc/systemd/system/awg-uplink-geo-domain-nft-rotate.timer")
        dns_refresh_py = str(root / "lib" / "awg-uplink-dns-refresh.py")
        fw_py = str(root / "lib" / "awg-uplink-firewall-apply.py")
        dns_svc = str(root / "systemd" / "awg-uplink-dns-refresh.service")
        dns_tmr = str(root / "systemd" / "awg-uplink-dns-refresh.timer")
        fw_svc = str(root / "systemd" / "awg-uplink-firewall.service")
        tl_py = str(root / "lib" / "awg-uplink-dns-transport-lock.py")
        tl_svc = str(root / "systemd" / "awg-uplink-dns-transport-lock.service")
        amn_watch_py = str(root / "lib" / "awg-uplink-amnezia-dns-watch.py")
        amn_watch_unit = str(root / "systemd" / "awg-uplink-amnezia-dns-watch.service")
        if (
            not Path(dns_refresh_py).exists()
            or not Path(fw_py).exists()
            or not Path(dns_svc).exists()
            or not Path(dns_tmr).exists()
            or not Path(fw_svc).exists()
            or not Path(tl_py).exists()
            or not Path(tl_svc).exists()
            or not Path(amn_watch_py).exists()
            or not Path(amn_watch_unit).exists()
        ):
            raise RuntimeError("dns/firewall runtime files are missing (lib/systemd)")
        shutil.copyfile(dns_refresh_py, "/usr/local/sbin/awg-uplink-dns-refresh.py")
        os.chmod("/usr/local/sbin/awg-uplink-dns-refresh.py", 0o755)
        shutil.copyfile(fw_py, "/usr/local/sbin/awg-uplink-firewall-apply.py")
        os.chmod("/usr/local/sbin/awg-uplink-firewall-apply.py", 0o755)
        shutil.copyfile(amn_watch_py, "/usr/local/sbin/awg-uplink-amnezia-dns-watch.py")
        os.chmod("/usr/local/sbin/awg-uplink-amnezia-dns-watch.py", 0o755)
        shutil.copyfile(amn_watch_unit, "/etc/systemd/system/awg-uplink-amnezia-dns-watch.service")
        shutil.copyfile(dns_svc, "/etc/systemd/system/awg-uplink-dns-refresh.service")
        shutil.copyfile(dns_tmr, "/etc/systemd/system/awg-uplink-dns-refresh.timer")
        shutil.copyfile(fw_svc, "/etc/systemd/system/awg-uplink-firewall.service")
        shutil.copyfile(tl_py, "/usr/local/sbin/awg-uplink-dns-transport-lock.py")
        os.chmod("/usr/local/sbin/awg-uplink-dns-transport-lock.py", 0o755)
        shutil.copyfile(tl_svc, "/etc/systemd/system/awg-uplink-dns-transport-lock.service")
        dc_unit = root / "systemd" / "dnscrypt-proxy.service"
        if not dc_unit.exists():
            raise RuntimeError("dnscrypt-proxy.service missing (systemd/)")
        shutil.copyfile(str(dc_unit), "/etc/systemd/system/dnscrypt-proxy.service")
        try:
            Path("/etc/systemd/system/dnscrypt-proxy.socket.d/awg-uplink.conf").unlink(missing_ok=True)
        except OSError:
            pass
        _run(["systemctl", "disable", "dnscrypt-proxy.socket"], timeout=5.0)
        _run(["systemctl", "stop", "dnscrypt-proxy.socket"], timeout=5.0)

    def _apply_iface_routing(self):
        self._install_iface_runtime()
        _run(["systemctl", "daemon-reload"], timeout=3.0)
        _run(["systemctl", "enable", "awg-webui-ifaces.service"], timeout=3.0)
        rc, out, err = _run(["systemctl", "restart", "awg-webui-ifaces.service"], timeout=5.0)
        if rc != 0:
            raise RuntimeError((err or out or "failed to restart awg-webui-ifaces.service").strip())
        _run(["systemctl", "start", "awg-uplink-firewall.service"], timeout=30.0)
        _run(["systemctl", "enable", "awg-uplink-dns-transport-lock.service"], timeout=3.0)
        _run(["systemctl", "restart", "awg-uplink-dns-transport-lock.service"], timeout=45.0)

    def _apply_geo_ip_runtime(self, cfg: dict, *, run_refresh_now: bool = True):
        """run_refresh_now: однократный запуск awg-uplink-geo-ip-refresh.service (подтянуть списки в nft).
        False — при сохранении interfaces без кнопки «Применить» в карточке georouting; таймер при enabled оставляем."""
        enabled = self._is_geo_ip_enabled(cfg)
        _run(["systemctl", "daemon-reload"], timeout=3.0)
        if enabled:
            _run(["systemctl", "enable", "awg-uplink-geo-ip-refresh.timer"], timeout=3.0)
            if run_refresh_now:
                _run(["systemctl", "start", "awg-uplink-geo-ip-refresh.service"], timeout=5.0)
            _run(["systemctl", "start", "awg-uplink-geo-ip-refresh.timer"], timeout=3.0)
        else:
            _run(["systemctl", "stop", "awg-uplink-geo-ip-refresh.timer"], timeout=3.0)
            _run(["systemctl", "disable", "awg-uplink-geo-ip-refresh.timer"], timeout=3.0)
            _run(["systemctl", "start", "awg-uplink-geo-ip-refresh.service"], timeout=5.0)

    def _apply_geo_domain_runtime(self, cfg: dict, *, run_refresh_now: bool = True):
        enabled = self._is_geo_domain_enabled(cfg)
        _run(["systemctl", "daemon-reload"], timeout=3.0)
        _run(["systemctl", "enable", "awg-uplink-geo-domain-nft-rotate.timer"], timeout=3.0)
        _run(["systemctl", "start", "awg-uplink-geo-domain-nft-rotate.timer"], timeout=3.0)
        if enabled:
            _run(["systemctl", "enable", "awg-uplink-geo-domain-refresh.timer"], timeout=3.0)
            if run_refresh_now:
                _run(["systemctl", "start", "awg-uplink-geo-domain-refresh.service"], timeout=5.0)
            _run(["systemctl", "start", "awg-uplink-geo-domain-refresh.timer"], timeout=3.0)
        else:
            _run(["systemctl", "stop", "awg-uplink-geo-domain-refresh.timer"], timeout=3.0)
            _run(["systemctl", "disable", "awg-uplink-geo-domain-refresh.timer"], timeout=3.0)
            _run(["systemctl", "start", "awg-uplink-geo-domain-refresh.service"], timeout=5.0)

    def _routing_runtime_status(self, cfg: dict) -> dict:
        egress_dev = str(cfg.get("egress_dev", "")).strip()
        egress_ip = str(cfg.get("egress_ip", "")).strip()
        ingress_dev = str(cfg.get("ingress_dev", "")).strip()
        ingress_ip = str(cfg.get("ingress_ip", "")).strip()
        ingress_enabled = bool(
            ingress_ip and ingress_dev and (ingress_ip != egress_ip or ingress_dev != egress_dev)
        )
        route_mode = str(cfg.get("route_mode", "egress") or "egress").strip().lower()
        if route_mode not in ("egress", "tunnel", "georouting"):
            route_mode = "egress"
        effective = self._effective_base_route_mode(cfg)

        egress_gw = str(cfg.get("egress_gw", "")).strip()
        e_rc, e_out, _ = _run(["ip", "-4", "route", "show", "default"], timeout=2.0)
        default_lines = [ln.strip() for ln in (e_out or "").splitlines() if ln.strip()] if e_rc == 0 else []
        default_line = default_lines[0] if default_lines else ""
        egress_ok = False
        if effective == "tunnel":
            # In tunnel mode, system default must point to awg-uplink.
            egress_ok = any("dev awg-uplink" in ln for ln in default_lines)
        else:
            for ln in default_lines:
                if f"dev {egress_dev}" not in ln:
                    continue
                if egress_gw and f"via {egress_gw}" not in ln:
                    continue
                egress_ok = True
                break
            # Some kernels/routes do not show explicit "src" in default route output,
            # so "dev + (optional via)" is treated as applied state.

        i_rc, i_out, _ = _run(["ip", "-4", "rule", "show"], timeout=2.0)
        ingress_rule_ok = bool(i_rc == 0 and ingress_enabled and ingress_ip and ingress_ip in i_out and "lookup 201" in i_out)
        if not ingress_enabled:
            ingress_rule_ok = True

        tunnel_rule_ok = True
        if effective == "tunnel":
            t_rc, t_out, _ = _run(["ip", "-4", "rule", "show", "priority", "90"], timeout=2.0)
            tunnel_rule_ok = bool(t_rc == 0 and "lookup 203" in (t_out or ""))

        svc = self._iface_service_state()
        applied = bool(svc.get("ok") and egress_ok and ingress_rule_ok and tunnel_rule_ok)
        return {
            "applied": applied,
            "egress_ok": egress_ok,
            "ingress_enabled": ingress_enabled,
            "ingress_ok": ingress_rule_ok,
            "route_mode": route_mode,
            "effective_route_mode": effective,
            "tunnel_rule_ok": tunnel_rule_ok,
            "service": svc,
            "default_route": default_line,
            "geo_ip_enabled": self._is_geo_ip_enabled(cfg),
            "geo_domain_enabled": self._is_geo_domain_enabled(cfg),
        }

    def _validate_iface_cfg(self, cfg: dict) -> tuple[bool, str]:
        ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
        for key in ("egress_dev", "egress_ip"):
            if not str(cfg.get(key, "")).strip():
                return False, f"{key} is required"
        for key in ("egress_ip", "egress_gw", "ingress_ip", "ingress_gw"):
            val = str(cfg.get(key, "")).strip()
            if val and not ip_re.match(val):
                return False, f"invalid {key}"
        return True, ""

    def _dev_default_gateway(self, dev: str) -> str:
        rc, out, _ = _run(["ip", "-4", "route", "show", "default", "dev", dev], timeout=2.0)
        if rc != 0:
            return ""
        for line in out.splitlines():
            m = re.search(r"\bvia\s+([0-9.]+)\b", line)
            if m:
                return m.group(1)
        return ""

    def _dev_cidrs(self, dev: str) -> list[str]:
        rc, out, _ = _run(["ip", "-4", "-o", "addr", "show", "dev", dev], timeout=2.0)
        if rc != 0:
            return []
        out_cidrs: list[str] = []
        for line in out.splitlines():
            parts = line.split()
            if "inet" not in parts:
                continue
            i = parts.index("inet")
            if i + 1 >= len(parts):
                continue
            cidr = parts[i + 1].strip()
            if "/" in cidr:
                out_cidrs.append(cidr)
        return out_cidrs

    def _recommended_gateway(self, dev: str, ip_addr: str, prefixlen: int | None) -> str:
        cidr = f"{ip_addr}/{prefixlen}" if prefixlen is not None else ""
        by_default = self._dev_default_gateway(dev)
        if by_default and cidr and _ip_in_subnet(by_default, cidr):
            return by_default
        if cidr:
            guessed = _guess_gateway_from_cidr(cidr)
            if guessed and guessed != ip_addr:
                return guessed
        for c in self._dev_cidrs(dev):
            guessed = _guess_gateway_from_cidr(c)
            if guessed:
                return guessed
        return ""

    def _normalize_gateway(self, dev: str, ip_addr: str, gw: str) -> str:
        if not ip_addr:
            return ""
        prefixlen = None
        for cidr in self._dev_cidrs(dev):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if ipaddress.ip_address(ip_addr) in net:
                    prefixlen = net.prefixlen
                    break
            except Exception:
                continue
        cidr = f"{ip_addr}/{prefixlen}" if prefixlen is not None else ""
        gw = (gw or "").strip()
        if gw and cidr and _ip_in_subnet(gw, cidr):
            return gw
        return self._recommended_gateway(dev, ip_addr, prefixlen)

    def _api_net_ifaces(self):
        rc, out, _ = _run(["ip", "-j", "-4", "addr", "show"], timeout=2.5)
        if rc != 0:
            return self._send_json(200, {"ifaces": []})
        try:
            items = json.loads(out)
        except Exception:
            return self._send_json(200, {"ifaces": []})

        ifaces = []
        for it in items:
            name = it.get("ifname")
            if not name:
                continue
            # Exclude non-selectable interfaces for ingress/egress UI.
            # - docker*, amnN: docker bridge / amnezia interfaces
            # - lo: loopback
            # - awg-uplink: tunnel itself
            if (
                name == "lo"
                or name == "awg-uplink"
                or name.startswith("docker")
                or (name.startswith("amn") and name[3:].isdigit())
            ):
                continue
            addrs = []
            addrs_info = []
            for a in it.get("addr_info", []) or []:
                if a.get("family") == "inet" and a.get("local"):
                    addrs.append(a["local"])
                    pfx = a.get("prefixlen")
                    try:
                        pfx_int = int(pfx) if pfx is not None else None
                    except Exception:
                        pfx_int = None
                    addrs_info.append(
                        {
                            "ip": a["local"],
                            "prefixlen": pfx_int,
                            "cidr": f'{a["local"]}/{pfx_int}' if pfx_int is not None else "",
                            "suggested_gw": self._recommended_gateway(name, a["local"], pfx_int),
                        }
                    )
            ifaces.append({"name": name, "ipv4": addrs, "ipv4_info": addrs_info})
        return self._send_json(200, {"ifaces": ifaces})

    def _api_status_awg(self):
        conf_path = "/etc/amnezia/amneziawg/awg-uplink.conf"
        rc, out, _ = _run(["ip", "-j", "link", "show", "dev", "awg-uplink"], timeout=2.0)
        if rc != 0:
            return self._send_json(200, {"exists": False, "configured": Path(conf_path).exists()})
        try:
            items = json.loads(out)
        except Exception:
            items = []
        if not items:
            return self._send_json(200, {"exists": False, "configured": Path(conf_path).exists()})
        it = items[0]
        flags = it.get("flags", []) or []
        state = "UP" if "UP" in flags else "DOWN"
        return self._send_json(
            200,
            {
                "exists": True,
                "configured": Path(conf_path).exists(),
                "state": state,
                "operstate": it.get("operstate"),
                "flags": flags,
            },
        )

    def _api_metrics_system(self):
        # CPU snapshot from /proc/stat
        stat = _read_text("/proc/stat", "")
        cpu_total = 0
        cpu_idle = 0
        if stat:
            for line in stat.splitlines():
                if line.startswith("cpu "):
                    parts = line.split()
                    nums = [int(x) for x in parts[1:]]
                    cpu_total = sum(nums)
                    idle = nums[3] if len(nums) > 3 else 0
                    iowait = nums[4] if len(nums) > 4 else 0
                    cpu_idle = idle + iowait
                    break

        # Memory from /proc/meminfo
        mem = _read_text("/proc/meminfo", "")
        mem_total_kb = 0
        mem_avail_kb = 0
        if mem:
            for line in mem.splitlines():
                if line.startswith("MemTotal:"):
                    mem_total_kb = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_avail_kb = int(line.split()[1])

        # Net bytes from /proc/net/dev
        net = _read_text("/proc/net/dev", "")
        rx_total = 0
        tx_total = 0
        if net:
            for line in net.splitlines()[2:]:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface = iface.strip()
                # Skip loopback and docker-like virtual links in monitoring totals
                if iface == "lo" or iface.startswith("docker") or iface.startswith("veth"):
                    continue
                vals = data.split()
                if len(vals) >= 16:
                    rx_total += int(vals[0])
                    tx_total += int(vals[8])

        # Load avg and uptime
        load_raw = _read_text("/proc/loadavg", "").strip().split()
        load1 = float(load_raw[0]) if len(load_raw) > 0 else 0.0
        load5 = float(load_raw[1]) if len(load_raw) > 1 else 0.0
        load15 = float(load_raw[2]) if len(load_raw) > 2 else 0.0

        uptime_raw = _read_text("/proc/uptime", "").strip().split()
        uptime_sec = int(float(uptime_raw[0])) if len(uptime_raw) > 0 else 0

        return self._send_json(
            200,
            {
                "ts": int(time.time()),
                "cpu_total": cpu_total,
                "cpu_idle": cpu_idle,
                "cpu_count": os.cpu_count() or 0,
                "mem_total_kb": mem_total_kb,
                "mem_avail_kb": mem_avail_kb,
                "net_rx_bytes": rx_total,
                "net_tx_bytes": tx_total,
                "load1": load1,
                "load5": load5,
                "load15": load15,
                "uptime_sec": uptime_sec,
            },
        )

    def _mtproto_config_path(self) -> str:
        return os.environ.get("AWG_MTPROTO_CONFIG", "/opt/mtproto-proxy/config.toml")

    def _mtproto_service_name(self) -> str:
        return os.environ.get("AWG_MTPROTO_SERVICE", "mtproto-proxy")

    def _mtproto_prefs_path(self) -> str:
        return str(Path(self._webui_cfg_dir()) / "mtproto.json")

    def _load_mtproto_prefs(self) -> dict:
        raw = _read_text(self._mtproto_prefs_path(), "")
        if not raw.strip():
            return {}
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _store_mtproto_prefs(self, prefs: dict):
        cur = self._load_mtproto_prefs()
        if isinstance(prefs, dict):
            cur.update(prefs)
        om = str(cur.get("outbound_mode", "")).strip().lower()
        if om not in ("direct", "egress", "tunnel"):
            cur.pop("outbound_mode", None)
        else:
            cur["outbound_mode"] = om
        cur.pop("upstream_target", None)
        _mkdir(self._webui_cfg_dir())
        _write_text(self._mtproto_prefs_path(), json.dumps(cur, ensure_ascii=False, indent=2) + "\n")

    def _tunnel_iface_for_mtproto(self) -> str:
        cfg = self._load_iface_config()
        ing = str(cfg.get("ingress_dev", "")).strip()
        return ing or "awg-uplink"

    def _sync_mtproto_derived_config(
        self,
        *,
        persist_outbound_mode: str | None = None,
        apply_upstream: bool = True,
    ) -> dict:
        cfg_path = self._mtproto_config_path()
        cfg_text = _read_text(cfg_path, "")
        if not cfg_text.strip():
            return {"ok": True, "skipped": True, "reason": "no mtproto config"}
        iface = self._load_iface_config()
        if persist_outbound_mode is not None:
            pm = str(persist_outbound_mode).strip().lower()
            if pm in ("direct", "egress", "tunnel"):
                self._store_mtproto_prefs({"outbound_mode": pm})
        prefs = self._load_mtproto_prefs()
        mode = _effective_mtproto_outbound_mode(prefs, cfg_text, iface)
        warnings: list[str] = []
        egress_dev = str(iface.get("egress_dev", "")).strip()
        tunnel_if = self._tunnel_iface_for_mtproto()
        new_text = cfg_text
        if apply_upstream:
            if mode == "egress" and not egress_dev:
                warnings.append(
                    "Режим Egress: не задан egress_dev в настройках интерфейсов — секция [upstream] не менялась."
                )
            else:
                new_text = _patch_mtproto_upstream_cfg(new_text, mode, egress_dev, tunnel_if)
        pub = _mtproto_public_ip_from_iface(iface)
        mid = _mtproto_middle_nat_from_iface(iface)
        server_updates: dict[str, str] = {}
        if pub:
            server_updates["public_ip"] = pub
        if mid and _ipv4_literal_ok(mid):
            server_updates["middle_proxy_nat_ip"] = mid
        if server_updates:
            new_text = _toml_merge_keys_in_section(new_text, "server", server_updates)
        try:
            _write_text(cfg_path, new_text)
        except OSError as e:
            return {"ok": False, "error": str(e)}
        _run(["chown", "mtproto:mtproto", cfg_path], timeout=2.0)
        svc = self._mtproto_service_name()
        rc, out, err = _run(["systemctl", "restart", svc], timeout=20.0)
        resp: dict = {
            "ok": rc == 0,
            "mode": mode,
            "warnings": warnings,
            "public_ip": pub,
            "middle_proxy_nat_ip": server_updates.get("middle_proxy_nat_ip", ""),
        }
        if rc != 0:
            resp["error"] = (err or out or "restart failed").strip()
        if mode == "tunnel" and not self._tunnel_iface_up():
            warnings.append("Интерфейс awg-uplink не UP — проверьте VPN.")
        resp["warnings"] = warnings
        return resp

    def _maybe_sync_mtproto_after_iface_change(self) -> str:
        """Возвращает предупреждение или пусто."""
        try:
            r = self._sync_mtproto_derived_config()
            if r.get("skipped"):
                return ""
            if not r.get("ok"):
                return str(r.get("error", "")).strip() or "mtproto sync failed"
            ws = r.get("warnings") or []
            return " ".join(str(x) for x in ws if x).strip()
        except Exception as ex:
            return str(ex)

    def _unit_state(self, unit_name: str) -> dict:
        name = str(unit_name or "").strip()
        if not name:
            return {"name": "", "active": "unknown", "enabled": "unknown", "ok": False}
        a_rc, a_out, _ = _run(["systemctl", "is-active", name], timeout=1.5)
        e_rc, e_out, _ = _run(["systemctl", "is-enabled", name], timeout=1.5)
        active = (a_out or "").strip() if a_rc == 0 else "inactive"
        enabled = (e_out or "").strip() if e_rc == 0 else "disabled"
        return {
            "name": name,
            "active": active,
            "enabled": enabled,
            "ok": active == "active" and enabled == "enabled",
        }

    def _api_mtproto_state(self):
        cfg_path = self._mtproto_config_path()
        cfg_text = _read_text(cfg_path, "")
        parsed = _parse_simple_toml(cfg_text) if cfg_text else {}
        users = _extract_access_users(cfg_text) if cfg_text else {}
        disabled_users = _extract_disabled_users(cfg_text) if cfg_text else {}

        server_sec = parsed.get("server", {}) if isinstance(parsed.get("server", {}), dict) else {}
        censor_sec = (
            parsed.get("censorship", {}) if isinstance(parsed.get("censorship", {}), dict) else {}
        )
        monitor_sec = parsed.get("monitor", {}) if isinstance(parsed.get("monitor", {}), dict) else {}

        links_by_user: dict[str, str] = {}
        links_tme_by_user: dict[str, str] = {}
        links_raw: list[str] = []
        if cfg_text:
            rc, out, _ = _run(["mtbuddy", "links", "--config", cfg_path], timeout=3.0)
            if rc == 0:
                current_user = ""
                for line in out.splitlines():
                    s = line.strip()
                    if not s:
                        continue
                    links_raw.append(s)
                    if s.endswith(":") and " " not in s[:-1]:
                        current_user = s[:-1].strip()
                        continue
                    if s.startswith("tg:"):
                        tg = s.split("tg:", 1)[1].strip()
                        if current_user and tg.startswith("tg://"):
                            links_by_user[current_user] = tg
                    if s.startswith("t.me:"):
                        tme = s.split("t.me:", 1)[1].strip()
                        if current_user and tme.startswith("http"):
                            links_tme_by_user[current_user] = tme

        # Parse latest session counters from mtproto-proxy logs:
        # users_total=3 unassigned=2 users{alice=1,bob=0}
        users_total = len(users) + len(disabled_users)
        sessions_total = 0
        sessions_cap = users_total * 9
        unassigned = 0
        sessions_by_user: dict[str, int] = {}
        rc, j_out, _ = _run(
            ["journalctl", "-u", "mtproto-proxy", "-n", "120", "--no-pager", "--output=cat"],
            timeout=2.0,
        )
        if rc == 0:
            lines = j_out.splitlines()
            for line in reversed(lines):
                if "conn stats:" not in line:
                    continue
                m_total = re.search(r"users_total=(\d+)", line)
                m_unassigned = re.search(r"unassigned=(\d+)", line)
                m_active = re.search(r"active=(\d+)/(\d+)", line)
                m_users = re.search(r"users\{([^}]*)\}", line)
                if m_total:
                    users_total = int(m_total.group(1))
                if m_unassigned:
                    unassigned = int(m_unassigned.group(1))
                if m_active:
                    sessions_total = int(m_active.group(1))
                    sessions_cap = int(m_active.group(2))
                if m_users:
                    chunk = m_users.group(1).strip()
                    if chunk:
                        for pair in chunk.split(","):
                            if "=" not in pair:
                                continue
                            k, v = pair.split("=", 1)
                            try:
                                sessions_by_user[k.strip()] = int(v.strip())
                            except Exception:
                                pass
                break

        mask_port = int(censor_sec.get("mask_port", 8443) or 8443)
        masking_ok = False
        try:
            with socket.create_connection(("127.0.0.1", mask_port), timeout=1.0):
                masking_ok = True
        except Exception:
            masking_ok = False

        users_out = []
        for u, sec in users.items():
            users_out.append(
                {
                    "username": u,
                    "secret": sec,
                    "link": links_by_user.get(u, ""),
                    "link_tme": links_tme_by_user.get(u, ""),
                    "enabled": True,
                    "sessions": int(sessions_by_user.get(u, 0)),
                }
            )
        for u, sec in disabled_users.items():
            if u in users:
                continue
            users_out.append(
                {
                    "username": u,
                    "secret": sec,
                    "link": "",
                    "link_tme": "",
                    "enabled": False,
                    "sessions": int(sessions_by_user.get(u, 0)),
                }
            )

        # Prefer embedded dashboard API stats when available (same source as mtproto dashboard UI).
        monitor_host = str(monitor_sec.get("host", "127.0.0.1") or "127.0.0.1")
        monitor_port = int(monitor_sec.get("port", 61208) or 61208)
        stats_json = None
        try:
            with urllib.request.urlopen(
                f"http://{monitor_host}:{monitor_port}/api/stats", timeout=1.5
            ) as r:
                stats_json = json.loads(r.read().decode("utf-8"))
        except Exception:
            stats_json = None

        stats_masking = None
        if isinstance(stats_json, dict):
            proxy = stats_json.get("proxy", {}) if isinstance(stats_json.get("proxy", {}), dict) else {}
            users_api = stats_json.get("users", {}) if isinstance(stats_json.get("users", {}), dict) else {}
            stats_masking = (
                stats_json.get("masking", {})
                if isinstance(stats_json.get("masking", {}), dict)
                else None
            )
            per_user = (
                proxy.get("per_user_active", {})
                if isinstance(proxy.get("per_user_active", {}), dict)
                else {}
            )
            # Keep config/mtbuddy as source-of-truth for user list (immediate after edits),
            # and enrich with live session counters from dashboard stats.
            users_api_map: dict[str, dict] = {}
            for it in users_api.get("items", []) or []:
                if isinstance(it, dict):
                    n = str(it.get("name", "")).strip()
                    if n:
                        users_api_map[n] = it

            for u in users_out:
                uname = str(u.get("username", ""))
                u["sessions"] = int(per_user.get(uname, 0) or 0)
                it = users_api_map.get(uname, {})
                # Prefer dashboard links if present.
                if isinstance(it, dict):
                    if it.get("tg_link"):
                        u["link"] = str(it.get("tg_link"))
                    if it.get("tme_link"):
                        u["link_tme"] = str(it.get("tme_link"))
                    if "enabled" in it:
                        u["enabled"] = bool(it.get("enabled"))

            users_total = len(users_out)
            sessions_total = int(proxy.get("users_active_total", 0) or 0)
            sessions_cap = int(proxy.get("active", 0) or 0)
            unassigned = int(proxy.get("unassigned_active", 0) or 0)
        else:
            if users_total <= 0:
                users_total = len(users_out)
            active_users = [x for x in users_out if x.get("enabled")]
            if active_users and all(int(x.get("sessions", 0)) == 0 for x in active_users) and len(active_users) == 1:
                active_users[0]["sessions"] = int(sessions_total)

        service_name = self._mtproto_service_name()
        svc_rc, svc_out, _ = _run(["systemctl", "is-active", service_name], timeout=1.5)
        service_state = (svc_out or "").strip() if svc_rc == 0 else "inactive"
        service_ok = service_state == "active"

        # Match the original dashboard data source: /api/stats -> masking.*
        # Fallback to local probes only when stats API is unavailable.
        if isinstance(stats_masking, dict):
            m_enabled = bool(stats_masking.get("enabled", False))
            m_mode = str(stats_masking.get("mode", "local") or "local")
            m_target = str(stats_masking.get("target", f"127.0.0.1:{mask_port}") or f"127.0.0.1:{mask_port}")
            m_endpoint_ok = bool(stats_masking.get("endpoint_ok", False))
            nginx_active = bool(stats_masking.get("nginx_active", False))
            nginx_enabled = bool(stats_masking.get("nginx_enabled", False))
            timer_active = bool(stats_masking.get("health_timer_active", False))
            timer_enabled = bool(stats_masking.get("health_timer_enabled", False))
            masking_overall_ok = bool(stats_masking.get("healthy", False))
            nginx_state = {
                "name": "nginx.service",
                "active": "active" if nginx_active else "down",
                "enabled": "enabled" if nginx_enabled else "disabled",
                "ok": nginx_active and nginx_enabled,
            }
            timer_state = {
                "name": "health.timer",
                "active": "active" if timer_active else "down",
                "enabled": "enabled" if timer_enabled else "disabled",
                "ok": timer_active and timer_enabled,
            }
            endpoint_status = "OK" if m_endpoint_ok else "DOWN"
            masking_mode = m_mode
            endpoint_target = m_target
        else:
            nginx_unit = os.environ.get("AWG_MTPROTO_NGINX_SERVICE", "nginx.service")
            timer_unit = os.environ.get("AWG_MTPROTO_HEALTH_TIMER", "mtproto-proxy-health.timer")
            nginx_state = self._unit_state(nginx_unit)
            timer_state = self._unit_state(timer_unit)
            endpoint_host = "127.0.0.1"
            endpoint_status = "OK" if masking_ok else "DOWN"
            masking_mode = "local" if endpoint_host in ("127.0.0.1", "localhost") else "remote"
            endpoint_target = f"{endpoint_host}:{mask_port}"
            m_enabled = True
            m_endpoint_ok = masking_ok
            masking_overall_ok = bool(masking_ok and nginx_state["ok"] and timer_state["ok"])

        iface_rt = self._load_iface_config()
        prefs = self._load_mtproto_prefs()
        inferred_mode = _infer_mtproto_outbound_mode(parsed, iface_rt)
        ui_mode = _effective_mtproto_outbound_mode(prefs, cfg_text, iface_rt)
        persisted_om = str(prefs.get("outbound_mode", "")).strip().lower()
        persisted_display = persisted_om if persisted_om in ("direct", "egress", "tunnel") else ""
        up_sec_p = parsed.get("upstream", {})
        cfg_upstream_type = ""
        if isinstance(up_sec_p, dict):
            cfg_upstream_type = str(up_sec_p.get("type", "") or "").strip().lower()
        tunnel_sec_p = parsed.get("upstream.tunnel", {})
        tunnel_if_cfg = ""
        if isinstance(tunnel_sec_p, dict):
            tunnel_if_cfg = str(tunnel_sec_p.get("interface", "") or "").strip()
        effective_tunnel_iface = self._tunnel_iface_for_mtproto()
        pub_derived = _mtproto_public_ip_from_iface(iface_rt)
        mid_raw = _mtproto_middle_nat_from_iface(iface_rt)
        mid_derived = mid_raw if _ipv4_literal_ok(mid_raw) else ""

        return self._send_json(
            200,
            {
                "config_path": cfg_path,
                "config_exists": bool(cfg_text),
                "config_text": cfg_text,
                "users": users_out,
                "users_total": users_total,
                "sessions_total": sessions_total,
                "sessions_cap": sessions_cap,
                "unassigned": unassigned,
                "links_raw": links_raw,
                "server": {
                    "public_ip": server_sec.get("public_ip", ""),
                    "middle_proxy_nat_ip": str(server_sec.get("middle_proxy_nat_ip", "") or ""),
                    "port": int(server_sec.get("port", 443) or 443),
                },
                "censorship": {
                    "tls_domain": censor_sec.get("tls_domain", ""),
                    "mask": bool(censor_sec.get("mask", True)),
                    "mask_port": mask_port,
                },
                "monitor": {
                    "host": monitor_host,
                    "port": monitor_port,
                },
                "upstream": {
                    "mode": ui_mode,
                    "persisted_mode": persisted_display,
                    "inferred_mode": inferred_mode,
                    "config_type": cfg_upstream_type,
                    "tunnel_interface_config": tunnel_if_cfg,
                    "tunnel_interface_effective": effective_tunnel_iface,
                    "egress_dev": str(iface_rt.get("egress_dev", "") or ""),
                    "ingress_dev": str(iface_rt.get("ingress_dev", "") or ""),
                    "public_ip_derived": pub_derived,
                    "middle_proxy_nat_ip_derived": mid_derived,
                    "tunnel_iface_up": self._tunnel_iface_up(),
                },
                "service": {
                    "name": service_name,
                    "state": service_state,
                    "ok": service_ok,
                },
                "masking_health": {
                    "ok": masking_overall_ok,
                    "enabled": m_enabled,
                    "mode": masking_mode,
                    "endpoint": endpoint_target,
                    "endpoint_ok": m_endpoint_ok,
                    "endpoint_status": endpoint_status,
                    "nginx": nginx_state,
                    "health_timer": timer_state,
                    "mask_port_open_local": masking_ok,
                },
            },
        )

    def do_GET(self):
        p = self.path.split("?", 1)[0]
        sp = self._strip_base(p)
        if sp is None:
            self.send_response(404)
            self.end_headers()
            return

        if self._auth_enabled and not self._require_session():
            # redirect to login "window"
            next_path = sp if sp.startswith("/") else self._base_path
            self.send_response(302)
            self.send_header("Location", f"{self._base_path}login.html?next={next_path}")
            self.end_headers()
            return

        if sp == "/config.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                (
                    f'window.__AWG_BASE_PATH__ = {json.dumps(self._base_path)};\n'
                    f'window.__AWG_AUTH_ENABLED__ = {json.dumps(bool(self._auth_enabled))};\n'
                ).encode("utf-8")
            )
            return

        if sp == "/api/auth/challenge":
            if not self._auth_enabled:
                return self._send_json(200, {"disabled": True})
            nonce = self._new_nonce()
            return self._send_json(
                200,
                {
                    "realm": self._realm,
                    "nonce": nonce,
                    "qop": "auth",
                    "algorithm": "SHA-256",
                },
            )

        if sp == "/api/auth/me":
            u = self._session_user()
            if self._auth_enabled and not u:
                return self._send_text(401, "Unauthorized")
            return self._send_json(200, {"user": u or self._username})

        if sp == "/api/net/ifaces":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_net_ifaces()

        if sp == "/api/net/routing-config":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            cfg = self._load_iface_config()
            if isinstance(cfg, dict):
                cfg = dict(cfg)
                cfg["geo"] = self._load_geo_config()
                cfg["firewall"] = self._iface_firewall_for_response(cfg)
            return self._send_json(
                200,
                {
                    "config": cfg,
                    "runtime": self._routing_runtime_status(cfg) if cfg else {},
                    "config_dir": self._webui_cfg_dir(),
                },
            )

        if sp == "/api/dns/config":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_dns_config()

        if sp == "/api/netplan/config":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            pth = self._netplan_path()
            return self._send_json(
                200,
                {
                    "path": pth,
                    "exists": Path(pth).exists(),
                    "config_text": _read_text(pth, ""),
                },
            )

        if sp == "/api/status/awg-uplink":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_status_awg()

        if sp == "/api/metrics/system":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_metrics_system()

        if sp == "/api/mtproto/state":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_mtproto_state()

        # SPA routes
        if sp == "/" or sp == "/app" or sp == "/app/":
            self.path = self._base_path + "index.html"
            return super().do_GET()

        self.path = sp
        return super().do_GET()

    def do_HEAD(self):
        # Same routing as GET, but without body.
        p = self.path.split("?", 1)[0]
        sp = self._strip_base(p)
        if sp is None:
            self.send_response(404)
            self.end_headers()
            return

        if self._auth_enabled and not self._require_session():
            next_path = sp if sp.startswith("/") else self._base_path
            self.send_response(302)
            self.send_header("Location", f"{self._base_path}login.html?next={next_path}")
            self.end_headers()
            return

        if sp == "/config.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.end_headers()
            return

        if sp == "/api/auth/me":
            u = self._session_user()
            if not u:
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            return

        if sp == "/api/auth/challenge":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            return

        if sp.startswith("/api/"):
            # Other API endpoints are POST-only; keep behavior simple.
            self.send_response(404)
            self.end_headers()
            return

        if sp == "/" or sp == "/app" or sp == "/app/":
            self.path = self._base_path + "index.html"
            return super().do_HEAD()

        self.path = sp
        return super().do_HEAD()

    def do_POST(self):
        p = self.path.split("?", 1)[0]
        sp = self._strip_base(p)
        if sp is None:
            self.send_response(404)
            self.end_headers()
            return

        if sp == "/api/auth/challenge":
            if not self._auth_enabled:
                return self._send_json(200, {"disabled": True})
            nonce = self._new_nonce()
            return self._send_json(
                200,
                {
                    "realm": self._realm,
                    "nonce": nonce,
                    "qop": "auth",
                    "algorithm": "SHA-256",
                },
            )

        if sp == "/api/auth/login":
            if not self._auth_enabled:
                return self._send_json(200, {"ok": True, "disabled": True})
            body = self._read_json_body()
            if not self._verify_digest_login(body):
                return self._send_text(401, "Unauthorized")
            token = secrets.token_hex(24)
            self.send_response(200)
            self._sessions[token] = {"u": self._username, "exp": time.time() + 12 * 3600}
            self._set_cookie(token)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(_json_bytes({"ok": True}))
            return

        if sp == "/api/auth/logout":
            if not self._auth_enabled:
                return self._send_json(200, {"ok": True, "disabled": True})
            tok = self._read_cookie("AWGSESS")
            if tok:
                self._sessions.pop(tok, None)
            self.send_response(200)
            self._clear_cookie()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(_json_bytes({"ok": True}))
            return

        if sp == "/api/net/routing/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            prev = self._load_iface_config()
            cfg = {
                "egress_dev": str(body.get("egress_dev", "")).strip(),
                "egress_ip": str(body.get("egress_ip", "")).strip(),
                "egress_gw": str(body.get("egress_gw", "")).strip(),
                "ingress_dev": str(body.get("ingress_dev", "")).strip(),
                "ingress_ip": str(body.get("ingress_ip", "")).strip(),
                "ingress_gw": str(body.get("ingress_gw", "")).strip(),
                "route_mode": str(body.get("route_mode", "") or "egress").strip().lower(),
                "geo": self._normalize_geo_cfg(body.get("geo", {})),
                "firewall": self._merge_iface_firewall_save(prev, body.get("firewall")),
                "updated_at": int(time.time()),
            }
            if cfg["route_mode"] not in ("egress", "tunnel", "georouting"):
                cfg["route_mode"] = "egress"
            route_mode_warning = ""
            if cfg.get("route_mode") == "tunnel" and not self._tunnel_iface_up():
                cfg["route_mode"] = "egress"
                route_mode_warning = (
                    "awg-uplink is not UP; сохранено и применено в режиме egress (split egress/ingress)."
                )
            ok, err = self._validate_iface_cfg(cfg)
            if not ok:
                return self._send_text(400, err)
            cfg["egress_gw"] = self._normalize_gateway(cfg["egress_dev"], cfg["egress_ip"], cfg["egress_gw"])
            cfg["ingress_gw"] = self._normalize_gateway(
                cfg["ingress_dev"] or cfg["egress_dev"],
                cfg["ingress_ip"],
                cfg["ingress_gw"],
            )
            try:
                self._store_geo_config(cfg.get("geo", {}))
                self._store_iface_config(cfg)
                self._write_iface_env(cfg)
                self._apply_iface_routing()
                # Немедленный прогон geo-ip только по кнопке «Применить» в georouting (app.js).
                self._apply_geo_ip_runtime(cfg, run_refresh_now=bool(body.get("apply_geo_ip_refresh")))
                self._apply_geo_domain_runtime(cfg, run_refresh_now=bool(body.get("apply_geo_ip_refresh")))
            except Exception as e:
                return self._send_text(500, f"apply failed: {e}")
            runtime = self._routing_runtime_status(cfg)
            if not runtime.get("applied"):
                return self._send_json(
                    500,
                    {
                        "ok": False,
                        "error": "routing not applied",
                        "config": cfg,
                        "runtime": runtime,
                    },
                )
            try:
                self._sync_dns_amnezia_if_domain_routing(self._load_iface_config())
            except Exception:
                pass
            resp = {
                "ok": True,
                "config": (lambda x: (dict(x) | {"geo": self._load_geo_config()}) if isinstance(x, dict) else {})(
                    self._load_iface_config()
                ),
                "runtime": runtime,
                "config_dir": self._webui_cfg_dir(),
            }
            if route_mode_warning:
                resp["warning"] = route_mode_warning
            mt_extra = self._maybe_sync_mtproto_after_iface_change()
            if mt_extra:
                resp["mtproto_sync_warning"] = mt_extra
            return self._send_json(200, resp)

        if sp == "/api/net/routing/mode":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            mode = str(body.get("route_mode", "")).strip().lower()
            if mode not in ("egress", "tunnel", "georouting"):
                return self._send_text(400, "route_mode must be egress|tunnel|georouting")
            if mode == "tunnel" and not self._tunnel_iface_up():
                return self._send_text(409, "awg-uplink tunnel is not UP")
            cfg = self._load_iface_config()
            if not cfg:
                return self._send_text(400, "interface config is empty")
            cfg["route_mode"] = mode
            cfg["updated_at"] = int(time.time())
            cfg["geo"] = self._load_geo_config()
            try:
                self._store_iface_config(cfg)
                self._write_iface_env(cfg)
                self._apply_iface_routing()
                self._apply_geo_ip_runtime(cfg)
                self._apply_geo_domain_runtime(cfg)
            except Exception as e:
                return self._send_text(500, f"apply failed: {e}")
            runtime = self._routing_runtime_status(cfg)
            if not runtime.get("applied"):
                return self._send_json(500, {"ok": False, "error": "routing not applied", "runtime": runtime})
            try:
                self._sync_dns_amnezia_if_domain_routing(self._load_iface_config())
            except Exception:
                pass
            mt_extra = self._maybe_sync_mtproto_after_iface_change()
            out = {"ok": True, "config": cfg, "runtime": runtime}
            if mt_extra:
                out["mtproto_sync_warning"] = mt_extra
            return self._send_json(200, out)

        if sp == "/api/dns/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            try:
                self._install_iface_runtime()
                return self._api_dns_save(body)
            except Exception as e:
                return self._send_text(500, f"dns apply failed: {e}")

        if sp == "/api/netplan/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            cfg_text = str(body.get("config_text", ""))
            if not cfg_text.strip():
                return self._send_text(400, "config_text is empty")
            pth = self._netplan_path()
            try:
                ok, err = self._validate_netplan_text(pth, cfg_text)
                if not ok:
                    return self._send_text(400, f"netplan syntax error:\n{err}")
                _mkdir(str(Path(pth).parent))
                _write_text(pth, cfg_text if cfg_text.endswith("\n") else (cfg_text + "\n"))
                rc, out, err = _run(["netplan", "apply"], timeout=20.0)
                if rc != 0:
                    return self._send_text(500, (err or out or "netplan apply failed").strip())
            except Exception as e:
                return self._send_text(500, f"netplan save/apply failed: {e}")
            return self._send_json(200, {"ok": True, "path": pth})

        if sp == "/api/netplan/validate":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            cfg_text = str(body.get("config_text", ""))
            if not cfg_text.strip():
                return self._send_text(400, "config_text is empty")
            pth = self._netplan_path()
            ok, err = self._validate_netplan_text(pth, cfg_text)
            if not ok:
                return self._send_text(400, f"netplan syntax error:\n{err}")
            return self._send_json(200, {"ok": True, "path": pth})

        if sp == "/api/tunnel/import":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            cfg_text = str(body.get("config_text", ""))
            if not cfg_text.strip():
                return self._send_text(400, "config_text is empty")
            try:
                ok, verr = _validate_tunnel_config(cfg_text)
                if not ok:
                    return self._send_text(400, f"tunnel config validation failed: {verr}")
                sanitized = _sanitize_tunnel_config(cfg_text)
                conf_path = Path("/etc/amnezia/amneziawg/awg-uplink.conf")
                _mkdir(str(conf_path.parent))
                _write_text(str(conf_path), sanitized)
                os.chmod(str(conf_path), 0o600)
                _run(["systemctl", "daemon-reload"], timeout=3.0)
                _run(["systemctl", "enable", "awg-quick@awg-uplink.service"], timeout=3.0)
                rc, out, err = _run(["systemctl", "restart", "awg-quick@awg-uplink.service"], timeout=10.0)
                if rc != 0:
                    return self._send_text(500, (err or out or "failed to restart awg-quick@awg-uplink").strip())
                routing_err = ""
                try:
                    self._apply_iface_routing()
                except Exception as ex:
                    routing_err = str(ex)
                payload = {
                    "ok": True,
                    "path": "/etc/amnezia/amneziawg/awg-uplink.conf",
                }
                if routing_err:
                    payload["routing_apply_error"] = routing_err
            except Exception as e:
                return self._send_text(500, f"tunnel import failed: {e}")
            else:
                return self._send_json(200, payload)

        if sp == "/api/tunnel/validate":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            cfg_text = str(body.get("config_text", ""))
            if not cfg_text.strip():
                return self._send_text(400, "config_text is empty")
            ok, verr = _validate_tunnel_config(cfg_text)
            if not ok:
                return self._send_text(400, f"tunnel config validation failed: {verr}")
            return self._send_json(200, {"ok": True})

        if sp == "/api/tunnel/restart":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            rc, out, err = _run(["systemctl", "restart", "awg-quick@awg-uplink.service"], timeout=12.0)
            if rc != 0:
                return self._send_text(500, (err or out or "failed to restart awg-quick@awg-uplink").strip())
            routing_err = ""
            try:
                self._apply_iface_routing()
            except Exception as ex:
                routing_err = str(ex)
            resp = {"ok": True}
            if routing_err:
                resp["routing_apply_error"] = routing_err
            return self._send_json(200, resp)

        if sp == "/api/mtproto/outbound/set":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            mode = str(body.get("mode", "")).strip().lower()
            if mode not in ("direct", "egress", "tunnel"):
                return self._send_text(400, "mode must be direct|egress|tunnel")
            cfg_path = self._mtproto_config_path()
            if not _read_text(cfg_path, "").strip():
                return self._send_text(400, "mtproto config missing")
            res = self._sync_mtproto_derived_config(persist_outbound_mode=mode, apply_upstream=True)
            return self._send_json(200, res)

        if sp == "/api/mtproto/config/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            cfg_text = str(body.get("config_text", ""))
            if not cfg_text.strip():
                return self._send_text(400, "config_text is empty")
            cfg_path = self._mtproto_config_path()
            try:
                _write_text(cfg_path, cfg_text)
            except OSError as e:
                return self._send_text(500, f"failed to write config: {e}")
            sync = self._sync_mtproto_derived_config(apply_upstream=False)
            return self._send_json(200, {"ok": True, "mtproto_sync": sync})

        if sp == "/api/mtproto/users/upsert":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            username = str(body.get("username", "")).strip()
            secret = str(body.get("secret", "")).strip()
            if not username or not secret:
                return self._send_text(400, "username/secret required")
            cfg_path = self._mtproto_config_path()
            cfg_text = _read_text(cfg_path, "")
            users = _extract_access_users(cfg_text)
            disabled_users = _extract_disabled_users(cfg_text)
            users[username] = secret
            disabled_users.pop(username, None)
            new_cfg = _replace_access_users_section(cfg_text, users)
            new_cfg = _replace_disabled_users_section(new_cfg, disabled_users)
            _write_text(cfg_path, new_cfg)
            return self._send_json(200, {"ok": True})

        if sp == "/api/mtproto/users/toggle":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            username = str(body.get("username", "")).strip()
            enabled = bool(body.get("enabled", True))
            if not username:
                return self._send_text(400, "username required")
            cfg_path = self._mtproto_config_path()
            cfg_text = _read_text(cfg_path, "")
            users = _extract_access_users(cfg_text)
            disabled_users = _extract_disabled_users(cfg_text)
            if enabled:
                if username in disabled_users:
                    users[username] = disabled_users.pop(username)
            else:
                if username in users:
                    disabled_users[username] = users.pop(username)
            new_cfg = _replace_access_users_section(cfg_text, users)
            new_cfg = _replace_disabled_users_section(new_cfg, disabled_users)
            _write_text(cfg_path, new_cfg)
            return self._send_json(200, {"ok": True})

        if sp == "/api/mtproto/users/delete":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            username = str(body.get("username", "")).strip()
            if not username:
                return self._send_text(400, "username required")
            cfg_path = self._mtproto_config_path()
            cfg_text = _read_text(cfg_path, "")
            users = _extract_access_users(cfg_text)
            disabled_users = _extract_disabled_users(cfg_text)
            users.pop(username, None)
            disabled_users.pop(username, None)
            new_cfg = _replace_access_users_section(cfg_text, users)
            new_cfg = _replace_disabled_users_section(new_cfg, disabled_users)
            _write_text(cfg_path, new_cfg)
            return self._send_json(200, {"ok": True})

        return self._send_text(404, "Not Found")

    def translate_path(self, path: str) -> str:
        # Same as base, but keep us inside directory.
        path = path.split("?", 1)[0]
        path = path.split("#", 1)[0]
        path = posixpath.normpath(path)
        words = [w for w in path.split("/") if w]

        base = Path(self.directory or os.getcwd()).resolve()
        for w in words:
            w = os.path.basename(w)
            base = (base / w).resolve()
        return str(base)

    def log_message(self, fmt, *args):
        # Keep logs concise
        super().log_message(fmt, *args)


def main():
    parser = argparse.ArgumentParser(description="awg-uplink web UI (static) with digest-style login")
    parser.add_argument("--host", default=os.environ.get("AWG_WEBUI_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AWG_WEBUI_PORT", "8080")))
    parser.add_argument(
        "--base-path",
        default=os.environ.get("AWG_WEBUI_BASE_PATH", "/"),
        help="Serve under this URL prefix, e.g. /ui/",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        default=_env_bool("AWG_WEBUI_NO_AUTH", False),
        help="Disable auth (debug only)",
    )
    args = parser.parse_args()

    auth_enabled = not args.no_auth
    if auth_enabled:
        user = _require_env("AWG_UI_USER")
        pwd = _require_env("AWG_UI_PASS")
    else:
        user = os.environ.get("AWG_UI_USER", "debug")
        pwd = os.environ.get("AWG_UI_PASS", "debug")
    base_path = _normalize_base_path(args.base_path)
    realm = "awg-uplink webui"
    secret = _sha256_hex(f"{user}:{realm}:{pwd}")

    directory = str(Path(__file__).parent.resolve())
    sessions: dict[str, dict] = {}
    nonces: dict[str, float] = {}

    def handler(*h_args, **h_kwargs):
        return WebUIHandler(
            *h_args,
            directory=directory,
            username=user,
            password=pwd,
            base_path=base_path,
            auth_enabled=auth_enabled,
            realm=realm,
            secret=secret,
            sessions=sessions,
            nonces=nonces,
            **h_kwargs,
        )

    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Serving {directory} on http://{args.host}:{args.port}{base_path}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()


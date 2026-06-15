#!/usr/bin/env python3
import argparse
import base64
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
import sys
import threading
import time
import tomllib
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse


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


def _webui_sessions_file() -> Path:
    return Path(os.environ.get("AWG_WEBUI_SESSIONS_FILE", "/var/lib/awg-uplink-webui/sessions.json"))


def _load_webui_sessions_from_disk() -> dict[str, dict]:
    """Restore cookie sessions across webui process restarts (tokens still valid by exp)."""
    p = _webui_sessions_file()
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    now = time.time()
    out: dict[str, dict] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or len(k) > 256:
            continue
        if not isinstance(v, dict):
            continue
        exp = v.get("exp")
        u = v.get("u")
        if not isinstance(exp, (int, float)) or exp < now:
            continue
        if not isinstance(u, str) or not u.strip():
            continue
        out[k] = {"u": u, "exp": float(exp)}
    return out


def _save_webui_sessions_to_disk(sessions: dict[str, dict]) -> None:
    p = _webui_sessions_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(sessions, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _json_bytes(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")


def _run(cmd: list[str], timeout: float = 2.5) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _semver_tuple(s: str) -> tuple[int, int, int]:
    t = (s or "").strip().lower().lstrip("v")
    if not t:
        return (0, 0, 0)
    chunk = t.split("-", 1)[0].strip()
    parts = chunk.split(".")
    nums: list[int] = []
    for p in parts[:3]:
        acc = ""
        for ch in p:
            if ch.isdigit():
                acc += ch
            else:
                break
        nums.append(int(acc) if acc else 0)
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def _semver_gt(a: str, b: str) -> bool:
    return _semver_tuple(a) > _semver_tuple(b)


def _fetch_remote_version(repo: str, branch: str) -> str:
    """VERSION с GitHub: raw + Contents API (API не зависит от CDN-кэша raw.githubusercontent.com)."""
    found: list[str] = []
    br_q = urllib.parse.quote(branch, safe="")
    try:
        v = _http_get_text(f"https://raw.githubusercontent.com/{repo}/{branch}/VERSION", timeout=10.0)
        v = v.splitlines()[0].strip() if v else ""
        if v:
            found.append(v)
    except Exception:
        pass
    try:
        data = _http_get_json(
            f"https://api.github.com/repos/{repo}/contents/VERSION?ref={br_q}",
            timeout=12.0,
        )
        if isinstance(data, dict) and str(data.get("encoding") or "") == "base64":
            raw = base64.b64decode(str(data.get("content") or ""))
            v = raw.decode("utf-8", errors="replace").splitlines()[0].strip()
            if v:
                found.append(v)
    except Exception:
        pass
    if not found:
        return ""
    best = found[0]
    for v in found[1:]:
        if _semver_gt(v, best):
            best = v
    return best


def _http_get_text(url: str, timeout: float = 8.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "awg-uplink-webui-update/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace").strip()


def _http_get_json(url: str, timeout: float = 10.0):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "awg-uplink-webui-update/1.0",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _parse_changelog_section(text: str, version: str) -> str:
    ver = str(version or "").strip()
    if not ver or not text:
        return ""
    hdr = re.compile(rf"^#{{1,3}}\s*\[?{re.escape(ver)}\]?\s*(?:\s|$)", re.IGNORECASE)
    any_hdr = re.compile(r"^#{1,3}\s+")
    body: list[str] = []
    in_section = False
    for line in text.splitlines():
        s = line.strip()
        if hdr.match(s):
            in_section = True
            continue
        if in_section and any_hdr.match(s) and not hdr.match(s):
            break
        if in_section:
            body.append(line.rstrip())
    return "\n".join(body).strip()


_CHANGELOG_VER_HDR = re.compile(
    r"^#{1,3}\s*\[?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)\]?\s*(?:\s|$)",
    re.IGNORECASE,
)


def _split_changelog_sections(text: str) -> list[tuple[str, str]]:
    """Список (version, body) в порядке файла."""
    if not text:
        return []
    sections: list[tuple[str, str]] = []
    cur_ver = ""
    cur_lines: list[str] = []
    for line in text.splitlines():
        m = _CHANGELOG_VER_HDR.match(line.strip())
        if m:
            if cur_ver:
                sections.append((cur_ver, "\n".join(cur_lines).strip()))
            cur_ver = m.group(1).strip()
            cur_lines = []
            continue
        if cur_ver:
            cur_lines.append(line.rstrip())
    if cur_ver:
        sections.append((cur_ver, "\n".join(cur_lines).strip()))
    return sections


def _parse_changelog_range(text: str, current: str, latest: str) -> str:
    """Все секции CHANGELOG с версией (current, latest] — для пропуска нескольких релизов."""
    cur = str(current or "").strip()
    lat = str(latest or "").strip()
    if not lat or not text:
        return ""
    picked: list[tuple[tuple[int, int, int], str, str]] = []
    for ver, body in _split_changelog_sections(text):
        if not ver or not body:
            continue
        if cur and not _semver_gt(ver, cur):
            continue
        if _semver_gt(ver, lat):
            continue
        picked.append((_semver_tuple(ver), ver, body))
    if not picked:
        return _parse_changelog_section(text, lat)
    picked.sort(key=lambda x: x[0], reverse=True)
    blocks = [f"## {ver}\n{body}" for _, ver, body in picked]
    return "\n\n".join(blocks).strip()


def _reload_or_restart_service(unit: str, reload_timeout: float = 8.0, restart_timeout: float = 20.0) -> tuple[int, str, str, str]:
    """
    Try systemctl reload first to avoid short connection drops,
    fallback to restart when reload is unsupported or fails.
    Returns (rc, out, err, action), where action is "reload" or "restart".
    """
    u = str(unit or "").strip()
    if not u:
        return 1, "", "empty unit name", "restart"
    rc, out, err = _run(["systemctl", "reload", u], timeout=reload_timeout)
    if rc == 0:
        return rc, out, err, "reload"
    rc, out, err = _run(["systemctl", "restart", u], timeout=restart_timeout)
    return rc, out, err, "restart"


def _schedule_mtproto_user_config_restart(unit: str, defer_s: float = 0.25, restart_timeout: float = 25.0) -> None:
    """
    MTProto picks up [access.users] changes only after a full restart; reload is not enough.
    When the browser uses the same :443 front (e.g. via the proxy), an in-request restart
    drops the TCP session and breaks the API call. Schedule restart after a short defer so
    the HTTP response can be delivered first.
    """

    def _worker():
        try:
            time.sleep(defer_s)
        except Exception:
            pass
        u = str(unit or "").strip()
        if not u:
            return
        rc, out, err = _run(["systemctl", "restart", u], timeout=restart_timeout)
        if rc != 0:
            msg = (err or out or "unknown error").strip()
            print(f"[awg-webui] deferred systemctl restart failed for {u}: {msg}", flush=True)

    threading.Thread(target=_worker, daemon=True).start()


def _read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return default


def _read_installed_app_version() -> str:
    """Single-line semver from /opt/awg-uplink/VERSION (next to webui/)."""
    p = Path(__file__).resolve().parent.parent / "VERSION"
    raw = _read_text(str(p), "").strip()
    if raw:
        return raw.splitlines()[0].strip()
    return "0.0.0"


def _write_text(path: str, data: str):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)


def _validate_toml_text(cfg_text: str) -> tuple[bool, str]:
    try:
        tomllib.loads(cfg_text)
        return True, ""
    except Exception as ex:
        return False, str(ex)


_MTPROTO_INSTALL_LOCK = threading.Lock()
_MTPROTO_INSTALL_STATE: dict = {
    "running": False,
    "action": "",
    "started_at": 0,
    "finished_at": 0,
    "ok": None,
    "error": "",
    "warnings": [],
    "phase": "",
}

_ASYNC_OPS_LOCK = threading.Lock()
_ASYNC_OPS: dict[str, dict] = {}

_UPDATE_CHECK_LOCK = threading.Lock()
_UPDATE_CHECK_CACHE: dict[str, tuple[float, dict]] = {}
_UPDATE_CHECK_TTL_SEC = 120.0


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


def _read_webui_env_value(key: str, default: str = "") -> str:
    env_path = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui")) / "webui.env"
    if not env_path.is_file():
        return (os.environ.get(key) or default).strip()
    prefix = f"{key}="
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return (os.environ.get(key) or default).strip()


def _webui_tls_self_signed() -> bool:
    mode = _read_webui_env_value("AWG_UI_TLS_MODE", "self-signed").strip().lower()
    return mode not in ("letsencrypt", "le")


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
    if ifname == ingress_dev or ifname in ("awg-uplink", "awg-uplink-2"):
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


def _upsert_mtproto_censorship_cfg(cfg_text: str, domain: str, mask_port: int) -> str:
    text = cfg_text or ""
    if "[censorship]" not in text:
        text = text.rstrip() + ("\n" if text.strip() else "") + "\n[censorship]\n"
    start = text.index("[censorship]")
    rest = text[start:]
    m = re.search(r"\n\[[^\n]+\]", rest[1:])
    end = start + (m.start() + 1 if m else len(rest))
    section = text[start:end]

    def replace_or_add(section_text: str, key: str, value: str) -> str:
        pattern = re.compile(rf"(?m)^(\s*{re.escape(key)}\s*=\s*).*$")
        if pattern.search(section_text):
            return pattern.sub(rf"\g<1>{value}", section_text)
        if not section_text.endswith("\n"):
            section_text += "\n"
        return section_text + f"{key} = {value}\n"

    section = replace_or_add(section, "mask", "true")
    section = replace_or_add(section, "mask_port", str(int(mask_port)))
    # Install sets drs=true; do not overwrite on every sync — allow manual edits in config.toml.
    if not re.search(r"(?m)^\s*drs\s*=", section):
        section = replace_or_add(section, "drs", "true")
    dom = str(domain or "").strip()
    if dom:
        section = replace_or_add(section, "tls_domain", f'"{dom}"')
    return text[:start] + section + text[end:]


_AMNEZIA_STACK_CACHE_LOCK = threading.Lock()
_AMNEZIA_STACK_CACHE_MONO = 0.0
_AMNEZIA_STACK_CACHE_VAL = False
_AMNEZIA_STACK_CACHE_TTL = 55.0


def _amnezia_stack_probe_cached(probe_fn) -> bool:
    """TTL cache for Docker-based Amnezia probes (metrics are polled frequently)."""
    global _AMNEZIA_STACK_CACHE_MONO, _AMNEZIA_STACK_CACHE_VAL
    now = time.monotonic()
    with _AMNEZIA_STACK_CACHE_LOCK:
        if now - _AMNEZIA_STACK_CACHE_MONO < _AMNEZIA_STACK_CACHE_TTL:
            return _AMNEZIA_STACK_CACHE_VAL
    v = bool(probe_fn())
    with _AMNEZIA_STACK_CACHE_LOCK:
        _AMNEZIA_STACK_CACHE_MONO = now
        _AMNEZIA_STACK_CACHE_VAL = v
    return v


class WebUIHandler(SimpleHTTPRequestHandler):
    server_version = "AWG-Split-Gate-webui/0.2"

    def __init__(self, *args, directory=None, username="", password="", **kwargs):
        self._username = username
        self._password = password
        self._base_path = kwargs.pop("base_path")
        self._auth_enabled = kwargs.pop("auth_enabled")
        self._realm = kwargs.pop("realm")
        self._secret = kwargs.pop("secret")
        self._sessions = kwargs.pop("sessions")
        self._sessions_lock: threading.Lock = kwargs.pop("sessions_lock")
        self._nonces = kwargs.pop("nonces")
        super().__init__(*args, directory=directory, **kwargs)

    def _persist_sessions(self) -> None:
        if not self._auth_enabled:
            return
        try:
            _save_webui_sessions_to_disk(self._sessions)
        except OSError:
            pass

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
        with self._sessions_lock:
            tok = self._read_cookie("AWGSESS")
            if not tok:
                return None
            s = self._sessions.get(tok)
            if not s:
                return None
            if s["exp"] < time.time():
                self._sessions.pop(tok, None)
                self._persist_sessions()
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
        return {"enabled": True, "egress_tcp_ports": [22], "ingress_tcp_ports": [22, 80, 443, 5000, 5001]}

    def _ntfy_port(self) -> int:
        raw = os.environ.get("AWG_UI_NTFY_PORT", "").strip()
        if not raw:
            env_path = Path(self._webui_cfg_dir()) / "webui.env"
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("AWG_UI_NTFY_PORT="):
                        raw = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
        if raw:
            try:
                n = int(raw)
                if 1 <= n <= 65535:
                    return n
            except ValueError:
                pass
        return 5001

    def _mask_port(self) -> int:
        raw = (os.environ.get("AWG_UI_MASK_PORT") or "").strip()
        if not raw:
            env_path = Path(self._webui_cfg_dir()) / "webui.env"
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
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
        return 5000

    def _reserved_tcp_ports(self) -> list[int]:
        return sorted({80, 443, self._mask_port(), self._ntfy_port()})

    @staticmethod
    def _strip_reserved_ports(ports: list[int], reserved: set[int]) -> list[int]:
        return sorted({p for p in ports if p not in reserved})

    @staticmethod
    def _union_reserved_ports(ports: list[int], reserved: list[int]) -> list[int]:
        return sorted(set(ports) | set(reserved))

    def _firewall_reserved_apply_on(self, cfg: dict) -> str:
        return "ingress" if _iface_split_active(cfg if isinstance(cfg, dict) else {}) else "egress"

    @staticmethod
    def _coerce_firewall_enabled(val) -> bool:
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return bool(val)
        if isinstance(val, str):
            return val.strip().lower() not in ("0", "false", "no", "off", "")
        return True

    def _iface_firewall_for_response(self, cfg: dict) -> dict:
        base = self._default_iface_firewall()
        fw = cfg.get("firewall") if isinstance(cfg.get("firewall"), dict) else {}
        eg = fw.get("egress_tcp_ports")
        ing = fw.get("ingress_tcp_ports")
        out = dict(base)
        if "enabled" in fw:
            out["enabled"] = self._coerce_firewall_enabled(fw.get("enabled"))
        if isinstance(eg, list) and eg and all(isinstance(x, int) and 1 <= x <= 65535 for x in eg):
            out["egress_tcp_ports"] = sorted(set(eg))
        if isinstance(ing, list) and ing and all(isinstance(x, int) and 1 <= x <= 65535 for x in ing):
            out["ingress_tcp_ports"] = sorted(set(ing))
        reserved = self._reserved_tcp_ports()
        reserved_set = set(reserved)
        apply_on = self._firewall_reserved_apply_on(cfg if isinstance(cfg, dict) else {})
        out["reserved_tcp_ports"] = reserved
        out["reserved_apply_on"] = apply_on
        if apply_on == "ingress":
            out["egress_tcp_ports"] = self._strip_reserved_ports(out["egress_tcp_ports"], reserved_set)
            out["ingress_tcp_ports"] = self._strip_reserved_ports(out["ingress_tcp_ports"], reserved_set)
        else:
            combined = sorted(set(out["egress_tcp_ports"]) | set(out["ingress_tcp_ports"]))
            out["egress_tcp_ports"] = self._strip_reserved_ports(combined, reserved_set)
            out["ingress_tcp_ports"] = []
        return out

    def _merge_iface_firewall_save(self, prev: dict, fw_body) -> dict:
        prev_cfg = prev if isinstance(prev, dict) else {}
        cur = self._iface_firewall_for_response(prev_cfg)
        if not isinstance(fw_body, dict):
            return self._store_iface_firewall_effective(prev_cfg, cur)
        eg = self._parse_dns_tcp_ports(fw_body.get("egress_tcp_ports"))
        ing = self._parse_dns_tcp_ports(fw_body.get("ingress_tcp_ports"))
        if eg is not None:
            cur["egress_tcp_ports"] = eg
        if ing is not None:
            cur["ingress_tcp_ports"] = ing
        if "enabled" in fw_body:
            cur["enabled"] = self._coerce_firewall_enabled(fw_body.get("enabled"))
        return self._store_iface_firewall_effective(prev_cfg, cur)

    def _store_iface_firewall_effective(self, iface_cfg: dict, fw: dict) -> dict:
        """Добавляет зарезервированные порты в списки для interfaces.json / UFW."""
        reserved = self._reserved_tcp_ports()
        apply_on = self._firewall_reserved_apply_on(iface_cfg)
        out = {
            "enabled": fw.get("enabled", True),
            "egress_tcp_ports": list(fw.get("egress_tcp_ports") or []),
            "ingress_tcp_ports": list(fw.get("ingress_tcp_ports") or []),
        }
        if apply_on == "ingress":
            out["ingress_tcp_ports"] = self._union_reserved_ports(out["ingress_tcp_ports"], reserved)
        else:
            merged = sorted(set(out["egress_tcp_ports"]) | set(out["ingress_tcp_ports"]))
            out["egress_tcp_ports"] = self._union_reserved_ports(merged, reserved)
            out["ingress_tcp_ports"] = self._strip_reserved_ports(out["ingress_tcp_ports"], set(reserved))
        return out

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

    def _webui_notifications_json(self) -> str:
        return str(Path(self._webui_cfg_dir()) / "notifications.json")

    def _default_notifications_cfg(self) -> dict:
        return {
            "enabled": False,
            "server_url": "",
            "topic": "",
            "publish_token": "",
            "publisher_user": "awg-publisher",
            "alerts": {
                "tunnels": True,
                "list_update_errors": True,
                "service_start_errors": True,
            },
            "notify_state": {
                "tunnel_down_active": False,
                "tunnel_unavailable_notified": {},
                "last_tunnel_failover_ts": 0,
                "last_tunnel_down_ts": 0,
            },
        }

    def _load_notifications_config(self) -> dict:
        raw = _read_text(self._webui_notifications_json(), "")
        base = self._default_notifications_cfg()
        if not raw.strip():
            return base
        try:
            obj = json.loads(raw)
        except Exception:
            return base
        if not isinstance(obj, dict):
            return base
        for key in ("enabled", "server_url", "topic", "publish_token", "publisher_user"):
            if key in obj:
                base[key] = obj[key]
        alerts = obj.get("alerts")
        if isinstance(alerts, dict):
            norm = dict(base["alerts"])
            if "tunnels" in alerts:
                norm["tunnels"] = bool(alerts["tunnels"])
            elif "tunnel_failover" in alerts or "tunnel_down" in alerts:
                norm["tunnels"] = bool(alerts.get("tunnel_failover", True)) or bool(
                    alerts.get("tunnel_down", True)
                )
            for k in ("list_update_errors", "service_start_errors"):
                if k in alerts:
                    norm[k] = bool(alerts[k])
            base["alerts"] = norm
        ns = obj.get("notify_state")
        if isinstance(ns, dict):
            for k in base["notify_state"]:
                if k in ns:
                    base["notify_state"][k] = ns[k]
        if "_publisher_pass" in obj:
            base["_publisher_pass"] = obj["_publisher_pass"]
        return base

    def _store_notifications_config(self, cfg: dict) -> None:
        _mkdir(self._webui_cfg_dir())
        _write_text(self._webui_notifications_json(), json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
        try:
            os.chmod(self._webui_notifications_json(), 0o600)
        except OSError:
            pass

    def _ntfy_public_host(self) -> str:
        domain = _read_webui_env_value("AWG_UI_DOMAIN", "")
        if _webui_tls_self_signed():
            iface = self._load_iface_config()
            if not isinstance(iface, dict):
                iface = {}
            ip = _mtproto_public_ip_from_iface(iface)
            if _ipv4_literal_ok(ip):
                return ip
        return domain

    def _ntfy_public_server_url(self) -> str:
        host = str(self._ntfy_public_host() or "").strip()
        if not host:
            return ""
        return f"https://{host}:{self._ntfy_port()}"

    def _patch_ntfy_server_yml_base_url(self, server_url: str) -> None:
        server_url = str(server_url or "").strip().rstrip("/")
        if not server_url:
            return
        path = Path("/etc/ntfy/server.yml")
        if not path.is_file():
            return
        try:
            text = path.read_text(encoding="utf-8")
            new_text, n = re.subn(
                r'^base-url:\s*".*"$',
                f'base-url: "{server_url}"',
                text,
                count=1,
                flags=re.M,
            )
            if n and new_text != text:
                path.write_text(new_text, encoding="utf-8")
                for unit in ("ntfy.service", "ntfy"):
                    rc, _, _ = _run(["systemctl", "restart", unit], timeout=15.0)
                    if rc == 0:
                        break
        except OSError:
            pass

    def _ensure_ntfy_public_url_synced(self) -> str:
        url = self._ntfy_public_server_url()
        if not url:
            return ""
        cfg = self._load_notifications_config()
        cur = str(cfg.get("server_url") or "").strip().rstrip("/")
        if cur != url:
            cfg["server_url"] = url
            self._store_notifications_config(cfg)
            self._patch_ntfy_server_yml_base_url(url)
        return url

    def _ntfy_subscribe_deeplink(self, server_url: str, topic: str) -> str:
        server_url = str(server_url or "").strip().rstrip("/")
        topic = str(topic or "").strip().strip("/")
        if not server_url or not topic:
            return ""
        try:
            u = urlparse(server_url)
            host = (u.hostname or "").strip()
            if not host:
                return ""
            if u.port:
                host = f"{host}:{u.port}"
            display = quote("AWG Split Gate")
            return f"ntfy://{host}/{topic}?display={display}"
        except Exception:
            return ""

    def _notifications_public_payload(self) -> dict:
        cfg = self._load_notifications_config()
        server_url = self._ensure_ntfy_public_url_synced()
        topic = str(cfg.get("topic") or "").strip().strip("/")
        ntfy_active = self._service_is_active("ntfy.service") or self._service_is_active("ntfy")
        return {
            "enabled": bool(cfg.get("enabled")),
            "server_url": server_url,
            "topic": topic,
            "subscribe_deeplink": self._ntfy_subscribe_deeplink(server_url, topic),
            "has_publish_token": bool(str(cfg.get("publish_token") or "").strip()),
            "ntfy_service_active": ntfy_active,
            "websocket_supported": ntfy_active,
            "alerts": dict(cfg.get("alerts") or {}),
            "notify_state": dict(cfg.get("notify_state") or {}),
        }

    def _notify_script_path(self) -> Path:
        for p in (
            Path("/usr/local/sbin/awg-ntfy-notify.py"),
            Path(__file__).resolve().parent.parent / "lib" / "awg-ntfy-notify.py",
        ):
            if p.is_file():
                return p
        return Path("/usr/local/sbin/awg-ntfy-notify.py")

    def _notify_service_start_error(self, service: str, error: str) -> None:
        script = self._notify_script_path()
        if not script.is_file():
            return
        payload = json.dumps({"service": service, "detail": error}, ensure_ascii=False)
        env = os.environ.copy()
        env["AWG_WEBUI_CFG_DIR"] = self._webui_cfg_dir()
        try:
            subprocess.run(
                [sys.executable, str(script), "event", "--kind", "service_start_error", "--json", payload],
                env=env,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except Exception:
            pass

    def _run_notify_test(self) -> tuple[bool, str]:
        script = self._notify_script_path()
        if not script.is_file():
            return False, "awg-ntfy-notify.py not installed"
        cfg = self._load_notifications_config()
        if not cfg.get("enabled"):
            return False, "Уведомления отключены"
        env = os.environ.copy()
        env["AWG_WEBUI_CFG_DIR"] = self._webui_cfg_dir()
        try:
            proc = subprocess.run(
                [sys.executable, str(script), "test"],
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except Exception as ex:
            return False, str(ex)
        if proc.returncode == 0:
            return True, ""
        msg = (proc.stderr or proc.stdout or "send failed").strip()
        return False, msg

    def _op_notifications_save(self, body: dict) -> dict:
        cur = self._load_notifications_config()
        if "enabled" in body:
            cur["enabled"] = bool(body.get("enabled"))
        alerts_in = body.get("alerts")
        if isinstance(alerts_in, dict):
            cur["alerts"] = {
                "tunnels": bool(alerts_in.get("tunnels", True)),
                "list_update_errors": bool(alerts_in.get("list_update_errors", True)),
                "service_start_errors": bool(alerts_in.get("service_start_errors", True)),
            }
        self._store_notifications_config(cur)
        return {"ok": True, "config": self._notifications_public_payload()}

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
        if not shutil.which("docker"):
            return False
        rc, out, _ = _run(["docker", "inspect", "-f", "{{.State.Running}}", n], timeout=6.0)
        return rc == 0 and (out or "").strip().lower() == "true"

    def _docker_daemon_ok(self) -> bool:
        if not shutil.which("docker"):
            return False
        rc, _, _ = _run(["docker", "info"], timeout=5.0)
        return rc == 0

    def _compute_amnezia_vpn_stack_present(self) -> bool:
        """Docker daemon up and host shows a typical Amnezia VPN Docker setup."""
        if not shutil.which("docker"):
            return False
        if not self._docker_daemon_ok():
            return False

        # Bridge can be amn0, amn1, ... depending on host/container lifecycle.
        try:
            for p in Path("/sys/class/net").glob("amn*"):
                if not p.name.startswith("amn"):
                    continue
                tail = p.name[3:]
                if tail and not tail.isdigit():
                    continue
                if (p / "bridge").is_dir():
                    return True
        except OSError:
            pass

        # Required container name rule: amnezia-awg[digits]
        rc, out, _ = _run(["docker", "ps", "--format", "{{.Names}}"], timeout=8.0)
        if rc != 0:
            return False
        for ln in (out or "").splitlines():
            name = ln.strip().lower()
            if not name:
                continue
            if re.fullmatch(r"amnezia-awg\d*", name):
                return True
        return False

    def _amnezia_vpn_stack_present(self) -> bool:
        return _amnezia_stack_probe_cached(self._compute_amnezia_vpn_stack_present)

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
        payload = self._dns_config_payload()
        return self._send_json(200, payload)

    def _dns_config_payload(self) -> dict:
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
        return {
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
        }

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
            msg = (err or out or "awg-uplink-dns-refresh.service failed").strip()
            self._notify_service_start_error("awg-uplink-dns-refresh.service", msg)
            raise RuntimeError(msg)
        self._restart_awg_uplink_firewall()
        _run(["systemctl", "enable", "awg-uplink-dns-transport-lock.service"], timeout=3.0)
        _run(["systemctl", "restart", "awg-uplink-dns-transport-lock.service"], timeout=45.0)
        _run(["systemctl", "enable", "awg-uplink-amnezia-dns-watch.service"], timeout=3.0)
        _run(["systemctl", "restart", "awg-uplink-amnezia-dns-watch.service"], timeout=20.0)
        _run(
            ["python3", "/usr/local/sbin/awg-uplink-amnezia-dns-watch.py", "--once"],
            timeout=45.0,
        )
        return self._dns_config_payload()

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

    def _tunnels_json_path(self) -> str:
        return str(Path(self._webui_cfg_dir()) / "tunnels.json")

    def _tunnel_manage_script(self) -> str:
        return "/usr/local/sbin/awg-uplink-tunnel-manage.py"

    def _migrate_tunnels_config(self, cfg: dict, *, initial: bool = False) -> tuple[dict, bool]:
        """Дополнить tunnels.json после апгрейда (--update-files-only не создавал файл)."""
        changed = bool(initial)
        defaults = self._default_tunnels_config()
        if initial:
            for tid in ("tunnel1", "tunnel2"):
                ifname = self._tunnel_ifname_from_cfg(cfg, tid)
                conf_paths = (
                    Path(f"/etc/amnezia/amneziawg/{ifname}.conf"),
                    Path(f"/etc/wireguard/{ifname}.conf"),
                )
                has_conf = any(p.exists() for p in conf_paths)
                if has_conf and not cfg.get(tid, {}).get("enabled"):
                    cfg.setdefault(tid, {})["enabled"] = True
                    changed = True
            if Path("/etc/amnezia/amneziawg/awg-uplink.conf").exists() and str(cfg.get("active") or "") not in (
                "tunnel1",
                "tunnel2",
            ):
                cfg["active"] = "tunnel1"
                changed = True
        h = cfg.setdefault("health", {})
        dh = defaults.get("health") if isinstance(defaults.get("health"), dict) else {}
        if not h.get("targets"):
            h["targets"] = list(dh.get("targets") or ["1.1.1.1", "8.8.8.8"])
            changed = True
        for key in ("interval_sec", "fail_count", "recover_count", "ping_timeout_sec"):
            if key not in h or h.get(key) in (None, "", 0):
                if key in dh:
                    h[key] = dh[key]
                    changed = True
        if not isinstance(cfg.get("health_state"), dict):
            cfg["health_state"] = defaults.get("health_state", {})
            changed = True
        return self._normalize_tunnels_config(cfg), changed

    def _tunnel_ifname_from_cfg(self, cfg: dict, tid: str) -> str:
        t = cfg.get(tid) if isinstance(cfg.get(tid), dict) else {}
        return str(t.get("ifname") or ("awg-uplink" if tid == "tunnel1" else "awg-uplink-2")).strip()

    def _load_tunnels_config(self) -> dict:
        path = Path(self._tunnels_json_path())
        initial = not path.exists() or not _read_text(str(path), "").strip()
        if initial:
            cfg = self._default_tunnels_config()
            cfg, changed = self._migrate_tunnels_config(cfg, initial=True)
            if changed:
                self._store_tunnels_config(cfg)
            return cfg
        raw = _read_text(str(path), "")
        try:
            obj = json.loads(raw)
            cfg = self._normalize_tunnels_config(obj if isinstance(obj, dict) else {})
        except Exception:
            cfg = self._default_tunnels_config()
        cfg, changed = self._migrate_tunnels_config(cfg, initial=False)
        if changed:
            self._store_tunnels_config(cfg)
        return cfg

    def _default_tunnels_config(self) -> dict:
        return {
            "tunnel1": {
                "id": "tunnel1",
                "ifname": "awg-uplink",
                "label": "Туннель 1",
                "enabled": True,
            },
            "tunnel2": {
                "id": "tunnel2",
                "ifname": "awg-uplink-2",
                "label": "Туннель 2",
                "enabled": False,
            },
            "active": "tunnel1",
            "health": {
                "targets": ["1.1.1.1", "8.8.8.8"],
                "interval_sec": 30,
                "fail_count": 3,
                "recover_count": 2,
                "ping_timeout_sec": 3,
            },
            "health_state": {
                "tunnel1": {"fail_streak": 0, "ok_streak": 0, "last_ping_ok": None, "last_check_at": None},
                "tunnel2": {"fail_streak": 0, "ok_streak": 0, "last_ping_ok": None, "last_check_at": None},
            },
        }

    def _normalize_tunnels_config(self, raw: dict) -> dict:
        base = self._default_tunnels_config()
        for tid in ("tunnel1", "tunnel2"):
            t = raw.get(tid) if isinstance(raw.get(tid), dict) else {}
            base[tid].update(
                {
                    "id": tid,
                    "ifname": str(t.get("ifname") or base[tid]["ifname"]).strip() or base[tid]["ifname"],
                    "label": str(t.get("label") or base[tid]["label"]).strip() or base[tid]["label"],
                    "enabled": bool(t.get("enabled", base[tid]["enabled"])),
                }
            )
        act = str(raw.get("active", "tunnel1") or "tunnel1").strip()
        if act not in ("tunnel1", "tunnel2"):
            act = "tunnel1"
        base["active"] = act
        h = raw.get("health") if isinstance(raw.get("health"), dict) else {}
        bh = base["health"]
        targets = h.get("targets")
        if isinstance(targets, list):
            parsed = [str(x).strip() for x in targets if str(x).strip()]
            if parsed:
                bh["targets"] = parsed
        elif isinstance(targets, str):
            parsed = [x.strip() for x in re.split(r"[\s,;]+", targets) if x.strip()]
            if parsed:
                bh["targets"] = parsed
        for key in ("interval_sec", "fail_count", "recover_count", "ping_timeout_sec"):
            if key in h:
                try:
                    bh[key] = max(1, int(h[key]))
                except (TypeError, ValueError):
                    pass
        hs = raw.get("health_state") if isinstance(raw.get("health_state"), dict) else {}
        for tid in ("tunnel1", "tunnel2"):
            st = hs.get(tid) if isinstance(hs.get(tid), dict) else {}
            base["health_state"][tid] = {
                "fail_streak": int(st.get("fail_streak", 0) or 0),
                "ok_streak": int(st.get("ok_streak", 0) or 0),
                "last_ping_ok": st.get("last_ping_ok"),
                "last_check_at": st.get("last_check_at"),
            }
        return base

    def _store_tunnels_config(self, cfg: dict) -> None:
        _mkdir(self._webui_cfg_dir())
        _write_text(self._tunnels_json_path(), json.dumps(self._normalize_tunnels_config(cfg), ensure_ascii=False, indent=2) + "\n")
        os.chmod(self._tunnels_json_path(), 0o600)

    def _tunnel_ifname(self, tunnel_id: str) -> str:
        cfg = self._load_tunnels_config()
        t = cfg.get(tunnel_id, {}) if isinstance(cfg.get(tunnel_id), dict) else {}
        defaults = {"tunnel1": "awg-uplink", "tunnel2": "awg-uplink-2"}
        return str(t.get("ifname") or defaults.get(tunnel_id, "awg-uplink")).strip()

    def _tunnel_conf_paths(self, ifname: str) -> list[Path]:
        return [
            Path(f"/etc/amnezia/amneziawg/{ifname}.conf"),
            Path(f"/etc/wireguard/{ifname}.conf"),
        ]

    def _tunnel_conf_exists(self, ifname: str) -> bool:
        return any(p.exists() for p in self._tunnel_conf_paths(ifname))

    def _active_tunnel_id(self) -> str:
        env = self._load_iface_env_values()
        act = str(env.get("TUNNEL_ACTIVE") or "").strip()
        if act in ("tunnel1", "tunnel2"):
            return act
        cfg = self._load_tunnels_config()
        return str(cfg.get("active") or "tunnel1")

    def _active_tunnel_ifname(self) -> str:
        env = self._load_iface_env_values()
        iface = str(env.get("TUNNEL_IFACE") or "").strip()
        if iface:
            return iface
        return self._tunnel_ifname(self._active_tunnel_id())

    def _tunnel_link_up(self, ifname: str) -> bool:
        rc, out, _ = _run(["ip", "-j", "link", "show", "dev", ifname], timeout=2.0)
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

    def _tunnel_iface_up(self) -> bool:
        """True if active tunnel device exists and is UP."""
        return self._tunnel_link_up(self._active_tunnel_ifname())

    def _apply_tunnels_runtime(self, *, restart_routing: bool = False) -> None:
        script = self._tunnel_manage_script()
        if not Path(script).is_file():
            return
        env = os.environ.copy()
        env["AWG_WEBUI_CFG_DIR"] = self._webui_cfg_dir()
        env["AWG_TUNNEL_RESTART_ROUTING"] = "1" if restart_routing else "0"
        proc = subprocess.run(
            ["python3", script, "apply"],
            capture_output=True,
            text=True,
            timeout=90.0,
            env=env,
            check=False,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "tunnel apply failed").strip()
            raise RuntimeError(err)
        cfg = self._load_tunnels_config()
        en = [tid for tid in ("tunnel1", "tunnel2") if cfg.get(tid, {}).get("enabled")]
        unit = "awg-uplink-tunnel-failover.service"
        if len(en) >= 1:
            _run(["systemctl", "enable", unit], timeout=5.0)
            _run(["systemctl", "restart", unit], timeout=15.0)
        else:
            _run(["systemctl", "stop", unit], timeout=15.0)
            _run(["systemctl", "disable", unit], timeout=5.0)

    def _tunnel_ping_meta(self, cfg: dict, tid: str) -> dict:
        if not cfg.get(tid, {}).get("enabled"):
            return {"ping_ok": None, "ping_checked": False, "ping_status": "выключен"}
        hs = cfg.get("health_state", {}).get(tid, {})
        if not isinstance(hs, dict):
            hs = {}
        last_at = hs.get("last_check_at")
        if last_at is None:
            return {"ping_ok": None, "ping_checked": False, "ping_status": "ожидает проверки"}
        ok = bool(hs.get("last_ping_ok"))
        if ok:
            return {"ping_ok": True, "ping_checked": True, "ping_status": "связь OK (ping)"}
        return {"ping_ok": False, "ping_checked": True, "ping_status": "нет связи (ping)"}

    def _tunnel_traffic_required(self) -> tuple[bool, str]:
        """Нужен ли хотя бы один включённый туннель для текущей маршрутизации/MTProto."""
        reasons: list[str] = []
        iface = self._load_iface_config()
        route_mode = str(iface.get("route_mode", "egress") or "egress").strip().lower()
        if route_mode == "tunnel":
            reasons.append("маршрут в туннель")
        elif route_mode == "georouting":
            geo = iface.get("geo") if isinstance(iface.get("geo"), dict) else self._load_geo_config()
            target = str(geo.get("target", "tunnel") or "tunnel").strip().lower()
            if target == "tunnel":
                reasons.append("georouting → туннель")
        prefs = self._load_mtproto_prefs()
        cfg_text = _read_text(self._mtproto_config_path(), "")
        mtp = _effective_mtproto_outbound_mode(prefs, cfg_text, iface)
        if mtp == "tunnel":
            reasons.append("MTProto → туннель")
        return bool(reasons), "; ".join(reasons)

    def _tunnel_is_viable_for_traffic(self, tcfg: dict, tid: str) -> bool:
        """Включён, есть конфиг, link UP, ping не подтверждён как провал."""
        ifname = self._tunnel_ifname(tid)
        if not self._tunnel_conf_exists(ifname):
            return False
        if not bool(tcfg.get(tid, {}).get("enabled")):
            return False
        if not self._tunnel_link_up(ifname):
            return False
        ping = self._tunnel_ping_meta(tcfg, tid)
        if ping.get("ping_checked") and ping.get("ping_ok") is False:
            return False
        return True

    def _tunnel_ui_policy(self, tcfg: dict) -> dict[str, dict]:
        """enabled/toggle_locked/delete_locked для UI и сохранения."""
        traffic_req, traffic_reason = self._tunnel_traffic_required()
        staged: dict[str, dict] = {}
        for tid in ("tunnel1", "tunnel2"):
            ifname = self._tunnel_ifname(tid)
            configured = self._tunnel_conf_exists(ifname)
            enabled = bool(tcfg.get(tid, {}).get("enabled"))
            if not configured:
                enabled = False
            staged[tid] = {"configured": configured, "enabled": enabled}
        enabled_ids = [tid for tid in ("tunnel1", "tunnel2") if staged[tid]["enabled"]]
        viable_ids = [tid for tid in enabled_ids if self._tunnel_is_viable_for_traffic(tcfg, tid)]
        lock_msg = f"Туннель используется ({traffic_reason}) — отключить нельзя"
        delete_msg = f"Туннель используется ({traffic_reason}) — удалить нельзя"
        out: dict[str, dict] = {}
        for tid in ("tunnel1", "tunnel2"):
            configured = staged[tid]["configured"]
            enabled = staged[tid]["enabled"]
            toggle_locked = False
            toggle_lock_reason = ""
            delete_locked = False
            delete_lock_reason = ""
            if not configured:
                toggle_locked = True
                enabled = False
                toggle_lock_reason = "Сначала импортируйте конфиг (.conf)"
                delete_locked = True
                delete_lock_reason = "Конфиг не задан"
            elif traffic_req and tid in enabled_ids:
                only_enabled_in_cfg = len(enabled_ids) == 1
                only_viable = tid in viable_ids and len(viable_ids) == 1
                if only_enabled_in_cfg or only_viable:
                    toggle_locked = True
                    enabled = True
                    toggle_lock_reason = lock_msg
                    delete_locked = True
                    delete_lock_reason = delete_msg
            out[tid] = {
                "enabled": enabled,
                "configured": configured,
                "toggle_locked": toggle_locked,
                "toggle_lock_reason": toggle_lock_reason,
                "delete_locked": delete_locked,
                "delete_lock_reason": delete_lock_reason,
            }
        return out

    def _tunnel_status_payload(self, tunnel_id: str | None = None) -> dict:
        cfg = self._load_tunnels_config()
        policy = self._tunnel_ui_policy(cfg)
        traffic_req, traffic_reason = self._tunnel_traffic_required()
        active = self._active_tunnel_id()
        out = {
            "active": active,
            "failover_enabled": False,
            "health_watch_enabled": False,
            "tunnel_traffic_required": traffic_req,
            "tunnel_traffic_reason": traffic_reason,
            "tunnels": {},
        }
        ids = [tunnel_id] if tunnel_id in ("tunnel1", "tunnel2") else ("tunnel1", "tunnel2")
        enabled_n = 0
        for tid in ids:
            ifname = self._tunnel_ifname(tid)
            conf_ok = self._tunnel_conf_exists(ifname)
            pol = policy.get(tid, {})
            en = bool(pol.get("enabled"))
            if en:
                enabled_n += 1
            ping_cfg = dict(cfg)
            ping_cfg[tid] = dict(cfg.get(tid, {}))
            ping_cfg[tid]["enabled"] = en
            out["tunnels"][tid] = {
                "id": tid,
                "ifname": ifname,
                "label": cfg.get(tid, {}).get("label") or tid,
                "enabled": en,
                "configured": conf_ok,
                "link_up": self._tunnel_link_up(ifname),
                "is_active": tid == active,
                "toggle_locked": bool(pol.get("toggle_locked")),
                "toggle_lock_reason": str(pol.get("toggle_lock_reason") or ""),
                "delete_locked": bool(pol.get("delete_locked")),
                "delete_lock_reason": str(pol.get("delete_lock_reason") or ""),
                **self._tunnel_ping_meta(ping_cfg, tid),
            }
        out["failover_enabled"] = enabled_n >= 2
        out["health_watch_enabled"] = enabled_n >= 1
        h = cfg.get("health") if isinstance(cfg.get("health"), dict) else {}
        dh = self._default_tunnels_config().get("health", {})
        if not h.get("targets"):
            h = dict(dh)
            h["targets"] = list(dh.get("targets") or ["1.1.1.1", "8.8.8.8"])
        out["health"] = h
        out["health_state"] = cfg.get("health_state")
        return out

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

    _PRESERVE_IFACE_ENV_KEYS = frozenset(
        {
            "TUNNEL_IFACE",
            "TUNNEL_ACTIVE",
            "TUNNEL1_IFACE",
            "TUNNEL2_IFACE",
            "TUNNEL_FAILOVER_ENABLED",
            "AWG_GEO_IP_AWG_IFACE",
            "AWG_GEO_DOMAIN_AWG_IFACE",
            "AWG_FW_AWG_IFACE",
        }
    )

    def _read_preserved_iface_env(self) -> dict[str, str]:
        path = Path(self._webui_iface_env())
        if not path.exists():
            return {}
        out: dict[str, str] = {}
        for line in _read_text(str(path), "").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if key in self._PRESERVE_IFACE_ENV_KEYS:
                out[key] = val.strip().strip("'\"")
        return out

    def _write_iface_env(self, cfg: dict, mtproto_outbound_mode: str | None = None):
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
        mtp_mode = str(mtproto_outbound_mode or "").strip().lower()
        if mtp_mode not in ("direct", "egress", "tunnel"):
            mtp_mode = ""

        ingress_enabled = bool(
            ingress_ip and ingress_dev and (ingress_ip != egress_ip or ingress_dev != egress_dev)
        )
        fw_en = True
        fw = cfg.get("firewall") if isinstance(cfg.get("firewall"), dict) else {}
        if isinstance(fw, dict) and "enabled" in fw:
            fw_en = self._coerce_firewall_enabled(fw.get("enabled"))
        env = [
            "ENABLE=1",
            f"AWG_FW_ENABLED={'1' if fw_en else '0'}",
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
            f"MTPROTO_OUTBOUND_MODE={shlex.quote(mtp_mode)}",
            "# Tunnel + Docker-VPN: optional knobs for awg-webui-iface-routing-apply.sh",
            "# DOCKER_FORCE_PORT=39983",
            "# DOCKER_MARK_IN=amn0",
        ]
        preserved = self._read_preserved_iface_env()
        tunnel_if = str(preserved.get("TUNNEL_IFACE", "") or "").strip()
        written = {line.split("=", 1)[0] for line in env if "=" in line and not line.startswith("#")}
        for key, val in preserved.items():
            if key in ("AWG_GEO_IP_AWG_IFACE", "AWG_GEO_DOMAIN_AWG_IFACE", "AWG_FW_AWG_IFACE") and tunnel_if:
                val = tunnel_if
            if key not in written and val:
                env.append(f"{key}={shlex.quote(val)}")
        env.append("")
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
        tun_py = str(root / "lib" / "awg-uplink-tunnel-manage.py")
        tun_svc = str(root / "systemd" / "awg-uplink-tunnel-failover.service")
        if Path(tun_py).exists():
            shutil.copyfile(tun_py, "/usr/local/sbin/awg-uplink-tunnel-manage.py")
            os.chmod("/usr/local/sbin/awg-uplink-tunnel-manage.py", 0o755)
        if Path(tun_svc).exists():
            shutil.copyfile(tun_svc, "/etc/systemd/system/awg-uplink-tunnel-failover.service")
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

    def _restart_awg_uplink_firewall(self) -> None:
        """Одноразовый unit с RemainAfterExit=yes: повторный `start` не запускает apply — нужен `restart`."""
        _run(["systemctl", "enable", "awg-uplink-firewall.service"], timeout=3.0)
        _run(["systemctl", "restart", "awg-uplink-firewall.service"], timeout=30.0)

    def _apply_iface_routing(self, cfg: dict | None = None):
        """Apply interface routing; optional cfg to refresh geo policy tables after restart."""
        if cfg is None:
            cfg = self._load_iface_config()
        self._install_iface_runtime()
        self._apply_tunnels_runtime()
        _run(["systemctl", "daemon-reload"], timeout=3.0)
        _run(["systemctl", "enable", "awg-webui-ifaces.service"], timeout=3.0)
        rc, out, err = _run(["systemctl", "restart", "awg-webui-ifaces.service"], timeout=5.0)
        if rc != 0:
            msg = (err or out or "failed to restart awg-webui-ifaces.service").strip()
            self._notify_service_start_error("awg-webui-ifaces.service", msg)
            raise RuntimeError(msg)
        self._restart_awg_uplink_firewall()
        _run(["systemctl", "enable", "awg-uplink-dns-transport-lock.service"], timeout=3.0)
        _run(["systemctl", "restart", "awg-uplink-dns-transport-lock.service"], timeout=45.0)
        if str(cfg.get("route_mode", "")).strip().lower() == "georouting":
            self._apply_geo_ip_runtime(cfg, run_refresh_now=True)
            self._apply_geo_domain_runtime(cfg, run_refresh_now=True)

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
            tun_dev = self._active_tunnel_ifname()
            egress_ok = any(f"dev {tun_dev}" in ln for ln in default_lines)
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
                or name in (self._tunnel_ifname("tunnel1"), self._tunnel_ifname("tunnel2"))
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

    def _api_status_awg(self, tunnel_id: str = "tunnel1"):
        if tunnel_id not in ("tunnel1", "tunnel2"):
            tunnel_id = "tunnel1"
        ifname = self._tunnel_ifname(tunnel_id)
        conf_path = Path(f"/etc/amnezia/amneziawg/{ifname}.conf")
        rc, out, _ = _run(["ip", "-j", "link", "show", "dev", ifname], timeout=2.0)
        cfg = self._load_tunnels_config()
        active = self._active_tunnel_id()
        base = {
            "tunnel_id": tunnel_id,
            "ifname": ifname,
            "active": active,
            "is_active": tunnel_id == active,
            "enabled": bool(cfg.get(tunnel_id, {}).get("enabled")),
        }
        if rc != 0:
            return self._send_json(200, {**base, "exists": False, "configured": conf_path.exists()})
        try:
            items = json.loads(out)
        except Exception:
            items = []
        if not items:
            return self._send_json(200, {**base, "exists": False, "configured": conf_path.exists()})
        it = items[0]
        flags = it.get("flags", []) or []
        state = "UP" if "UP" in flags else "DOWN"
        return self._send_json(
            200,
            {
                **base,
                "exists": True,
                "configured": conf_path.exists(),
                "state": state,
                "operstate": it.get("operstate"),
                "flags": flags,
            },
        )

    def _api_tunnels_config(self):
        return self._send_json(200, self._tunnel_status_payload())

    def _op_tunnels_save(self, body: dict) -> dict:
        cfg = self._load_tunnels_config()
        policy_before = self._tunnel_ui_policy(cfg)
        enabled_before = {tid: bool(cfg.get(tid, {}).get("enabled")) for tid in ("tunnel1", "tunnel2")}
        for tid in ("tunnel1", "tunnel2"):
            b = body.get(tid) if isinstance(body.get(tid), dict) else {}
            pol = policy_before.get(tid, {})
            if pol.get("toggle_locked"):
                cfg[tid]["enabled"] = bool(pol.get("enabled"))
            elif "enabled" in b:
                cfg[tid]["enabled"] = bool(b.get("enabled"))
            if "label" in b:
                cfg[tid]["label"] = str(b.get("label") or cfg[tid]["label"]).strip()
        h = body.get("health") if isinstance(body.get("health"), dict) else {}
        if h:
            ch = cfg.setdefault("health", {})
            targets = h.get("targets")
            if targets is not None:
                if isinstance(targets, list):
                    ch["targets"] = [str(x).strip() for x in targets if str(x).strip()]
                else:
                    ch["targets"] = [x.strip() for x in re.split(r"[\s,;]+", str(targets)) if x.strip()]
            for key in ("interval_sec", "fail_count", "recover_count", "ping_timeout_sec"):
                if key not in h:
                    continue
                try:
                    if key == "interval_sec":
                        ch[key] = max(5, int(h[key]))
                    else:
                        ch[key] = max(1, int(h[key]))
                except (TypeError, ValueError):
                    pass
        enabled_after = {tid: bool(cfg.get(tid, {}).get("enabled")) for tid in ("tunnel1", "tunnel2")}
        enabled_changed = enabled_before != enabled_after
        self._store_tunnels_config(cfg)
        iface = self._load_iface_config()
        route_mode = str(iface.get("route_mode", "")).strip().lower()
        need_iface_restart = False
        if enabled_changed:
            if route_mode == "tunnel":
                need_iface_restart = True
            elif route_mode == "georouting":
                geo = iface.get("geo") if isinstance(iface.get("geo"), dict) else self._load_geo_config()
                # target=egress: базовый default в туннель — нужен apply ifaces
                need_iface_restart = str(geo.get("target", "tunnel") or "tunnel").strip().lower() == "egress"
            else:
                need_iface_restart = True
        self._apply_tunnels_runtime(restart_routing=need_iface_restart)
        if route_mode == "georouting" and (enabled_changed or h):
            try:
                self._apply_geo_ip_runtime(iface, run_refresh_now=True)
                self._apply_geo_domain_runtime(iface, run_refresh_now=True)
            except Exception:
                pass
        return {"ok": True, "config": self._tunnel_status_payload()}

    def _op_tunnel_delete(self, body: dict) -> dict:
        tunnel_id = self._tunnel_id_from_body(body)
        cfg = self._load_tunnels_config()
        policy = self._tunnel_ui_policy(cfg)
        pol = policy.get(tunnel_id, {})
        if pol.get("delete_locked"):
            raise RuntimeError(pol.get("delete_lock_reason") or "cannot delete tunnel config")

        ifname = self._tunnel_ifname(tunnel_id)
        conf_path = Path(f"/etc/amnezia/amneziawg/{ifname}.conf")
        was_enabled = bool(cfg.get(tunnel_id, {}).get("enabled"))

        unit = f"awg-quick@{ifname}.service"
        _run(["systemctl", "stop", unit], timeout=12.0)
        _run(["systemctl", "disable", unit], timeout=5.0)
        if conf_path.exists():
            conf_path.unlink()

        cfg[tunnel_id]["enabled"] = False
        if str(cfg.get("active") or "tunnel1") == tunnel_id:
            other = "tunnel2" if tunnel_id == "tunnel1" else "tunnel1"
            if cfg.get(other, {}).get("enabled"):
                cfg["active"] = other
        self._store_tunnels_config(cfg)

        iface = self._load_iface_config()
        route_mode = str(iface.get("route_mode", "")).strip().lower()
        need_iface_restart = False
        if was_enabled:
            if route_mode == "tunnel":
                need_iface_restart = True
            elif route_mode == "georouting":
                geo = iface.get("geo") if isinstance(iface.get("geo"), dict) else self._load_geo_config()
                need_iface_restart = str(geo.get("target", "tunnel") or "tunnel").strip().lower() == "egress"
            else:
                need_iface_restart = True
        self._apply_tunnels_runtime(restart_routing=need_iface_restart)
        if route_mode == "georouting":
            try:
                self._apply_geo_ip_runtime(iface, run_refresh_now=True)
                self._apply_geo_domain_runtime(iface, run_refresh_now=True)
            except Exception:
                pass
        return {"ok": True, "tunnel_id": tunnel_id, "config": self._tunnel_status_payload()}

    def _tunnel_id_from_body(self, body: dict) -> str:
        tid = str(body.get("tunnel_id", "tunnel1") or "tunnel1").strip()
        return tid if tid in ("tunnel1", "tunnel2") else "tunnel1"

    def _app_root_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent

    def _update_repo_and_branch(self) -> tuple[str, str]:
        repo = (os.environ.get("AWG_UI_UPDATE_REPO") or "antspopov/awg-uplink").strip()
        if "/" not in repo:
            repo = "antspopov/awg-uplink"
        br = (os.environ.get("AWG_UI_UPDATE_BRANCH") or "main").strip() or "main"
        return repo, br

    def _update_checks_enabled(self) -> bool:
        return _env_bool("AWG_UI_UPDATE_CHECK", True)

    def _read_local_version(self) -> str:
        return _read_installed_app_version()

    def _fetch_update_release_notes(self, repo: str, branch: str, current: str, latest: str) -> dict:
        """CHANGELOG.md + коммиты GitHub (compare по тегу или последние на ветке)."""
        out: dict = {"update_changelog": "", "update_commits": []}
        if not latest:
            return out
        cl_url = f"https://raw.githubusercontent.com/{repo}/{branch}/CHANGELOG.md"
        try:
            cl_text = _http_get_text(cl_url, timeout=12.0)
            out["update_changelog"] = _parse_changelog_range(cl_text, current, latest)
        except Exception:
            pass
        commits: list[dict] = []
        br_q = urllib.parse.quote(branch, safe="")
        for tag_from in (f"v{current}", current):
            if not tag_from or not current:
                break
            cmp_url = f"https://api.github.com/repos/{repo}/compare/{urllib.parse.quote(tag_from, safe='')}...{br_q}"
            try:
                data = _http_get_json(cmp_url, timeout=15.0)
                if isinstance(data, dict) and data.get("status") not in ("diverged", "identical"):
                    for item in (data.get("commits") or [])[:80]:
                        if not isinstance(item, dict):
                            continue
                        c = item.get("commit") if isinstance(item.get("commit"), dict) else {}
                        msg = str(c.get("message", "") or "").strip()
                        sha = str(item.get("sha", "") or "")[:7]
                        if msg and sha:
                            commits.append({"sha": sha, "message": msg.split("\n", 1)[0].strip()})
                    if commits:
                        break
            except Exception:
                continue
        if not commits:
            list_url = f"https://api.github.com/repos/{repo}/commits?sha={br_q}&per_page=20"
            try:
                data = _http_get_json(list_url, timeout=15.0)
                if isinstance(data, list):
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        c = item.get("commit") if isinstance(item.get("commit"), dict) else {}
                        msg = str(c.get("message", "") or "").strip()
                        sha = str(item.get("sha", "") or "")[:7]
                        if msg and sha:
                            commits.append({"sha": sha, "message": msg.split("\n", 1)[0].strip()})
            except Exception:
                pass
        out["update_commits"] = commits
        return out

    def _compute_update_info_uncached(self) -> dict:
        repo, branch = self._update_repo_and_branch()
        out: dict = {
            "update_check_enabled": self._update_checks_enabled(),
            "update_repo": repo,
            "update_branch": branch,
            "update_current_version": self._read_local_version(),
            "update_latest_version": "",
            "update_available": False,
            "update_check_error": "",
            "update_can_apply": os.geteuid() == 0 and Path("/usr/local/sbin/awg-webui-self-update.sh").is_file(),
            "update_apply_blocked_reason": "",
        }
        if not out["update_check_enabled"]:
            out["update_apply_blocked_reason"] = "Проверка обновлений отключена (AWG_UI_UPDATE_CHECK)."
            return out
        if os.geteuid() != 0:
            out["update_apply_blocked_reason"] = "Сервис не запущен от root — обновление из панели недоступно."
        elif not Path("/usr/local/sbin/awg-webui-self-update.sh").is_file():
            out["update_apply_blocked_reason"] = "Не установлен awg-webui-self-update.sh (нужен bootstrap)."
        try:
            remote = _fetch_remote_version(repo, branch)
            out["update_latest_version"] = remote
            cur = out["update_current_version"]
            if remote and _semver_gt(remote, cur):
                out["update_available"] = True
                try:
                    notes = self._fetch_update_release_notes(repo, branch, cur, remote)
                    out.update(notes)
                except Exception as ex:
                    out["update_notes_error"] = str(ex)[:300]
        except Exception as ex:
            out["update_check_error"] = str(ex)[:500]
        return out

    def _compute_update_info(self, use_cache: bool = True) -> dict:
        repo, branch = self._update_repo_and_branch()
        key = f"{repo.strip().lower()}:{branch.strip().lower()}"
        now = time.monotonic()
        with _UPDATE_CHECK_LOCK:
            if use_cache:
                ent = _UPDATE_CHECK_CACHE.get(key)
                if isinstance(ent, tuple) and len(ent) == 2:
                    ts, data = ent
                    if now - ts < _UPDATE_CHECK_TTL_SEC and isinstance(data, dict):
                        return dict(data)
        data = self._compute_update_info_uncached()
        with _UPDATE_CHECK_LOCK:
            _UPDATE_CHECK_CACHE[key] = (now, dict(data))
        return data

    def _async_op_name_running(self, name: str) -> bool:
        with _ASYNC_OPS_LOCK:
            for st in _ASYNC_OPS.values():
                if st.get("name") == name and st.get("running") is True:
                    return True
        return False

    def _op_webui_self_update(self, body: dict) -> dict:
        if os.geteuid() != 0:
            raise RuntimeError("Требуется запуск webui от root.")
        script = "/usr/local/sbin/awg-webui-self-update.sh"
        if not Path(script).is_file():
            raise RuntimeError("Отсутствует /usr/local/sbin/awg-webui-self-update.sh")
        info = self._compute_update_info(use_cache=False)
        if not info.get("update_check_enabled", True):
            raise RuntimeError("Проверка обновлений отключена.")
        if not info.get("update_available"):
            raise RuntimeError("Нет доступной новой версии.")
        repo = str(info.get("update_repo") or "antspopov/awg-uplink")
        branch = str(info.get("update_branch") or "main")
        env = os.environ.copy()
        env.setdefault("DEBIAN_FRONTEND", "noninteractive")
        p = subprocess.run(
            ["/bin/bash", script, repo, branch],
            capture_output=True,
            text=True,
            timeout=3600,
            env=env,
        )
        if p.returncode != 0:
            tail = ((p.stderr or "") + "\n" + (p.stdout or "")).strip()
            tail = tail[-8000:]
            raise RuntimeError(tail or f"self-update exit {p.returncode}")
        with _UPDATE_CHECK_LOCK:
            _UPDATE_CHECK_CACHE.clear()
        nv = self._read_local_version()
        return {"ok": True, "repo": repo, "branch": branch, "installed_version": nv}

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

        stack = self._amnezia_vpn_stack_present()
        upd = self._compute_update_info()
        payload = {
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
            # Web UI: баннер установки Amnezia, если нет Docker/демона или нет типичного стека контейнеров Amnezia
            "amnezia_setup_banner": not stack,
            # Синхронизация тоггла файрвола между вкладками / устройствами (poll /api/metrics/system).
            "iface_firewall_enabled": self._runtime_iface_firewall_enabled(),
        }
        for k, v in upd.items():
            payload[k] = v
        return self._send_json(200, payload)

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
        return self._active_tunnel_ifname()

    def _load_iface_env_values(self) -> dict[str, str]:
        out: dict[str, str] = {}
        raw = _read_text(self._webui_iface_env(), "")
        for line in raw.splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
        return out

    def _runtime_iface_firewall_enabled(self) -> bool:
        """AWG_FW_ENABLED из interfaces.env — совпадает с тем, что применяет awg-uplink-firewall."""
        raw = (self._load_iface_env_values().get("AWG_FW_ENABLED") or "1").strip().lower()
        return raw not in ("0", "false", "no", "off", "")

    def _detect_tunnel_middle_nat_ip(self) -> str:
        if not self._tunnel_iface_up():
            return ""
        if not shutil.which("curl"):
            return ""
        probes = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
        ]
        for url in probes:
            rc, out, _ = _run(
                [
                    "curl",
                    "-4",
                    "--interface",
                    self._active_tunnel_ifname(),
                    "--connect-timeout",
                    "2",
                    "--max-time",
                    "5",
                    "-fsSL",
                    url,
                ],
                timeout=6.0,
            )
            if rc != 0:
                continue
            ip = (out or "").strip()
            if _ipv4_literal_ok(ip):
                return ip
        return ""

    def _derive_middle_proxy_nat_ip(self, iface: dict, mode: str) -> str:
        mode_norm = str(mode or "").strip().lower()
        egress_ip = str(iface.get("egress_ip", "")).strip()
        if mode_norm == "egress":
            return egress_ip
        if mode_norm == "tunnel":
            return self._detect_tunnel_middle_nat_ip()
        # direct: follow current default-route mode from interfaces.env (ROUTE_MODE).
        env_map = self._load_iface_env_values()
        route_mode = str(env_map.get("ROUTE_MODE", "")).strip().lower()
        if route_mode == "tunnel":
            return self._detect_tunnel_middle_nat_ip()
        return egress_ip

    def _mtproto_install_status(self) -> dict:
        with _MTPROTO_INSTALL_LOCK:
            st = dict(_MTPROTO_INSTALL_STATE)
            st["warnings"] = list(st.get("warnings") or [])
            return st

    def _set_mtproto_install_status(self, **updates):
        with _MTPROTO_INSTALL_LOCK:
            _MTPROTO_INSTALL_STATE.update(updates)

    def _start_async_op(self, name: str, worker):
        task_id = secrets.token_hex(12)
        with _ASYNC_OPS_LOCK:
            _ASYNC_OPS[task_id] = {
                "task_id": task_id,
                "name": name,
                "running": True,
                "ok": None,
                "error": "",
                "result": None,
                "started_at": int(time.time()),
                "finished_at": 0,
            }

        def _runner():
            try:
                result = worker()
                with _ASYNC_OPS_LOCK:
                    st = _ASYNC_OPS.get(task_id, {})
                    st.update(
                        {
                            "running": False,
                            "ok": True,
                            "result": result,
                            "finished_at": int(time.time()),
                        }
                    )
                    _ASYNC_OPS[task_id] = st
            except Exception as ex:
                with _ASYNC_OPS_LOCK:
                    st = _ASYNC_OPS.get(task_id, {})
                    st.update(
                        {
                            "running": False,
                            "ok": False,
                            "error": str(ex),
                            "finished_at": int(time.time()),
                        }
                    )
                    _ASYNC_OPS[task_id] = st

        threading.Thread(target=_runner, daemon=True).start()
        return task_id

    def _get_async_op(self, task_id: str) -> dict | None:
        with _ASYNC_OPS_LOCK:
            st = _ASYNC_OPS.get(task_id)
            return dict(st) if isinstance(st, dict) else None

    def _op_net_routing_save(self, body: dict) -> dict:
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
            route_mode_warning = "awg-uplink is not UP; сохранено и применено в режиме egress (split egress/ingress)."
        ok, err = self._validate_iface_cfg(cfg)
        if not ok:
            raise RuntimeError(err)
        cfg["egress_gw"] = self._normalize_gateway(cfg["egress_dev"], cfg["egress_ip"], cfg["egress_gw"])
        cfg["ingress_gw"] = self._normalize_gateway(
            cfg["ingress_dev"] or cfg["egress_dev"], cfg["ingress_ip"], cfg["ingress_gw"]
        )
        self._store_geo_config(cfg.get("geo", {}))
        self._store_iface_config(cfg)
        self._write_iface_env(cfg)
        self._apply_iface_routing(cfg)
        self._apply_geo_ip_runtime(cfg, run_refresh_now=bool(body.get("apply_geo_ip_refresh")))
        self._apply_geo_domain_runtime(cfg, run_refresh_now=bool(body.get("apply_geo_ip_refresh")))
        try:
            self._sync_dns_amnezia_if_domain_routing(self._load_iface_config())
        except Exception:
            pass
        runtime = self._routing_runtime_status(cfg)
        if not runtime.get("applied"):
            raise RuntimeError("routing not applied")
        loaded = self._load_iface_config()
        if isinstance(loaded, dict):
            loaded = dict(loaded)
            loaded["geo"] = self._load_geo_config()
            loaded["firewall"] = self._iface_firewall_for_response(loaded)
        else:
            loaded = {}
        resp = {
            "ok": True,
            "config": loaded,
            "runtime": runtime,
            "config_dir": self._webui_cfg_dir(),
        }
        if route_mode_warning:
            resp["warning"] = route_mode_warning
        mt_extra = self._maybe_sync_mtproto_after_iface_change()
        if mt_extra:
            resp["mtproto_sync_warning"] = mt_extra
        try:
            self._ensure_ntfy_public_url_synced()
        except Exception:
            pass
        return resp

    def _op_net_routing_mode(self, body: dict) -> dict:
        mode = str(body.get("route_mode", "")).strip().lower()
        if mode not in ("egress", "tunnel", "georouting"):
            raise RuntimeError("route_mode must be egress|tunnel|georouting")
        if mode == "tunnel" and not self._tunnel_iface_up():
            raise RuntimeError("awg-uplink tunnel is not UP")
        cfg = self._load_iface_config()
        if not cfg:
            raise RuntimeError("interface config is empty")
        cfg["route_mode"] = mode
        cfg["updated_at"] = int(time.time())
        cfg["geo"] = self._load_geo_config()
        self._store_iface_config(cfg)
        self._write_iface_env(cfg)
        self._apply_iface_routing(cfg)
        self._apply_geo_ip_runtime(cfg)
        self._apply_geo_domain_runtime(cfg)
        try:
            self._sync_dns_amnezia_if_domain_routing(self._load_iface_config())
        except Exception:
            pass
        runtime = self._routing_runtime_status(cfg)
        if not runtime.get("applied"):
            raise RuntimeError("routing not applied")
        mt_extra = self._maybe_sync_mtproto_after_iface_change()
        try:
            self._ensure_ntfy_public_url_synced()
        except Exception:
            pass
        out = {"ok": True, "config": cfg, "runtime": runtime}
        if mt_extra:
            out["mtproto_sync_warning"] = mt_extra
        return out

    def _op_dns_save(self, body: dict) -> dict:
        self._install_iface_runtime()
        return self._api_dns_save(body)

    def _op_netplan_save(self, body: dict) -> dict:
        cfg_text = str(body.get("config_text", ""))
        if not cfg_text.strip():
            raise RuntimeError("config_text is empty")
        pth = self._netplan_path()
        ok, err = self._validate_netplan_text(pth, cfg_text)
        if not ok:
            raise RuntimeError(f"netplan syntax error:\n{err}")
        _mkdir(str(Path(pth).parent))
        _write_text(pth, cfg_text if cfg_text.endswith("\n") else (cfg_text + "\n"))
        rc, out, err = _run(["netplan", "apply"], timeout=20.0)
        if rc != 0:
            raise RuntimeError((err or out or "netplan apply failed").strip())
        cfg = self._load_iface_config()
        if isinstance(cfg, dict) and cfg:
            cfg["geo"] = self._load_geo_config()
            self._write_iface_env(cfg)
            self._apply_iface_routing(cfg)
            self._apply_geo_ip_runtime(cfg, run_refresh_now=False)
            self._apply_geo_domain_runtime(cfg, run_refresh_now=False)
            try:
                self._sync_dns_amnezia_if_domain_routing(self._load_iface_config())
            except Exception:
                pass
            try:
                self._maybe_sync_mtproto_after_iface_change()
            except Exception:
                pass
        return {"ok": True, "path": pth}

    def _run_mtproto_install_worker(self, action: str):
        installer = "/usr/local/sbin/awg-mtproto-install.sh"
        self._set_mtproto_install_status(phase="install", error="", warnings=[], ok=None)
        try:
            rc, out, err = _run([installer], timeout=1800.0)
            if rc != 0:
                msg = (err or out or "mtproto install failed").strip()
                self._set_mtproto_install_status(
                    running=False,
                    finished_at=int(time.time()),
                    ok=False,
                    error=msg,
                    phase="failed",
                )
                return

            warnings: list[str] = []
            self._set_mtproto_install_status(phase="drs")
            drs_rc, drs_out, drs_err = _run(["mtbuddy", "setup", "drs"], timeout=120.0)
            if drs_rc != 0:
                warnings.append((drs_err or drs_out or "mtbuddy setup drs failed").strip())

            self._set_mtproto_install_status(phase="sync")
            sync = self._sync_mtproto_derived_config(apply_upstream=True)
            if not sync.get("ok"):
                msg = str(sync.get("error", "")).strip() or "mtproto sync failed"
                self._set_mtproto_install_status(
                    running=False,
                    finished_at=int(time.time()),
                    ok=False,
                    error=msg,
                    warnings=warnings,
                    phase="failed",
                )
                return
            for w in sync.get("warnings") or []:
                if w:
                    warnings.append(str(w))

            self._set_mtproto_install_status(
                running=False,
                finished_at=int(time.time()),
                ok=True,
                error="",
                warnings=warnings,
                phase="done",
            )
        except Exception as ex:
            self._set_mtproto_install_status(
                running=False,
                finished_at=int(time.time()),
                ok=False,
                error=str(ex),
                phase="failed",
            )

    def _sync_mtproto_derived_config(
        self,
        *,
        persist_outbound_mode: str | None = None,
        apply_upstream: bool = True,
        restart_mtproto: bool = True,
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
        try:
            self._write_iface_env(iface, mtproto_outbound_mode=mode)
        except Exception:
            pass
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
        parsed_now = _parse_simple_toml(new_text) if new_text.strip() else {}
        censor_now = parsed_now.get("censorship", {}) if isinstance(parsed_now.get("censorship", {}), dict) else {}
        env_domain = str(os.environ.get("AWG_UI_DOMAIN", "") or "").strip()
        domain_for_mask = env_domain or str(censor_now.get("tls_domain", "") or "").strip()
        env_mask_port = str(os.environ.get("AWG_UI_MASK_PORT", "") or "").strip()
        try:
            mask_port_for_mask = int(env_mask_port) if env_mask_port else int(censor_now.get("mask_port", 5000) or 5000)
        except Exception:
            mask_port_for_mask = 5000
        new_text = _upsert_mtproto_censorship_cfg(new_text, domain_for_mask, mask_port_for_mask)
        pub = _mtproto_public_ip_from_iface(iface)
        mid = self._derive_middle_proxy_nat_ip(iface, mode)
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
        # MTProto policy routing lives in awg-webui-ifaces runtime script/unit.
        # Reinstall+restart the routing runtime to ensure latest project changes are applied.
        try:
            self._apply_iface_routing()
        except Exception as ex:
            return {
                "ok": False,
                "mode": mode,
                "warnings": warnings,
                "error": str(ex),
            }
        if not restart_mtproto:
            resp: dict = {
                "ok": True,
                "mode": mode,
                "warnings": warnings,
                "service_action": "none",
                "public_ip": pub,
                "middle_proxy_nat_ip": server_updates.get("middle_proxy_nat_ip", ""),
            }
            if mode == "tunnel" and not self._tunnel_iface_up():
                warnings.append("Интерфейс awg-uplink не UP — проверьте VPN.")
            resp["warnings"] = warnings
            return resp
        svc = self._mtproto_service_name()
        rc, out, err, action = _reload_or_restart_service(svc, reload_timeout=8.0, restart_timeout=20.0)
        resp = {
            "ok": rc == 0,
            "mode": mode,
            "warnings": warnings,
            "service_action": action,
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
                    if "tg:" in s.lower():
                        tg = s.split("tg:", 1)[1].strip()
                        if current_user and tg.startswith("tg://"):
                            links_by_user[current_user] = tg
                    if "t.me:" in s.lower():
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
            timer_unit = os.environ.get("AWG_MTPROTO_HEALTH_TIMER", "mtproto-mask-health.timer")
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
        mid_raw = self._derive_middle_proxy_nat_ip(iface_rt, ui_mode)
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
            # API clients use fetch() + JSON: 302 to login returns HTML and breaks res.json().
            # Return 401 for /api/* (except /api/auth/*); keep 302 for full-page navigation.
            if not (sp.startswith("/api/") and not sp.startswith("/api/auth/")):
                next_path = sp if sp.startswith("/") else self._base_path
                self.send_response(302)
                self.send_header("Location", f"{self._base_path}login.html?next={next_path}")
                self.end_headers()
                return

        if sp == "/config.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.end_headers()
            app_ver = _read_installed_app_version()
            self.wfile.write(
                (
                    f'window.__AWG_BASE_PATH__ = {json.dumps(self._base_path)};\n'
                    f'window.__AWG_AUTH_ENABLED__ = {json.dumps(bool(self._auth_enabled))};\n'
                    f'window.__AWG_APP_VERSION__ = {json.dumps(app_ver)};\n'
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
            q = parse_qs(urlparse(self.path).query)
            tid = (q.get("tunnel_id") or ["tunnel1"])[0]
            return self._api_status_awg(str(tid))

        if sp == "/api/tunnels/config":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_tunnels_config()

        if sp == "/api/metrics/system":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_metrics_system()

        if sp == "/api/mtproto/state":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._api_mtproto_state()

        if sp == "/api/mtproto/install/status":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._send_json(200, self._mtproto_install_status())

        if sp == "/api/notifications/config":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            return self._send_json(200, {"config": self._notifications_public_payload()})

        if sp == "/api/op/status":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            q = parse_qs(urlparse(self.path).query)
            task_id = str((q.get("task_id") or [""])[0]).strip()
            if not task_id:
                return self._send_text(400, "task_id is required")
            st = self._get_async_op(task_id)
            if not st:
                return self._send_text(404, "task not found")
            return self._send_json(200, st)

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
            if not (sp.startswith("/api/") and not sp.startswith("/api/auth/")):
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
            with self._sessions_lock:
                self._sessions[token] = {"u": self._username, "exp": time.time() + 12 * 3600}
                self._persist_sessions()
            self.send_response(200)
            self._set_cookie(token)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(_json_bytes({"ok": True}))
            return

        if sp == "/api/auth/logout":
            if not self._auth_enabled:
                return self._send_json(200, {"ok": True, "disabled": True})
            tok = self._read_cookie("AWGSESS")
            with self._sessions_lock:
                if tok:
                    self._sessions.pop(tok, None)
                self._persist_sessions()
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
            task_id = self._start_async_op("net-routing-save", lambda: self._op_net_routing_save(body))
            return self._send_json(202, {"ok": True, "task_id": task_id})

        if sp == "/api/net/routing/mode":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            task_id = self._start_async_op("net-routing-mode", lambda: self._op_net_routing_mode(body))
            return self._send_json(202, {"ok": True, "task_id": task_id})

        if sp == "/api/dns/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            task_id = self._start_async_op("dns-save", lambda: self._op_dns_save(body))
            return self._send_json(202, {"ok": True, "task_id": task_id})

        if sp == "/api/notifications/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            if not isinstance(body, dict):
                body = {}
            try:
                result = self._op_notifications_save(body)
                return self._send_json(200, result)
            except Exception as ex:
                return self._send_text(500, str(ex))

        if sp == "/api/notifications/test":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            ok, err = self._run_notify_test()
            return self._send_json(200, {"ok": bool(ok), "error": err or ""})

        if sp == "/api/netplan/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            task_id = self._start_async_op("netplan-save", lambda: self._op_netplan_save(body))
            return self._send_json(202, {"ok": True, "task_id": task_id})

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
            tunnel_id = self._tunnel_id_from_body(body)
            ifname = self._tunnel_ifname(tunnel_id)
            try:
                ok, verr = _validate_tunnel_config(cfg_text)
                if not ok:
                    return self._send_text(400, f"tunnel config validation failed: {verr}")
                sanitized = _sanitize_tunnel_config(cfg_text)
                conf_path = Path(f"/etc/amnezia/amneziawg/{ifname}.conf")
                _mkdir(str(conf_path.parent))
                _write_text(str(conf_path), sanitized)
                os.chmod(str(conf_path), 0o600)
                tcfg = self._load_tunnels_config()
                tcfg[tunnel_id]["enabled"] = True
                act = str(tcfg.get("active") or "tunnel1")
                if act not in ("tunnel1", "tunnel2") or not tcfg.get(act, {}).get("enabled"):
                    tcfg["active"] = tunnel_id
                self._store_tunnels_config(tcfg)
                routing_err = ""
                try:
                    self._apply_iface_routing()
                except Exception as ex:
                    routing_err = str(ex)
                payload = {
                    "ok": True,
                    "tunnel_id": tunnel_id,
                    "ifname": ifname,
                    "path": str(conf_path),
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
            body = self._read_json_body()
            tunnel_id = self._tunnel_id_from_body(body if isinstance(body, dict) else {})
            ifname = self._tunnel_ifname(tunnel_id)
            tcfg = self._load_tunnels_config()
            if not tcfg.get(tunnel_id, {}).get("enabled"):
                return self._send_text(400, f"{tunnel_id} disabled — enable tunnel in panel first")
            unit = f"awg-quick@{ifname}.service"
            rc, out, err = _run(["systemctl", "restart", unit], timeout=12.0)
            if rc != 0:
                msg = (err or out or f"failed to restart {unit}").strip()
                self._notify_service_start_error(unit, msg)
                return self._send_text(500, msg)
            routing_err = ""
            try:
                self._apply_iface_routing()
            except Exception as ex:
                routing_err = str(ex)
            resp = {"ok": True, "tunnel_id": tunnel_id, "ifname": ifname}
            if routing_err:
                resp["routing_apply_error"] = routing_err
            return self._send_json(200, resp)

        if sp == "/api/tunnel/delete":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            try:
                return self._send_json(200, self._op_tunnel_delete(body))
            except Exception as ex:
                return self._send_text(500, str(ex))

        if sp == "/api/tunnels/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            try:
                return self._send_json(200, self._op_tunnels_save(body))
            except Exception as ex:
                return self._send_text(500, str(ex))

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

        if sp == "/api/mtproto/install":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            action = str(body.get("action", "auto") or "auto").strip().lower()
            if action not in ("auto", "install", "update"):
                return self._send_text(400, "action must be auto|install|update")
            installer = "/usr/local/sbin/awg-mtproto-install.sh"
            if not Path(installer).exists():
                return self._send_text(500, f"installer script is missing: {installer}")
            st = self._mtproto_install_status()
            if st.get("running"):
                return self._send_json(200, {"ok": True, "started": False, "running": True, "status": st})
            now = int(time.time())
            self._set_mtproto_install_status(
                running=True,
                action=action,
                started_at=now,
                finished_at=0,
                ok=None,
                error="",
                warnings=[],
                phase="queued",
            )
            t = threading.Thread(target=self._run_mtproto_install_worker, args=(action,), daemon=True)
            t.start()
            return self._send_json(202, {"ok": True, "started": True, "running": True, "status": self._mtproto_install_status()})

        if sp == "/api/mtproto/config/save":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            body = self._read_json_body()
            cfg_text = str(body.get("config_text", ""))
            if not cfg_text.strip():
                return self._send_text(400, "config_text is empty")
            ok_toml, toml_err = _validate_toml_text(cfg_text)
            if not ok_toml:
                return self._send_text(400, f"invalid TOML: {toml_err}")
            cfg_path = self._mtproto_config_path()
            try:
                _write_text(cfg_path, cfg_text)
            except OSError as e:
                return self._send_text(500, f"failed to write config: {e}")
            sync = self._sync_mtproto_derived_config(apply_upstream=False, restart_mtproto=False)
            if not sync.get("ok"):
                return self._send_text(500, str(sync.get("error", "")).strip() or "mtproto sync failed")
            applied_cfg = _read_text(cfg_path, "")
            svc = self._mtproto_service_name()
            _schedule_mtproto_user_config_restart(svc)
            return self._send_json(
                200,
                {
                    "ok": True,
                    "mtproto_sync": sync,
                    "service_action": "restart",
                    "restart_deferred": True,
                    "config_text_applied": applied_cfg,
                },
            )

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
            svc = self._mtproto_service_name()
            _schedule_mtproto_user_config_restart(svc)
            return self._send_json(
                200,
                {"ok": True, "service_action": "restart", "restart_deferred": True},
            )

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
            if not enabled and username in users and len(users) <= 1:
                return self._send_text(400, "Нельзя выключить последнего активного пользователя MTProto.")
            if enabled:
                if username in disabled_users:
                    users[username] = disabled_users.pop(username)
            else:
                if username in users:
                    disabled_users[username] = users.pop(username)
            new_cfg = _replace_access_users_section(cfg_text, users)
            new_cfg = _replace_disabled_users_section(new_cfg, disabled_users)
            _write_text(cfg_path, new_cfg)
            svc = self._mtproto_service_name()
            _schedule_mtproto_user_config_restart(svc)
            return self._send_json(
                200,
                {"ok": True, "service_action": "restart", "restart_deferred": True},
            )

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
            if username in users and len(users) <= 1:
                return self._send_text(400, "Нельзя удалить последнего активного пользователя MTProto.")
            users.pop(username, None)
            disabled_users.pop(username, None)
            new_cfg = _replace_access_users_section(cfg_text, users)
            new_cfg = _replace_disabled_users_section(new_cfg, disabled_users)
            _write_text(cfg_path, new_cfg)
            svc = self._mtproto_service_name()
            _schedule_mtproto_user_config_restart(svc)
            return self._send_json(
                200,
                {"ok": True, "service_action": "restart", "restart_deferred": True},
            )

        if sp == "/api/update/start":
            if self._auth_enabled and not self._session_user():
                return self._send_text(401, "Unauthorized")
            if self._async_op_name_running("webui-self-update"):
                return self._send_text(409, "Update already running")
            body = self._read_json_body()
            if not isinstance(body, dict):
                body = {}
            task_id = self._start_async_op("webui-self-update", lambda: self._op_webui_self_update(body))
            return self._send_json(202, {"ok": True, "task_id": task_id})

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
    parser = argparse.ArgumentParser(description="AWG Split Gate web UI (static) with digest-style login")
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
    realm = "AWG Split Gate webui"
    secret = _sha256_hex(f"{user}:{realm}:{pwd}")

    directory = str(Path(__file__).parent.resolve())
    sessions: dict[str, dict] = _load_webui_sessions_from_disk() if auth_enabled else {}
    nonces: dict[str, float] = {}
    sessions_lock = threading.Lock()

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
            sessions_lock=sessions_lock,
            nonces=nonces,
            **h_kwargs,
        )

    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Serving {directory} on http://{args.host}:{args.port}{base_path}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()


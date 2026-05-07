#!/usr/bin/env python3
"""Следит за контейнером Amnezia DNS (Unbound): держит forward зоны «.» на plain DNS → dnsmasq на шлюзе docker-сети."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

CFG_DIR = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
DNS_JSON = CFG_DIR / "dns.json"
STATE_PATH = Path(os.environ.get("AWG_AMNEZIA_DNS_STATE", "/var/lib/awg-uplink/amnezia-dns-watch.json"))
FORWARD_PATH = "/opt/unbound/etc/unbound/forward-records.conf"
INTERVAL = max(5, int(os.environ.get("AWG_AMNEZIA_DNS_WATCH_INTERVAL", "30")))

MARKER = "awg-uplink-amnezia-dns-watch"


def run(cmd: list[str], *, check: bool = True, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def run_rc(cmd: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def load_dns_cfg() -> dict:
    if not DNS_JSON.exists():
        return {}
    try:
        o = json.loads(DNS_JSON.read_text(encoding="utf-8"))
        return o if isinstance(o, dict) else {}
    except Exception:
        return {}


def docker_gateway(network: str) -> str | None:
    p = run_rc(
        ["docker", "network", "inspect", network, "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"],
        timeout=15.0,
    )
    if p.returncode != 0:
        return None
    g = (p.stdout or "").strip()
    return g or None


def container_running(name: str) -> bool:
    p = run_rc(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=15.0)
    return p.returncode == 0 and (p.stdout or "").strip().lower() == "true"


def docker_cat_file(container: str, path: str) -> str | None:
    p = run_rc(["docker", "exec", container, "cat", path], timeout=30.0)
    if p.returncode != 0:
        return None
    return p.stdout or ""


def forward_zone_root_span(lines: list[str]) -> tuple[int, int] | None:
    i = 0
    n = len(lines)
    while i < n:
        if lines[i].strip().startswith("forward-zone:"):
            start = i
            i += 1
            while i < n:
                line = lines[i]
                if line.strip() == "":
                    i += 1
                    continue
                if line[0] not in " \t":
                    break
                i += 1
            stanza = "".join(lines[start:i])
            if re.search(r"^\s*name:\s*\.\s*$", stanza, re.MULTILINE):
                return (start, i)
            continue
        i += 1
    return None


def root_forward_matches(text: str, ip: str) -> bool:
    if re.search(r"forward-tls-upstream\s*:\s*yes", text):
        return False
    if MARKER not in text:
        return False
    return bool(re.search(rf"^\s*forward-addr:\s*{re.escape(ip)}\s*$", text, re.MULTILINE))


def build_root_forward_stanza(ip: str) -> str:
    return (
        "forward-zone:\n"
        "   name: .\n"
        f"   # {MARKER}: plain DNS to host dnsmasq\n"
        f"   forward-addr: {ip}\n"
    )


def patch_forward_records(content: str, ip: str) -> tuple[str | None, bool]:
    lines = content.splitlines(keepends=True)
    span = forward_zone_root_span(lines)
    if span is None:
        return None, False
    start, end = span
    old = "".join(lines[start:end])
    if root_forward_matches(old, ip):
        return content, False
    lines[start:end] = [build_root_forward_stanza(ip)]
    return "".join(lines), True


def docker_cp_string(container: str, dest_path: str, content: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".conf") as tf:
        tf.write(content)
        tmp = tf.name
    try:
        run(["docker", "cp", tmp, f"{container}:{dest_path}"], timeout=60.0)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def restart_dns_container(container: str) -> None:
    """Полный restart контейнера: у Unbound SIGHUP часто оставляет старые TLS-сессии к прежним forward (DoT :853)."""
    run(["docker", "restart", container], timeout=180.0)


def write_state(
    *,
    status: str,
    detail: str = "",
    enabled: bool = False,
    forward_ip: str = "",
    container: str = "",
    patched: bool = False,
) -> None:
    now = int(time.time())
    STATE_PATH.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    prev: dict = {}
    if STATE_PATH.exists():
        try:
            prev = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            prev = {}
    if not isinstance(prev, dict):
        prev = {}
    last_patch = prev.get("last_patch_unix")
    if patched:
        last_patch = now
    obj = {
        "status": status,
        "detail": detail,
        "enabled": enabled,
        "forward_ip": forward_ip,
        "container": container,
        "last_run_unix": now,
        "last_patch_unix": last_patch,
    }
    tmp = STATE_PATH.with_suffix(f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, STATE_PATH)
    try:
        os.chmod(STATE_PATH, 0o644)
    except OSError:
        pass


_MSG_NO_CONTAINER = (
    "Отсутствует сервис AmneziaDNS — установите его на сервер из приложения AmneziaVPN"
)


def cycle_once() -> None:
    cfg = load_dns_cfg()
    enabled = bool(cfg.get("amnezia_dns_watch_enabled", True))
    container = str(cfg.get("amnezia_dns_container", "amnezia-dns") or "amnezia-dns").strip() or "amnezia-dns"
    network = str(cfg.get("amnezia_dns_network", "amnezia-dns-net") or "amnezia-dns-net").strip() or "amnezia-dns-net"
    manual_ip = str(cfg.get("amnezia_dns_forward_ip", "") or "").strip()

    if not enabled:
        write_state(status="disabled", detail="выключено в dns.json", enabled=False, container=container)
        return

    forward_ip = manual_ip
    if not forward_ip:
        forward_ip = docker_gateway(network) or ""

    if not forward_ip:
        write_state(
            status="error",
            detail=f"не удалось получить Gateway сети {network} (docker network inspect)",
            enabled=True,
            container=container,
        )
        return

    if not container_running(container):
        write_state(
            status="no_container",
            detail=_MSG_NO_CONTAINER,
            enabled=True,
            forward_ip=forward_ip,
            container=container,
        )
        return

    cur = docker_cat_file(container, FORWARD_PATH)
    if cur is None:
        write_state(
            status="error",
            detail="не прочитать forward-records.conf в контейнере",
            enabled=True,
            forward_ip=forward_ip,
            container=container,
        )
        return

    new_text, changed = patch_forward_records(cur, forward_ip)
    if new_text is None:
        write_state(
            status="error",
            detail="нет forward-zone с name: . в forward-records.conf",
            enabled=True,
            forward_ip=forward_ip,
            container=container,
        )
        return
    if not changed:
        write_state(
            status="ok",
            detail=f"Unbound → {forward_ip}:53",
            enabled=True,
            forward_ip=forward_ip,
            container=container,
        )
        return

    try:
        docker_cp_string(container, FORWARD_PATH, new_text)
        # Только здесь перезапуск контейнера — не на каждом цикле проверки.
        restart_dns_container(container)
    except Exception as e:
        write_state(
            status="error",
            detail=str(e)[:500],
            enabled=True,
            forward_ip=forward_ip,
            container=container,
        )
        return

    write_state(
        status="ok",
        detail=f"исправлено: Unbound → {forward_ip}:53",
        enabled=True,
        forward_ip=forward_ip,
        container=container,
        patched=True,
    )


def main() -> None:
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        try:
            cycle_once()
        except Exception as e:
            write_state(status="error", detail=str(e)[:500], enabled=True)
            raise SystemExit(1) from e
        return

    while True:
        try:
            cycle_once()
        except Exception as e:
            write_state(status="error", detail=str(e)[:500], enabled=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Управление двумя туннелями AmneziaWG и failover по ping.

Команды:
  apply          — start/stop awg-quick@ по tunnels.json, синхрон TUNNEL_* в interfaces.env
  migrate        — создать/дополнить tunnels.json при апгрейде со старой версии (один туннель, health)
  failover-once  — одна проверка health + переключение active при необходимости
  watch          — цикл failover-once (для systemd)
  status         — JSON статуса на stdout
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

CFG = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
TUNNELS_JSON = CFG / "tunnels.json"
IFACE_ENV = CFG / "interfaces.env"
IFACE_JSON = CFG / "interfaces.json"
GEO_JSON = CFG / "georouting.json"
AMNEZIA_DIR = Path("/etc/amnezia/amneziawg")

TUNNEL_DEFS = {
    "tunnel1": {"ifname": "awg-uplink", "label": "Туннель 1", "order": 1},
    "tunnel2": {"ifname": "awg-uplink-2", "label": "Туннель 2", "order": 2},
}


def log(msg: str) -> None:
    print(f"[awg-uplink-tunnel] {msg}", file=sys.stderr, flush=True)


def default_config() -> dict:
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


def load_config() -> dict:
    base = default_config()
    if not TUNNELS_JSON.exists():
        return base
    try:
        raw = json.loads(TUNNELS_JSON.read_text(encoding="utf-8"))
    except Exception:
        return base
    if not isinstance(raw, dict):
        return base
    for tid, ddef in TUNNEL_DEFS.items():
        t = raw.get(tid) if isinstance(raw.get(tid), dict) else {}
        base[tid].update(
            {
                "id": tid,
                "ifname": str(t.get("ifname") or ddef["ifname"]).strip() or ddef["ifname"],
                "label": str(t.get("label") or ddef["label"]).strip() or ddef["label"],
                "enabled": bool(t.get("enabled", base[tid]["enabled"])),
            }
        )
    act = str(raw.get("active", "tunnel1") or "tunnel1").strip()
    if act not in TUNNEL_DEFS:
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
    for tid in TUNNEL_DEFS:
        st = hs.get(tid) if isinstance(hs.get(tid), dict) else {}
        base["health_state"][tid] = {
            "fail_streak": int(st.get("fail_streak", 0) or 0),
            "ok_streak": int(st.get("ok_streak", 0) or 0),
            "last_ping_ok": st.get("last_ping_ok"),
            "last_check_at": st.get("last_check_at"),
        }
    return base


def save_config(cfg: dict) -> None:
    CFG.mkdir(parents=True, exist_ok=True)
    TUNNELS_JSON.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(TUNNELS_JSON, 0o600)


def migrate_config(cfg: dict, *, initial: bool = False) -> tuple[dict, bool]:
    """Апгрейд со старой установки: tunnels.json отсутствует или health.targets пуст."""
    changed = bool(initial)
    defaults = default_config()
    if initial:
        for tid, ddef in TUNNEL_DEFS.items():
            ifname = ddef["ifname"]
            conf_paths = [AMNEZIA_DIR / f"{ifname}.conf", Path(f"/etc/wireguard/{ifname}.conf")]
            has_conf = any(p.exists() for p in conf_paths)
            if has_conf and not cfg.get(tid, {}).get("enabled"):
                cfg[tid]["enabled"] = True
                changed = True
        if (AMNEZIA_DIR / "awg-uplink.conf").exists():
            if cfg.get("active") not in TUNNEL_DEFS:
                cfg["active"] = "tunnel1"
                changed = True
    h = cfg.setdefault("health", {})
    dh = defaults["health"]
    if not h.get("targets"):
        h["targets"] = list(dh["targets"])
        changed = True
    for key in ("interval_sec", "fail_count", "recover_count", "ping_timeout_sec"):
        if key not in h or h.get(key) in (None, "", 0):
            h[key] = dh[key]
            changed = True
    if not isinstance(cfg.get("health_state"), dict):
        cfg["health_state"] = dict(defaults["health_state"])
        changed = True
    return cfg, changed


def cmd_migrate() -> None:
    initial = not TUNNELS_JSON.exists()
    cfg = default_config() if initial else load_config()
    cfg, changed = migrate_config(cfg, initial=initial)
    if changed:
        save_config(cfg)
        log("tunnels.json migrated/created")
    print(json.dumps({"ok": True, "migrated": changed}, ensure_ascii=False))


def conf_path(ifname: str) -> Path:
    return AMNEZIA_DIR / f"{ifname}.conf"


def link_up(ifname: str) -> bool:
    proc = subprocess.run(
        ["ip", "-j", "link", "show", "dev", ifname],
        capture_output=True,
        text=True,
        timeout=4,
    )
    if proc.returncode != 0:
        return False
    try:
        items = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return False
    if not items:
        return False
    return "UP" in (items[0].get("flags") or [])


def systemd_unit(ifname: str) -> str:
    return f"awg-quick@{ifname}.service"


def run_systemctl(*args: str, timeout: float = 30.0) -> bool:
    proc = subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        log(f"systemctl {' '.join(args)} failed: {msg}")
        if args and args[0] in ("start", "restart") and len(args) > 1:
            _notify_event("service_start_error", {"service": args[1], "detail": msg})
        return False
    return True


def enabled_tunnels(cfg: dict) -> list[str]:
    out = []
    for tid in sorted(TUNNEL_DEFS, key=lambda x: TUNNEL_DEFS[x]["order"]):
        if cfg.get(tid, {}).get("enabled"):
            out.append(tid)
    return out


def ifname_for(cfg: dict, tid: str) -> str:
    t = cfg.get(tid, {})
    return str(t.get("ifname") or TUNNEL_DEFS[tid]["ifname"]).strip()


def pick_active(cfg: dict) -> str:
    en = enabled_tunnels(cfg)
    if not en:
        return cfg.get("active") or "tunnel1"
    act = str(cfg.get("active") or "tunnel1")
    if act in en:
        return act
    return en[0]


def sync_iface_env(cfg: dict) -> None:
    active = pick_active(cfg)
    t1 = ifname_for(cfg, "tunnel1")
    t2 = ifname_for(cfg, "tunnel2")
    active_if = ifname_for(cfg, active)
    lines: list[str] = []
    if IFACE_ENV.exists():
        lines = IFACE_ENV.read_text(encoding="utf-8").splitlines()
    keys = {
        "TUNNEL_IFACE": active_if,
        "TUNNEL_ACTIVE": active,
        "TUNNEL1_IFACE": t1,
        "TUNNEL2_IFACE": t2,
        "TUNNEL_FAILOVER_ENABLED": "1" if len(enabled_tunnels(cfg)) >= 2 else "0",
        "AWG_GEO_IP_AWG_IFACE": active_if,
        "AWG_GEO_DOMAIN_AWG_IFACE": active_if,
        "AWG_FW_AWG_IFACE": active_if,
    }
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        k = line.split("=", 1)[0].strip() if "=" in line else ""
        if k in keys:
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    for k, v in keys.items():
        out.append(f'{k}={v}')
    out.append("")
    IFACE_ENV.write_text("\n".join(out), encoding="utf-8")


def _georouting_active() -> bool:
    try:
        iface = json.loads(IFACE_JSON.read_text(encoding="utf-8")) if IFACE_JSON.exists() else {}
        return str(iface.get("route_mode", "")).strip().lower() == "georouting"
    except Exception:
        return False


def _geo_policy_table_id() -> str:
    try:
        geo = json.loads(GEO_JSON.read_text(encoding="utf-8")) if GEO_JSON.exists() else {}
        target = str(geo.get("target", "tunnel")).strip().lower()
        return "207" if target == "tunnel" else "208"
    except Exception:
        return "207"


def geo_policy_needs_resync(active_if: str) -> bool:
    """table 207/208 должна вести на активный туннель (иначе georouting уходит в egress)."""
    if not _georouting_active() or not active_if:
        return False
    table_id = _geo_policy_table_id()
    proc = subprocess.run(
        ["ip", "-4", "route", "show", "table", table_id],
        capture_output=True,
        text=True,
        timeout=5,
    )
    out = (proc.stdout or "").strip()
    if proc.returncode != 0 or "default" not in out:
        return True
    for line in out.splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        dev = parts[parts.index("dev") + 1]
        if dev == active_if:
            return False
    return True


def restart_geo_refresh_if_needed() -> None:
    """После смены активного туннеля — пересобрать table 207/208 и nft oif под правильный ifname."""
    try:
        iface = json.loads(IFACE_JSON.read_text(encoding="utf-8")) if IFACE_JSON.exists() else {}
        if str(iface.get("route_mode", "")).strip().lower() != "georouting":
            return
        geo = json.loads(GEO_JSON.read_text(encoding="utf-8")) if GEO_JSON.exists() else {}
        domain_on = bool(geo.get("domainMode", False))
        ip_on = bool(geo.get("ipMode", False))
        if domain_on and not ip_on:
            # domain-only: geo-ip refresh только восстанавливает table 207/208
            run_systemctl("start", "awg-uplink-geo-ip-refresh.service", timeout=90.0)
        elif ip_on:
            run_systemctl("start", "awg-uplink-geo-ip-refresh.service", timeout=120.0)
        if domain_on:
            run_systemctl("start", "awg-uplink-geo-domain-refresh.service", timeout=120.0)
    except Exception as ex:
        log(f"geo refresh after tunnel change: {ex}")


def apply_tunnel_unit(ifname: str, want_run: bool, *, skip_restart_if_up: bool = False) -> None:
    unit = systemd_unit(ifname)
    path = conf_path(ifname)
    if want_run:
        if not path.exists():
            log(f"{ifname}: конфиг {path} отсутствует — не запускаем")
            run_systemctl("stop", unit, timeout=15.0)
            run_systemctl("disable", unit, timeout=10.0)
            return
        run_systemctl("enable", unit, timeout=10.0)
        if skip_restart_if_up and link_up(ifname):
            return
        run_systemctl("daemon-reload", timeout=10.0)
        run_systemctl("restart", unit, timeout=20.0)
    else:
        run_systemctl("stop", unit, timeout=15.0)
        run_systemctl("disable", unit, timeout=10.0)


def apply_tunnels(restart_routing: bool | None = None) -> dict:
    if restart_routing is None:
        restart_routing = os.environ.get("AWG_TUNNEL_RESTART_ROUTING", "1").strip() not in (
            "0",
            "false",
            "no",
        )
    cfg = load_config()
    en = enabled_tunnels(cfg)
    for tid in TUNNEL_DEFS:
        ifname = ifname_for(cfg, tid)
        want = tid in en
        apply_tunnel_unit(ifname, want, skip_restart_if_up=want)
    cfg["active"] = pick_active(cfg)
    save_config(cfg)
    sync_iface_env(cfg)
    if restart_routing:
        run_systemctl("restart", "awg-webui-ifaces.service", timeout=45.0)
        run_systemctl("restart", "awg-uplink-firewall.service", timeout=35.0)
        restart_geo_refresh_if_needed()
    if enabled_tunnels(cfg):
        try:
            failover_once()
        except Exception as ex:
            log(f"initial health check failed: {ex}")
    return cfg


def ping_via_iface(ifname: str, target: str, timeout_sec: int) -> bool:
    if not link_up(ifname):
        return False
    proc = subprocess.run(
        [
            "ping",
            "-4",
            "-I",
            ifname,
            "-c",
            "1",
            "-W",
            str(max(1, timeout_sec)),
            target,
        ],
        capture_output=True,
        text=True,
        timeout=timeout_sec + 4,
    )
    return proc.returncode == 0


def tunnel_health_ok(cfg: dict, tid: str) -> bool:
    ifname = ifname_for(cfg, tid)
    health = cfg.get("health") if isinstance(cfg.get("health"), dict) else {}
    targets = health.get("targets") or ["1.1.1.1", "8.8.8.8"]
    timeout_sec = int(health.get("ping_timeout_sec", 3) or 3)
    for target in targets:
        if ping_via_iface(ifname, str(target).strip(), timeout_sec):
            return True
    return False


def update_streak(cfg: dict, tid: str, ok: bool) -> None:
    hs = cfg.setdefault("health_state", {})
    st = hs.setdefault(tid, {"fail_streak": 0, "ok_streak": 0, "last_ping_ok": None, "last_check_at": None})
    st["last_ping_ok"] = bool(ok)
    st["last_check_at"] = int(time.time())
    if ok:
        st["ok_streak"] = int(st.get("ok_streak", 0)) + 1
        st["fail_streak"] = 0
    else:
        st["fail_streak"] = int(st.get("fail_streak", 0)) + 1
        st["ok_streak"] = 0


def tunnel_ping_meta(cfg: dict, tid: str) -> dict:
    """Метаданные последней ping-проверки для API/панели."""
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


NOTIFY_SCRIPT = Path("/usr/local/sbin/awg-ntfy-notify.py")


def _notify_event(kind: str, payload: dict) -> None:
    if not NOTIFY_SCRIPT.is_file():
        return
    try:
        subprocess.run(
            [
                sys.executable,
                str(NOTIFY_SCRIPT),
                "event",
                "--kind",
                kind,
                "--json",
                json.dumps(payload, ensure_ascii=False),
            ],
            env={**os.environ, "AWG_WEBUI_CFG_DIR": str(CFG)},
            capture_output=True,
            timeout=15,
            check=False,
        )
    except Exception as ex:
        log(f"notify {kind}: {ex}")


def _tunnel_label(cfg: dict, tid: str) -> str:
    t = cfg.get(tid) if isinstance(cfg.get(tid), dict) else {}
    return str(t.get("label") or TUNNEL_DEFS.get(tid, {}).get("label") or tid)


def _assess_tunnel_alerts(cfg: dict, result: dict, *, fail_n: int) -> None:
    en = enabled_tunnels(cfg)
    if not en:
        return
    active = str(cfg.get("active") or en[0])
    checks = result.get("checks") if isinstance(result.get("checks"), dict) else {}
    hs = cfg.get("health_state", {})

    for tid in en:
        ok = bool(checks.get(tid))
        st = hs.get(tid, {}) if isinstance(hs, dict) else {}
        label = _tunnel_label(cfg, tid)
        if ok:
            _notify_event(
                "tunnel_unavailable_recovered",
                {"tunnel_id": tid, "tunnel_label": label},
            )
            continue
        fail_streak = int(st.get("fail_streak", 0) or 0)
        if fail_streak < fail_n:
            continue
        detail = "Ping через туннель недоступен."
        if len(en) >= 2 and not any(bool(checks.get(t)) for t in en):
            detail = "Все включённые туннели недоступны по ping."
        _notify_event(
            "tunnel_unavailable",
            {
                "tunnel_id": tid,
                "tunnel_label": label,
                "is_active": tid == active,
                "detail": detail,
            },
        )


def failover_once() -> dict:
    cfg = load_config()
    en = enabled_tunnels(cfg)
    health = cfg.get("health") if isinstance(cfg.get("health"), dict) else {}
    fail_n = int(health.get("fail_count", 3) or 3)
    recover_n = int(health.get("recover_count", 2) or 2)

    result = {"switched": False, "active": cfg.get("active"), "checks": {}}

    if len(en) == 0:
        save_config(cfg)
        return result
    if len(en) == 1:
        only = en[0]
        if cfg.get("active") != only:
            cfg["active"] = only
            save_config(cfg)
            sync_iface_env(cfg)
            run_systemctl("restart", "awg-webui-ifaces.service", timeout=45.0)
            restart_geo_refresh_if_needed()
            result["switched"] = True
            result["active"] = only
        for tid in TUNNEL_DEFS:
            if tid in en:
                ok = tunnel_health_ok(cfg, tid)
                result["checks"][tid] = ok
                update_streak(cfg, tid, ok)
            else:
                result["checks"][tid] = False
        save_config(cfg)
        result["active"] = cfg.get("active")
        _assess_tunnel_alerts(cfg, result, fail_n=fail_n)
        return result

    t1, t2 = "tunnel1", "tunnel2"
    ok1 = tunnel_health_ok(cfg, t1)
    ok2 = tunnel_health_ok(cfg, t2)
    result["checks"] = {t1: ok1, t2: ok2}
    update_streak(cfg, t1, ok1)
    update_streak(cfg, t2, ok2)

    active = str(cfg.get("active") or "tunnel1")
    prev_active = active
    _assess_tunnel_alerts(cfg, result, fail_n=fail_n)

    hs = cfg.get("health_state", {})
    s1 = hs.get(t1, {})
    s2 = hs.get(t2, {})

    new_active = active
    if active == t1:
        if int(s1.get("fail_streak", 0)) >= fail_n and ok2:
            new_active = t2
            log(f"failover: {t1} недоступен, {t2} OK — переключаем трафик на {t2}")
    elif active == t2:
        if ok1 and int(s1.get("ok_streak", 0)) >= recover_n:
            new_active = t1
            log(f"failover: {t1} восстановился — возвращаем трафик на {t1}")

    if new_active != active:
        cfg["active"] = new_active
        result["switched"] = True
        _notify_event(
            "tunnel_failover",
            {
                "from_tid": _tunnel_label(cfg, prev_active),
                "to_tid": _tunnel_label(cfg, new_active),
            },
        )

    save_config(cfg)
    sync_iface_env(cfg)
    active_if = ifname_for(cfg, cfg.get("active"))

    if result["switched"]:
        run_systemctl("restart", "awg-webui-ifaces.service", timeout=45.0)
        run_systemctl("restart", "awg-uplink-firewall.service", timeout=35.0)
        restart_geo_refresh_if_needed()
    elif geo_policy_needs_resync(active_if):
        log(f"geo: policy table не совпадает с {active_if} — обновляем georouting")
        restart_geo_refresh_if_needed()

    result["active"] = cfg.get("active")
    return result


def cmd_status() -> None:
    cfg = load_config()
    tunnels = {}
    for tid in TUNNEL_DEFS:
        ifname = ifname_for(cfg, tid)
        tunnels[tid] = {
            "id": tid,
            "ifname": ifname,
            "label": cfg.get(tid, {}).get("label") or TUNNEL_DEFS[tid]["label"],
            "enabled": bool(cfg.get(tid, {}).get("enabled")),
            "configured": conf_path(ifname).exists(),
            "link_up": link_up(ifname),
            "unit": systemd_unit(ifname),
            "is_active": tid == pick_active(cfg),
            **tunnel_ping_meta(cfg, tid),
        }
    en = enabled_tunnels(cfg)
    out = {
        "active": pick_active(cfg),
        "failover_enabled": len(en) >= 2,
        "health_watch_enabled": len(en) >= 1,
        "tunnels": tunnels,
        "health": cfg.get("health"),
        "health_state": cfg.get("health_state"),
    }
    print(json.dumps(out, ensure_ascii=False))


def cmd_watch() -> None:
    cfg = load_config()
    health = cfg.get("health") if isinstance(cfg.get("health"), dict) else {}
    interval = max(5, int(health.get("interval_sec", 30) or 30))
    log(f"watch: interval={interval}s")
    while True:
        try:
            failover_once()
        except Exception as ex:
            log(f"watch tick error: {ex}")
        time.sleep(interval)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    cmd = sys.argv[1].strip().lower()
    if cmd == "apply":
        apply_tunnels()
    elif cmd == "migrate":
        cmd_migrate()
    elif cmd == "failover-once":
        failover_once()
    elif cmd == "watch":
        cmd_watch()
    elif cmd == "status":
        cmd_status()
    else:
        log(f"unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()

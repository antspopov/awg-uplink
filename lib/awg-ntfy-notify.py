#!/usr/bin/env python3
"""Отправка push-уведомлений через self-hosted ntfy (HTTP API)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CFG = Path(os.environ.get("AWG_WEBUI_CFG_DIR", "/etc/awg-uplink-webui"))
NOTIFY_JSON = CFG / "notifications.json"

DEFAULT_ALERTS = {
    "tunnels": True,
    "list_update_errors": True,
    "service_start_errors": True,
}


def log(msg: str) -> None:
    print(f"[awg-ntfy-notify] {msg}", file=sys.stderr, flush=True)


def default_config() -> dict:
    return {
        "enabled": False,
        "server_url": "",
        "topic": "",
        "publish_token": "",
        "publisher_user": "awg-publisher",
        "alerts": dict(DEFAULT_ALERTS),
        "notify_state": {
            "tunnel_down_active": False,
            "tunnel_unavailable_notified": {},
            "last_tunnel_failover_ts": 0,
            "last_tunnel_down_ts": 0,
        },
    }


def _normalize_alerts(alerts) -> dict:
    out = dict(DEFAULT_ALERTS)
    if not isinstance(alerts, dict):
        return out
    if "tunnels" in alerts:
        out["tunnels"] = bool(alerts["tunnels"])
    elif "tunnel_failover" in alerts or "tunnel_down" in alerts:
        out["tunnels"] = bool(alerts.get("tunnel_failover", True)) or bool(alerts.get("tunnel_down", True))
    for key in ("list_update_errors", "service_start_errors"):
        if key in alerts:
            out[key] = bool(alerts[key])
    return out


def load_config() -> dict:
    base = default_config()
    if not NOTIFY_JSON.exists():
        return base
    try:
        raw = json.loads(NOTIFY_JSON.read_text(encoding="utf-8"))
    except Exception:
        return base
    if not isinstance(raw, dict):
        return base
    for key in ("enabled", "server_url", "topic", "publish_token", "publisher_user"):
        if key in raw:
            base[key] = raw[key]
    base["alerts"] = _normalize_alerts(raw.get("alerts"))
    ns = raw.get("notify_state")
    if isinstance(ns, dict):
        st = base["notify_state"]
        if "tunnel_down_active" in ns:
            st["tunnel_down_active"] = bool(ns["tunnel_down_active"])
        tun_nf = ns.get("tunnel_unavailable_notified")
        if isinstance(tun_nf, dict):
            st["tunnel_unavailable_notified"] = {
                str(k): bool(v) for k, v in tun_nf.items()
            }
        for ts_key in ("last_tunnel_failover_ts", "last_tunnel_down_ts"):
            if ts_key in ns:
                try:
                    st[ts_key] = int(ns[ts_key] or 0)
                except Exception:
                    pass
    return base


def save_config(cfg: dict) -> None:
    NOTIFY_JSON.parent.mkdir(parents=True, exist_ok=True)
    NOTIFY_JSON.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(NOTIFY_JSON, 0o600)
    except OSError:
        pass


def _normalize_server_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def subscribe_url(cfg: dict) -> str:
    base = _normalize_server_url(str(cfg.get("server_url") or ""))
    topic = str(cfg.get("topic") or "").strip().strip("/")
    if not base or not topic:
        return ""
    return f"{base}/{topic}"


def _priority_name(priority: int) -> str:
    if priority >= 5:
        return "high"
    if priority >= 4:
        return "default"
    if priority >= 3:
        return "low"
    return "min"


def _http_header_val(s: str) -> str:
    """urllib требует latin-1 в заголовках; ntfy принимает UTF-8 через utf-8→latin-1."""
    if not s:
        return ""
    return s.encode("utf-8").decode("latin-1")


def _publish_base_url(cfg: dict) -> str:
    internal = (os.environ.get("AWG_NTFY_INTERNAL_URL") or "http://127.0.0.1:8093").strip().rstrip("/")
    if internal:
        return internal
    return _normalize_server_url(str(cfg.get("server_url") or ""))


def send_message(
    title: str,
    message: str,
    *,
    priority: int = 4,
    tags: list[str] | None = None,
    cfg: dict | None = None,
) -> bool:
    cfg = cfg if cfg is not None else load_config()
    if not cfg.get("enabled"):
        return False
    topic = str(cfg.get("topic") or "").strip()
    token = str(cfg.get("publish_token") or "").strip()
    base = _publish_base_url(cfg)
    if not topic or not base:
        log("skip: server_url or topic missing")
        return False

    url = f"{base}/{topic}"
    headers = {
        "Title": _http_header_val((title or "AWG Split Gate")[:250]),
        "Priority": _priority_name(int(priority or 4)),
        "User-Agent": "awg-uplink-notify/1.0",
    }
    if tags:
        headers["Tags"] = ",".join(str(t).strip() for t in tags if str(t).strip())[:200]
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = (message or "").encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return 200 <= int(getattr(resp, "status", 200) or 200) < 300
    except urllib.error.HTTPError as ex:
        log(f"HTTP {ex.code}: {ex.reason}")
        return False
    except Exception as ex:
        log(f"send failed: {ex}")
        return False


def _alert_enabled(cfg: dict, name: str) -> bool:
    alerts = cfg.get("alerts") if isinstance(cfg.get("alerts"), dict) else {}
    return bool(alerts.get(name, DEFAULT_ALERTS.get(name, False)))


def notify_tunnel_failover(*, from_tid: str, to_tid: str, detail: str = "") -> bool:
    cfg = load_config()
    if not cfg.get("enabled") or not _alert_enabled(cfg, "tunnels"):
        return False
    title = "Переключение туннеля"
    msg = f"Активный туннель: {from_tid} → {to_tid}"
    if detail:
        msg = f"{msg}\n{detail}"
    ok = send_message(title, msg, priority=5, tags=["warning", "tunnel"], cfg=cfg)
    if ok:
        ns = cfg.setdefault("notify_state", {})
        ns["last_tunnel_failover_ts"] = int(time.time())
        save_config(cfg)
    return ok


def notify_tunnel_unavailable(
    *,
    tunnel_id: str,
    tunnel_label: str,
    detail: str = "",
    is_active: bool = False,
) -> bool:
    cfg = load_config()
    if not cfg.get("enabled") or not _alert_enabled(cfg, "tunnels"):
        return False
    tid = str(tunnel_id or "").strip()
    if not tid:
        return False
    ns = cfg.setdefault("notify_state", {})
    notified = ns.setdefault("tunnel_unavailable_notified", {})
    if not isinstance(notified, dict):
        notified = {}
        ns["tunnel_unavailable_notified"] = notified
    if notified.get(tid):
        return False
    label = str(tunnel_label or tid).strip()
    title = "Туннель недоступен"
    if is_active:
        msg = f"Нет связи через активный туннель ({label})."
    else:
        msg = f"Нет связи через туннель ({label})."
    if detail:
        msg = f"{msg}\n{detail}".strip()
    ok = send_message(title, msg, priority=5, tags=["rotating_light", "tunnel"], cfg=cfg)
    if ok:
        notified[tid] = True
        ns["tunnel_down_active"] = True
        ns["last_tunnel_down_ts"] = int(time.time())
        save_config(cfg)
    return ok


def notify_tunnel_unavailable_recovered(*, tunnel_id: str, tunnel_label: str) -> None:
    cfg = load_config()
    tid = str(tunnel_id or "").strip()
    if not tid:
        return
    ns = cfg.setdefault("notify_state", {})
    notified = ns.setdefault("tunnel_unavailable_notified", {})
    if not isinstance(notified, dict):
        notified = {}
        ns["tunnel_unavailable_notified"] = notified
    if not notified.pop(tid, None):
        return
    if not any(notified.values()):
        ns["tunnel_down_active"] = False
    save_config(cfg)
    if cfg.get("enabled") and _alert_enabled(cfg, "tunnels"):
        label = str(tunnel_label or tid).strip()
        send_message(
            "Туннель восстановлен",
            f"Связь через {label} снова доступна.",
            priority=4,
            tags=["white_check_mark", "tunnel"],
            cfg=cfg,
        )


def notify_tunnel_down(*, active_tid: str, detail: str = "") -> bool:
    """Legacy: полный простой (все туннели недоступны)."""
    return notify_tunnel_unavailable(
        tunnel_id="all",
        tunnel_label=active_tid,
        detail=detail,
        is_active=True,
    )


def notify_tunnel_recovered(*, active_tid: str) -> None:
    notify_tunnel_unavailable_recovered(tunnel_id="all", tunnel_label=active_tid)


def notify_list_update_error(*, list_kind: str, url: str, detail: str = "") -> bool:
    cfg = load_config()
    if not cfg.get("enabled") or not _alert_enabled(cfg, "list_update_errors"):
        return False
    kind_label = "IP" if str(list_kind).lower() == "ip" else "доменов"
    title = f"Ошибка обновления списка {kind_label}"
    msg = f"URL: {url}".strip()
    if detail:
        msg = f"{msg}\n{detail}".strip()
    return send_message(title, msg[:3500], priority=5, tags=["x", "clipboard"], cfg=cfg)


def notify_service_start_error(*, service: str, detail: str = "") -> bool:
    cfg = load_config()
    if not cfg.get("enabled") or not _alert_enabled(cfg, "service_start_errors"):
        return False
    title = "Ошибка запуска сервиса"
    svc = str(service or "service").strip()
    msg = svc
    if detail:
        msg = f"{svc}\n{detail}".strip()
    return send_message(title, msg[:3500], priority=5, tags=["x", "gear"], cfg=cfg)


def notify_test() -> bool:
    cfg = load_config()
    if not cfg.get("enabled"):
        return False
    return send_message(
        "Тест AWG Split Gate",
        "Уведомления ntfy настроены и работают.",
        priority=4,
        tags=["white_check_mark"],
        cfg=cfg,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="AWG Split Gate ntfy notifications")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="Send arbitrary notification")
    p_send.add_argument("--title", required=True)
    p_send.add_argument("--message", required=True)
    p_send.add_argument("--priority", type=int, default=4)
    p_send.add_argument("--tags", default="")

    p_event = sub.add_parser("event", help="Send predefined event notification")
    p_event.add_argument("--kind", required=True)
    p_event.add_argument("--json", default="{}")

    sub.add_parser("test", help="Send test notification")

    args = parser.parse_args()
    if args.cmd == "send":
        tags = [t.strip() for t in str(args.tags).split(",") if t.strip()]
        ok = send_message(args.title, args.message, priority=args.priority, tags=tags or None)
        return 0 if ok else 1
    if args.cmd == "test":
        return 0 if notify_test() else 1
    if args.cmd == "event":
        try:
            payload = json.loads(args.json or "{}")
        except Exception:
            payload = {}
        kind = str(args.kind)
        if kind == "tunnel_failover":
            ok = notify_tunnel_failover(
                from_tid=str(payload.get("from_tid", "?")),
                to_tid=str(payload.get("to_tid", "?")),
                detail=str(payload.get("detail", "")),
            )
        elif kind == "tunnel_unavailable":
            ok = notify_tunnel_unavailable(
                tunnel_id=str(payload.get("tunnel_id", "")),
                tunnel_label=str(payload.get("tunnel_label", "")),
                detail=str(payload.get("detail", "")),
                is_active=bool(payload.get("is_active")),
            )
        elif kind == "tunnel_unavailable_recovered":
            notify_tunnel_unavailable_recovered(
                tunnel_id=str(payload.get("tunnel_id", "")),
                tunnel_label=str(payload.get("tunnel_label", "")),
            )
            ok = True
        elif kind == "tunnel_down":
            ok = notify_tunnel_down(
                active_tid=str(payload.get("active_tid", "?")),
                detail=str(payload.get("detail", "")),
            )
        elif kind == "tunnel_recovered":
            notify_tunnel_recovered(active_tid=str(payload.get("active_tid", "?")))
            ok = True
        elif kind == "list_update_error":
            ok = notify_list_update_error(
                list_kind=str(payload.get("list_kind", "list")),
                url=str(payload.get("url", "")),
                detail=str(payload.get("detail", "")),
            )
        elif kind == "service_start_error":
            ok = notify_service_start_error(
                service=str(payload.get("service", "service")),
                detail=str(payload.get("detail", "")),
            )
        else:
            log(f"unknown event kind: {kind}")
            return 2
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

# AWG Split Gate — web UI

Веб-интерфейс управления шлюзом (репозиторий и пути установки по-прежнему `awg-uplink`).

Сейчас:
- Есть **авторизация**: отдельная страница входа + digest (challenge-response) и cookie-сессия.
- Есть **визуальные** секции настроек (tunnel/egress/ingress).
- Чтение статуса/интерфейсов идёт через `ip` (без применения настроек).

## Запуск (локально на сервере)

Требуется Python 3.

```bash
cd webui
AWG_UI_USER=admin AWG_UI_PASS=admin python3 server.py --host 0.0.0.0 --port 8080
```

Откройте в браузере: `http://<server-ip>:8080/` (перенаправит на `/login.html`)

## Запуск под дополнительным путём

Например, если нужно обслуживать UI как `ip:port/ui/`:

```bash
cd webui
AWG_UI_USER=admin AWG_UI_PASS=admin python3 server.py --host 0.0.0.0 --port 8080 --base-path /ui/
```

## Параметры

- `AWG_UI_USER`: логин (обязательно)
- `AWG_UI_PASS`: пароль (обязательно)

Если не заданы, сервер откажется стартовать (чтобы случайно не поднять UI без пароля).

## Отключить авторизацию (для отладки)

```bash
cd webui
python3 server.py --host 0.0.0.0 --port 8080 --no-auth
```


# awg-uplink

Набор скриптов для Linux-сервера с **AmneziaVPN в Docker**: поднимается отдельный интерфейс **AmneziaWG** `awg-uplink`, policy routing (uplink по умолчанию через туннель), опционально **MTProto-прокси** ([mtproto.zig](https://github.com/sleep3r/mtproto.zig) через **mtbuddy**).

Исходный экспортированный `.conf` из приложения **только читается**; в систему пишется канонический конфиг и hook’и.

## Требования

- **root** (apt, `/etc`, `systemctl`, Docker).
- Уже развёрнут и **запущен** контейнер Amnezia (AmneziaWG). По умолчанию имя контейнера ищется по шаблону **`^amnezia-awg`** (`amnezia-awg`, `amnezia-awg2`, …). Свой шаблон: `AMNEZIA_DOCKER_NAME_PATTERN`; явный список имён: `AMNEZIA_DOCKER_NAMES="имя1 имя2"`.
- **Docker** доступен (`docker ps`).
- Поддерживаемый дистрибутив для установки **amneziawg** из пакета (см. скрипт) или сборка из исходников (`--amneziawg-from-source`).

## Быстрый старт

```bash
git clone https://github.com/antspopov/awg-uplink.git
cd awg-uplink
sudo ./awg-uplink-bootstrap.sh /путь/к/exported.conf
```

После успеха: `systemctl status awg-quick@awg-uplink`.

Полный список опций и переменных окружения:

```bash
./awg-uplink-bootstrap.sh --help
```

## Что делает `awg-uplink-bootstrap.sh`

1. Проверяет, что контейнер Amnezia в Docker запущен.
2. Ставит **amneziawg** (из PPA/Launchpad или из Git + DKMS при `--amneziawg-from-source`).
3. Запускает **`lib/awg-inject-uplink-policy.sh`**: готовит `/etc/amnezia/amneziawg/awg-uplink.conf`, `awg-uplink-policy.sh`, `awg-uplink-policy.env`, PostUp/PostDown; копирует systemd drop-in при наличии `systemctl`.
4. Включает и перезапускает **`awg-quick@awg-uplink`**.
5. Опционально (`--with-mtproto-proxy`): **mtbuddy** install, правки `public_ip` / `middle_proxy_nat_ip` / `drs` в `/opt/mtproto-proxy/config.toml`, дашборд и nginx для `/dashboard/` — см. `--help`.

## Примеры запуска

Только AmneziaWG и uplink (без MTProto):

```bash
sudo ./awg-uplink-bootstrap.sh ~/Downloads/amnezia_exported.conf
```

Без PPA — сборка модуля и **amneziawg-tools** из исходников:

```bash
sudo ./awg-uplink-bootstrap.sh --amneziawg-from-source ~/Downloads/amnezia_exported.conf
```

С MTProto-прокси (порт 443, домен маскировки по умолчанию из скрипта):

```bash
sudo ./awg-uplink-bootstrap.sh --with-mtproto-proxy ~/Downloads/amnezia_exported.conf
```

Параметры MTProto (порт, домен, секрет, `public_ip`, дашборд, nginx и т.д.) — в **`--help`** и через переменные окружения (`MTPROTO_*`, `WITH_MTPROTO_PROXY=1`).

## Split-routing (разные адреса для клиентов и для исходящего трафика)

Если на сервере несколько публичных IPv4 (например на `eth0`), можно:

- выбрать **ingress** — адрес, на который клиенты стучатся в WireGuard (правило `ip rule from <ingress> → table uplink`);
- выбрать **egress** — адрес и интерфейс, с которых должен уходить **общий** трафик ОС и маршрутизация uplink в таблице `200` (в т.ч. `src=` на default в policy table).

Интерактивный мастер (нужен TTY):

```bash
sudo ./lib/awg-uplink-split-wizard.sh
```

Или вместе с bootstrap (после inject):

```bash
sudo ./awg-uplink-bootstrap.sh --split-routing-wizard /путь/к/exported.conf
```

После мастера: файл **`/etc/awg-uplink-split.env`** (общесистемный, не привязан к каталогу Amnezia), unit **`awg-uplink-split@<iface>.service`**, скрипт **`/usr/local/sbin/awg-uplink-split-main.sh`** — при поднятии линка выставляет в **main** таблице default IPv4 с `src=<egress>`. Hook **`awg-uplink-policy.sh`** читает тот же файл при PostUp (путь можно переопределить переменной **`AWG_UPLINK_SPLIT_ENV`** в `awg-uplink-policy.env`). Старый путь `…/amneziawg/awg-uplink-split.env` подхватывается только если нового файла ещё нет.

Отключить split: удалите или задайте `AWG_SPLIT_ENABLE=0` в `/etc/awg-uplink-split.env`, затем `systemctl disable awg-uplink-split@…` и при необходимости перезапустите `awg-quick@awg-uplink`.

## Только обновить конфиг и policy (без apt / MTProto)

Если amneziawg уже стоит и нужно перелить новый экспорт в канонический конфиг:

```bash
sudo ./lib/awg-inject-uplink-policy.sh /путь/к/любому_exported.conf
```

Подробности полей **`awg-uplink-policy.env`**: `./lib/awg-inject-uplink-policy.sh --help`.

При записи канона из экспорта Amnezia автоматически:

- удаляются пустые строки вида **`I2 =`**, **`I3 =`**, … (awg-quick на них ругается);
- из **`AllowedIPs`** убираются IPv6-элементы (например `::/0`), остаётся IPv4.

## Файлы в системе (после bootstrap / inject)

| Назначение | Путь |
|------------|------|
| Конфиг интерфейса | `/etc/amnezia/amneziawg/awg-uplink.conf` |
| PostUp / PostDown hook | `/etc/amnezia/amneziawg/awg-uplink-policy.sh` |
| Параметры policy | `/etc/amnezia/amneziawg/awg-uplink-policy.env` |
| Split-routing (если настроено) | `/etc/awg-uplink-split.env`, `systemctl status awg-uplink-split@eth0` (имя интерфейса из мастера) |
| systemd drop-in (если скопирован) | `/etc/systemd/system/awg-quick@awg-uplink.service.d/override.conf` |
| MTProto (если ставили) | `/opt/mtproto-proxy/config.toml`, unit `mtproto-proxy` |

## Внешние ссылки

- [AmneziaWG (ядро и tools)](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)  
- [mtproto.zig / mtbuddy](https://github.com/sleep3r/mtproto.zig)

## Лицензия

В репозитории скрипты помечены **GPL-2.0** (см. заголовки файлов).

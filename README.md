# RU whitelist -> sing-box rule-sets

Скрипт регулярно скачивает белые списки российского мобильного интернета,
создаёт rule-set для sing-box в форматах JSON и SRS и загружает изменившиеся
файлы в указанный репозиторий GitHub.

Дополнительные Python-пакеты не нужны. sing-box скачивается автоматически из
релизов GitHub и сохраняется в локальном кэше.

## Быстрый старт

1. Скопируйте `.env.example` в `.env`.
2. Укажите токен GitHub и репозиторий назначения:

  GH_PAT=ваш_github_token
  DEPLOY_REPO=LaronDambon/sing-box-src

3. Запустите одну проверку:

  python sync_whitelist.py

Для токена нужен доступ `Contents: Read and write` к репозиторию назначения.
Токен хранится только в `.env`; этот файл не добавляется в Git.

## Куда загружаются файлы

По умолчанию файлы копируются в корень `DEPLOY_REPO`. Чтобы использовать
отдельную папку, укажите путь в `.env`:

  DEPLOY_DIR=rulesets

Или:

  DEPLOY_DIR=config/sing-box/rulesets

В выбранную папку загружаются:

- `whitelist-ru.json` и `whitelist-ru.srs` — домены;
- `ipwhitelist-ru.json` и `ipwhitelist-ru.srs` — IP-адреса.

## Как работает проверка

1. Скачивает `whitelist.txt` и `ipwhitelist.txt` из исходного репозитория.
2. Сравнивает SHA-256 с `work/state.json`.
3. Если данные изменились, создаёт JSON rule-set.
4. Компилирует JSON в `.srs` с помощью sing-box.
5. Клонирует `DEPLOY_REPO`, копирует файлы, создаёт коммит и выполняет push.

Если списки не изменились, скрипт ничего не собирает и не отправляет.

## Настройки

Все параметры задаются переменными окружения или в `.env`:

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `GH_PAT` | нет | GitHub-токен для записи в репозиторий |
| `DEPLOY_REPO` | нет | Репозиторий назначения в формате `owner/name` |
| `DEPLOY_BRANCH` | `main` | Ветка для push |
| `DEPLOY_DIR` | корень | Папка внутри репозитория назначения |
| `SRC_REPO` | `hxehex/russia-mobile-internet-whitelist` | Исходный репозиторий |
| `SRC_BRANCH` | `main` | Ветка исходного репозитория |
| `SING_BOX_PATH` | авто | Путь к готовому бинарнику sing-box |
| `SING_BOX_VERSION` | `latest` | Версия sing-box для скачивания |
| `RULESET_VERSION` | `5` | Версия формата rule-set |
| `NO_COMPILE` | `0` | `1` — создавать только JSON |
| `COMMIT_ON_CHANGES` | `1` | `0` — копировать без коммита и push |
| `DRY_RUN` | `0` | `1` — тест без изменений в GitHub |
| `DAEMON` | `0` | `1` — запуск в постоянном режиме |
| `CHECK_INTERVAL_HOURS` | `24` | Интервал проверок в daemon-режиме |
| `WORK_DIR` | `work` | Кэш, состояние и временные файлы |

## Постоянный запуск

### Windows

Для непрерывной работы запустите:

  python sync_whitelist.py --daemon

Скрипт проверяет списки каждые 24 часа. Интервал можно изменить:

  python sync_whitelist.py --daemon --interval 6

Эту команду можно запускать через Планировщик заданий Windows или NSSM.

### Linux и systemd

Создайте `/etc/systemd/system/sync-whitelist.service`:

  [Unit]
  Description=RU whitelist sing-box rules sync
  After=network-online.target

  [Service]
  WorkingDirectory=/opt/singbox-whitelist
  Environment=GH_PAT=ваш_github_token
  Environment=DEPLOY_REPO=owner/repository
  ExecStart=/usr/bin/python3 sync_whitelist.py --daemon
  Restart=on-failure

  [Install]
  WantedBy=multi-user.target

Запустите сервис:

  sudo systemctl enable --now sync-whitelist

Остановить его можно командой:

  sudo systemctl stop sync-whitelist

## Использование в sing-box

  {
    "route": {
      "rule_set": [
        { "type": "local", "tag": "ru-domains", "path": "whitelist-ru.srs" },
        { "type": "local", "tag": "ru-ips", "path": "ipwhitelist-ru.srs" }
      ],
      "rules": [
        { "rule_set": ["ru-domains", "ru-ips"], "outbound": "direct" }
      ]
    }
  }

Файлы также можно подключить напрямую через raw-ссылки GitHub как remote
rule-set.

## Коды завершения

- `0` — успешно или изменений нет;
- `1` — ошибка сети, компиляции или Git;
- `2` — не удалось скачать ни один список.

## Файлы проекта

- `sync_whitelist.py` — основной скрипт;
- `.env.example` — пример конфигурации;
- `sing-box/` — локальные бинарники и лицензия;
- `work/` — локальный кэш, состояние, собранные файлы и клон репозитория.
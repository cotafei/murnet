# MurNet

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Experimental](https://img.shields.io/badge/status-experimental-orange)](docs/ARCHITECTURE.md)

**MurNet** — экспериментальная децентрализованная P2P-сеть с onion-маршрутизацией, DHT и VPN-туннелем.

Узлы связываются напрямую, без центральных серверов. Трафик проходит через многослойное шифрование (X25519 + AES-256-GCM). Архитектура построена по принципу **security by design**.

> ⚠️ **Учебный прототип.** Не прошёл криптографический аудит. Не использовать для трафика, требующего реальной анонимности.

---

## Возможности

| Компонент | Описание |
|---|---|
| **Onion routing** | 3-хоп circuit, X25519 ECDH + AES-256-GCM |
| **Relay discovery** | Gossip-анонсы — relay-ноды находят друг друга автоматически |
| **DHT** | Kademlia с HMAC-аутентификацией |
| **VPN / SOCKS5** | Туннель TCP-трафика через onion-цепочку |
| **Identity** | Ed25519 ключи, Base58 адреса, NodeID на Blake2b |
| **REST API** | FastAPI для управления узлом |
| **TUI Chat** | Textual-интерфейс для anonymous-чата в терминале |

---

## Установка

```bash
pip install murnet                    # из PyPI (стабильная)
pip install -e .                      # из исходников (dev)
pip install -e ".[tui,dev]"           # с extras
```

Дополнительные extras:

| Extra | Назначение |
|---|---|
| `tui` | Textual TUI для `murnet-node` chat-режима |
| `browser` | PyQt6 для onion-браузера |
| `build` | PyInstaller для сборки EXE |
| `dev` | pytest, pytest-asyncio, pytest-cov |

Python 3.11+ обязателен.

---

## Быстрый старт

После установки доступны команды:

| Команда | Что делает |
|---|---|
| `murnet` | CLI полного узла |
| `murnet-node` | Relay-нода или chat-участник |
| `murnet-vpn` | VPN/SOCKS5 клиент |
| `murnet-desktop` | Desktop GUI |

### Onion-чат (5 терминалов, localhost)

```bash
# 3 relay-ноды, каждая анонсирует себя в gossip
murnet-node --bind 127.0.0.1:9001 --name Guard  --announce
murnet-node --bind 127.0.0.1:9002 --name Middle --announce
murnet-node --bind 127.0.0.1:9003 --name Exit   --announce

# Bob — строит circuit Exit → Middle → Alice
murnet-node --bind 127.0.0.1:9004 --name Bob \
    --peer Exit=127.0.0.1:9003 --peer Middle=127.0.0.1:9002 \
    --peer Alice=127.0.0.1:9000 --circuit Exit,Middle,Alice

# Alice — auto-discovery, знает только Guard
murnet-node --bind 127.0.0.1:9000 --name Alice \
    --peer Guard=127.0.0.1:9001 --circuit auto
```

### VPN / SOCKS5

```bash
murnet-vpn --mode local
# SOCKS5 прокси на 127.0.0.1:1080
curl --socks5 127.0.0.1:1080 http://example.com
```

### Полный узел

```bash
murnet --port 8888 --data-dir ./murnet-data
```

---

## Программный API

```python
from murnet import MurnetNode, Identity, MurnetConfig

# Идентификация узла (Ed25519)
identity = Identity.generate()
print(identity.node_id)        # Blake2b NodeID
print(identity.address)        # Base58 адрес

# Запуск узла
config = MurnetConfig(port=8888, data_dir="./data")
node = MurnetNode(identity, config)
await node.start()
```

Onion-цепочки:

```python
from murnet.core.onion.circuit import CircuitManager
from murnet.core.onion.router import OnionRouter

router = OnionRouter(identity)
circuit = await router.build_circuit(["Guard", "Middle", "Exit"])
await router.send(circuit.id, b"hello onion")
```

---

## Структура проекта

```
murnet/                      ← Python-пакет
├── __init__.py              реэкспорты публичного API
├── cli.py                   точка входа `murnet`
├── desktop_app.py           точка входа `murnet-desktop`
├── murnet_vpn.py            VPN runtime
├── network_viz.py           визуализатор сети
├── build_exe.py             PyInstaller сборка
├── core/
│   ├── identity/            Ed25519, X25519, NodeID, keystore
│   ├── net/                 UDP transport, Kademlia DHT, link-state routing
│   ├── onion/               onion routing: cell, circuit, router, transport
│   ├── node/                AsyncMurnetNode, pubsub
│   ├── data/                content-addressed storage, SQLite
│   ├── vpn/                 TunnelManager, SOCKS5 server
│   └── config.py
├── api/                     FastAPI server, JWT auth, Pydantic-модели
├── demos/                   onion_node.py, onion_chat.py, vpn_client.py
├── mobile/                  battery, network, sync — оптимизации для мобильных
└── vds/                     Docker/systemd генераторы для VDS-деплоя

docs/                        Документация
tests/                       pytest: unit/, integration/, security/, performance/
scripts/                     CLI-скрипты (генерация конфига, миграция, статус)
configs/                     Шаблоны конфигов VPN
```

---

## Тесты

```bash
pip install -e ".[dev]"

pytest tests/unit/ -q                       # 460+ unit-тестов
pytest tests/integration/ -v --timeout=60   # e2e onion circuit
pytest tests/security/ -v                   # security-проверки
pytest --cov=murnet --cov-report=term-missing
```

---

## Архитектура (коротко)

```
Alice  →  Guard  →  Middle  →  Bob
         видит        видит        видит
         Alice        Guard        Middle
         Guard        Middle       (расшифрованные данные)
```

Каждый хоп получает независимый сессионный ключ через X25519 ECDH + HKDF-SHA256. Компрометация одного хопа не раскрывает остальные.

Подробности: [docs/ONION.md](docs/ONION.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md).

---

## NAT и где живут узлы

| Сценарий | Что нужно |
|---|---|
| **VDS с публичным IP** | Открыть TCP-порт через firewall — узел работает как relay |
| **Домашний компьютер за роутером** | Сейчас — только client-режим (инициирует, не принимает). UPnP/STUN — в roadmap |
| **CGNAT / симметричный NAT** | Только client. Hole-punching через rendezvous-relay — в roadmap |

Обратные ответы идут по тому же TCP-соединению, что инициировал клиент, — relay никогда не открывает обратное соединение, поэтому клиент за NAT может пользоваться сетью, но не быть relay'ем. Подробнее: [docs/ONION.md](docs/ONION.md#nat-traversal).

---

## VDS деплой relay-нод

```bash
# Деплой Guard/Middle/Exit через SCP + systemd
./scripts/vds.sh deploy

# Статус (curl на API каждой ноды)
./scripts/vds.sh status

# Логи
./scripts/vds.sh logs Guard
```

Подробности: [docs/VDS.md](docs/VDS.md).

---

## Документация

| Файл | Содержание |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Архитектура узла, слои, потоки данных |
| [docs/ONION.md](docs/ONION.md) | Onion routing: протокол, циклы CREATE/EXTEND, NAT, gossip |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | UDP wire-протокол, форматы сообщений |
| [docs/API.md](docs/API.md) | REST API, JWT-аутентификация, эндпоинты |
| [docs/VDS.md](docs/VDS.md) | Деплой на VDS, systemd, Docker, мониторинг |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Сборка, тесты, contributing |
| [docs/MOBILE.md](docs/MOBILE.md) | Мобильные оптимизации (battery, network, sync) |

---

## Безопасность

Это **учебный** проект:

- Криптографический аудит **не проводился**
- Анонимность гарантирована только при наличии многих независимых relay-нод
- В текущей конфигурации (3 узла на одном VDS) — анонимности фактически нет, маршрутизация декоративная
- TLS-обёртка отключена из-за DPI — узлы используют голый X25519+PSK

Не использовать для угроз жизни, медицинских данных, юридически чувствительной переписки. Для этого есть [Tor](https://www.torproject.org/), [I2P](https://geti2p.net/), [Briar](https://briarproject.org/).

---

## Лицензия

MIT — см. [LICENSE](LICENSE).

# MurNet v6.2

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Experimental](https://img.shields.io/badge/status-experimental-orange)](docs/ARCHITECTURE.md)
[![CI](https://github.com/cotafei/murnet/actions/workflows/build.yml/badge.svg)](https://github.com/cotafei/MurNet/actions/workflows/build.yml)

**MurNet** — децентрализованная P2P-сеть с onion routing, DHT и VPN-туннелем.

Узлы связываются напрямую, без центральных серверов. Весь трафик проходит через многоуровневое шифрование (X25519 + AES-256-GCM). Проект построен по принципу **Security by Design**.

> **Важно:** Экспериментальный прототип для образовательных целей. Не прошёл аудит безопасности.

---

## Возможности v6.2

| Компонент | Описание |
|---|---|
| **Onion routing** | 3-хоп circuit, X25519 ECDH + AES-256-GCM, NAT traversal |
| **Relay discovery** | Gossip-анонсы — находит relay-ноды автоматически |
| **VPN / SOCKS5** | Туннель TCP-трафика через MurNet P2P |
| **DHT** | Kademlia-хранилище с HMAC-аутентификацией |
| **Link-state routing** | Signed LSA, Dijkstra, ECMP |
| **Identity** | Ed25519 ключи, Base58 адреса, Blake2b NodeID |
| **REST API** | FastAPI для управления узлом и relay-статусом |
| **TUI Chat** | Textual-интерфейс для onion-чата в терминале |

---

## Быстрый старт

```bash
git clone https://github.com/cotafei/MurNet.git
cd MurNet
pip install -r requirements.txt
```

### Onion chat — 5 терминалов

```bash
# Relay-ноды (анонсируют себя через gossip)
python demos/onion_node.py --bind 127.0.0.1:9001 --name Guard  --announce
python demos/onion_node.py --bind 127.0.0.1:9002 --name Middle --announce
python demos/onion_node.py --bind 127.0.0.1:9003 --name Exit   --announce

# Bob
python demos/onion_node.py --bind 127.0.0.1:9004 --name Bob \
    --peer Exit=127.0.0.1:9003 --peer Middle=127.0.0.1:9002 \
    --peer Alice=127.0.0.1:9000 --circuit Exit,Middle,Alice

# Alice (auto-discovery через Guard)
python demos/onion_node.py --bind 127.0.0.1:9000 --name Alice \
    --peer Guard=127.0.0.1:9001 --peer Bob=127.0.0.1:9004 \
    --circuit auto
```

### In-process демо (1 терминал, требует `textual`)

```bash
python demos/onion_chat.py
```

### VPN / SOCKS5

```bash
python demos/vpn_client.py --mode local
# SOCKS5 прокси на 127.0.0.1:1080
curl --socks5 127.0.0.1:1080 http://example.com
```

### Полный узел

```bash
python desktop_app.py --port 8888
# или CLI:
python cli.py --port 8888
```

---

## Структура проекта

```
core/
  onion/      — onion routing (cell, hop_key, circuit, router, transport, directory)
  net/        — UDP transport, link-state routing, DHT, protocol
  identity/   — Ed25519/X25519 ключи, Base58 адреса, NodeID
  node/       — AsyncMurnetNode, PubSub (gossip pub/sub)
  data/       — content-addressed ObjectStore, SQLite
  vpn/        — TunnelManager (TCP-over-MurNet), SOCKS5 server
api/
  server.py       — FastAPI полного узла
  onion_api.py    — лёгкий HTTP API relay-ноды
demos/
  onion_chat.py   — all-in-one TUI демо
  onion_node.py   — relay / chat участник (real TCP)
  vpn_client.py   — VPN SOCKS5 демо
tests/
  unit/           — юнит-тесты (150+ тестов)
  integration/    — e2e тесты onion circuit
  security/       — security тесты
scripts/
  vds.sh          — управление relay-нодами на VDS
docs/
  ONION.md        — onion routing протокол и wire-формат
  ARCHITECTURE.md — архитектура узла
  PROTOCOL.md     — UDP wire-протокол
  API.md          — REST API
```

---

## Тесты

```bash
pip install pytest pytest-asyncio pytest-cov

# Все юнит-тесты
pytest tests/unit/ -q

# С покрытием
pytest tests/unit/ --cov=core --cov-report=term-missing

# E2E onion тесты
pytest tests/integration/test_onion_e2e.py -v
```

---

## VDS деплой relay-нод

```bash
# Деплой и запуск Guard/Middle/Exit на 80.93.52.15
./scripts/vds.sh deploy

# Статус + curl API каждой ноды
./scripts/vds.sh status

# Логи
./scripts/vds.sh logs Guard
```

API статус: `http://<VDS>:8081/api/status` (Guard), `:8082` (Middle), `:8083` (Exit)

---

## Документация

- [ONION.md](docs/ONION.md) — onion routing: протокол, NAT, gossip
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — архитектура узла
- [PROTOCOL.md](docs/PROTOCOL.md) — UDP wire-протокол
- [API.md](docs/API.md) — REST API
- [VDS.md](docs/VDS.md) — деплой на сервер

---

## Зависимости

```bash
pip install cryptography fastapi uvicorn textual
```

Python 3.11+. Полный список в [requirements.txt](requirements.txt).

---

## Лицензия

MIT — [LICENSE](LICENSE)

# Руководство разработчика — Murnet v6.2.3

> **Дисклеймер.** Murnet является экспериментальным студенческим проектом.
> Pull Request'ы с новой функциональностью должны сопровождаться тестами.
> Криптографические изменения требуют отдельного обоснования.

---

## Требования

- Python 3.11+
- Git

---

## Настройка окружения

```bash
git clone https://github.com/cotafei/MurNet.git
cd MurNet

python -m venv venv
source venv/bin/activate      # Linux/macOS
# venv\Scripts\activate       # Windows

pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov
```

---

## Структура проекта

```
MurNet/
├── core/
│   ├── config.py        — Конфигурация (профили: mobile, vds, desktop)
│   ├── integrity.py     — Layer 1: Ed25519-подпись сборки, TamperedBuildError (v6.2.2)
│   ├── net/
│   │   ├── transport.py      — UDP-транспорт, HMAC-аутентификация, replay-защита
│   │   ├── async_transport.py — asyncio DatagramProtocol
│   │   ├── routing.py        — Link-State протокол, Dijkstra, LSA, Trust Score
│   │   ├── dht_rpc.py        — DHT RPC сетевой уровень
│   │   ├── protocol.py       — Типизированные сообщения v6.1 (HelloMsg, DataMsg)
│   │   ├── murnaked.py       — DHT верхнего уровня (Kademlia)
│   │   └── network_auth.py   — Layer 3: HMAC-SHA256 Network Secret (v6.2.2)
│   ├── identity/
│   │   ├── crypto.py         — Ed25519, AES-GCM, Argon2id, Blake2b, Base58
│   │   ├── identity.py       — NodeID (Blake2b), IdentityStore, XOR-метрика
│   │   └── keystore.py       — EncryptedKeystore, Argon2id+AES-GCM (v6.2.1)
│   ├── data/
│   │   ├── storage.py        — SQLite, LRU-кеш, сжатие
│   │   ├── objects.py        — MurObject, ObjectStore (v6.2)
│   │   └── migrations.py     — Версионированные миграции БД
│   └── node/
│       ├── node.py           — SecureMurnetNode (потоки)
│       ├── async_node.py     — AsyncMurnetNode (asyncio, основной)
│       └── pubsub.py         — PubSubManager, topic_id (v6.2)
├── api/
│   ├── server.py        — FastAPI, JWT, security middleware
│   └── models.py        — Pydantic-модели
├── mobile/
│   ├── battery.py       — Оптимизация батареи
│   ├── network.py       — Адаптация к типу сети
│   ├── sync.py          — Очередь синхронизации
│   └── push.py          — Push-уведомления (FCM/APNS/webhook)
├── vds/
│   ├── docker.py        — Генератор Docker-конфигов
│   ├── monitoring.py    — Prometheus-метрики, HealthChecker
│   └── systemd.py       — Генератор systemd-юнитов
├── scripts/
│   ├── deploy.sh        — Деплой на VDS (venv, systemd)
│   ├── backup.sh        — Резервное копирование данных
│   ├── node_status.py   — Проверка состояния узла через API
│   └── generate_config.py — Генератор config.yaml
├── tests/
│   ├── conftest.py      — Общие фикстуры
│   ├── unit/            — Юнит-тесты
│   ├── integration/     — Интеграционные тесты (2–3 узла)
│   ├── simulation/      — Симуляции многоузловой сети (реальные сокеты)
│   ├── security/        — Тесты безопасности
│   └── performance/     — Нагрузочные тесты
├── network_viz.py       — Визуализатор топологии сети (force-directed, tkinter, v6.2.1)
├── tools/
│   └── sign_build.py    — CLI для подписи и верификации сборок (v6.2.2)
├── setup_cython.py      — Layer 4: компиляция core/identity/ в .so/.pyd (v6.2.2)
├── BUILD_SIGNATURE      — Ed25519-подпись текущей сборки (обновлять при каждом релизе)
├── docs/                — Документация
├── requirements.txt
└── README.md
```

---

## v6.2.2–6.2.3 — Security Layers

### Workflow: вносишь изменения в `core/`

После любого изменения файлов в `core/` нужно переподписать сборку:

```bash
# Подписать (требует build_key.pem — только у владельца)
python tools/sign_build.py --sign --key-file build_key.pem

# Убедиться что подпись валидна
python tools/sign_build.py --verify   # → OK

# Закоммитить новую подпись вместе с изменениями
git add BUILD_SIGNATURE core/... && git commit -m "..."
```

Если пропустить этот шаг — `verify_integrity()` при старте любого узла выбросит `TamperedBuildError`.

### Network Secret

Все узлы в официальной сети используют хардкодный секрет из `core/net/network_auth.py`.
Для тестовой/приватной сети можно переопределить через env-var:

```bash
export MURNET_SECRET=<новый_64_char_hex>
```

**Никогда не заменяй хардкодный секрет в `network_auth.py`** без переподписи сборки —
иначе официальные узлы отклонят рукопожатие.

### Тесты security-слоёв

```bash
# Layer 3 — Network Secret (20 тестов)
python -m pytest tests/unit/test_network_auth.py -v

# Layer 1 — Build Signing (15 тестов)
python -m pytest tests/unit/test_integrity.py -v

# Интеграция обоих слоёв с Transport
python -m pytest tests/security/test_security_layers.py -v
```

---

## v6.2.1 — Security Hardening

### Encrypted Keystore (`core/identity/keystore.py`)

Хранит приватный ключ узла под паролем пользователя (нет пароля — нет доступа):

```python
from core.keystore import EncryptedKeystore, WrongPasswordError, WeakPasswordError

ks = EncryptedKeystore("./data")

# Первый запуск — создание
if not ks.exists():
    ks.create(identity.to_bytes(), password="мой_пароль_123")

# Разблокировка
try:
    key_bytes = ks.load("мой_пароль_123")   # Argon2id + AES-256-GCM
    identity = Identity.from_bytes(key_bytes)
except WrongPasswordError:
    print("Неверный пароль")   # + автоматическая задержка ~0.5–0.8 с
```

**Что обеспечивает:**
- `create()` — Argon2id(time=3, mem=64MB) → 32-byte key → AES-256-GCM encrypt → JSON файл с правами `0o600`
- `load()` — задержка `0.5 + random(0..0.3)` сек при неверном пароле (антибрутфорс)
- `change_password(old, new)` — атомарная смена без копирования ключа в открытом виде
- `wipe()` — перезапись случайными байтами + `fsync` + удаление (best-effort; см. ограничения SSD)
- version migration: v1 формат (nonce inside ciphertext) читается автоматически
- memory hygiene: ключ деривируется в `bytearray`, обнуляется в `finally`

**AsyncMurnetNode** принимает `password=` в конструкторе:

```python
# Первый запуск — создаёт keystore
node = AsyncMurnetNode(data_dir="./data", port=8888, password="мой_пароль_123")

# Последующие — разблокировка; WrongPasswordError если неверный
node = AsyncMurnetNode(data_dir="./data", port=8888, password="мой_пароль_123")
```

**CLI:** при старте вызывает `prompt_password_cli()` — getpass, двойной ввод при создании.

**Desktop GUI:** `PasswordDialog` — диалог с тёмной темой, режимы create/unlock/change, показ/скрытие пароля.

### Network Visualizer (`network_viz.py`)

Автономный визуализатор топологии (force-directed layout, tkinter):

```bash
# Demo-режим (не нужен реальный узел)
python network_viz.py --demo

# Реальный API
python network_viz.py --api http://127.0.0.1:8080 --token <JWT> --poll 5
```

---

## v6.2 — Новые модули

### Object System (`core/data/objects.py`)

Контент-адресуемые, подписываемые объекты:

```python
from core.objects import MurObject, ObjectStore
from core.identity import NodeIdentity

identity = NodeIdentity(private_key_bytes=node.identity.to_bytes())
store = ObjectStore("./data")

# Создание и подпись объекта
obj = MurObject.create(
    obj_type="msg",
    owner=node.address,
    data={"text": "Привет!", "to": "1RecipAddr..."},
    identity=identity,
)
print(obj.id)        # 64-char blake2b-256 hex
print(obj.is_valid()) # True

# Сохранение и получение
store.put(obj)
loaded = store.get(obj.id)
assert loaded == obj
```

### Pub/Sub (`core/node/pubsub.py`)

Gossip-слой издатель/подписчик:

```python
from core.pubsub import PubSubManager, topic_id

mgr = PubSubManager(
    object_store=node.object_store,
    node_address=node.address,
    transport=node.transport,
)

# Подписка
mgr.subscribe("room:general", lambda tid, obj: print(obj.data["text"]))

# Публикация (gossip к пирам, TTL=3)
await node.pubsub.async_publish("room:general", obj)

# ID топика (32-char Blake2b-128 hex)
tid = topic_id("room:general")
```

**Встроено в AsyncMurnetNode:**

```python
node.object_store   # ObjectStore
node.pubsub         # PubSubManager (автоматически маршрутизирует murnet_pubsub пакеты)
```

## v6.1 — Новые модули

### Identity Layer (`core/identity/identity.py`)

NodeID теперь первоклассный тип: `NodeID = blake2b(ed25519_pubkey, 32 bytes)`.

```python
from core.identity import NodeID, NodeIdentity, IdentityStore

# Создание/загрузка идентификатора
store = IdentityStore("./data")
identity = store.load_or_create()

print(identity.node_id)          # 64-char hex NodeID
print(identity.address)          # base58 human address (совместимость)

# XOR-расстояние (для Kademlia)
a = NodeID.from_pubkey(pubkey_a)
b = NodeID.from_pubkey(pubkey_b)
print(a.distance(b))             # int, XOR-метрика
```

### Protocol Schema (`core/net/protocol.py`)

Типизированные сообщения с версией 6.1:

```python
from core.protocol import HelloMsg, DataMsg, parse_message, make_node_id

# Создание сообщения
hello = HelloMsg(
    sender_id=str(identity.node_id),
    x25519_pubkey=identity.x25519_pubkey.hex(),
    ed25519_pubkey=identity.ed25519_pubkey.hex(),
    listen_port=8888,
)

# Сериализация / десериализация
raw = hello.to_bytes()              # JSON bytes
msg = parse_message(raw)            # → HelloMsg
sig_input = hello.canonical_bytes() # deterministic, без поля sig
```

### Simulation-тесты (`tests/simulation/`)

```bash
# Запустить только симуляции
python -m pytest tests/simulation/ -v -m simulation
```

---

## Тестирование

### Запуск всех тестов

```bash
python -m pytest tests/ -q
```

### Только быстрые тесты (без сетевого взаимодействия)

```bash
python -m pytest tests/ -q -m "not slow"
```

### По категориям

```bash
# Юнит-тесты
python -m pytest tests/unit/ -v

# Тесты сетевого уровня (200+ тестов)
python -m pytest tests/unit/test_network.py -v

# Интеграционные тесты (запускают реальные узлы)
python -m pytest tests/integration/ -v

# Тесты безопасности
python -m pytest tests/security/ -v

# Нагрузочные тесты
python -m pytest tests/performance/ -v

# Simulation-тесты (реальные сокеты, многоузловая сеть — выполняются дольше обычного)
python -m pytest tests/simulation/ -v -m simulation
```

### Pytest-метки

| Метка | Назначение |
|-------|------------|
| `pytest.mark.slow` | Тесты с сетевым взаимодействием или увеличенным временем выполнения |
| `pytest.mark.simulation` | Симуляция многоузловой сети; используют реальные сокеты и занимают значительное время |

> **Важно:** simulation-тесты открывают реальные UDP-сокеты и требуют свободных портов.
> Не запускайте их в CI-окружениях с жёсткими ограничениями по времени без явного `-m simulation`.

### Покрытие кода

```bash
python -m pytest tests/ --cov=core --cov=api --cov=mobile --cov-report=term-missing
```

---

## Структура тестов

| Модуль | Тестов | Что проверяется |
|--------|--------|-----------------|
| `test_network.py` | 200+ | PacketHeader, PeerConnection, RateLimiter, Transport, LSA/LSDB, Dijkstra/ECMP, DHT put/get, Name Service, Replay Protection |
| `test_transport.py` | — | Транспортный уровень |
| `test_routing.py` | — | Маршрутизация и LSA |
| `test_crypto.py` | — | Криптографические примитивы |
| `test_storage.py` | — | SQLite-хранилище |
| `test_dht.py` | — | DHT операции |
| `test_objects.py` | 43 | MurObject, ObjectStore, topic_id, PubSubManager (v6.2) |
| `test_keystore.py` | 24 | EncryptedKeystore: create/load/wipe/change_pwd, tamper, salt uniqueness, v1 migration, brute-force delay (v6.2.1) |
| `test_node_discovery.py` | 25+ | E2E: обнаружение пиров, обмен сообщениями, Name Service, DHT cross-node |
| `test_security.py` | 30 | Атаки replay, flood, инъекции, timing |
| `test_performance.py` | — | Пропускная способность, латентность |

### Написание тестов

**Юнит-тест транспорта:**

```python
import struct
from core.transport import PacketHeader

def test_packet_header_size():
    fmt_size = struct.calcsize(PacketHeader.STRUCT_FORMAT)
    assert PacketHeader.SIZE == fmt_size        # 20 байт
    assert PacketHeader.FULL_SIZE == fmt_size + 16  # 36 байт

def test_default_auth_tag():
    hdr = PacketHeader()
    assert hdr.auth_tag == b'\x00' * 16
    assert len(hdr.auth_tag) == 16
```

**Тест с реальным узлом:**

```python
import pytest
from core.node import SecureMurnetNode

@pytest.fixture
def node():
    n = SecureMurnetNode(port=0)  # port=0 → случайный порт
    n.start()
    yield n
    n.stop()

def test_node_has_address(node):
    assert node.address
    assert len(node.address) > 10
```

**Интеграционный тест:**

```python
@pytest.mark.slow
def test_two_nodes_connect(node_a, node_b):
    node_a.connect_to_peer(node_b.host, node_b.port)
    time.sleep(1.0)  # Ждём handshake
    assert node_b.address in node_a.get_peers()
```

---

## Правила написания кода

### Безопасность

- Никогда не логируйте приватные ключи, session keys, JWT-токены
- Используйте `hmac.compare_digest()` для сравнения секретных значений
- Все данные из сети/API проходят валидацию перед использованием
- Не изобретайте криптографических примитивов — используйте существующие в `core/identity/crypto.py`

### Структура кода

- Блокировки: используйте `with self._lock:` (`threading.RLock`)
- Базы данных: всегда `with conn:` для транзакций
- Исключения: перехватывайте конкретные типы, не голые `except:`
- Параметры: проверяйте входные данные на границах модулей

### Пример добавления нового метода в узел

```python
# core/node.py — правильный паттерн
def get_peer_count(self) -> int:
    """Возвращает количество активных пиров."""
    with self._lock:
        return len([p for p in self.transport.peers.values() if p.is_active])
```

---

## Добавление нового эндпоинта API

1. Добавьте Pydantic-модель в `api/models.py`
2. Реализуйте эндпоинт в `api/server.py` с JWT-зависимостью
3. Добавьте юнит-тест в `tests/unit/`
4. Обновите `docs/API.md`

```python
# api/server.py
@app.get("/my/endpoint", dependencies=[Depends(verify_token)])
async def my_endpoint():
    return {"result": node.my_method()}
```

---

## Добавление нового типа пакета

1. Добавьте константу в `PacketType` (`core/net/transport.py`)
2. Добавьте обработчик в `_process_packet()`
3. Обновите `docs/PROTOCOL.md` (раздел 1.2)
4. Добавьте тест в `tests/unit/test_network.py`

---

## Отправка изменений

1. Создайте ветку: `git checkout -b feature/your-feature`
2. Сделайте изменения, добавьте тесты
3. Убедитесь, что все тесты проходят: `python -m pytest tests/ -q`
4. Создайте коммит с понятным сообщением
5. Откройте Pull Request на GitHub с описанием изменений

**Обязательные условия для PR:**
- Все существующие тесты проходят
- Новая функциональность покрыта тестами
- Криптографические изменения содержат ссылки на источники

---

## Исправленные баги (история)

| Файл | Баг | Статус |
|------|-----|--------|
| `core/identity/crypto.py` | `b'\\x00'` вместо `b'\x00'` в base58_decode | Исправлен |
| `core/identity/crypto.py` | Недетерминированный seed (случайный salt Argon2) | Исправлен |
| `core/net/routing.py` | Отсутствовал `import hmac` | Исправлен |
| `core/net/routing.py` | `LinkState` enum не сериализовался в JSON | Исправлен |
| `core/net/transport.py` | `SIZE=22/FULL_SIZE=38` вместо `20/36` | Исправлен |
| `core/net/transport.py` | `b'\\x00' * 16` (строка) вместо null-байт | Исправлен |
| `core/data/storage.py` | `save_message()` не принимал параметр `read` | Исправлен |
| `core/node/node.py` | Отсутствовали `register_name()` / `lookup_name()` | Исправлен |
| `api/server.py` | Regex `r'\\.'` матчил `\` + любой символ | Исправлен |
| `api/server.py` | Null-byte check искал строку `'\\x00'` | Исправлен |
| `tests/security/test_security.py` | `test_invalid_base64_handling` ожидал raise; `verify()` намеренно возвращает False | Исправлен |
| `tests/security/test_security.py` | `test_replay_protection_sequence_numbers` seq=0 в окне 1000 | Исправлен (window_size=0) |
| `tests/security/test_security.py` | `test_trust_score_degradation` отрицательные sequence не деградируют trust | Исправлен (неверная подпись) |
| `core/net/transport.py` | `on_peer_connected` callback определён, но никогда не вызывался → `routing.add_neighbor()` не срабатывал | Исправлен (вызов в `_handle_hello()`) |
| `tests/integration/test_integration.py` | `UnboundLocalError` + `NameError: MurnetNode not defined` в `test_two_nodes_communication` | Исправлен |
| `tests/integration/test_node_discovery.py` | `neighbors` всегда 0 из-за race condition (0.6 s sleep недостаточно) | Исправлен (1.5 s) |

---

## Полезные команды

```bash
# Проверить calcsize для struct формата
python -c "import struct; print(struct.calcsize('!BBIIHII'))"  # → 20

# Запустить один тест
python -m pytest tests/unit/test_network.py::TestPacketHeader::test_encode_decode -v

# Запустить тесты с выводом print()
python -m pytest tests/ -s -v

# Показать самые медленные тесты
python -m pytest tests/ --durations=10
```

# Архитектура Murnet v6.2.3

> **Дисклеймер.** Описанная архитектура является учебной реализацией P2P-протокола.
> Проект не прошёл аудит безопасности и не предназначен для хранения
> конфиденциальных данных или использования в производственных системах.

---

## Обзор компонентов

В v6.2.1 основным оркестратором является `AsyncMurnetNode` (`core/node/async_node.py`),
построенный на asyncio. `SecureMurnetNode` (`core/node/node.py`) сохраняется для обратной
совместимости. Каждый слой взаимодействует с соседними через явно определённые интерфейсы.

```
┌──────────────────────────────────────────────────────────────────┐
│        CLI / Desktop GUI / REST API / Network Visualizer         │
├──────────────────────────────────────────────────────────────────┤
│                       AsyncMurnetNode                            │
│                    (core/node/async_node.py)                     │
├──────────┬──────────┬──────────┬──────────┬──────────────────────┤
│  Async   │ Routing  │  DHT     │ Storage  │  E2E Encryption      │
│Transport │ Table    │(Murnaked)│ (SQLite) │  (E2EEncryption)     │
│(net/async│(net/rout)│(net/murn)│(data/    │  (identity/crypto)   │
│transport)│          │          │ storage) │                      │
├──────────┴──────────┴──────────┴──────────┴──────────────────────┤
│  Object System (core/data/objects.py)  PubSubManager (node/)    │
│  MurObject · ObjectStore · hash-addressed · Ed25519-signed       │
│  topic_id() · gossip TTL · dedup · subscribe/publish             │
├──────────────────────────────────────────────────────────────────┤
│      Encrypted Keystore (core/identity/keystore.py) [v6.2.1]    │
│  Argon2id(pass→key) · AES-256-GCM · 0o600 · brute-force delay   │
├──────────────────────────────────────────────────────────────────┤
│         Identity Layer (core/identity/identity.py)               │
│         NodeID = blake2b(ed25519_pubkey, 32) · XOR distance      │
├──────────────────────────────────────────────────────────────────┤
│          Protocol Schema (core/net/protocol.py)                  │
│         MurMessage · 18 MessageType · parse_message()            │
├──────────────────────────────────────────────────────────────────┤
│  ■ SECURITY LAYERS (v6.2.2–6.2.3)                               │
│  Layer 1: Build Signing  — Ed25519 manifest · TamperedBuildError │
│  Layer 3: Network Secret — HMAC-SHA256 token в каждом HELLO      │
│  Layer 4: Cython         — core/identity/ → нативный .so/.pyd   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 0. Identity Layer (`core/identity/identity.py`)

Слой идентичности обеспечивает криптографически стойкие адреса узлов и их персистентность.

**NodeID:**
- Вычисляется как `blake2b(ed25519_pubkey, digest_size=32)` — 32-байтный детерминированный
  идентификатор, производный от публичного ключа
- Расстояние между двумя NodeID определяется XOR-метрикой: `dist(a, b) = a XOR b`,
  что обеспечивает базу для k-bucket-маршрутизации (Kademlia-совместимый DHT)

**Классы:**
- `NodeIdentity` — обёртка над `crypto.Identity`; добавляет поле `node_id` (NodeID)
  и экспортирует удобные методы `sign()` / `verify()` с типизацией NodeID
- `IdentityStore` — персистентность идентичности: сохраняет и загружает
  сериализованный ключевой материал из `core/data/storage.py` (таблица `identity`);
  при первом запуске генерирует новую пару ключей

**Взаимодействие:**
- `AsyncMurnetNode` инициализирует `IdentityStore` при старте и передаёт
  `NodeIdentity` во все зависимые слои (Transport, DHT, Routing)
- NodeID используется в RoutingTable как первичный ключ узла и в MurnakedNode
  для расчёта XOR-близости при поиске ответственного узла

---

## 1. Crypto (`core/identity/crypto.py`)

Отвечает за все криптографические операции узла.

**Классы:**
- `Identity` — хранит пару Ed25519-ключей, генерирует адрес, подписывает и верифицирует данные
- `E2EEncryption` — шифрует и дешифрует прикладные сообщения (AES-256-GCM + X25519)
- `SecureChannel` — сессионный канал с эфемерными ключами для forward secrecy

**Ключевые функции:**
- `base58_encode / base58_decode` — кодирование адресов
- `blake2b_hash` — хеширование (замена SHA-256 там, где не нужна совместимость)
- `derive_key_argon2` — Argon2id деривация для seed/паролей
- `canonical_json` — детерминированная сериализация для подписей

**Защита:**
- Constant-time сравнение (`hmac.compare_digest`) против timing-атак
- Приватный ключ не передаётся вовне объекта Identity (Chalkias protection)
- Попытка затирания ключа в `__del__` (best-effort; Python не гарантирует немедленное выполнение)

---

## 2. Transport (`core/net/transport.py` и `core/net/async_transport.py`)

В v6.1 транспортный уровень представлен двумя реализациями:

| Модуль | Класс | Используется в |
|---|---|---|
| `core/net/transport.py` | `Transport` (sync, threading) | `SecureMurnetNode` |
| `core/net/async_transport.py` | `AsyncTransport` (asyncio) | `AsyncMurnetNode` |

**`Transport` (sync):**
- Управляет сокетом, потоками приёма/отправки
- `PacketHeader` — 36-байтный заголовок (кодирование/декодирование через `struct`)
- `PeerConnection` — состояние одного пира: sequence window, RTT, session key
- `RateLimiter` — token-bucket лимитер per-IP
- Потоки `_recv_loop`, `_process_packet`, `_send_loop`

**`AsyncTransport` (asyncio):**
- Использует `asyncio.DatagramProtocol` вместо потоков; не блокирует event loop
- Тот же формат пакетов и HMAC-аутентификация, что и в `Transport`
- `register_handler(msg_type, coro)` — слой совместимости: позволяет регистрировать
  как синхронные функции, так и корутины; синхронные вызовы оборачиваются в
  `asyncio.get_event_loop().run_in_executor()` для неблокирующего выполнения

**Ограничения (актуальные для обеих реализаций):**
- Per-peer rate limit в `Transport` реализован через `deque(maxlen=100)`, что делает
  его неэффективным при высоком pps
- NAT traversal не реализован
- Фрагментация пакетов (DATA_FRAG) реализована частично

---

## 3. Routing (`core/net/routing.py`)

Link-state протокол для построения топологии и вычисления путей.

**Классы:**
- `RoutingTable` — публичный интерфейс маршрутизации; делегирует LSDB и Dijkstra
- `LinkStateDatabase` — хранит LSA всех узлов, строит граф сети
- `DijkstraEngine` — вычисляет кратчайшие пути с учётом trust score и ECMP
- `LSA` — объявление связей с подписью и hash-chain
- `Link` — описание одного ребра (cost, bandwidth, latency, loss_rate, state)

**Алгоритм стоимости ребра:**
```python
effective_cost = cost + loss_rate * 10 + latency / 10
effective_cost *= (1 + (1000 - bandwidth) / 1000)
if state == DOWN: effective_cost = inf

adjusted_cost = effective_cost / trust_score(neighbor)
```

**LSA pipeline:**
1. `RoutingTable.add_link()` → `lsdb.originate_lsa()` — подписывает и публикует LSA
2. `receive_lsa()` — проверяет временную метку, sequence, подпись; обновляет trust
3. Flood detection: >10 LSA/сек с одного origin → игнорируется
4. После любого обновления LSDB запускается `recompute()` → Dijkstra

---

## 4. DHT — MurnakedNode (`core/net/murnaked.py`, `core/net/dht_rpc.py`)

Распределённое хранилище ключ–значение, основанное на Kademlia.

**Классы:**
- `MurnakedNode` — верхний уровень; предоставляет `store`, `retrieve`, `register_name`, `get_name`, `save_file`, `get_file`
- `ConsistentHashRing` — кольцо с виртуальными узлами (10 vnode/узел)
- `DHTRPCManager` — сетевой уровень DHT; аутентифицирует запросы через HMAC-SHA3-256
- `BloomFilter` — вероятностная проверка наличия ключа без полного поиска

**NodeID XOR-расстояние и k-bucket маршрутизация:**
- В v6.1 `MurnakedNode` использует NodeID из Identity Layer для вычисления XOR-близости
  при поиске ответственного узла: `responsible = min(peers, key=lambda p: p.node_id XOR target_id)`
- Это обеспечивает базу для k-bucket-таблицы маршрутизации (160 бакетов по 20 узлов),
  совместимой с оригинальным Kademlia (BEP-5)
- `ConsistentHashRing` сохраняется для балансировки нагрузки внутри ответственного региона

**Схема надёжности:**
- Replication factor = 3: каждый ключ хранится на трёх узлах кольца
- Hinted handoff: если целевой узел недоступен, данные временно хранятся у текущего
- Anti-entropy: периодическая сверка реплик между соседями

**Схема ключей:**
```
msg:<uuid>    — прикладное сообщение
name:<имя>   — запись Name Service
file:<uuid>  — файл
```

---

## 5. Storage (`core/data/storage.py`)

Персистентный слой на SQLite с кешированием.

**Класс:** `Storage`

**Таблицы:**
- `messages` — входящие/исходящие сообщения (`id`, `from_addr`, `to_addr`, `content`, `timestamp`, `delivered`, `read`, `compressed`, ...)
- `dht_data` — локальная копия DHT (`key`, `value`, `value_type`, `ttl`, `version`, ...)
- `identity` — сериализованный ключевой материал узла

**Оптимизации:**
- WAL-режим SQLite для параллельного чтения
- LRU-кеш (1000 записей) для горячих данных
- zlib-сжатие сообщений длиннее 100 байт
- DHT-значения длиннее 1000 байт сжимаются и маркируются `:gzip` в `value_type`

---

## 6. API Server (`api/server.py`)

REST API и WebSocket-сервер на FastAPI.

**Security middleware:**
- JWT-аутентификация (Bearer token) на всех эндпоинтах кроме `/health`
- Rate limit: 30 запросов/минуту на `/messages/send`
- Security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CSP: default-src 'self'`, `HSTS`
- Строгая валидация имён файлов (`validate_filename`): только `[a-zA-Z0-9_-]+\.[a-zA-Z0-9]{1,10}`, без `..`, `/`, `\`, null-байт

**Безопасность загрузки файлов:**
- Стриминговая загрузка чанками по 64 КБ (нет полной буферизации в RAM)
- Проверка MIME-типа через puremagic (magic bytes), не расширение
- UUID генерируется сервером; имя файла из запроса не используется как путь

---

## 7. Оркестраторы узла

### AsyncMurnetNode (`core/node/async_node.py`)

Основной оркестратор v6.1, построенный на `asyncio`. Управляет всеми слоями
асинхронно: запускает `AsyncTransport`, `RoutingTable`, `MurnakedNode`, `Storage`
и `E2EEncryption` как набор скоординированных корутин в одном event loop.

- Инициализация: `await node.start()` → поднимает `AsyncTransport`, загружает
  `IdentityStore`, подключает обработчики через `register_handler()`
- Завершение: `await node.stop()` — корректно дожидается завершения всех задач
- `CircuitBreaker` и `BackpressureController` адаптированы под asyncio
  (`asyncio.Lock` вместо `threading.RLock`)

### SecureMurnetNode (`core/node/node.py`)

Оркестратор на потоках (threading); сохраняется для обратной совместимости.

**Паттерны отказоустойчивости:**
- `CircuitBreaker` — блокирует отправку после N последовательных ошибок; автовосстановление через `recovery_timeout`
- `BackpressureController` — throttle при заполнении очереди >80%, снятие при <30%
- `MetricsCollector` — скользящие гистограммы латентности, счётчики security-событий

**Очереди обработки:**
```
outbox_queue  (maxsize=100000) → _outbox_loop → _process_outgoing
retry_queue   (maxsize=100000) → _retry_loop  (повторная отправка через 30с, до 3 раз)
handler_queue (maxsize=100000) → _handler_loop → _handle_packet
```

**Поток отправки сообщения:**
```
send_message(to, text)
  │
  ├─ sign(message)           ← Ed25519
  ├─ encrypt(text, peer_key) ← AES-256-GCM (если известен pubkey получателя)
  ├─ storage.save_message()  ← SQLite
  ├─ outbox_queue.put()
  └─ pending_acks[msg_id]    ← запись для отслеживания ACK

_process_outgoing(message)
  │
  ├─ routing.get_next_hop(to) → следующий хоп
  ├─ transport.peers[hop]     → PeerConnection
  └─ transport.send_to()      → UDP + HMAC-Blake2b
```

---

## 8. Object System + Pub/Sub (`core/data/objects.py`, `core/node/pubsub.py`)

Введены в v6.2. Обеспечивают контент-адресуемое хранение данных и механизм
издатель/подписчик поверх существующего транспорта.

### MurObject (`core/data/objects.py`)

Неизменяемый, подписываемый объект с хеш-идентификатором:

```json
{
  "id":        "<blake2b-256 hex содержимого>",
  "type":      "<строка типа: msg / profile / text / ...>",
  "owner":     "<base58 адрес создателя>",
  "timestamp": 1712345678.123,
  "data":      { "...": "произвольный JSON-payload" },
  "signature": "<base64 Ed25519-подписи canonical_bytes()>"
}
```

- `id` — `blake2b-256(canonical JSON без полей id/signature)` — подтверждение содержимого
- `MurObject.create(type, owner, data, identity)` — создаёт и подписывает объект
- `verify_id()` / `verify_signature(pubkey_hex)` / `is_valid()` — проверка целостности

### ObjectStore (`core/data/objects.py`)

Хеш-адресуемое хранилище:

- In-memory LRU-кеш (512 записей)
- Шардированный диск: `objects/<первые 2 символа id>/<id>.json` (как у Git)
- Интерфейс: `put` / `get` / `has` / `delete` / `list_ids` / `list_by_type` / `stats`
- `put()` отклоняет объекты с несовпадающим ID (проверка целостности на границе хранилища)

### PubSubManager (`core/node/pubsub.py`)

Gossip-слой издатель/подписчик:

- `topic_id(name)` — отображает имя топика в 32-символьный Blake2b-128 hex
- `subscribe(topic, callback)` / `unsubscribe(topic, callback)` — локальные подписки
- `publish(topic, obj)` / `async_publish()` — сохраняет локально, вызывает callbacks, рассылает gossip
- Gossip с TTL-полем (по умолчанию 3 хопа); кольцевой буфер dedup на 4096 записей
- `handle_raw()` / `async_handle_raw()` — путь приёма из транспорта
- Объекты с неверным ID (tamper) отбрасываются на пути приёма

**Интеграция с AsyncMurnetNode:**

```python
node.object_store  # ObjectStore — доступен напрямую
node.pubsub        # PubSubManager — подписка и публикация

node.pubsub.subscribe("room:general", callback)
obj = MurObject.create("text", node.address, {"text": "Привет!"}, identity)
await node.pubsub.async_publish("room:general", obj)
```

**Wire-формат gossip-сообщения** (JSON, тип DATA)::

```json
{
  "murnet_pubsub": true,
  "action":        "publish",
  "topic":         "<32-char topic_id hex>",
  "object":        { "<MurObject>" },
  "ttl":           3,
  "seen_by":       ["<адрес отправителя>"]
}
```

---

## 9. Encrypted Keystore (`core/identity/keystore.py`) — v6.2.1

Защита приватного ключа узла паролем пользователя.

**Принцип:** нет пароля — нет доступа к узлу. Восстановление не предусмотрено.

**Схема шифрования:**

```
password ──┐
           ├─ Argon2id(time=3, mem=64MB, par=4) ──► enc_key (32 bytes)
salt(32B) ─┘
                                                       │
identity_bytes ──────────────────────────────────────► AES-256-GCM.encrypt
                                                       │  nonce(12B)
                                                       ▼
                                              ciphertext + 16-byte tag
                                                       │
                                              JSON { version, salt, nonce, ciphertext }
                                                       │ permissions: 0o600
                                                    disk file
```

**Класс `EncryptedKeystore`:**

| Метод | Описание |
|-------|----------|
| `exists()` | Проверяет наличие файла |
| `create(key_bytes, password)` | Шифрует и сохраняет ключ (WeakPasswordError < 8 символов) |
| `load(password)` | Расшифровывает; WrongPasswordError + задержка 0.5–0.8 с при неверном |
| `change_password(old, new)` | Перешифровка с новым паролем |
| `wipe()` | Перезапись случайными байтами + fsync + удаление (best-effort) |

**Меры безопасности (v6.2.1):**

1. **Антибрутфорс:** `time.sleep(0.5 + jitter)` при `WrongPasswordError` — ~10 попыток/мин максимум
2. **Миграция версий:** `version=1` (nonce в составе ciphertext) автоматически читается `_migrate_v1_to_v2()`
3. **Memory hygiene:** ключ деривируется в `bytearray`, поля обнуляются в блоке `finally`
4. **Wipe limitations:** на SSD/NVMe/journaling FS физическое уничтожение не гарантируется; рекомендуется шифрование диска (LUKS/BitLocker/FileVault)

**Интеграция в AsyncMurnetNode:**

```python
# Первый запуск: создаёт зашифрованный keystore
node = AsyncMurnetNode(data_dir="./data", port=8888, password="мой_пароль_123")

# Последующие запуски: разблокировка
node = AsyncMurnetNode(data_dir="./data", port=8888, password="мой_пароль_123")
# → WrongPasswordError если пароль неверный
```

**CLI:** `prompt_password_cli(data_dir)` — интерактивный промпт (getpass), двойной ввод при создании.

**Desktop GUI:** `PasswordDialog` — tkinter-диалог с режимами `create / unlock / change`, тёмная тема, кнопка показа/скрытия.

---

## 10. Network Visualizer (`network_viz.py`)

Автономный инструмент визуализации топологии сети.  Не требует дополнительных
зависимостей (только стандартная библиотека Python + tkinter).

**Архитектура:**

```
                  ┌─────────────────┐
                  │   APIClient     │  HTTP poll → /network/status + /network/peers
                  │   (threading)   │  (Bearer JWT, configurable interval)
                  └────────┬────────┘
                           │ NetworkSnapshot
                  ┌────────▼────────┐
                  │  ForceLayout    │  Fruchterman-Reingold физика
                  │  (репульсия +   │  → координаты (x, y) для каждого узла
                  │   притяжение)   │
                  └────────┬────────┘
                           │
                  ┌────────▼────────────────────────┐
                  │       NetworkVisualizer          │
                  │       (tkinter Canvas)           │
                  │  ─ drag/pin nodes                │
                  │  ─ pan + zoom                    │
                  │  ─ sidebar: stats, legend        │
                  │  ─ node info panel               │
                  └──────────────────────────────────┘
```

**Режимы запуска:**

```bash
# Demo-режим (без реального API): синтетическая 6-нодовая топология
python network_viz.py --demo

# Подключиться к реальному узлу
python network_viz.py --api http://127.0.0.1:8080 --token <JWT>

# Настроить интервал опроса
python network_viz.py --api http://127.0.0.1:8080 --poll 5
```

**Управление:**

| Клавиша / действие | Описание |
|--------------------|----------|
| Перетащить узел | Переместить в новую позицию (pin) |
| ПКМ по узлу | Снять/поставить pin |
| Тащить фон | Pan вида |
| Прокрутка / `+`/`-` | Zoom |
| `Space` | Сбросить вид |
| `R` | Принудительный refresh |
| `Q` / `Esc` | Выход |

---

## 11. Protocol Schema (`core/net/protocol.py`)  <!-- was 9 -->

Единая схема сообщений для всех слоёв протокола Murnet v6.1.

**Базовый класс:**
- `MurMessage` — базовый класс всех сообщений; содержит обязательные поля
  `version` (фиксировано `"6.1"`), `msg_type`, `sender_id` (NodeID), `timestamp`,
  `nonce` и опциональный `payload`

**Типы сообщений:**
`MurMessage` поддерживает 18 значений `MessageType`:

| Группа | Типы |
|---|---|
| Маршрутизация | `LSA`, `LSA_ACK`, `ROUTE_REQUEST`, `ROUTE_REPLY` |
| DHT | `DHT_STORE`, `DHT_FIND_NODE`, `DHT_FIND_VALUE`, `DHT_STORE_ACK` |
| Прикладной уровень | `MSG_SEND`, `MSG_ACK`, `MSG_NACK`, `FILE_OFFER`, `FILE_CHUNK`, `FILE_ACK` |
| Управление | `PING`, `PONG`, `PEER_EXCHANGE`, `ERROR`, `HANDSHAKE` |

**Ключевые функции:**
- `parse_message(raw: bytes) -> MurMessage` — фабричный метод; десериализует bytes,
  проверяет поле `version == "6.1"`, возвращает конкретный подкласс по `msg_type`
- `canonical_bytes(msg: MurMessage) -> bytes` — детерминированная сериализация
  для подписи: поля сортируются по ключу, `nonce` и `signature` исключаются;
  используется в `Identity.sign()` / `NodeIdentity.verify()`

**Версионирование:**
- Поле `version` позволяет отклонять пакеты от узлов с несовместимой версией
  протокола; при несоответствии `parse_message()` бросает `ProtocolVersionError`

---

## 12. Mobile Optimizers (`mobile/`)

Набор модулей для адаптации работы на мобильных устройствах.

**BatteryOptimizer (`battery.py`):**

| Состояние | Заряд | Интервал синхронизации |
|-----------|-------|----------------------|
| CHARGING | любой | 30 с |
| NORMAL | >30% | 60 с |
| SAVER | 15–30% | 120 с |
| CRITICAL | <15% | 900 с, DHT repair отключён |

**MobileNetworkManager (`network.py`):**
- Определяет тип сети через RTT-эвристику (WiFi / 4G / 3G / 2G)
- При metered-соединении может приостанавливать синхронизацию
- Офлайн-очередь: сообщения буферизуются и отправляются при восстановлении

**SyncManager (`sync.py`):**
- Приоритетная очередь задач: CRITICAL > HIGH > NORMAL > LOW > BACKGROUND
- Экспоненциальный backoff при сбоях

---

## 13. Потоки и параллелизм

Каждый запущенный узел создаёт следующие потоки:

| Поток | Имя | Функция |
|-------|-----|---------|
| Recv | `Transport-recv` | Приём UDP-пакетов |
| Send | `Transport-send` | Отправка из очереди |
| Outbox | `SecureNode-Outbox` | Маршрутизация исходящих |
| Retry | `SecureNode-Retry` | Повторная отправка неподтверждённых |
| Handler | `SecureNode-Handler` | Обработка входящих |
| Metrics | `SecureNode-Metrics` | Сбор метрик каждые 1 с |
| Security | `SecureNode-Security` | Мониторинг безопасности каждые 60 с |

ThreadPoolExecutor: 20 воркеров (`SecureNode-v6-*`) для параллельных операций.

`AsyncMurnetNode` не создаёт собственных потоков — все операции выполняются
в event loop; блокирующие вызовы (SQLite, crypto) передаются в
`loop.run_in_executor(executor)`.

---

## 14. Известные ограничения

- **Thread safety**: большинство структур защищены `threading.RLock`, но есть
  не-атомарные операции в `BackpressureController` (поля `current_load`, `is_throttled`
  изменяются без блокировки)
- **Memory clearing**: `Identity.__del__` пытается затереть ключ, но CPython
  не гарантирует немедленный вызов деструктора; ключ может оставаться в памяти
- **Rate limiter**: per-peer лимит через `deque(maxlen=100)` не блокирует при
  высоком pps из-за эффекта maxlen
- **X25519 из Ed25519 ключа**: корректно в данном контексте только потому, что
  оба ключа — 32 байта случайных данных; не является общепринятой практикой

---

## 15. Security Layers (`core/net/network_auth.py`, `core/integrity.py`) — v6.2.2–6.2.3

Три независимых слоя защиты от несанкционированного использования кода.

### Layer 1 — Build Signing (`core/integrity.py`)

При каждом официальном релизе все файлы `core/` подписываются Ed25519-ключом.
При старте узла вызывается `verify_integrity()`:

```
1. SHA-256(каждый .py в core/)  →  manifest dict
2. JSON(manifest, sorted_keys)  →  bytes
3. Ed25519.verify(sig, bytes, _SIGNING_PUBLIC_KEY)
   ↳ OK  → узел стартует
   ↳ FAIL → TamperedBuildError (узел не запустится)
```

- `_SIGNING_PUBLIC_KEY` вшит в код — заменить его невозможно без изменения файла,
  что само по себе инвалидирует подпись
- `BUILD_SIGNATURE` хранится в корне репо; приватный ключ — только у владельца

### Layer 3 — Network Secret (`core/net/network_auth.py`)

Каждый HELLO-пакет содержит одноразовый токен:

```
nonce  = os.urandom(32)          # свежий для каждого рукопожатия
ts     = int(time.time())
token  = HMAC-SHA256(NETWORK_SECRET, nonce || ts_big_endian_8)
```

Принимающий узел проверяет:
1. Токен присутствует
2. `|now - ts| ≤ 300 с` (защита от replay)
3. HMAC совпадает

Если хотя бы одна проверка не прошла — HELLO молча игнорируется без
отправки ошибки (не раскрывает причину отказа).

**Конфигурация:**

| Источник | Приоритет | Описание |
|---|---|---|
| Хардкод в `network_auth.py` | базовый | Работает "из коробки" в официальной сборке |
| `MURNET_SECRET=<hex>` env-var | переопределяет | Для тестовых/приватных сетей |
| `na.set_secret(bytes)` | переопределяет | Программная установка |

### Layer 4 — Cython (`setup_cython.py`)

Компиляция `core/identity/{crypto,keystore,identity}.py` в нативные расширения:

```bash
pip install cython
python setup_cython.py build_ext --inplace
# → core/identity/crypto.cpython-3XX.so
# → core/identity/keystore.cpython-3XX.so
# → core/identity/identity.cpython-3XX.so
```

Python автоматически предпочитает `.so` файл `.py` при одинаковом имени.
Исходники можно удалить из дистрибутива после сборки.

### Workflow релиза

```bash
# 1. Внести изменения в core/
# 2. Подписать новую сборку (приватный ключ только у владельца)
python tools/sign_build.py --sign --key-file build_key.pem

# 3. Проверить подпись
python tools/sign_build.py --verify   # → OK

# 4. Закоммитить BUILD_SIGNATURE вместе с изменениями
git add BUILD_SIGNATURE && git commit -m "..."
```

# Murnet REST API & WebSocket — v6.1

> **Дисклеймер.** API является частью экспериментального студенческого проекта.
> JWT-реализация не проходила аудит безопасности. Не используйте этот сервер
> для обработки конфиденциальных данных в производственных системах.

---

## Обзор

REST API и WebSocket реализованы на FastAPI (`api/server.py`).

По умолчанию сервер слушает `127.0.0.1:8080`.
В VDS-конфигурации хост меняется на `0.0.0.0:8080`.

**Security middleware (применяется ко всем запросам):**

| Заголовок | Значение |
|-----------|----------|
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'self'` |
| `Strict-Transport-Security` | `max-age=31536000` |

---

## Authentication

All endpoints except `GET /health` require a JWT Bearer token in the `Authorization` header.

### JWT Flow

1. **Obtain a token** — send a `POST /auth/login` request with your node credentials:

```http
POST /auth/login HTTP/1.1
Content-Type: application/json

{}
```

Response:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": 1712345678.0,
  "node_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
}
```

2. **Use the token** — include it as a Bearer token in every subsequent request:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

3. **Revoke the token** — call `POST /auth/logout` when done. The token is invalidated server-side immediately.

Tokens are node-scoped: each node generates its own secret at first launch and stores it in the node configuration. There is no shared user database.

Rate limit: 30 requests/minute on `/messages/send`.

---

## Аутентификация

Все эндпоинты кроме `/health` требуют JWT Bearer-токен:

```
Authorization: Bearer <token>
```

Токен выдаётся при первом запуске узла и хранится в конфигурации.
Получить его можно через:

```
POST /auth/login
```

Rate limit: 30 запросов/минуту на `/messages/send`.

---

## Эндпоинты

### Здоровье узла

#### `GET /health`

Не требует аутентификации. Используется для health-check.

**Ответ 200:**
```json
{
  "status": "healthy",
  "node_running": true,
  "uptime": 3600,
  "peers": 3,
  "timestamp": 1712345678.0
}
```

---

### Аутентификация

#### `POST /auth/login`

Получить JWT-токен.

**Ответ 200:**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": 1712345678.0,
  "node_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
}
```

#### `POST /auth/logout`

Отозвать текущий токен.

**Заголовки:** `Authorization: Bearer <token>`

**Ответ 200:**
```json
{"success": true}
```

---

### Сообщения

#### `POST /messages/send`

Отправить сообщение пиру.

**Заголовки:** `Authorization: Bearer <token>`

**Тело запроса:**
```json
{
  "to_address": "1RecipientAddress...",
  "content": "Текст сообщения",
  "message_type": "text",
  "encrypt": true
}
```

| Поле | Тип | Описание |
|------|-----|----------|
| `to_address` | string | Base58-адрес получателя |
| `content` | string | Текст сообщения (до 1 МБ) |
| `message_type` | string | `"text"` (по умолчанию) |
| `encrypt` | bool | Применить E2E шифрование (AES-256-GCM) |

**Ответ 200:**
```json
{
  "success": true,
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Message queued"
}
```

**Ответ 429:** Rate limit превышен.

#### `GET /messages/inbox`

Получить входящие сообщения.

**Заголовки:** `Authorization: Bearer <token>`

**Query-параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `limit` | int | 50 | Максимальное число сообщений |
| `offset` | int | 0 | Смещение (пагинация) |
| `unread_only` | bool | false | Только непрочитанные |

**Ответ 200:** Массив объектов `MessageInfo`:
```json
[
  {
    "id": "550e8400-...",
    "from": "1SenderAddress...",
    "to": "1MyAddress...",
    "content_preview": "Текст сообщения...",
    "timestamp": 1712345678.0,
    "delivered": true,
    "read": false
  }
]
```

---

### Файлы

#### `POST /files/upload`

Загрузить файл в сеть.

**Заголовки:** `Authorization: Bearer <token>`

**Content-Type:** `multipart/form-data`

**Поля формы:**

| Поле | Описание |
|------|----------|
| `file` | Файл для загрузки (до 50 МБ) |
| `to_address` | (опционально) Адрес получателя — отправить файл как сообщение |

Имя файла проверяется регулярным выражением `^[a-zA-Z0-9][a-zA-Z0-9_-]*\.[a-zA-Z0-9]{1,10}$`.
MIME-тип проверяется по magic bytes (через puremagic), а не по расширению.
Файл загружается стримингом чанками по 64 КБ — без буферизации всего файла в RAM.

**Ответ 200:**
```json
{
  "success": true,
  "file_id": "generated-uuid",
  "filename": "document.pdf",
  "size": 102400,
  "hash": "blake2b-hex-hash"
}
```

**Ответ 400:** Имя файла не прошло валидацию.

#### `GET /files/{file_id}`

Скачать файл по ID.

**Заголовки:** `Authorization: Bearer <token>`

**Ответ:** Стриминговая отдача файла с заголовком `Content-Disposition`.

---

### Сеть

#### `GET /network/status`

Получить полный статус узла.

**Заголовки:** `Authorization: Bearer <token>`

**Ответ 200:**
```json
{
  "node": {
    "address": "1A1zP1...",
    "public_key": "hex-pubkey",
    "status": "running",
    "uptime": 3600,
    "version": "v6.0"
  },
  "network": {
    "peers_count": 3,
    "neighbors": 2,
    "is_connected": true
  },
  "storage": {
    "messages_count": 42,
    "dht_entries": 100
  },
  "dht": {
    "local_entries": 100,
    "ring_size": 30
  }
}
```

#### `GET /network/peers`

Список подключённых пиров.

**Заголовки:** `Authorization: Bearer <token>`

**Ответ 200:** Массив объектов `PeerInfo`:
```json
[
  {
    "address": "1PeerAddress...",
    "ip": "192.168.1.100",
    "port": 8888,
    "rtt": 12.5,
    "is_active": true
  }
]
```

#### `POST /network/connect`

Инициировать подключение к пиру.

**Заголовки:** `Authorization: Bearer <token>`

**Тело запроса:**
```json
{
  "ip": "192.168.1.100",
  "port": 8888,
  "address": "1OptionalKnownAddress..."
}
```

**Ответ 200:**
```json
{"success": true, "message": "Connection initiated"}
```

---

### DHT и хранилище

#### `GET /dht/stats`

Статистика по DHT.

**Заголовки:** `Authorization: Bearer <token>`

**Ответ 200:**
```json
{
  "local_entries": 100,
  "ring_size": 30,
  "replication_factor": 3
}
```

#### `GET /storage/stats`

Статистика по хранилищу SQLite.

**Заголовки:** `Authorization: Bearer <token>`

**Ответ 200:**
```json
{
  "messages_count": 42,
  "dht_entries": 100,
  "db_size_bytes": 524288
}
```

---

### Name Service

#### `POST /names/register`

Зарегистрировать имя для своего адреса (сохраняется в DHT с Ed25519-подписью).

**Заголовки:** `Authorization: Bearer <token>`

**Тело запроса:**
```json
{
  "name": "alice"
}
```

Ограничения: имя до 64 символов, только через `register_name()` узла.

**Ответ 200:**
```json
{"success": true, "name": "alice", "address": "1A1zP1..."}
```

#### `GET /names/lookup/{name}`

Найти адрес по имени (запрос в DHT).

**Заголовки:** `Authorization: Bearer <token>`

**Ответ 200:**
```json
{
  "success": true,
  "name": "alice",
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
}
```

**Ответ 404:** Имя не найдено в DHT.

---

## WebSocket API

**Endpoint:** `ws://127.0.0.1:8080/ws`

In VDS configuration the host changes to `ws://0.0.0.0:8080/ws`.

### Authentication flow

WebSocket connections use the same JWT tokens as REST endpoints. The token must be sent as the **first message** immediately after the WebSocket handshake completes:

1. Open a WebSocket connection to `/ws`.
2. Send the authentication frame (JSON):

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "node_address": "1A1zP1..."
}
```

3. If authentication succeeds the server starts sending events. If the token is invalid or missing the server closes the connection with **close code 4001**.

Obtain a token first via `POST /auth/login` as described in the [Authentication](#authentication) section above.

### Типы сообщений

**Клиент → Сервер:**

| Тип | Описание |
|-----|----------|
| `ping` | Проверка соединения |
| `status` | Запрос текущего статуса узла |

**Сервер → Клиент:**

| Тип | Описание |
|-----|----------|
| `pong` | Ответ на ping |
| `status` | Текущий статус узла |
| `message_new` | Уведомление о новом входящем сообщении |
| `peer_connected` | Пир подключился |
| `peer_disconnected` | Пир отключился |
| `sync_start` | Начало синхронизации |
| `sync_complete` | Синхронизация завершена |

**Пример: `message_new`:**
```json
{
  "type": "message_new",
  "message": {
    "id": "uuid",
    "from": "1SenderAddr...",
    "content_preview": "Привет!",
    "timestamp": 1712345678.0
  }
}
```

---

## Коды ошибок

| HTTP-код | Описание |
|----------|----------|
| 200 | Успех |
| 400 | Неверный запрос (валидация не пройдена) |
| 401 | Неверный или отсутствующий JWT-токен |
| 404 | Ресурс не найден |
| 429 | Rate limit превышен |
| 500 | Внутренняя ошибка сервера |

---

## Ограничения

| Параметр | Значение |
|----------|----------|
| Максимальный размер сообщения | 1 МБ |
| Максимальный размер файла | 50 МБ |
| Rate limit на `/messages/send` | 30 запросов/минуту |
| Максимальная длина имени | 64 символа |

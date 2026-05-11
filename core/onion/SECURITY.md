# MurNet Onion Stack — Security Audit

**Threat model:** Nation-state DPI (passive observation + active probing) + Active adversary trying to deanonymize hidden services.
**Date:** 2026-05-11
**Scope:** `core/onion/*.py`
**Methodology:** STRIDE + cryptographic primitive review.

---

## Findings — отсортированы по риску

| # | Severity | STRIDE | Файл | Состояние |
|---|---|---|---|---|
| F1 | **Critical** | T (Tampering/Replay) | `obfs.py:116-148` | Handshake без nonce → replay possible |
| F2 | **High** | I (Information Disclosure) | `hop_key.py:52` | AES-GCM random nonce → collision at 2³² msgs |
| F3 | **High** | I | `obfs.py:81` | Hardcoded shared PSK = пароль на дверь, не security boundary |
| F4 | **High** | D (DoS) | `obfs_transport.py:_on_accept` | No rate limit → X25519 CPU exhaustion |
| F5 | **High** | S (Spoofing) | `transport.py:124-129` | Relays не аутентифицируются ключом — MITM на пути |
| F6 | **Medium** | I | `obfs.py:150` | Timing leak: silent drop vs network slow distinguishable |
| F7 | **Medium** | S | `hidden_service.py:228` | 160-bit address → birthday attack 2⁸⁰ для коллизии |
| F8 | **Medium** | D | `transport.py:162` | Gossip flooding — directory растёт без лимита |
| F9 | **Medium** | I/T | `hs_client.py:170` | stream_id не связан с circuit → cross-circuit leak |
| F10 | **Low** | T/D | многие | JSON wire protocol = memory bomb / recursion DoS surface |

---

## F1. Handshake без replay protection ⚠️ CRITICAL

**Файл:** `core/onion/obfs.py:116-148`

**Что:** Текущий handshake:
```
Client → Server: pubkey_c || HMAC(PSK, pubkey_c)
Client ← Server: pubkey_s || HMAC(PSK, pubkey_s)
```

Атакующий пишет легитимный handshake клиента. Через час replay-ит его — сервер **не отличит**:
- HMAC валиден (PSK тот же)
- pubkey_c свежий (X25519 ephemeral, но сервер этого не знает)
- Сервер делает ECDH с peer_pk → получает session_key. Атакующий **session_key не знает** (нет priv_c), но:
  - Может заполнять connection table (DoS)
  - Может использовать для traffic correlation (timing pattern from C&C)
  - На уровне DPI — добавляет шум для классификатора

**Fix:** добавить challenge-response nonce.
```
Client → Server: pubkey_c || nonce_c || HMAC(PSK, pubkey_c || nonce_c)
Server validates HMAC. If OK:
Client ← Server: pubkey_s || nonce_s || HMAC(PSK, pubkey_s || nonce_s || nonce_c)
                                              # nonce_c included → server proves freshness

KDF salt = pubkey_c || pubkey_s || nonce_c || nonce_s
```

Это даёт **session uniqueness** + защиту от replay (server-side hmac binds к новому nonce_c). Реализую ниже.

---

## F2. AES-GCM nonce collision risk ⚠️ HIGH

**Файл:** `core/onion/hop_key.py:52`

```python
def hop_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)            # 96-bit random nonce
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
```

NIST SP 800-38D: безопасный лимит для random nonces = **2³² сообщений per key**. При collision AES-GCM полностью ломается (forge messages, recover plaintexts). Hop keys у нас живут долго в circuit — теоретически могут переплыть лимит при активном чате.

**Fix варианты:**
- (a) Counter-based nonce + key rotation после 2³² msgs. Сложно — нужна синхронизация state.
- (b) **Миграция на ChaCha20-Poly1305 с 12-byte counter nonce** (т.е. counter в nonce) — стандартный путь.
- (c) **XChaCha20-Poly1305** — 24-byte random nonce, безопасен до 2⁹² сообщений. Самый простой.

Рекомендую (c) — минимум изменений кода.

---

## F3. PSK = пароль на дверь, не security boundary ⚠️ HIGH

**Файл:** `core/onion/obfs.py:81`

```python
self._psk = psk or b"murnet-default-psk-v1"
```

PSK захардкожен, лежит в открытом коде, распространяется со всеми клиентами. Любой `grep` в публичном repo → PSK у атакующего. После этого:
- Атакующий аутентифицируется к любому relay
- DPI с PSK может **активно зондировать** все наши порты (но мы и так открыты)
- Реально PSK защищает только от **dumb scanner-ов** (Shodan), не от targeted attacker

**Fix:** PSK должен быть **per-network-instance**, не глобальный. Или вообще убрать его и положиться на X25519 + identity keys (как Tor). Tor v3 не использует PSK — он использует Ed25519 identity ключи relays.

Это не "написать код", это **архитектурное решение**. Логирую в roadmap.

---

## F4. DoS via X25519 CPU exhaustion ⚠️ HIGH

**Файл:** `core/onion/obfs_transport.py:_on_accept`

Любой может открыть TCP коннект → сервер делает X25519 ECDH per handshake (~0.1ms на современном CPU, но 10k conn/s = 100% CPU + memory pressure).

**Fix:** rate limit per source IP перед handshake:
```python
self._conn_rate: dict[str, deque[float]] = {}  # IP → [timestamps]
# в _on_accept: если >5 conn за последнюю секунду от IP → close без handshake
```

Реализую ниже.

---

## F5. Нет relay authentication ⚠️ HIGH

**Файл:** `core/onion/transport.py:124-129`

Когда originator отправляет CREATE к relay, он узнаёт relay по адресу `host:port`. **Нет проверки** что relay действительно тот, за кого себя выдаёт. Active MITM может терминировать TCP и подставить себя.

Tor решает это через `identity descriptor`: каждый relay имеет долгоживущий Ed25519 ключ, его pubkey известен заранее, в CREATE кладётся `expected_relay_pubkey`, relay подписывает CREATED.

**Fix:** в roadmap — это значимое архитектурное изменение.

---

## F6. Timing leak в silent drop

**Файл:** `core/onion/obfs.py:150-153`

Сервер при wrong PSK делает `writer.close()` мгновенно. Сервер при slow network не закрывает — read timeout наступает по другому таймеру. Это даёт active prober возможность отличить «wrong PSK» от «network problem» по миллисекундному паттерну.

**Fix:** добавить случайную задержку (50-500ms) перед close при PSK mismatch.

---

## F7. 160-bit hidden service address → birthday attack

**Файл:** `core/onion/hidden_service.py:228`

```python
hash160 = blake2b_hash(public_bytes, digest_size=20)   # 160 bit
```

Birthday-attack complexity = 2⁸⁰ операций. Это **слабо** для криптоадреса. Tor v2 был на 80-bit (SHA1/2 truncated) и его сломали. Tor v3 = 56-char base32 от **полного** Ed25519 pubkey (256 bit).

**Fix:** перейти на base32(full_pubkey) — длинные адреса (~52 символа), но reasonable security.

---

## F8. Gossip flooding

**Файл:** `core/onion/transport.py:162, hidden_service.py:172`

`_announce_loop` отправляет анонс каждые 30s. Malicious peer может отправлять тысячи fake announces с разными адресами — directory растёт без границ, memory exhaustion.

**Fix:** rate limit announce per source + max directory size + proof-of-work для записи в directory (как Tor v3 hsdir).

---

## F9. stream_id smuggling

**Файл:** `core/onion/hs_client.py:170`

```python
sid = str(uuid.uuid4())   # client-side random
```

stream_id — client-side random, не связан с circuit криптографически. На relay-side через `RELAY_BACK` приходит SID, и в `_on_circuit_data` мы делаем `self._queues.get(sid)`. Если два circuit'а имеют одинаковый SID (коллизия UUID на одном клиенте маловероятна, но возможна) — данные одного circuit'а попадут в queue другого.

**Fix:** SID = HMAC(circuit_key, counter), уникальность гарантирована per-circuit.

---

## F10. JSON wire protocol attack surface

**Файл:** многие — везде где `json.loads(raw)` на untrusted данных.

Атакующий может послать:
- Огромный JSON (например 100 MB) → memory bomb
- Глубоко вложенный JSON → recursion DoS
- Поля с null bytes

**Fix:**
- max length per cell = 64 KB (читать через `readexactly` с size header)
- `json.loads` с `parse_constant=lambda c: None` — отключить inf/-inf/NaN
- depth limit (Python recursion limit = 1000 by default — не катастрофа, но логично явно ограничить)

Long term: **бинарный протокол** (CBOR / protobuf / собственный TLV).

---

## Что я реализую сейчас (Этап А)

1. **F1 — replay-protected handshake** — переписываю `obfs.py` под challenge-nonce. *Breaking change для VDS, нужен перезалив.*
2. **F4 — rate limit в `_on_accept`** — простой token bucket per source.
3. **F6 — timing leak fix** — random sleep before silent drop.
4. **F10 — JSON size limit** — `readexactly(N)` with cap, не `readline()` без лимита.

## Что в roadmap (Этап Б, требует обсуждения)

- **F2** — миграция AES-GCM → XChaCha20-Poly1305 (значимое: меняет формат cells)
- **F3** — переход с global PSK на per-instance + identity keys (как Tor v3)
- **F5** — relay identity authentication
- **F7** — длинные адреса (56-char) из full pubkey
- **F8** — gossip rate limit + proof-of-work
- **F9** — stream_id binding к circuit
- **F10 long-term** — бинарный протокол вместо JSON

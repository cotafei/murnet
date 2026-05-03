# MurNet Onion Routing — v6.2

> **Дисклеймер.** Учебная реализация. Не проходила криптографический аудит.
> Не использовать для передачи данных, требующих реальной анонимности.

---

## Обзор

Onion-слой MurNet обеспечивает многоуровневое шифрование поверх обычного TCP.
Каждое сообщение проходит через цепочку relay-нод (circuit), каждая из которых
видит только соседей — не источник и не назначение.

```
Alice  →  Guard  →  Middle  →  Bob
         видит        видит      видит
         Alice        Guard      Middle
         Guard        Middle     (данные)
```

---

## Криптография

| Примитив | Назначение |
|---|---|
| X25519 ECDH | Обмен ключами при построении circuit |
| HKDF-SHA256 | Деривация сессионного ключа из ECDH-секрета |
| AES-256-GCM | Симметричное шифрование каждого слоя |

Каждый хоп получает **независимый** сессионный ключ. Компрометация одного хопа
не раскрывает ключи остальных.

---

## Построение Circuit (CREATE / EXTEND)

### Leg 1 — прямое соединение с первым хопом

```
Alice → CREATE(cid_1, ephem_pub_1) → Guard
Alice ← CREATED(cid_1, guard_ephem_pub) ← Guard
# Alice вычисляет K1 = HKDF(X25519(alice_priv, guard_pub))
```

### Leg 2 — расширение через существующий хоп

```
Alice → RELAY_FWD(cid_1, enc_K1({EXTEND, next:Middle, ephem_pub_2, new_cid:cid_2})) → Guard
Guard: расшифровывает K1, видит EXTEND → CREATE(cid_2, ephem_pub_2) → Middle
Middle → CREATED(cid_2, middle_ephem_pub) → Guard
Guard → RELAY_BACK(cid_1, enc_K1({EXTENDED, cid_2, middle_ephem_pub})) → Alice
# Alice расшифровывает K1, вычисляет K2
```

Leg 3 аналогично — EXTEND идёт через два существующих хопа.

---

## Отправка данных (RELAY_FWD / RELAY_BACK)

Alice оборачивает данные в N слоёв шифрования (по одному на каждый хоп):

```
payload = enc_K1(enc_K2(enc_K3(data)))
```

Каждый relay снимает один слой, видит `RELAY_NEXT` → передаёт дальше.
Exit-нода видит `RELAY_DATA` → вызывает `router.on_data(stream_id, data)`.

Обратный путь: Exit оборачивает ответ в K3, Middle добавляет K2, Guard — K1.
Alice снимает слои в обратном порядке.

---

## Wire-протокол (TCP)

Одна JSON-строка на соединение, завершается `\n`:

```json
{"src": "80.93.52.15:9001", "cell": {"oc_ver": 1, "cmd": "RELAY_FWD", "cid": "...", "data": "<base64>"}}
```

Gossip-анонс relay-ноды:

```json
{"src": "80.93.52.15:9001", "announce": {"addr": "80.93.52.15:9001", "name": "Guard", "timestamp": 1234567890.0, "ttl": 300}, "ttl": 4}
```

---

## NAT Traversal

Relay-ноды на VDS имеют открытые порты. Alice/Bob на ноутбуке — нет.

Решение: ответы всегда идут **по тому же TCP-соединению**, которое инициировал клиент.
Guard никогда не открывает новое соединение к Alice — только отвечает на входящее.

```
Alice → [открывает TCP] → Guard:9001
Guard: сохраняет writer в _inc["Alice-addr"]
Guard → [пишет в тот же writer] → Alice
```

---

## Relay Discovery (Gossip)

Ноды с флагом `--announce` периодически рассылают анонс соседям.
Соседи пересылают дальше с `ttl-1`. Alice, зная только один relay,
за несколько секунд узнаёт всю сеть.

```
Guard  →  announce(Guard)  →  Middle
Middle →  announce(Guard)  →  Exit
Middle →  announce(Middle) →  Exit
# Alice подключается к Guard, получает анонсы Guard+Middle+Exit
```

Директория хранится в `OnionTransport.directory: RelayDirectory`.
Запись живёт 300 секунд без обновления.

---

## Компоненты

| Файл | Назначение |
|---|---|
| `core/onion/cell.py` | `OnionCell`, `OnionCmd` — формат ячеек |
| `core/onion/hop_key.py` | X25519 + HKDF + AES-256-GCM |
| `core/onion/circuit.py` | `CircuitOrigin`, `RelayEntry`, `CircuitManager` |
| `core/onion/router.py` | `OnionRouter` — логика CREATE/EXTEND/RELAY |
| `core/onion/transport.py` | `OnionTransport` — TCP + NAT + gossip |
| `core/onion/directory.py` | `RelayDirectory` — реестр известных relay-нод |
| `api/onion_api.py` | Лёгкий HTTP API для relay-нод |
| `demos/onion_node.py` | Relay-нода или chat-участник (CLI) |
| `demos/onion_chat.py` | In-process демо с Textual TUI |

---

## Быстрый старт (5 терминалов, localhost)

```bash
# 3 relay-ноды
python demos/onion_node.py --bind 127.0.0.1:9001 --name Guard  --announce
python demos/onion_node.py --bind 127.0.0.1:9002 --name Middle --announce
python demos/onion_node.py --bind 127.0.0.1:9003 --name Exit   --announce

# Bob — строит circuit через Exit, Middle, Alice
python demos/onion_node.py --bind 127.0.0.1:9004 --name Bob \
    --peer Exit=127.0.0.1:9003 --peer Middle=127.0.0.1:9002 \
    --peer Alice=127.0.0.1:9000 --circuit Exit,Middle,Alice

# Alice — строит circuit через Guard, Middle, Bob
python demos/onion_node.py --bind 127.0.0.1:9000 --name Alice \
    --peer Guard=127.0.0.1:9001 --peer Middle=127.0.0.1:9002 \
    --peer Bob=127.0.0.1:9004 --circuit Guard,Middle,Bob
```

С auto-discovery (Alice знает только Guard):

```bash
python demos/onion_node.py --bind 127.0.0.1:9000 --name Alice \
    --peer Guard=127.0.0.1:9001 --circuit auto
```

---

## VDS-деплой

```bash
./scripts/vds.sh deploy   # SCP + restart
./scripts/vds.sh status   # процессы + curl API
./scripts/vds.sh logs Guard
```

Статус API каждой relay-ноды: `http://VDS_IP:808{1,2,3}/api/status`

# MurNet Architecture v6.2.3

> **Disclaimer.** The described architecture is an educational implementation of a P2P protocol.
> The project has not undergone a security audit and is not intended for storing
> sensitive data or use in production systems.

---

## Component Overview

In v6.2.1, the primary orchestrator is `AsyncMurnetNode` (`core/node/async_node.py`),
built on asyncio. `SecureMurnetNode` (`core/node/node.py`) is maintained for backward
compatibility. Each layer interacts with its neighbors through explicitly defined interfaces.

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
│  Layer 3: Network Secret — HMAC-SHA256 token in every HELLO      │
│  Layer 4: Cython         — core/identity/ → native .so/.pyd    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 0. Identity Layer (`core/identity/identity.py`)

The identity layer provides cryptographically strong node addresses and their persistence.

**NodeID:**
- Calculated as `blake2b(ed25519_pubkey, digest_size=32)` — a 32-byte deterministic
  identifier derived from the public key.
- The distance between two NodeIDs is determined by the XOR metric: `dist(a, b) = a XOR b`,
  providing the basis for k-bucket routing (Kademlia-compatible DHT).

**Classes:**
- `NodeIdentity` — a wrapper over `crypto.Identity`; adds the `node_id` (NodeID) field
  and exports convenient `sign()` / `verify()` methods with NodeID typing.
- `IdentityStore` — identity persistence: saves and loads
  serialized key material from `core/data/storage.py` (the `identity` table);
  generates a new key pair on the first run.

**Interaction:**
- `AsyncMurnetNode` initializes `IdentityStore` at startup and passes
  `NodeIdentity` to all dependent layers (Transport, DHT, Routing).
- NodeID is used in RoutingTable as the node's primary key and in MurnakedNode
  to calculate XOR proximity when searching for the responsible node.

---

## 1. Crypto (`core/identity/crypto.py`)

Responsible for all cryptographic operations of the node.

**Classes:**
- `Identity` — stores an Ed25519 key pair, generates an address, signs and verifies data.
- `E2EEncryption` — encrypts and decrypts application messages (AES-256-GCM + X25519).
- `SecureChannel` — a session channel with ephemeral keys for forward secrecy.

**Key Functions:**
- `base58_encode / base58_decode` — address encoding.
- `blake2b_hash` — hashing (replaces SHA-256 where compatibility is not needed).
- `derive_key_argon2` — Argon2id derivation for seeds/passwords.
- `canonical_json` — deterministic serialization for signatures.

**Protection:**
- Constant-time comparison (`hmac.compare_digest`) against timing attacks.
- Private key is never passed outside the Identity object (Chalkias protection).
- Best-effort key wiping attempt in `__del__` (Python does not guarantee immediate execution).

---

## 2. Transport (`core/net/transport.py` and `core/net/async_transport.py`)

In v6.1, the transport layer is represented by two implementations:

| Module | Class | Used in |
|---|---|---|
| `core/net/transport.py` | `Transport` (sync, threading) | `SecureMurnetNode` |
| `core/net/async_transport.py` | `AsyncTransport` (asyncio) | `AsyncMurnetNode` |

**`Transport` (sync):**
- Manages socket, receive/send threads.
- `PacketHeader` — 36-byte header (encoding/decoding via `struct`).
- `PeerConnection` — state of a single peer: sequence window, RTT, session key.
- `RateLimiter` — per-IP token-bucket limiter.
- `_recv_loop`, `_process_packet`, `_send_loop` threads.

**`AsyncTransport` (asyncio):**
- Uses `asyncio.DatagramProtocol` instead of threads; does not block the event loop.
- Same packet format and HMAC authentication as in `Transport`.
- `register_handler(msg_type, coro)` — compatibility layer: allows registering
  both synchronous functions and coroutines; synchronous calls are wrapped in
  `asyncio.get_event_loop().run_in_executor()` for non-blocking execution.

**Limitations (applicable to both implementations):**
- Per-peer rate limit in `Transport` is implemented via `deque(maxlen=100)`, making
  it inefficient at high pps.
- NAT traversal is not implemented.
- Packet fragmentation (DATA_FRAG) is partially implemented.

---

## 3. Routing (`core/net/routing.py`)

Link-state protocol for building topology and calculating paths.

**Classes:**
- `RoutingTable` — public routing interface; delegates to LSDB and Dijkstra.
- `LinkStateDatabase` — stores LSAs of all nodes, builds the network graph.
- `DijkstraEngine` — calculates shortest paths considering trust score and ECMP.
- `LSA` — signed link-state advertisement with a hash-chain.
- `Link` — description of a single edge (cost, bandwidth, latency, loss_rate, state).

**Edge Cost Algorithm:**
```python
effective_cost = cost + loss_rate * 10 + latency / 10
effective_cost *= (1 + (1000 - bandwidth) / 1000)
if state == DOWN: effective_cost = inf

adjusted_cost = effective_cost / trust_score(neighbor)
```

**LSA pipeline:**
1. `RoutingTable.add_link()` → `lsdb.originate_lsa()` — signs and publishes LSA.
2. `receive_lsa()` — checks timestamp, sequence, signature; updates trust.
3. Flood detection: >10 LSAs/sec from one origin → ignored.
4. After any LSDB update, `recompute()` is triggered → Dijkstra.

---

## 4. DHT — MurnakedNode (`core/net/murnaked.py`, `core/net/dht_rpc.py`)

Distributed key-value store based on Kademlia.

**Classes:**
- `MurnakedNode` — top level; provides `store`, `retrieve`, `register_name`, `get_name`, `save_file`, `get_file`.
- `ConsistentHashRing` — ring with virtual nodes (10 vnodes/node).
- `DHTRPCManager` — DHT network layer; authenticates requests via HMAC-SHA3-256.
- `BloomFilter` — probabilistic key existence check without a full search.

**NodeID XOR Distance and k-bucket Routing:**
- In v6.1, `MurnakedNode` uses NodeID from the Identity Layer to calculate XOR proximity
  when searching for the responsible node: `responsible = min(peers, key=lambda p: p.node_id XOR target_id)`.
- This provides the basis for a k-bucket routing table (160 buckets of 20 nodes each),
  compatible with original Kademlia (BEP-5).
- `ConsistentHashRing` is maintained for load balancing within the responsible region.

**Reliability Scheme:**
- Replication factor = 3: each key is stored on three ring nodes.
- Hinted handoff: if the target node is unavailable, data is temporarily stored by the current node.
- Anti-entropy: periodic replica reconciliation between neighbors.

**Key Schema:**
```
msg:<uuid>    — application message
name:<name>   — Name Service record
file:<uuid>   — file
```

---

## 5. Storage (`core/data/storage.py`)

Persistent layer on SQLite with caching.

**Class:** `Storage`

**Tables:**
- `messages` — incoming/outgoing messages (`id`, `from_addr`, `to_addr`, `content`, `timestamp`, `delivered`, `read`, `compressed`, ...).
- `dht_data` — local DHT copy (`key`, `value`, `value_type`, `ttl`, `version`, ...).
- `identity` — serialized node key material.

**Optimizations:**
- SQLite WAL mode for parallel reading.
- LRU cache (1000 entries) for hot data.
- zlib compression for messages longer than 100 bytes.
- DHT values longer than 1000 bytes are compressed and marked `:gzip` in `value_type`.

---

## 6. API Server (`api/server.py`)

REST API and WebSocket server on FastAPI.

**Security middleware:**
- JWT authentication (Bearer token) on all endpoints except `/health`.
- Rate limit: 30 requests/minute on `/messages/send`.
- Security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CSP: default-src 'self'`, `HSTS`.
- Strict filename validation (`validate_filename`): only `[a-zA-Z0-9_-]+\.[a-zA-Z0-9]{1,10}`, no `..`, `/`, `\`, null-bytes.

**File Upload Security:**
- Streaming upload in 64 KB chunks (no full RAM buffering).
- MIME type check via puremagic (magic bytes), not extension.
- UUID generated by the server; the filename from the request is not used as a path.

---

## 7. Node Orchestrators

### AsyncMurnetNode (`core/node/async_node.py`)

The primary v6.1 orchestrator, built on `asyncio`. Manages all layers
asynchronously: runs `AsyncTransport`, `RoutingTable`, `MurnakedNode`, `Storage`,
and `E2EEncryption` as a set of coordinated coroutines in a single event loop.

- Initialization: `await node.start()` → starts `AsyncTransport`, loads
  `IdentityStore`, connects handlers via `register_handler()`.
- Shutdown: `await node.stop()` — correctly waits for all tasks to complete.
- `CircuitBreaker` and `BackpressureController` are adapted for asyncio
  (`asyncio.Lock` instead of `threading.RLock`).

### SecureMurnetNode (`core/node/node.py`)

Thread-based orchestrator (threading); maintained for backward compatibility.

**Resilience Patterns:**
- `CircuitBreaker` — blocks sending after N consecutive errors; auto-recovery via `recovery_timeout`.
- `BackpressureController` — throttles when queue filling >80%, releases at <30%.
- `MetricsCollector` — sliding latency histograms, security event counters.

**Processing Queues:**
```
outbox_queue  (maxsize=100000) → _outbox_loop → _process_outgoing
retry_queue   (maxsize=100000) → _retry_loop  (retry after 30s, up to 3 times)
handler_queue (maxsize=100000) → _handler_loop → _handle_packet
```

**Message Send Flow:**
```
send_message(to, text)
  │
  ├─ sign(message)           ← Ed25519
  ├─ encrypt(text, peer_key) ← AES-256-GCM (if recipient's pubkey is known)
  ├─ storage.save_message()  ← SQLite
  ├─ outbox_queue.put()
  └─ pending_acks[msg_id]    ← record for ACK tracking

_process_outgoing(message)
  │
  ├─ routing.get_next_hop(to) → next hop
  ├─ transport.peers[hop]     → PeerConnection
  └─ transport.send_to()      → UDP + HMAC-Blake2b
```

---

## 8. Object System + Pub/Sub (`core/data/objects.py`, `core/node/pubsub.py`)

Introduced in v6.2. Provides content-addressable data storage and a
publisher/subscriber mechanism on top of the existing transport.

### MurObject (`core/data/objects.py`)

Immutable, signable object with a hash identifier:

```json
{
  "id":        "<blake2b-256 hex of content>",
  "type":      "<type string: msg / profile / text / ...>",
  "owner":     "<base58 address of creator>",
  "timestamp": 1712345678.123,
  "data":      { "...": "arbitrary JSON payload" },
  "signature": "<base64 of Ed25519 signature of canonical_bytes()>"
}
```

- `id` — `blake2b-256(canonical JSON without id/signature fields)` — content verification.
- `MurObject.create(type, owner, data, identity)` — creates and signs an object.
- `verify_id()` / `verify_signature(pubkey_hex)` / `is_valid()` — integrity check.

### ObjectStore (`core/data/objects.py`)

Hash-addressed storage:

- In-memory LRU cache (512 entries).
- Sharded disk: `objects/<first 2 chars of id>/<id>.json` (like Git).
- Interface: `put` / `get` / `has` / `delete` / `list_ids` / `list_by_type` / `stats`.
- `put()` rejects objects with mismatched IDs (integrity check at the storage boundary).

### PubSubManager (`core/node/pubsub.py`)

Gossip publisher/subscriber layer:

- `topic_id(name)` — maps topic name to a 32-character Blake2b-128 hex.
- `subscribe(topic, callback)` / `unsubscribe(topic, callback)` — local subscriptions.
- `publish(topic, obj)` / `async_publish()` — saves locally, calls callbacks, sends gossip.
- Gossip with TTL field (default 3 hops); dedup ring buffer of 4096 entries.
- `handle_raw()` / `async_handle_raw()` — path for receiving from transport.
- Objects with incorrect ID (tamper) are dropped on the receive path.

**Integration with AsyncMurnetNode:**

```python
node.object_store  # ObjectStore — accessible directly
node.pubsub        # PubSubManager — subscription and publication

node.pubsub.subscribe("room:general", callback)
obj = MurObject.create("text", node.address, {"text": "Hello!"}, identity)
await node.pubsub.async_publish("room:general", obj)
```

**Wire format of gossip message** (JSON, DATA type):

```json
{
  "murnet_pubsub": true,
  "action":        "publish",
  "topic":         "<32-char topic_id hex>",
  "object":        { "<MurObject>" },
  "ttl":           3,
  "seen_by":       ["<sender address>"]
}
```

---

## 9. Encrypted Keystore (`core/identity/keystore.py`) — v6.2.1

Node private key protection using a user password.

**Principle:** no password — no node access. Recovery is not provided.

**Encryption Scheme:**

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

**Class `EncryptedKeystore`:**

| Method | Description |
|-------|----------|
| `exists()` | Checks for file existence |
| `create(key_bytes, password)` | Encrypts and saves the key (WeakPasswordError < 8 characters) |
| `load(password)` | Decrypts; WrongPasswordError + delay of 0.5–0.8 s on failure |
| `change_password(old, new)` | Re-encryption with a new password |
| `wipe()` | Overwrites with random bytes + fsync + deletion (best-effort) |

**Security Measures (v6.2.1):**

1. **Anti-bruteforce:** `time.sleep(0.5 + jitter)` on `WrongPasswordError` — ~10 attempts/min maximum.
2. **Version Migration:** `version=1` (nonce included in ciphertext) is automatically read by `_migrate_v1_to_v2()`.
3. **Memory Hygiene:** the key is derived into a `bytearray`, fields are zeroed out in a `finally` block.
4. **Wipe Limitations:** physical destruction on SSD/NVMe/journaling FS is not guaranteed; disk encryption (LUKS/BitLocker/FileVault) is recommended.

**Integration in AsyncMurnetNode:**

```python
# First run: creates encrypted keystore
node = AsyncMurnetNode(data_dir="./data", port=8888, password="my_password_123")

# Subsequent runs: unlock
node = AsyncMurnetNode(data_dir="./data", port=8888, password="my_password_123")
# → WrongPasswordError if the password is wrong
```

**CLI:** `prompt_password_cli(data_dir)` — interactive prompt (getpass), double entry upon creation.

**Desktop GUI:** `PasswordDialog` — tkinter dialog with `create / unlock / change` modes, dark theme, show/hide button.

---

## 10. Network Visualizer (`network_viz.py`)

Autonomous network topology visualization tool. Does not require additional
dependencies (only standard Python library + tkinter).

**Architecture:**

```
                  ┌─────────────────┐
                  │   APIClient     │  HTTP poll → /network/status + /network/peers
                  │   (threading)   │  (Bearer JWT, configurable interval)
                  └────────┬────────┘
                           │ NetworkSnapshot
                  ┌────────▼────────┐
                  │  ForceLayout    │  Fruchterman-Reingold physics
                  │  (repulsion +   │  → (x, y) coordinates for each node
                  │   attraction)   │
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

**Launch Modes:**

```bash
# Demo mode (without real API): synthetic 6-node topology
python network_viz.py --demo

# Connect to a real node
python network_viz.py --api http://127.0.0.1:8080 --token <JWT>

# Configure polling interval
python network_viz.py --api http://127.0.0.1:8080 --poll 5
```

**Controls:**

| Key / Action | Description |
|--------------------|----------|
| Drag node | Move to a new position (pin) |
| RMB on node | Toggle pin |
| Drag background | Pan view |
| Scroll / `+`/`-` | Zoom |
| `Space` | Reset view |
| `R` | Forced refresh |
| `Q` / `Esc` | Exit |

---

## 11. Protocol Schema (`core/net/protocol.py`)

Unified message schema for all Murnet v6.1 protocol layers.

**Base Class:**
- `MurMessage` — base class for all messages; contains mandatory fields
  `version` (fixed as `"6.1"`), `msg_type`, `sender_id` (NodeID), `timestamp`,
  `nonce`, and an optional `payload`.

**Message Types:**
`MurMessage` supports 18 `MessageType` values:

| Group | Types |
|---|---|
| Routing | `LSA`, `LSA_ACK`, `ROUTE_REQUEST`, `ROUTE_REPLY` |
| DHT | `DHT_STORE`, `DHT_FIND_NODE`, `DHT_FIND_VALUE`, `DHT_STORE_ACK` |
| Application Layer | `MSG_SEND`, `MSG_ACK`, `MSG_NACK`, `FILE_OFFER`, `FILE_CHUNK`, `FILE_ACK` |
| Control | `PING`, `PONG`, `PEER_EXCHANGE`, `ERROR`, `HANDSHAKE` |

**Key Functions:**
- `parse_message(raw: bytes) -> MurMessage` — factory method; deserializes bytes,
  checks the `version == "6.1"` field, returns a specific subclass based on `msg_type`.
- `canonical_bytes(msg: MurMessage) -> bytes` — deterministic serialization
  for signature: fields are sorted by key, `nonce` and `signature` are excluded;
  used in `Identity.sign()` / `NodeIdentity.verify()`.

**Versioning:**
- The `version` field allows rejecting packets from nodes with incompatible protocol versions;
  `parse_message()` throws `ProtocolVersionError` on mismatch.

---

## 12. Mobile Optimizers (`mobile/`)

A set of modules for adapting operation on mobile devices.

**BatteryOptimizer (`battery.py`):**

| State | Charge | Sync Interval |
|-----------|-------|----------------------|
| CHARGING | any | 30 s |
| NORMAL | >30% | 60 s |
| SAVER | 15–30% | 120 s |
| CRITICAL | <15% | 900 s, DHT repair disabled |

**MobileNetworkManager (`network.py`):**
- Determines network type via RTT heuristics (WiFi / 4G / 3G / 2G).
- Can pause synchronization on metered connections.
- Offline queue: messages are buffered and sent upon restoration.

**SyncManager (`sync.py`):**
- Priority task queue: CRITICAL > HIGH > NORMAL > LOW > BACKGROUND.
- Exponential backoff on failures.

---

## 13. Threads and Concurrency

Each running node creates the following threads:

| Thread | Name | Function |
|-------|-----|---------|
| Recv | `Transport-recv` | Receiving UDP packets |
| Send | `Transport-send` | Sending from queue |
| Outbox | `SecureNode-Outbox` | Outgoing routing |
| Retry | `SecureNode-Retry` | Retrying unconfirmed packets |
| Handler | `SecureNode-Handler` | Incoming packet processing |
| Metrics | `SecureNode-Metrics` | Metrics collection every 1 s |
| Security | `SecureNode-Security` | Security monitoring every 60 s |

ThreadPoolExecutor: 20 workers (`SecureNode-v6-*`) for parallel operations.

`AsyncMurnetNode` does not create its own threads — all operations are executed
in the event loop; blocking calls (SQLite, crypto) are passed to
`loop.run_in_executor(executor)`.

---

## 14. Known Limitations

- **Thread safety**: most structures are protected by `threading.RLock`, but there are
  non-atomic operations in `BackpressureController` (`current_load`, `is_throttled`
  fields are modified without locking).
- **Memory clearing**: `Identity.__del__` attempts to wipe the key, but CPython
  does not guarantee immediate destructor call; the key might remain in memory.
- **Rate limiter**: per-peer limit via `deque(maxlen=100)` does not block at
  high pps due to the maxlen effect.
- **X25519 from Ed25519 key**: correct in this context only because both keys
  are 32 bytes of random data; not a common practice.

---

## 15. Security Layers (`core/net/network_auth.py`, `core/integrity.py`) — v6.2.2–6.2.3

Three independent layers of protection against unauthorized code usage.

### Layer 1 — Build Signing (`core/integrity.py`)

With every official release, all files in `core/` are signed with an Ed25519 key.
Upon node startup, `verify_integrity()` is called:

```
1. SHA-256(each .py in core/)  →  manifest dict
2. JSON(manifest, sorted_keys)  →  bytes
3. Ed25519.verify(sig, bytes, _SIGNING_PUBLIC_KEY)
   ↳ OK  → node starts
   ↳ FAIL → TamperedBuildError (node will not start)
```

- `_SIGNING_PUBLIC_KEY` is embedded in the code — it's impossible to replace it without changing the file,
  which itself invalidates the signature.
- `BUILD_SIGNATURE` is stored in the repo root; the private key is held only by the owner.

### Layer 3 — Network Secret (`core/net/network_auth.py`)

Every HELLO packet contains a one-time token:

```
nonce  = os.urandom(32)          # fresh for each handshake
ts     = int(time.time())
token  = HMAC-SHA256(NETWORK_SECRET, nonce || ts_big_endian_8)
```

The receiving node verifies:
1. Token is present.
2. `|now - ts| ≤ 300 s` (replay protection).
3. HMAC matches.

If any check fails — the HELLO is silently ignored without
sending an error (does not reveal the reason for rejection).

**Configuration:**

| Source | Priority | Description |
|---|---|---|
| Hardcoded in `network_auth.py` | base | Works "out of the box" in official builds |
| `MURNET_SECRET=<hex>` env-var | overrides | For test/private networks |
| `na.set_secret(bytes)` | overrides | Programmatic setting |

### Layer 4 — Cython (`setup_cython.py`)

Compiling `core/identity/{crypto,keystore,identity}.py` into native extensions:

```bash
pip install cython
python setup_cython.py build_ext --inplace
# → core/identity/crypto.cpython-3XX.so
# → core/identity/keystore.cpython-3XX.so
# → core/identity/identity.cpython-3XX.so
```

Python automatically prefers the `.so` file over the `.py` file when they have the same name.
Sources can be removed from the distribution after the build.

### Release Workflow

```bash
# 1. Make changes in core/
# 2. Sign new build (private key only with owner)
python tools/sign_build.py --sign --key-file build_key.pem

# 3. Verify signature
python tools/sign_build.py --verify   # → OK

# 4. Commit BUILD_SIGNATURE along with changes
git add BUILD_SIGNATURE && git commit -m "..."
```

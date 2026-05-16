# 📡 MurNet Protocol Specification (v6.2.3)

This document provides a comprehensive technical description of all protocols, routing layers, data structures, and security mechanisms laid into the foundation of MurNet v6.2.3.

> **Disclaimer.** This specification describes an experimental P2P protocol developed within the *Security by Design* paradigm.

---

## 1. Layered Architecture Concept

MurNet departs from the classical OSI model, implementing its own hierarchy of data protection and node consensus:

* **Layer 1 (Binary Integrity):** Validation of local executable code authenticity.
* **Layer 2 (Identity & Keystore):** Generation, storage, and protection of cryptographic keys.
* **Layer 3 (Transport & Network Secret):** Protection at the UDP segment level, noise filtering, anti-replay.
* **Layer 4 (Handshake & KEX):** Establishment of session keys using the Diffie-Hellman algorithm.
* **Layer 5 (E2E & Data):** End-to-End encryption of payload, Pub/Sub gossip, and MurObject storage.
* **Layer 6 (Routing & DHT):** Route discovery (LSA) and peer location (Kademlia).

---

## 2. Layer 1: Integrity & Tamper-Detection

To prevent the introduction of backdoors (supply chain attacks or local viruses), MurNet v6.2.3 introduces a **Build Signing** system.

1. Before a release, the developer signs all core Python files (`core/*.py`) using `tools/sign_build.py`.
2. A `BUILD_SIGNATURE` manifest is created, containing file hashes (`SHA-256`) and a cryptographic signature of the entire manifest (`Ed25519`).
3. Upon node startup (before network initialization), the system reads the manifest. If any byte in the source code has been changed or the manifest signature does not match the hardcoded public key of the trusted release manager, the node **refuses to start**.

---

## 3. Layer 2: Cryptography and Identity

### 3.1. Key Pair and NodeID
The foundation of node identity is **Ed25519** asymmetric cryptography.
* `private_key` (32 bytes) — kept strictly secret.
* `public_key` (32 bytes) — publicly broadcast to the network.
* **NodeID:** A unique node identifier is calculated as a 32-byte hash: `Blake2b-256(public_key)`.
* **Address (Alias):** For UI display, the public key is hashed, a version prefix and checksum are added, and the result is encoded in Base58 (similar to Bitcoin addresses).

### 3.2. Encrypted Keystore
The private key is stored locally on disk in encrypted form.
* **KDF (Key Derivation Function):** `Argon2id` is used (64MB RAM, 4 lanes, 3 iterations) — an algorithm resistant to GPU/ASIC attacks. It transforms a user password into a 32-byte symmetric key.
* **Encryption:** The symmetric key is used in `AES-256-GCM` to encrypt the Ed25519 private key itself.
* **Anti-bruteforce:** An artificial delay (0.5–0.8 seconds) is programmatically introduced upon each incorrect password entry, making automated password brute-forcing pointless.
* File access permissions are strictly set to `0o600` (read/write only for the OS owner).

---

## 4. Layer 3: Transport Layer (UDP)

ALL network exchange goes through an asynchronous datagram protocol (`asyncio.DatagramProtocol`).

### 4.1 Packet Format (36-byte header)
Each UDP packet consists of a binary header and a Payload.
`struct.pack('!BBIIHII', version, type, seq, ack, len, time, rsv) + 16_byte_MAC`

* `version` (1 byte): Protocol version.
* `packet_type` (1 byte): Type (`PING=0x01`, `HELLO=0x03`, `DATA=0x10`, etc.).
* `sequence` (4 bytes): Monotonically increasing packet number.
* `timestamp` (4 bytes): Unix timestamp.
* `auth_tag` (16 bytes): HMAC-Blake2b packet authentication tag.

### 4.2 Network Secret Token
Each `HELLO` packet must carry an HMAC-SHA256 token signed with a hardcoded `NETWORK_SECRET`. This immediately discards any scanning garbage from attackers (Nmap, random packets), reducing CPU load before cryptographic calculations begin.

### 4.3 Anti-Replay and Rate Limiting
* **Sliding Window:** The node remembers the `sequence` of the last 1000 packets. If a packet has an old sequence or a `timestamp` that is too old (drift more than 300 seconds), it is dropped.
* **Limits:** A Token Bucket is built-in for a maximum of 100 packets per second from a single IP. Exceeding this leads to a temporary ban.

---

## 5. Layer 4: Handshake and Key Exchange (KEX)

Before sending data, nodes establish a secure channel.

1. Node A sends a `HELLO` (its Ed25519 public key).
2. Node B responds with its `HELLO`.
3. Both nodes implicitly convert each other's `Ed25519` public keys into Montgomery curve (`X25519`) and perform **Elliptic Curve Diffie-Hellman (ECDH)**.
4. The resulting shared secret is passed through **HKDF-SHA256**, generating a 32-byte session key.
5. From this point on, all `DATA` packets are signed (HMAC) and encrypted with this session key.

---

## 6. Layer 5: Data, Objects, and Pub/Sub

### 6.1 End-to-End Encryption
The payload (`DATA`) is represented as JSON.
Before sending, the `text` from the JSON is encrypted using **AES-256-GCM** (where the `session_key` from Layer 4 acts as the key). GCM guarantees that even if someone replaces 1 bit in the encrypted message, the AEAD tag will not match and the packet will be discarded.

### 6.2 MurObject (Content-Addressable Memory)
MurNet supports the transmission of files and immutable records through the `MurObject` abstraction.
* Each object is serialized, after which its `Blake2b` hash is calculated. This hash becomes the object ID.
* The owner signs the object with their `Ed25519` key.
* Nodes cache objects (LRU Cache) and can request them from each other by hash, guaranteeing that it's impossible to forge a file (the hash would change).

### 6.3 PubSubManager (Gossip Protocol)
A Gossip protocol is implemented for communication in rooms ("topics"):
1. A node forms a message and specifies a `topic_id`.
2. The node broadcasts it to all its active peers.
3. The message has a `TTL = 3` (Time To Live) parameter.
4. The receiving node checks the local deduplication buffer (LRU with 4096 elements). If the message is new, it decrements the TTL by 1 and retransmits it to its neighbors (except for the one it came from).
This guarantees network coverage (flooding) without infinite loops (broadcast storms).

---

## 7. Layer 6: Routing and Kademlia DHT

Since nodes can be behind NAT, MurNet uses two mechanisms for discovery and delivery.

### 7.1 Kademlia DHT (`murnaked`)
A distributed hash table. Each node is a point in XOR space.
* Used for **Name Service** (when a user registers an alias `name:alice`, the DHT stores the binding `alice -> NodeID`, signed with Alice's key).
* Used to find node IP addresses if only their NodeID is known.

### 7.2 Link-State Routing (LSA)
Inspired by the OSPF protocol.
* Each node periodically creates an **LSA** (Link-State Advertisement) — a list of its neighbors and pings (latency) to them.
* The LSA is signed with the node's key and broadcast across the entire network.
* Each node collects LSAs from everyone and builds a 100% accurate mathematical graph of the entire network in its memory.
* To send a message to a node outside direct visibility, **Dijkstra's Algorithm** is run. It calculates the shortest path (considering latency).
* **Trust Score:** If a neighbor sends corrupted LSAs or fake data, its Trust Score drops. At Score < 0.3, it is excluded from routes.

---
**Summary:** The combination of Kademlia for discovery, OSPF routing for delivery, and AES-256-GCM + Argon2id for security makes MurNet v6.2.3 an extremely attack-resistant experimental P2P suite.

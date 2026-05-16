# MurNet Onion Routing — v6.2

> **Disclaimer.** Educational implementation. Not cryptographically audited.
> Do not use for transmitting data that requires real anonymity.

---

## Overview

The MurNet onion layer provides multi-level encryption on top of regular TCP.
Every message passes through a chain of relay nodes (circuit), each of which
only sees its neighbors — not the source and not the destination.

```
Alice  →  Guard  →  Middle  →  Bob
         sees         sees       sees
         Alice        Guard      Middle
         Guard        Middle     (data)
```

---

## Cryptography

| Primitive | Purpose |
|---|---|
| X25519 ECDH | Key exchange during circuit construction |
| HKDF-SHA256 | Session key derivation from ECDH secret |
| AES-256-GCM | Symmetric encryption of each layer |

Each hop receives an **independent** session key. Compromising one hop
does not reveal the keys of the others.

---

## Circuit Construction (CREATE / EXTEND)

### Leg 1 — Direct connection to the first hop

```
Alice → CREATE(cid_1, ephem_pub_1) → Guard
Alice ← CREATED(cid_1, guard_ephem_pub) ← Guard
# Alice calculates K1 = HKDF(X25519(alice_priv, guard_pub))
```

### Leg 2 — Extension through an existing hop

```
Alice → RELAY_FWD(cid_1, enc_K1({EXTEND, next:Middle, ephem_pub_2, new_cid:cid_2})) → Guard
Guard: decrypts K1, sees EXTEND → CREATE(cid_2, ephem_pub_2) → Middle
Middle → CREATED(cid_2, middle_ephem_pub) → Guard
Guard → RELAY_BACK(cid_1, enc_K1({EXTENDED, cid_2, middle_ephem_pub})) → Alice
# Alice decrypts K1, calculates K2
```

Leg 3 is similar — EXTEND goes through two existing hops.

---

## Data Transmission (RELAY_FWD / RELAY_BACK)

Alice wraps the data in N layers of encryption (one for each hop):

```
payload = enc_K1(enc_K2(enc_K3(data)))
```

Each relay removes one layer, sees `RELAY_NEXT` → passes it further.
The exit node sees `RELAY_DATA` → calls `router.on_data(stream_id, data)`.

Reverse path: The Exit node wraps the response in K3, Middle adds K2, Guard — K1.
Alice removes the layers in reverse order.

---

## Wire Protocol (TCP)

One JSON string per connection, terminated by `\n`:

```json
{"src": "80.93.52.15:9001", "cell": {"oc_ver": 1, "cmd": "RELAY_FWD", "cid": "...", "data": "<base64>"}}
```

Gossip announcement of a relay node:

```json
{"src": "80.93.52.15:9001", "announce": {"addr": "80.93.52.15:9001", "name": "Guard", "timestamp": 1234567890.0, "ttl": 300}, "ttl": 4}
```

---

## NAT Traversal

When `OnionTransport.start()` is launched, a three-step public address determination is performed:

### Step 1 — UPnP (IGD)

The node sends an SSDP M-SEARCH to `239.255.255.250:1900`. If the home router
responds within 3 seconds — an `AddPortMapping` is requested via SOAP. Upon success:

```
public_addr = f"{router_external_ip}:{bind_port}"
nat_type    = "open"
upnp_active = True   # DeletePortMapping will be called at stop()
```

When shutting down, `stop()` automatically calls `DeletePortMapping`.

### Step 2 — STUN (if UPnP is unavailable)

Two Binding Requests (RFC 5389) are sent to `stun.l.google.com:19302`
(and others from the list) from different local ports.

| Result | `nat_type` | Description |
|---|---|---|
| public_port == bind_port | `open` | No NAT or 1:1 (VDS) |
| both requests → same port | `cone` | Port-preserving NAT, accessible from outside |
| different public ports | `symmetric` | Symmetric NAT, inaccessible |
| no response | `blocked` | Firewall or STUN unavailable |

If `open` or `cone`:
```
public_addr = f"{stun_public_ip}:{stun_public_port}"
```

### Step 3 — client-only fallback

If neither UPnP nor STUN provided a reachable address (`symmetric` / `blocked`):
```
public_addr = None
```
The node operates in **client-only** mode: connects to relay nodes as a client,
but does not announce itself as a relay via gossip.

### Incoming Connections (Passive NAT)

Clients behind NAT receive responses even without UPnP/STUN: responses always go
**via the same TCP connection** initiated by the client.
The Guard never opens a new connection to Alice — it only responds to the incoming one.

```
Alice → [opens TCP] → Guard:9001
Guard: saves writer in _inc["Alice-addr"]
Guard → [writes to the same writer] → Alice
```

> **VDS Nodes:** UPnP is not needed and doesn't work. STUN correctly determines `open`
> (public IP == external IP), `public_addr` is set automatically.

---

## Relay Discovery (Gossip)

Nodes with the `--announce` flag periodically send an announcement to neighbors.
Neighbors forward it with `ttl-1`. Alice, knowing only one relay,
learns the entire network within a few seconds.

```
Guard  →  announce(Guard)  →  Middle
Middle →  announce(Guard)  →  Exit
Middle →  announce(Middle) →  Exit
# Alice connects to Guard, receives Guard+Middle+Exit announcements
```

The directory is stored in `OnionTransport.directory: RelayDirectory`.
A record lives for 300 seconds without an update.

---

## Components

| File | Purpose |
|---|---|
| `core/onion/cell.py` | `OnionCell`, `OnionCmd` — cell format |
| `core/onion/hop_key.py` | X25519 + HKDF + AES-256-GCM |
| `core/onion/circuit.py` | `CircuitOrigin`, `RelayEntry`, `CircuitManager` |
| `core/onion/router.py` | `OnionRouter` — CREATE/EXTEND/RELAY logic |
| `core/onion/transport.py` | `OnionTransport` — TCP + UPnP/STUN NAT + gossip |
| `core/net/stun.py` | `StunClient` — RFC 5389 public IP/port + NAT type detection |
| `core/net/upnp.py` | `UPnPClient` — IGD SSDP/SOAP port mapping |
| `core/onion/directory.py` | `RelayDirectory` — registry of known relay nodes |
| `api/onion_api.py` | Lightweight HTTP API for relay nodes |
| `demos/onion_node.py` | Relay node or chat participant (CLI) |
| `demos/onion_chat.py` | In-process demo with Textual TUI |

---

## Quick Start (5 terminals, localhost)

```bash
# 3 relay nodes
python demos/onion_node.py --bind 127.0.0.1:9001 --name Guard  --announce
python demos/onion_node.py --bind 127.0.0.1:9002 --name Middle --announce
python demos/onion_node.py --bind 127.0.0.1:9003 --name Exit   --announce

# Bob — builds a circuit through Exit, Middle, Alice
python demos/onion_node.py --bind 127.0.0.1:9004 --name Bob \
    --peer Exit=127.0.0.1:9003 --peer Middle=127.0.0.1:9002 \
    --peer Alice=127.0.0.1:9000 --circuit Exit,Middle,Alice

# Alice — builds a circuit through Guard, Middle, Bob
python demos/onion_node.py --bind 127.0.0.1:9000 --name Alice \
    --peer Guard=127.0.0.1:9001 --peer Middle=127.0.0.1:9002 \
    --peer Bob=127.0.0.1:9004 --circuit Guard,Middle,Bob
```

With auto-discovery (Alice only knows Guard):

```bash
python demos/onion_node.py --bind 127.0.0.1:9000 --name Alice \
    --peer Guard=127.0.0.1:9001 --circuit auto
```

---

## VDS Deployment

```bash
./scripts/vds.sh deploy   # SCP + restart
./scripts/vds.sh status   # processes + curl API
./scripts/vds.sh logs Guard
```

API status of each relay node: `http://VDS_IP:808{1,2,3}/api/status`

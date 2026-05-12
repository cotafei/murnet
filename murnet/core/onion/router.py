"""
OnionRouter — MurNet onion routing engine.

Combines originator and relay roles in a single object.

────────────────── Forward path (3 hops) ──────────────────

Originator builds layered cell:
  enc_K1( {RELAY_NEXT, cid_2, enc_K2( {RELAY_NEXT, cid_3, enc_K3( cmd )} )} )

→ R1 strips K1, sees RELAY_NEXT → forwards enc_K2(enc_K3(cmd)) to R2 via cid_2
→ R2 strips K2, sees RELAY_NEXT → forwards enc_K3(cmd) to R3 via cid_3
→ R3 strips K3, executes cmd (RELAY_DATA / RELAY_BEGIN / RELAY_END)

────────────────── Backward path ──────────────────

R3 emits RELAY_BACK(cid_3, enc_K3(cmd)) toward R2.
R2 wraps: RELAY_BACK(cid_2, enc_K2(enc_K3(cmd))) toward R1.
R1 wraps: RELAY_BACK(cid_1, enc_K1(enc_K2(enc_K3(cmd)))) toward originator.
Originator peels K1→K2→K3 to recover cmd.

────────────────── Circuit build (EXTEND) ──────────────────

Leg 1 (direct):
  Originator → CREATE(cid_1, ephem_pub_1)  → R1
               CREATED(cid_1, r1_ephem_pub) ← R1
  Originator derives K1.

Leg 2 (extend via existing 1-hop circuit):
  Originator sends RELAY_FWD(cid_1, enc_K1({EXTEND, next:R2, ephem_pub_2, new_cid:cid_2})) → R1
  R1: strips K1, sees EXTEND → sends CREATE(cid_2, ephem_pub_2) to R2
  R2: CREATED(cid_2, r2_ephem_pub) → R1
  R1: RELAY_BACK(cid_1, enc_K1({EXTENDED, new_cid:cid_2, ephem_pub:r2_ephem_pub})) → originator
  Originator: strips K1, derives K2.

Leg 3: same as leg 2 but the EXTEND is routed through 2 existing hops.

────────────────── Transport interface ──────────────────

  router.send_fn = async (peer_addr: str, cell: OnionCell) → None

Injected externally so the router stays independent of the MurNet node layer.
In production: lambda peer, cell: node.send_vpn(peer, cell.to_dict())
In tests:       direct dict-passing between fake routers.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from typing import Awaitable, Callable, Dict, Optional, Tuple

from murnet.core.onion.cell import OnionCell, OnionCmd
from murnet.core.onion.hop_key import (
    derive_hop_key,
    generate_ephemeral_keypair,
    hop_decrypt,
    hop_encrypt,
)
from murnet.core.onion.circuit import (
    CircuitManager,
    CircuitOrigin,
    HopState,
    RelayEntry,
)

logger = logging.getLogger("murnet.onion.router")

_BUILD_TIMEOUT = 10.0   # seconds to wait for CREATE/EXTEND reply
_STREAM_TIMEOUT = 30.0  # seconds to wait for stream data


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _d64(s: str) -> bytes:
    return base64.b64decode(s)


class OnionRouter:
    """
    Combined originator + relay onion router.

    Parameters
    ----------
    addr : str
        This node's MurNet address (used for logging).
    send_fn : Callable[[str, OnionCell], Awaitable[None]]
        Injected transport: async function to deliver a cell to a peer.
    """

    def __init__(self, addr: str) -> None:
        self.addr    = addr
        self.send_fn: Callable[[str, OnionCell], Awaitable[None]] = _noop_send

        # Relay-side state
        self._relays = CircuitManager()

        # Originator-side: cid → asyncio.Future[bytes]  (ephem pub from CREATED/EXTENDED)
        self._pending: Dict[str, asyncio.Future] = {}

        # Data streams: stream_id → asyncio.Queue[bytes]
        self._streams: Dict[str, asyncio.Queue] = {}

        # Callback when data arrives at this node as an exit
        self.on_data: Optional[Callable[[str, bytes], None]] = None

        # Originator circuits indexed by first_cid (instance variable, not shared)
        self._circuit_index: Dict[str, "CircuitOrigin"] = {}

    # ──────────────────────────────────────────────────────────────────────────
    # Public originator API
    # ──────────────────────────────────────────────────────────────────────────

    async def build_circuit(self, relay_addrs: list[str]) -> CircuitOrigin:
        """
        Build a multi-hop onion circuit.

        relay_addrs[0] is the guard, relay_addrs[-1] is the exit.
        Minimum 1 hop, recommended 3.
        """
        if not relay_addrs:
            raise ValueError("Need at least one relay")

        circuit = CircuitOrigin()

        for i, relay in enumerate(relay_addrs):
            ephem_priv, ephem_pub = generate_ephemeral_keypair()
            new_cid = str(uuid.uuid4())

            if i == 0:
                # Direct CREATE to first relay
                cell = OnionCell(OnionCmd.CREATE, new_cid, ephem_pub)
                fut  = self._make_future(new_cid)
                await self.send_fn(relay, cell)
                relay_ephem_pub = await asyncio.wait_for(fut, _BUILD_TIMEOUT)

            else:
                # Register partial circuit NOW so RELAY_BACK can be routed back
                self._circuit_index[circuit.first_cid] = circuit

                extend_cmd = json.dumps({
                    "cmd":      "EXTEND",
                    "next_peer": relay,
                    "ephem_pub": _b64(ephem_pub),
                    "new_cid":  new_cid,
                }).encode()

                layered = self._wrap_forward(circuit, extend_cmd)
                cell    = OnionCell(OnionCmd.RELAY_FWD, circuit.first_cid, layered)
                fut     = self._make_future(new_cid)
                await self.send_fn(circuit.first_peer, cell)
                relay_ephem_pub = await asyncio.wait_for(fut, _BUILD_TIMEOUT)

            key = derive_hop_key(ephem_priv, relay_ephem_pub)
            circuit.hops.append(HopState(relay, new_cid, key))

        logger.info("[%s] circuit built: %d hops → %s",
                    self.addr[:8], circuit.depth, circuit.id[:8])
        return circuit

    async def send_data(
        self,
        circuit: CircuitOrigin,
        stream_id: str,
        data: bytes,
    ) -> None:
        """Send raw bytes through an established circuit."""
        cmd = json.dumps({
            "cmd":       "RELAY_DATA",
            "stream_id": stream_id,
            "data":      _b64(data),
        }).encode()
        layered = self._wrap_forward(circuit, cmd)
        cell = OnionCell(OnionCmd.RELAY_FWD, circuit.first_cid, layered)
        await self.send_fn(circuit.first_peer, cell)

    async def open_stream(
        self,
        circuit: CircuitOrigin,
        stream_id: str,
        dst_host: str,
        dst_port: int,
    ) -> asyncio.Queue:
        """
        Send RELAY_BEGIN to exit node, return a Queue that will receive
        incoming data chunks.
        """
        self._streams[stream_id] = asyncio.Queue()
        cmd = json.dumps({
            "cmd":       "RELAY_BEGIN",
            "stream_id": stream_id,
            "dst_host":  dst_host,
            "dst_port":  dst_port,
        }).encode()
        layered = self._wrap_forward(circuit, cmd)
        cell = OnionCell(OnionCmd.RELAY_FWD, circuit.first_cid, layered)
        await self.send_fn(circuit.first_peer, cell)
        return self._streams[stream_id]

    async def close_stream(
        self,
        circuit: CircuitOrigin,
        stream_id: str,
    ) -> None:
        cmd = json.dumps({
            "cmd":       "RELAY_END",
            "stream_id": stream_id,
        }).encode()
        layered = self._wrap_forward(circuit, cmd)
        cell = OnionCell(OnionCmd.RELAY_FWD, circuit.first_cid, layered)
        await self.send_fn(circuit.first_peer, cell)
        self._streams.pop(stream_id, None)

    async def destroy_circuit(self, circuit: CircuitOrigin) -> None:
        cell = OnionCell(OnionCmd.DESTROY, circuit.first_cid)
        await self.send_fn(circuit.first_peer, cell)

    # ──────────────────────────────────────────────────────────────────────────
    # Incoming cell dispatcher (call this from the transport layer)
    # ──────────────────────────────────────────────────────────────────────────

    async def handle_cell(self, cell: OnionCell, from_peer: str) -> None:
        """Entry point for all incoming onion cells."""
        try:
            if cell.cmd == OnionCmd.CREATE:
                await self._handle_create(cell, from_peer)
            elif cell.cmd == OnionCmd.CREATED:
                self._handle_created(cell)
            elif cell.cmd == OnionCmd.RELAY_FWD:
                await self._handle_relay_fwd(cell, from_peer)
            elif cell.cmd == OnionCmd.RELAY_BACK:
                await self._handle_relay_back(cell, from_peer)
            elif cell.cmd == OnionCmd.DESTROY:
                self._relays.remove(cell.circuit_id)
        except Exception:
            logger.exception("[%s] error handling cell %s cid=%s",
                             self.addr[:8], cell.cmd, cell.circuit_id[:8])

    # ──────────────────────────────────────────────────────────────────────────
    # Internal: relay-side CREATE handling
    # ──────────────────────────────────────────────────────────────────────────

    async def _handle_create(self, cell: OnionCell, from_peer: str) -> None:
        """Relay receives CREATE: perform ECDH, store entry, reply CREATED."""
        originator_ephem_pub = cell.data
        my_ephem_priv, my_ephem_pub = generate_ephemeral_keypair()
        key = derive_hop_key(my_ephem_priv, originator_ephem_pub)

        entry = RelayEntry(
            key=key,
            upstream_peer=from_peer,
            upstream_cid=cell.circuit_id,
        )
        self._relays.add(entry)

        reply = OnionCell(OnionCmd.CREATED, cell.circuit_id, my_ephem_pub)
        await self.send_fn(from_peer, reply)
        logger.debug("[%s] CREATED cid=%s", self.addr[:8], cell.circuit_id[:8])

    def _handle_created(self, cell: OnionCell) -> None:
        """Originator receives CREATED: resolve pending future."""
        fut = self._pending.pop(cell.circuit_id, None)
        if fut and not fut.done():
            fut.set_result(cell.data)  # relay's ephemeral pubkey

    # ──────────────────────────────────────────────────────────────────────────
    # Internal: relay-side RELAY_FWD handling
    # ──────────────────────────────────────────────────────────────────────────

    async def _handle_relay_fwd(self, cell: OnionCell, from_peer: str) -> None:
        entry = self._relays.get(cell.circuit_id)

        if entry is None:
            # We are the originator: this shouldn't arrive as FWD — ignore
            logger.warning("[%s] RELAY_FWD for unknown cid %s",
                           self.addr[:8], cell.circuit_id[:8])
            return

        # Peel our layer
        inner_bytes = hop_decrypt(entry.key, cell.data)
        inner       = json.loads(inner_bytes)
        cmd         = inner.get("cmd")

        if cmd == "RELAY_NEXT":
            # Forward stripped payload to downstream hop
            next_cid     = inner["next_cid"]
            next_payload = _d64(inner["payload"])

            if entry.downstream_peer is None:
                logger.error("[%s] RELAY_NEXT but no downstream for cid=%s",
                             self.addr[:8], cell.circuit_id[:8])
                return

            fwd = OnionCell(OnionCmd.RELAY_FWD, next_cid, next_payload)
            await self.send_fn(entry.downstream_peer, fwd)

        elif cmd == "EXTEND":
            # This relay should extend the circuit to the next hop
            await self._relay_extend(entry, cell.circuit_id, inner)

        elif cmd in ("RELAY_DATA", "RELAY_BEGIN", "RELAY_END"):
            # We are the exit node for this stream command
            await self._handle_exit_cmd(entry, cell.circuit_id, inner)

        else:
            logger.warning("[%s] unknown relay cmd %r", self.addr[:8], cmd)

    async def _relay_extend(
        self,
        entry: RelayEntry,
        my_cid: str,
        inner: dict,
    ) -> None:
        """Relay: create next leg on behalf of originator."""
        next_peer     = inner["next_peer"]
        ephem_pub     = _d64(inner["ephem_pub"])
        new_cid       = inner["new_cid"]

        # Store downstream circuit ID before we even hear back
        self._relays.set_downstream(my_cid, next_peer, new_cid)

        # Wait for CREATED from the next relay
        fut = self._make_future(new_cid)
        create_cell = OnionCell(OnionCmd.CREATE, new_cid, ephem_pub)
        await self.send_fn(next_peer, create_cell)

        try:
            next_ephem_pub = await asyncio.wait_for(fut, _BUILD_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error("[%s] EXTEND timed out to %s", self.addr[:8], next_peer)
            self._relays.remove(my_cid)
            return

        # Reply to originator with EXTENDED wrapped in one K1 layer
        extended_inner = json.dumps({
            "cmd":      "EXTENDED",
            "new_cid":  new_cid,
            "ephem_pub": _b64(next_ephem_pub),
        }).encode()
        back_payload = hop_encrypt(entry.key, extended_inner)
        back_cell    = OnionCell(OnionCmd.RELAY_BACK, my_cid, back_payload)
        await self.send_fn(entry.upstream_peer, back_cell)
        logger.debug("[%s] EXTENDED cid=%s → %s",
                     self.addr[:8], my_cid[:8], new_cid[:8])

    async def _handle_exit_cmd(
        self,
        entry: RelayEntry,
        my_cid: str,
        inner: dict,
    ) -> None:
        """We are the exit node — fire on_data or handle stream commands."""
        cmd       = inner["cmd"]
        stream_id = inner.get("stream_id", "")

        if cmd == "RELAY_DATA":
            data = _d64(inner.get("data", ""))
            if self.on_data:
                self.on_data(stream_id, data)
            # Echo back for tests (real exit would forward to dst_host:dst_port)
            await self._exit_send_back(entry, my_cid, stream_id, data)

        elif cmd == "RELAY_BEGIN":
            dst_host = inner.get("dst_host", "")
            dst_port = inner.get("dst_port", 0)
            logger.info("[%s] RELAY_BEGIN %s:%s stream=%s",
                        self.addr[:8], dst_host, dst_port, stream_id[:8])

        elif cmd == "RELAY_END":
            logger.info("[%s] RELAY_END stream=%s", self.addr[:8], stream_id[:8])

    async def _exit_send_back(
        self,
        entry: RelayEntry,
        my_cid: str,
        stream_id: str,
        data: bytes,
    ) -> None:
        """Exit wraps one K layer and sends RELAY_BACK upstream."""
        inner = json.dumps({
            "cmd":       "RELAY_DATA",
            "stream_id": stream_id,
            "data":      _b64(data),
        }).encode()
        payload   = hop_encrypt(entry.key, inner)
        back_cell = OnionCell(OnionCmd.RELAY_BACK, my_cid, payload)
        await self.send_fn(entry.upstream_peer, back_cell)

    # ──────────────────────────────────────────────────────────────────────────
    # Internal: RELAY_BACK handling
    # ──────────────────────────────────────────────────────────────────────────

    async def _handle_relay_back(self, cell: OnionCell, from_peer: str) -> None:
        entry = self._relays.get(cell.circuit_id)

        if entry is None:
            # We are the originator: peel all circuit layers
            await self._originator_peel(cell)
            return

        # We are a relay: add our encryption layer and forward upstream
        wrapped   = hop_encrypt(entry.key, cell.data)
        back_cell = OnionCell(OnionCmd.RELAY_BACK, entry.upstream_cid, wrapped)
        await self.send_fn(entry.upstream_peer, back_cell)

    async def _originator_peel(self, cell: OnionCell) -> None:
        """
        Originator receives RELAY_BACK: determine which circuit this belongs to
        by matching the circuit_id, then peel all hop layers.
        """
        # Find the circuit whose first_cid matches
        circuit = self._find_circuit_by_cid(cell.circuit_id)
        if circuit is None:
            logger.warning("[%s] RELAY_BACK for unknown circuit cid=%s",
                           self.addr[:8], cell.circuit_id[:8])
            return

        payload = cell.data
        for hop in circuit.hops:
            payload = hop_decrypt(hop.key, payload)

        inner = json.loads(payload)
        cmd   = inner.get("cmd")

        if cmd == "EXTENDED":
            new_cid = inner["new_cid"]
            fut = self._pending.pop(new_cid, None)
            if fut and not fut.done():
                fut.set_result(_d64(inner["ephem_pub"]))

        elif cmd == "RELAY_DATA":
            stream_id = inner.get("stream_id", "")
            data      = _d64(inner.get("data", ""))
            q = self._streams.get(stream_id)
            if q:
                await q.put(data)
            if self.on_data:
                self.on_data(stream_id, data)

        else:
            logger.debug("[%s] originator got back cmd=%r", self.addr[:8], cmd)

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _wrap_forward(self, circuit: CircuitOrigin, innermost: bytes) -> bytes:
        """
        Build the layered forward payload for a circuit.

        innermost: plaintext command bytes destined for the exit node.

        Result: enc_K1({RELAY_NEXT, cid_2, enc_K2({RELAY_NEXT, cid_3, enc_K3(innermost)})})
        """
        # Start from exit hop, work inward toward guard
        payload = hop_encrypt(circuit.hops[-1].key, innermost)

        for i in range(circuit.depth - 2, -1, -1):
            hop      = circuit.hops[i]
            next_hop = circuit.hops[i + 1]
            wrapper  = json.dumps({
                "cmd":     "RELAY_NEXT",
                "next_cid": next_hop.circuit_id,
                "payload":  _b64(payload),
            }).encode()
            payload = hop_encrypt(hop.key, wrapper)

        return payload

    def _make_future(self, cid: str) -> asyncio.Future:
        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self._pending[cid] = fut
        return fut

    def register_circuit(self, circuit: CircuitOrigin) -> None:
        self._circuit_index[circuit.first_cid] = circuit

    def _find_circuit_by_cid(self, cid: str) -> Optional[CircuitOrigin]:
        return self._circuit_index.get(cid)


# ──────────────────────────────────────────────────────────────────────────────
# Override build_circuit to auto-register circuits
# ──────────────────────────────────────────────────────────────────────────────

_orig_build = OnionRouter.build_circuit


async def _build_and_register(
    self: OnionRouter,
    relay_addrs: list[str],
) -> CircuitOrigin:
    circuit = await _orig_build(self, relay_addrs)
    self._circuit_index[circuit.first_cid] = circuit
    return circuit


OnionRouter.build_circuit = _build_and_register   # type: ignore[method-assign]


async def _noop_send(peer: str, cell: OnionCell) -> None:
    logger.warning("OnionRouter.send_fn not configured — dropped cell to %s", peer)

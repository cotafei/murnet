"""
MurNet closed / private network demo.

A "closed network" is one where every node shares a secret token.
Nodes that don't know the token are silently dropped at the transport
level — they can connect but every cell they send is discarded.

────────────────────────────────────────────────────────────────
QUICK START  (4 terminals)
────────────────────────────────────────────────────────────────

  # 1. Guard relay — knows the secret
  python demos/network_secret.py --bind 127.0.0.1:9101 --name Guard \\
      --secret mysecrettoken

  # 2. Middle relay — knows the secret
  python demos/network_secret.py --bind 127.0.0.1:9102 --name Middle \\
      --secret mysecrettoken

  # 3. Alice — builds circuit through Guard+Middle to Bob
  python demos/network_secret.py --bind 127.0.0.1:9100 --name Alice \\
      --secret mysecrettoken \\
      --peer Guard=127.0.0.1:9101 --peer Middle=127.0.0.1:9102 \\
      --peer Bob=127.0.0.1:9103 \\
      --circuit Guard,Middle,Bob

  # 4. Bob — also knows the secret, will receive Alice's messages
  python demos/network_secret.py --bind 127.0.0.1:9103 --name Bob \\
      --secret mysecrettoken \\
      --peer Alice=127.0.0.1:9100

  # Outsider — wrong secret, all packets discarded
  python demos/network_secret.py --bind 127.0.0.1:9200 --name Eve \\
      --secret wrongtoken \\
      --peer Guard=127.0.0.1:9101 \\
      --circuit Guard,Middle,Bob

────────────────────────────────────────────────────────────────
HOW IT WORKS
────────────────────────────────────────────────────────────────

  Each node wraps every outgoing TCP envelope with an HMAC-SHA256
  tag derived from the shared secret.  The receiving transport checks
  the tag before processing.  Invalid (or missing) tags are rejected
  and counted separately.

  This is NOT a replacement for the onion-layer encryption.  The
  per-cell AES-256-GCM keys are negotiated independently.  The HMAC
  wrapper is a network-level access control that prevents outsiders
  from even talking to the relays.

  Wire format (newline-delimited JSON):
    {"mac": "<hex16>", "src": "...", "cell": {...}}
    {"mac": "<hex16>", "src": "...", "announce": {...}, "ttl": N}

  mac = first 8 bytes (16 hex chars) of HMAC-SHA256(secret, raw_json_of_rest)
────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.onion.cell import OnionCell, is_onion_cell
from core.onion.directory import RelayDirectory, RelayInfo
from core.onion.router import OnionRouter

logger = logging.getLogger("murnet.demo.secret")

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(name)s %(levelname)s  %(message)s",
)

_CONN_TIMEOUT   = 8.0
_ANNOUNCE_EVERY = 30.0
_ANNOUNCE_TTL   = 4
_MAC_BYTES      = 8    # first 8 bytes of HMAC-SHA256


# ─────────────────────────────────────────────────────────────────────────────
# MAC helpers
# ─────────────────────────────────────────────────────────────────────────────

def _compute_mac(secret_bytes: bytes, payload: bytes) -> str:
    """Return first _MAC_BYTES bytes of HMAC-SHA256(secret, payload) as hex."""
    tag = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
    return tag[:_MAC_BYTES].hex()


def _wrap(secret_bytes: bytes, inner: dict) -> bytes:
    """Serialize inner dict, compute MAC, return full JSON line bytes."""
    raw = json.dumps(inner, separators=(",", ":")).encode()
    mac = _compute_mac(secret_bytes, raw)
    envelope = {"mac": mac, **inner}
    return json.dumps(envelope, separators=(",", ":")).encode() + b"\n"


def _unwrap(secret_bytes: bytes, line: bytes) -> dict | None:
    """
    Parse JSON line, verify MAC, return inner dict (without 'mac' key).
    Returns None on any failure (bad JSON, missing mac, wrong mac).
    """
    try:
        envelope = json.loads(line)
    except json.JSONDecodeError:
        return None
    mac_recv = envelope.pop("mac", None)
    if not mac_recv:
        return None
    raw = json.dumps(envelope, separators=(",", ":")).encode()
    mac_expected = _compute_mac(secret_bytes, raw)
    if not hmac.compare_digest(mac_recv, mac_expected):
        return None
    return envelope


# ─────────────────────────────────────────────────────────────────────────────
# Secret-aware transport
# ─────────────────────────────────────────────────────────────────────────────

class SecretOnionTransport:
    """
    Drop-in replacement for OnionTransport that adds HMAC-MAC gating.

    Only nodes sharing `secret` can exchange cells.  Every other message
    is silently discarded and counted in `rejected_count`.
    """

    def __init__(
        self,
        router: OnionRouter,
        bind_host: str,
        bind_port: int,
        secret: str,
        peers: dict[str, str] | None = None,
        self_name: str | None = None,
    ) -> None:
        self.router    = router
        self.bind_host = bind_host
        self.bind_port = bind_port
        self._secret   = secret.encode()
        self.peers: dict[str, str] = dict(peers or {})
        self.self_name = self_name
        self.directory = RelayDirectory()

        self._out: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._inc: dict[str, asyncio.StreamWriter] = {}
        self._server: asyncio.Server | None = None
        self._announce_task: asyncio.Task | None = None

        self.accepted_count = 0
        self.rejected_count = 0

        router.send_fn = self._send_cell

    # ── public ───────────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, self.bind_host, self.bind_port
        )
        # Pre-connect to known peers.
        for peer_addr in self.peers.values():
            asyncio.create_task(self._connect_out(peer_addr))
        if self.self_name:
            self._announce_task = asyncio.create_task(self._announce_loop())

    async def stop(self) -> None:
        if self._announce_task:
            self._announce_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for _r, w in self._out.values():
            w.close()

    def resolve(self, name_or_addr: str) -> str:
        return self.peers.get(name_or_addr, name_or_addr)

    # ── outgoing ─────────────────────────────────────────────────────────────

    async def _send_cell(self, peer_addr: str, cell: OnionCell) -> None:
        inner = {"src": f"{self.bind_host}:{self.bind_port}", "cell": cell.to_dict()}
        data  = _wrap(self._secret, inner)
        writer = await self._get_writer(peer_addr)
        writer.write(data)
        await writer.drain()

    async def _get_writer(self, addr: str) -> asyncio.StreamWriter:
        if addr in self._inc:
            return self._inc[addr]
        if addr not in self._out:
            await self._connect_out(addr)
        _r, w = self._out[addr]
        return w

    async def _connect_out(self, addr: str) -> None:
        if addr in self._out:
            return
        host, port = addr.rsplit(":", 1)
        for attempt in range(5):
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, int(port)), _CONN_TIMEOUT
                )
                self._out[addr] = (r, w)
                asyncio.create_task(self._read_loop_out(addr, r))
                return
            except Exception:
                await asyncio.sleep(1.5 * (attempt + 1))
        logger.warning("Could not connect to %s", addr)

    # ── incoming ─────────────────────────────────────────────────────────────

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_ip = writer.get_extra_info("peername", ("?", 0))[0]
        src_addr: str | None = None
        try:
            async for line in reader:
                line = line.strip()
                if not line:
                    continue
                wrapper = _unwrap(self._secret, line)
                if wrapper is None:
                    self.rejected_count += 1
                    logger.debug("MAC reject from %s", peer_ip)
                    continue
                self.accepted_count += 1
                src_addr = wrapper.get("src", src_addr)
                if src_addr:
                    self._inc[src_addr] = writer
                await self._dispatch(wrapper)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            if src_addr and self._inc.get(src_addr) is writer:
                del self._inc[src_addr]
            writer.close()

    async def _read_loop_out(self, addr: str, reader: asyncio.StreamReader) -> None:
        try:
            async for line in reader:
                line = line.strip()
                if not line:
                    continue
                wrapper = _unwrap(self._secret, line)
                if wrapper is None:
                    self.rejected_count += 1
                    continue
                self.accepted_count += 1
                await self._dispatch(wrapper)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            self._out.pop(addr, None)

    # ── dispatch ─────────────────────────────────────────────────────────────

    async def _dispatch(self, wrapper: dict) -> None:
        if "announce" in wrapper:
            asyncio.create_task(self._handle_announce(
                wrapper.get("src", ""), wrapper["announce"], wrapper.get("ttl", 1)
            ))
            return
        cell_dict = wrapper.get("cell")
        if cell_dict and is_onion_cell(cell_dict):
            cell = OnionCell.from_dict(cell_dict)
            src  = wrapper.get("src", "")
            asyncio.create_task(self.router.receive(cell, src))

    # ── gossip announce ───────────────────────────────────────────────────────

    async def _announce_loop(self) -> None:
        while True:
            await asyncio.sleep(_ANNOUNCE_TTL)
            await self._broadcast_announce(_ANNOUNCE_TTL)
            await asyncio.sleep(_ANNOUNCE_EVERY - _ANNOUNCE_TTL)

    async def _broadcast_announce(self, ttl: int) -> None:
        info = RelayInfo(
            addr=f"{self.bind_host}:{self.bind_port}",
            name=self.self_name or "",
            timestamp=time.time(),
            ttl=300,
        )
        inner = {
            "src":      f"{self.bind_host}:{self.bind_port}",
            "announce": info.to_dict(),
            "ttl":      ttl,
        }
        data = _wrap(self._secret, inner)
        for peer_addr in list(self._out):
            try:
                _r, w = self._out[peer_addr]
                w.write(data)
                await w.drain()
            except Exception:
                pass

    async def _handle_announce(self, src: str, data: dict, ttl: int) -> None:
        try:
            info = RelayInfo.from_dict(data)
        except Exception:
            return
        is_new = self.directory.announce(info)
        if ttl > 1 and is_new:
            await self._forward_announce(src, data, ttl - 1)

    async def _forward_announce(self, origin: str, data: dict, ttl: int) -> None:
        inner = {"src": origin, "announce": data, "ttl": ttl}
        fwd   = _wrap(self._secret, inner)
        for peer_addr, (_r, w) in list(self._out.items()):
            if peer_addr == origin:
                continue
            try:
                w.write(fwd)
                await w.drain()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Simple stdio chat (no TUI dependency)
# ─────────────────────────────────────────────────────────────────────────────

async def run_node(args: argparse.Namespace) -> None:
    host, port = args.bind.rsplit(":", 1)
    bind_addr  = f"{host}:{port}"
    peers      = {}
    for p in args.peer:
        name, addr = p.split("=", 1)
        peers[name] = addr

    router    = OnionRouter(bind_addr)
    transport = SecretOnionTransport(
        router, host, int(port),
        secret=args.secret,
        peers=peers,
        self_name=args.name if args.announce else None,
    )

    received: list[str] = []

    def _on_data(stream_id: str, data: bytes) -> None:
        try:
            msg = json.loads(data)
            if msg.get("type") == "chat":
                ts   = time.strftime("%H:%M:%S", time.localtime(msg.get("ts", time.time())))
                line = f"[{ts}] {msg.get('from', '?')}: {msg.get('text', '')}"
                received.append(line)
                print(f"\r{line}\n{args.name}> ", end="", flush=True)
        except Exception:
            pass

    router.on_data = _on_data

    await transport.start()
    print(f"[{args.name}]  {bind_addr}  |  secret: {args.secret[:4]}{'*' * (len(args.secret) - 4)}")
    print(f"  Peers: {', '.join(peers) or 'none'}")

    circuit = None

    if args.circuit:
        hops     = [h.strip() for h in args.circuit.split(",")]
        resolved = [transport.resolve(h) for h in hops]
        path_str = " → ".join(hops)
        print(f"  Building circuit: {path_str}…")
        try:
            circuit = await router.build_circuit(resolved)
            print(f"  Circuit ready.  Type messages below (Ctrl+C to quit).\n")
        except Exception as exc:
            print(f"  Circuit FAILED: {exc}")
            await transport.stop()
            return
    else:
        print(f"  Relay mode — no --circuit given.  Ctrl+C to stop.\n")
        try:
            while True:
                await asyncio.sleep(5)
                print(
                    f"  [{args.name}]  accepted: {transport.accepted_count}"
                    f"  rejected: {transport.rejected_count}"
                    f"  dir: {len(transport.directory)} relays"
                )
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await transport.stop()
        return

    # Interactive chat loop
    loop = asyncio.get_event_loop()

    def _read_stdin() -> None:
        import sys as _sys
        while True:
            try:
                line = input(f"{args.name}> ")
            except (EOFError, KeyboardInterrupt):
                break
            if not line.strip():
                continue
            payload = json.dumps({
                "type": "chat",
                "from": args.name,
                "text": line.strip(),
                "ts":   time.time(),
            }).encode()
            future = asyncio.run_coroutine_threadsafe(
                router.send_data(circuit, "chat", payload), loop
            )
            try:
                future.result(timeout=5)
            except Exception as exc:
                print(f"  Send error: {exc}")

    import threading
    stdin_thread = threading.Thread(target=_read_stdin, daemon=True)
    stdin_thread.start()

    try:
        while True:
            await asyncio.sleep(10)
            print(
                f"  [{args.name}]  accepted: {transport.accepted_count}"
                f"  rejected: {transport.rejected_count}"
            )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await transport.stop()
        print(f"\n[{args.name}]  stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MurNet closed-network demo — HMAC-MAC access control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  python demos/network_secret.py --bind 127.0.0.1:9101 --name Guard \\\n"
            "      --secret mysecrettoken\n"
            "  python demos/network_secret.py --bind 127.0.0.1:9100 --name Alice \\\n"
            "      --secret mysecrettoken \\\n"
            "      --peer Guard=127.0.0.1:9101 \\\n"
            "      --circuit Guard,Bob\n"
        ),
    )
    p.add_argument("--bind",     required=True, metavar="HOST:PORT",
                   help="Address to listen on (e.g. 127.0.0.1:9100)")
    p.add_argument("--name",     default="Node",
                   help="Display name for this node")
    p.add_argument("--secret",   required=True,
                   help="Shared secret; only nodes with the same secret can communicate")
    p.add_argument("--peer",     action="append", default=[], metavar="NAME=HOST:PORT",
                   help="Known peer (can repeat: --peer Guard=127.0.0.1:9101)")
    p.add_argument("--circuit",  default="",
                   help="Comma-separated hop list (names or addresses): Guard,Middle,Bob")
    p.add_argument("--announce", action="store_true",
                   help="Announce this node as a relay via gossip")
    return p.parse_args()


if __name__ == "__main__":
    asyncio.run(run_node(parse_args()))

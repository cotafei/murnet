"""Smoke: replay-protected handshake (C1 + W1 from adversarial review)."""
from __future__ import annotations
import asyncio
import sys
import time

sys.path.insert(0, ".")
from core.onion.obfs import ObfsStream


async def run():
    seen: dict[bytes, float] = {}

    def check(nonce: bytes) -> bool:
        if nonce in seen:
            return False
        seen[nonce] = time.monotonic()
        return True

    accepted: list[ObfsStream] = []

    async def handle(r, w):
        s = ObfsStream(r, w, is_server=True, check_nonce_fn=check)
        try:
            await s.handshake()
            accepted.append(s)
        except Exception:
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())

    # 1) normal handshake
    r, w = await asyncio.open_connection("127.0.0.1", port)
    client = ObfsStream(r, w, is_server=False)
    await asyncio.wait_for(client.handshake(), 5)
    await asyncio.sleep(0.1)
    assert len(accepted) == 1, f"expected 1 accepted, got {len(accepted)}"
    print(f"1) normal handshake: OK (seen={len(seen)})")

    # 2) capture client's first message, replay it
    class Tap:
        def __init__(self, w):
            self._w = w
            self.buf = bytearray()
        def write(self, d):
            self.buf.extend(d)
            self._w.write(d)
        async def drain(self):
            await self._w.drain()
        def close(self):
            self._w.close()
        def is_closing(self):
            return self._w.is_closing()
        def get_extra_info(self, *a, **kw):
            return self._w.get_extra_info(*a, **kw)

    r2, w2 = await asyncio.open_connection("127.0.0.1", port)
    tap = Tap(w2)
    cc = ObfsStream(r2, tap, is_server=False)
    await asyncio.wait_for(cc.handshake(), 5)
    captured = bytes(tap.buf)
    await asyncio.sleep(0.1)
    assert len(accepted) == 2, f"expected 2 accepted after legit, got {len(accepted)}"
    print(f"2) captured {len(captured)} bytes, seen={len(seen)}, accepted={len(accepted)}")

    # 3) replay attack — open raw TCP, send captured bytes
    t0 = time.monotonic()
    r3, w3 = await asyncio.open_connection("127.0.0.1", port)
    w3.write(captured)
    await w3.drain()
    try:
        data = await asyncio.wait_for(r3.read(100), timeout=2)
    except (asyncio.TimeoutError, ConnectionError):
        data = b""
    elapsed_ms = (time.monotonic() - t0) * 1000
    await asyncio.sleep(0.2)

    assert len(data) == 0, f"replay should be silent-closed, got {len(data)} bytes"
    assert len(accepted) == 2, f"replay should NOT be accepted, got {len(accepted)}"
    assert 30 <= elapsed_ms <= 700, f"jitter out of range: {elapsed_ms:.0f}ms"
    print(f"3) replay REJECTED, jitter={elapsed_ms:.0f}ms (expect 50-550ms)")

    server.close()
    server_task.cancel()
    print()
    print("ALL SMOKE TESTS PASS")


if __name__ == "__main__":
    asyncio.run(run())

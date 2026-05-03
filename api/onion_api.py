"""
Lightweight HTTP status API for onion relay / chat nodes.

No dependency on the full MurNet node — works with just OnionRouter + OnionTransport.

Endpoints
---------
GET /health              200 {"ok": true}
GET /api/status          Relay stats, connection counts, uptime
GET /api/peers           Known peers list
GET /api/circuits        Active relay entries (anonymised)
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.onion.router import OnionRouter
    from core.onion.transport import OnionTransport

try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


def make_app(router: "OnionRouter", transport: "OnionTransport") -> "FastAPI":
    if not HAS_FASTAPI:
        raise RuntimeError("fastapi / uvicorn not installed")

    app = FastAPI(title="MurNet Onion Node", docs_url=None, redoc_url=None)
    _start = time.time()

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/api/status")
    async def status():
        cm = getattr(router, "_relays", None)
        relay_count = 0
        if cm is not None and hasattr(cm, "_by_cid"):
            seen = set()
            for entry in cm._by_cid.values():
                eid = id(entry)
                if eid not in seen:
                    seen.add(eid)
                    relay_count += 1

        return {
            "addr":             router.addr,
            "uptime_s":         round(time.time() - _start, 1),
            "relay_entries":    relay_count,
            "pending_circuits": len(getattr(router, "_pending", {})),
            "connections": {
                "outgoing": len(transport._out),
                "incoming": len(transport._inc),
            },
        }

    @app.get("/api/peers")
    async def peers():
        return {"peers": transport.peers}

    @app.get("/api/circuits")
    async def circuits():
        cm = getattr(router, "_relays", None)
        if cm is None or not hasattr(cm, "_by_cid"):
            return {"circuits": []}

        seen: set[int] = set()
        result = []
        for cid, entry in cm._by_cid.items():
            eid = id(entry)
            if eid in seen:
                continue
            seen.add(eid)
            result.append({
                "upstream_cid":   entry.upstream_cid,
                "downstream_cid": entry.downstream_cid,
                "has_upstream":   bool(entry.upstream_peer),
                "has_downstream": bool(entry.downstream_peer),
            })
        return {"circuits": result}

    return app


async def serve(
    router: "OnionRouter",
    transport: "OnionTransport",
    host: str = "0.0.0.0",
    port: int = 8080,
) -> None:
    """Start uvicorn in-process (non-blocking — call from asyncio task)."""
    app = make_app(router, transport)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()

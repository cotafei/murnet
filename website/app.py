"""
MurNet официальный сайт — FastAPI.

Запускается на 127.0.0.1:8383 (тот же порт что отдавал старый встроенный
HTML из vds_hidden_service.py). Hidden service router проксирует HTTP на
этот сокет, так что .murnet адрес → этот FastAPI.

Routes:
    GET /                  → landing.html
    GET /about             → about.html
    GET /download          → download.html
    GET /directory         → directory.html
    GET /docs (built-in)   → FastAPI Swagger
    GET /api/status        → JSON со статусом сети
    GET /api/services      → JSON список публичных .murnet сервисов
    GET /static/*          → static assets (logos, css)
    *                       → 404.html
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="MurNet",
    description="Official site",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

ROOT  = Path(__file__).parent
PAGES = ROOT / "static" / "pages"
ASSETS = ROOT / "static" / "assets"
APP_STARTED = time.time()


# ── Pages ────────────────────────────────────────────────────────────────

def _page(name: str) -> HTMLResponse:
    f = PAGES / name
    if not f.exists():
        return _page_404()
    return HTMLResponse(content=f.read_text(encoding="utf-8"))


def _page_404() -> HTMLResponse:
    f = PAGES / "404.html"
    body = f.read_text(encoding="utf-8") if f.exists() else "<h1>404</h1>"
    return HTMLResponse(content=body, status_code=404)


@app.get("/", response_class=HTMLResponse)
def landing():
    return _page("landing.html")


@app.get("/about", response_class=HTMLResponse)
def about():
    return _page("about.html")


@app.get("/download", response_class=HTMLResponse)
def download():
    return _page("download.html")


@app.get("/directory", response_class=HTMLResponse)
def directory():
    return _page("directory.html")


# ── API ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/status")
def status():
    """Сводка по сети — для виджетов на лендинге."""
    uptime = int(time.time() - APP_STARTED)
    return {
        "network":    "online",
        "uptime_seconds": uptime,
        "uptime_human":   _fmt_uptime(uptime),
        "vds": {
            "ip":    "80.93.52.15",
            "ports": {"guard": 9211, "middle": 9212, "hs": 9213},
            "location": "SPB",
        },
        "protocol": {
            "handshake": "X25519 + HMAC-PSK with replay protection (v2)",
            "frame":     "ChaCha20-Poly1305 + random padding",
            "address":   "Ed25519 → Blake2b-160 → Base58Check + .murnet",
        },
        "services_count": _count_services(),
    }


@app.get("/api/services")
def services():
    """Публичный каталог .murnet сервисов."""
    db = ROOT / "data" / "services.json"
    if db.exists():
        return json.loads(db.read_text(encoding="utf-8"))
    return {
        "services": [
            {
                "addr": "fgsesxh6fbmktj1od9mcu9ycyo4zuzwnxf.murnet",
                "name": "MurNet Official",
                "category": "core",
                "online": True,
            },
        ]
    }


@app.get("/api/version")
def version():
    return {
        "site":      "1.0.0",
        "protocol":  "v2",
        "build":     "2026",
    }


# ── Static assets ────────────────────────────────────────────────────────

if ASSETS.exists():
    app.mount("/static/assets", StaticFiles(directory=ASSETS), name="assets")


# ── Catch-all 404 ────────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return _page_404()


# ── helpers ──────────────────────────────────────────────────────────────

def _fmt_uptime(seconds: int) -> str:
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _   = divmod(rem, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def _count_services() -> int:
    db = ROOT / "data" / "services.json"
    if not db.exists():
        return 1
    try:
        data = json.loads(db.read_text(encoding="utf-8"))
        return len(data.get("services", []))
    except Exception:
        return 0


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8383, log_level="info")

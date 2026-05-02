"""
MurNet Hidden Service — VDS сервер.

Запуск на VDS:
  python scripts/vds_hidden_service.py

Переменные окружения:
  VDS_IP      — публичный IP (default: 80.93.52.15)
  HS_PORT     — порт HS relay (default: 9213)
  GUARD_PORT  — порт Guard relay (default: 9211)
  SITE_PORT   — порт локального HTTP сервера (default: 8383)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.onion.router          import OnionRouter
from core.onion.obfs_transport  import ObfsTransport as OnionTransport
from core.onion.hidden_service  import (
    HiddenServiceIdentity, HiddenServiceAnnounce, HiddenServiceDirectory,
)
from core.onion.hs_router     import HiddenServiceRouter

logging.basicConfig(level=logging.WARNING,
                    format="%(asctime)s %(name)s %(levelname)s  %(message)s")

VDS_IP     = os.environ.get("VDS_IP",    "80.93.52.15")
HS_PORT    = int(os.environ.get("HS_PORT",    "9213"))
GUARD_PORT = int(os.environ.get("GUARD_PORT", "9211"))
SITE_PORT  = int(os.environ.get("SITE_PORT",  "8383"))

# ── HTML сайт ─────────────────────────────────────────────────────────────

def _make_html(addr: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MurNet — Hidden Node</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#000;color:#e6edf3;font-family:'Courier New',monospace;overflow:hidden;height:100vh}}
canvas{{position:fixed;top:0;left:0;z-index:0}}
.ui{{position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;
     justify-content:center;height:100vh;gap:1.5rem;padding:1rem}}
.clock{{font-size:3.5rem;font-weight:bold;letter-spacing:6px;
        text-shadow:0 0 30px rgba(88,166,255,.4);color:#e6edf3}}
.date{{color:#8b949e;font-size:.8rem;letter-spacing:3px;text-transform:uppercase}}
.card{{background:rgba(13,17,23,.88);border:1px solid #30363d;border-radius:12px;
       padding:2rem 2.8rem;max-width:640px;width:100%;
       box-shadow:0 0 60px rgba(88,166,255,.08);backdrop-filter:blur(12px)}}
.logo{{display:flex;align-items:center;gap:.6rem;font-size:1.4rem;font-weight:bold;
       color:#58a6ff;letter-spacing:3px;text-shadow:0 0 20px #58a6ff66;margin-bottom:.4rem}}
.dot{{width:10px;height:10px;border-radius:50%;background:#3fb950;
      box-shadow:0 0 10px #3fb950;animation:blink 2s ease-in-out infinite;flex-shrink:0}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:.25}}}}
.sub{{color:#8b949e;font-size:.82rem;margin-bottom:1.4rem}}
.lbl{{color:#8b949e;font-size:.68rem;text-transform:uppercase;letter-spacing:2px;margin-bottom:.35rem}}
.addr{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.55rem .9rem;
       color:#7ee787;font-size:.82rem;word-break:break-all;
       text-shadow:0 0 8px #7ee78744;margin-bottom:1.4rem}}
.circuit{{display:flex;align-items:center;flex-wrap:wrap;gap:.35rem;margin-bottom:1.4rem}}
.node{{background:#21262d;border:1px solid #30363d;border-radius:4px;
       padding:.18rem .55rem;font-size:.68rem;color:#58a6ff}}
.node.hs{{color:#7ee787;border-color:#3fb95044}}
.arrow{{color:#444;font-size:.75rem}}
.badges{{display:flex;flex-wrap:wrap;gap:.4rem}}
.badge{{border-radius:20px;padding:.22rem .7rem;font-size:.68rem;border:1px solid #30363d;color:#8b949e}}
.badge.b{{border-color:#58a6ff33;color:#58a6ff}}
.badge.g{{border-color:#3fb95033;color:#3fb950}}
.badge.p{{border-color:#bc8cff33;color:#bc8cff}}
.scanline{{position:fixed;top:0;left:0;width:100%;height:100%;
           background:repeating-linear-gradient(0deg,transparent,transparent 2px,
           rgba(0,0,0,.05) 2px,rgba(0,0,0,.05) 4px);pointer-events:none;z-index:2}}
</style>
</head>
<body>
<canvas id="c"></canvas>
<div class="scanline"></div>
<div class="ui">
  <div>
    <div class="clock" id="clk">--:--:--</div>
    <div class="date" id="dt">loading...</div>
  </div>
  <div class="card">
    <div class="logo"><span class="dot"></span>MURNET NODE</div>
    <div class="sub">Скрытый сервис активен &mdash; реальный IP скрыт за onion-цепочкой</div>

    <div class="lbl">Onion Address</div>
    <div class="addr" id="adr">{addr}</div>

    <div class="lbl">Onion Circuit</div>
    <div class="circuit">
      <span class="node">CLIENT</span>
      <span class="arrow">──▶</span>
      <span class="node">GUARD</span>
      <span class="arrow">──▶</span>
      <span class="node">MIDDLE</span>
      <span class="arrow">──▶</span>
      <span class="node hs">HIDDEN SERVICE</span>
      <span class="arrow">──▶</span>
      <span class="node hs">SITE</span>
    </div>

    <div class="badges">
      <span class="badge b">X25519 ECDH</span>
      <span class="badge b">AES-256-GCM</span>
      <span class="badge g">Ed25519</span>
      <span class="badge g">Blake2b-160</span>
      <span class="badge p">Base58Check</span>
      <span class="badge">.murnet TLD</span>
    </div>
  </div>
</div>
<script>
(function(){{
  // Matrix rain
  var c=document.getElementById('c'),ctx=c.getContext('2d');
  var W=c.width=window.innerWidth,H=c.height=window.innerHeight;
  var chars='アイウエオカキクケコサシスセソタチツテトナニヌネ0123456789ABCDEFмурнет';
  var cols=Math.floor(W/16),drops=Array(cols).fill(0).map(()=>Math.random()*H/16|0);
  var colors=['#58a6ff','#3fb950','#7ee787','#bc8cff'];
  function rain(){{
    ctx.fillStyle='rgba(0,0,0,0.05)';ctx.fillRect(0,0,W,H);
    ctx.font='13px monospace';
    drops.forEach(function(y,i){{
      ctx.fillStyle=colors[i%colors.length];
      ctx.fillText(chars[Math.random()*chars.length|0],i*16,y*16);
      if(y*16>H&&Math.random()>.97)drops[i]=0; else drops[i]++;
    }});
  }}
  setInterval(rain,35);
  window.addEventListener('resize',function(){{W=c.width=window.innerWidth;H=c.height=window.innerHeight;}});

  // Clock
  function tick(){{
    var n=new Date();
    document.getElementById('clk').textContent=n.toTimeString().slice(0,8);
    document.getElementById('dt').textContent=
      n.toLocaleDateString('ru-RU',{{weekday:'long',year:'numeric',month:'long',day:'numeric'}});
  }}
  setInterval(tick,1000);tick();

  // Typing effect for address
  var el=document.getElementById('adr'),full=el.textContent,i=0;
  el.textContent='';
  var ti=setInterval(function(){{
    el.textContent+=full[i++];
    if(i>=full.length)clearInterval(ti);
  }},25);
}})();
</script>
</body>
</html>"""


# ── HTTP сервер ───────────────────────────────────────────────────────────

_SITE_HTML = b""

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_SITE_HTML)))
        self.end_headers()
        self.wfile.write(_SITE_HTML)
    def log_message(self, *a): pass


def _start_http(addr: str) -> None:
    global _SITE_HTML
    _SITE_HTML = _make_html(addr).encode()
    s = HTTPServer(("127.0.0.1", SITE_PORT), _Handler)
    Thread(target=s.serve_forever, daemon=True).start()


# ── main ──────────────────────────────────────────────────────────────────

async def main() -> None:
    print("\n  MurNet Hidden Service — VDS")
    print("  " + "-"*40)
    print(f"  VDS IP:    {VDS_IP}")

    key_file = os.path.join(os.path.dirname(__file__), ".vds_hs.key")
    identity = HiddenServiceIdentity(key_file)
    hs_addr  = f"{VDS_IP}:{HS_PORT}"
    print(f"  Address:   {identity.address}")
    print(f"  HS relay:  {hs_addr}")

    _start_http(identity.address)

    guard_r = OnionRouter(f"{VDS_IP}:{GUARD_PORT}")
    guard_t = OnionTransport(guard_r, "0.0.0.0", GUARD_PORT)
    await guard_t.start()

    hs_r = HiddenServiceRouter(hs_addr, identity, service_port=SITE_PORT)
    hs_t = OnionTransport(hs_r, "0.0.0.0", HS_PORT,
                          peers={"Guard": f"{VDS_IP}:{GUARD_PORT}"})
    await hs_t.start()

    directory = HiddenServiceDirectory()
    guard_t.hs_directory = directory
    hs_t.hs_directory    = directory

    directory._entries[identity.address.lower()] = {
        "pubkey":    identity.public_bytes.hex(),
        "relay":     hs_addr,
        "timestamp": time.time(),
    }

    announce = HiddenServiceAnnounce(identity, hs_t, relay=hs_addr)
    await announce.broadcast_now()
    announce.start()

    # Пишем JSON для клиентов
    peers = {
        "services": {
            identity.address.lower(): {
                "pubkey":    identity.public_bytes.hex(),
                "relay":     hs_addr,
                "timestamp": time.time(),
            }
        }
    }
    peers_path = os.path.join(os.path.dirname(__file__), "..", ".murnet_vds.json")
    with open(peers_path, "w") as f:
        json.dump(peers, f, indent=2)

    print(f"\n  Порты открыты:")
    print(f"    Guard relay : {VDS_IP}:{GUARD_PORT}/tcp")
    print(f"    HS relay    : {VDS_IP}:{HS_PORT}/tcp")
    print(f"    Local site  : 127.0.0.1:{SITE_PORT}")
    print(f"\n  .murnet адрес для браузера:")
    print(f"\n    http://{identity.address.lower()}/")
    print(f"\n  Peers JSON: .murnet_vds.json")
    print(f"\n  " + "-"*40)
    print("  Ctrl+C для остановки\n")

    try:
        while True:
            await asyncio.sleep(30)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await asyncio.gather(
            guard_t.stop(), hs_t.stop(), return_exceptions=True
        )
        print("\n  Остановлено.")


if __name__ == "__main__":
    asyncio.run(main())

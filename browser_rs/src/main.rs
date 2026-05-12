// MurNet Browser — Rust UI
//
// Архитектура:
//   - tao создаёт нативное окно (Win32 / Cocoa / GTK).
//   - wry монтирует системный WebView (WebView2 на Windows / WKWebView на macOS / WebKitGTK на Linux).
//   - Весь HTTP-трафик webview маршрутизируется через прокси 127.0.0.1:18888.
//   - Прокси поднимает Python-демон `murnet_proxy.py` (3-hop onion: Guard → Middle → HS на VDS).
//
// UI shell — встроенная HTML-страница с адресной строкой, кнопками назад/вперёд/обновить
// и iframe для контента. Историю и навигацию ведёт JS внутри shell.
//
// Запуск:
//   1. `python ../murnet_proxy.py`   (отдельный терминал — поднимает прокси)
//   2. `cargo run --release`         (этот бинарь)

#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::{ProxyConfig, ProxyEndpoint, WebViewBuilder};

const PROXY_HOST: &str = "127.0.0.1";
const PROXY_PORT: &str = "18888";

const SHELL_HTML: &str = r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>MurNet Browser</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI','Helvetica Neue',sans-serif}
html,body{height:100%;background:#0d1117;color:#e6edf3;overflow:hidden}
.wrap{display:flex;flex-direction:column;height:100vh}
.bar{display:flex;gap:6px;background:#161b22;border-bottom:1px solid #30363d;padding:8px}
.btn{background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;cursor:pointer;font-size:14px;min-width:34px;transition:background .15s,border-color .15s}
.btn:hover{background:#30363d;border-color:#58a6ff}
.btn:disabled{opacity:.4;cursor:default}
input{flex:1;background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 12px;border-radius:4px;font-family:Consolas,'Courier New',monospace;font-size:13px;transition:border-color .15s}
input:focus{outline:none;border-color:#58a6ff;box-shadow:0 0 0 2px rgba(88,166,255,.15)}
iframe{flex:1;width:100%;border:0;background:#0d1117}
.status{padding:4px 12px;background:#161b22;border-top:1px solid #30363d;color:#8b949e;font-size:11px;font-family:Consolas,monospace;display:flex;justify-content:space-between;align-items:center}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#3fb950;margin-right:6px;box-shadow:0 0 6px #3fb950;animation:p 2s ease-in-out infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.3}}
.welcome{height:100%;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;padding:20px}
.welcome h1{color:#58a6ff;font-size:28px;letter-spacing:6px;text-shadow:0 0 20px rgba(88,166,255,.3)}
.welcome p{color:#8b949e;font-size:14px}
.welcome code{background:#161b22;color:#7ee787;padding:8px 14px;border-radius:6px;font-family:Consolas,monospace;border:1px solid #30363d}
.scanline{position:fixed;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 4px);z-index:9999}
</style>
</head>
<body>
<div class="scanline"></div>
<div class="wrap">
  <div class="bar">
    <button class="btn" id="back" title="Назад (Alt+←)" disabled>←</button>
    <button class="btn" id="fwd"  title="Вперёд (Alt+→)" disabled>→</button>
    <button class="btn" id="rel"  title="Обновить (F5)">⟳</button>
    <input id="addr" placeholder="http://xxxxxxxxxx.murnet/" autofocus spellcheck="false">
    <button class="btn" id="go"   title="Перейти (Enter)">↵</button>
  </div>
  <iframe id="view" srcdoc='<!DOCTYPE html><html><head><style>body{margin:0;background:#0d1117;color:#e6edf3;font-family:Segoe UI,sans-serif;height:100vh;display:flex;align-items:center;justify-content:center}div{text-align:center}h1{color:#58a6ff;font-size:32px;letter-spacing:8px;margin-bottom:12px;text-shadow:0 0 20px rgba(88,166,255,.4)}p{color:#8b949e;margin:6px 0}code{background:#161b22;color:#7ee787;padding:6px 12px;border-radius:4px;font-family:Consolas,monospace;display:inline-block;border:1px solid #30363d}</style></head><body><div><h1>🌌 MURNET</h1><p>Введи .murnet адрес в строке выше</p><br><code>http://fgsesxh6fbmktj1od9mcu9ycyo4zuzwnxf.murnet/</code><p style="margin-top:14px;font-size:12px">Onion: Client → Guard → Middle → HS</p></div></body></html>'></iframe>
  <div class="status">
    <div><span class="dot"></span><span id="st">MurNet · proxy 127.0.0.1:18888 · Onion routing active</span></div>
    <div id="cnt">×</div>
  </div>
</div>
<script>
const v=document.getElementById('view'),a=document.getElementById('addr'),s=document.getElementById('st'),
      bb=document.getElementById('back'),bf=document.getElementById('fwd'),br=document.getElementById('rel'),bg=document.getElementById('go'),cnt=document.getElementById('cnt');
let hist=[],i=-1,nav_count=0;
function upd(){bb.disabled=i<=0;bf.disabled=i>=hist.length-1;cnt.textContent='nav: '+nav_count}
function go(u){
  if(!u)return;
  u=u.trim();
  if(!/^https?:\/\//.test(u))u='http://'+u;
  if(hist[i]!==u){hist=hist.slice(0,i+1);hist.push(u);i=hist.length-1}
  v.src=u;a.value=u;s.textContent='⏳ Загрузка: '+u;nav_count++;upd();
}
function jump(d){const n=i+d;if(n<0||n>=hist.length)return;i=n;v.src=hist[i];a.value=hist[i];upd()}
bg.onclick=()=>go(a.value);
bb.onclick=()=>jump(-1);
bf.onclick=()=>jump(1);
br.onclick=()=>{if(hist[i])v.src=hist[i]};
a.addEventListener('keydown',e=>{if(e.key==='Enter')go(a.value);else if(e.key==='Escape')a.blur()});
v.addEventListener('load',()=>{s.textContent='● Подключено · '+(hist[i]||'idle')});
v.addEventListener('error',()=>{s.textContent='✕ Ошибка загрузки'});
document.addEventListener('keydown',e=>{
  if(e.key==='F5'){e.preventDefault();br.click()}
  else if(e.altKey&&e.key==='ArrowLeft'){e.preventDefault();jump(-1)}
  else if(e.altKey&&e.key==='ArrowRight'){e.preventDefault();jump(1)}
  else if(e.ctrlKey&&e.key==='l'){e.preventDefault();a.focus();a.select()}
});
upd();
</script>
</body>
</html>"#;

fn main() -> wry::Result<()> {
    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("MurNet Browser")
        .with_inner_size(LogicalSize::new(1100.0, 720.0))
        .with_min_inner_size(LogicalSize::new(640.0, 400.0))
        .build(&event_loop)
        .expect("failed to create window");

    let proxy = ProxyConfig::Http(ProxyEndpoint {
        host: PROXY_HOST.into(),
        port: PROXY_PORT.into(),
    });

    let _webview = WebViewBuilder::new(&window)
        .with_proxy_config(proxy)
        .with_html(SHELL_HTML)
        .with_devtools(cfg!(debug_assertions))
        .build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

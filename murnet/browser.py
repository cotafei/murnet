"""
MurNet Browser — встроенный браузер для .murnet сайтов.

Запуск:
  pip install PyQt6 PyQt6-WebEngine
  python murnet_browser.py

Что внутри:
  - Guard + Middle relay запускаются автоматически
  - Встроенный HTTP-прокси на 127.0.0.1:18888
  - Chromium (QWebEngine) настроен на этот прокси
  - Поддержка .murnet адресов без внешних зависимостей

Для .murnet сайта рядом нужен запущенный hidden_service_demo.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading

# ── VDS endpoints (real production) ───────────────────────────────────────
_PROXY_PORT  = 18888
_VDS_IP      = "80.93.52.15"
_VDS_GUARD   = 9211
_VDS_MIDDLE  = 9212
_VDS_HS      = 9213
_CLIENT_PORT = 18204

# QTWEBENGINE_CHROMIUM_FLAGS is the correct way to pass Chromium flags
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    f"--proxy-server=http://127.0.0.1:{_PROXY_PORT} "
    f"--proxy-bypass-list=<-loopback>"   # route even localhost .murnet through proxy
)
sys.path.insert(0, os.path.dirname(__file__))

from PyQt6.QtCore    import QUrl, Qt, QObject, pyqtSignal
from PyQt6.QtGui     import QKeySequence, QShortcut, QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QToolBar, QLineEdit,
    QPushButton, QStatusBar, QLabel, QProgressBar,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore    import QWebEngineProfile, QWebEngineSettings

from murnet.core.onion.router          import OnionRouter
from murnet.core.onion.obfs_transport  import ObfsTransport as OnionTransport
from murnet.core.onion.hidden_service  import HiddenServiceDirectory
from murnet.core.onion.hs_client       import HiddenServiceClient

# ── HTML-шаблоны ──────────────────────────────────────────────────────────

_CSS = """
  body { font-family: monospace; background: #0d1117; color: #e6edf3;
         display: flex; align-items: center; justify-content: center;
         height: 100vh; margin: 0; }
  .box { border: 1px solid #30363d; padding: 2em 3em;
         border-radius: 8px; text-align: center; max-width: 500px; }
  h2   { color: #58a6ff; margin-top: 0; }
  code { background: #161b22; padding: .2em .5em;
         border-radius: 4px; color: #7ee787; display:block;
         margin: .4em 0; font-size: .85em; word-break: break-all; }
  .dim { color: #8b949e; font-size: .85em; }
"""

_PAGE_LOADING = f"""<html><head><style>{_CSS}</style></head>
<body><div class="box">
  <h2>&#9711; MurNet Browser</h2>
  <p>Запуск onion-нод…</p>
  <p class="dim">Guard · Middle · Client</p>
</div></body></html>"""

_PAGE_READY = f"""<html><head><style>{_CSS}</style></head>
<body><div class="box">
  <h2>&#9679; MurNet Browser</h2>
  <p>Введи <b>.murnet</b> адрес в строке выше</p>
  <code>http://xxxx.murnet/</code>
  <p class="dim">Onion routing активен · X25519 + AES-256-GCM</p>
</div></body></html>"""

_PAGE_ERROR = lambda msg: f"""<html><head><style>{_CSS}</style></head>
<body><div class="box">
  <h2 style="color:#f85149">&#9888; Ошибка запуска</h2>
  <code>{msg}</code>
  <p class="dim">Проверь что порты 18201/18202/18204/18888 свободны</p>
</div></body></html>"""


# ── Сигналы (thread-safe Qt→main) ─────────────────────────────────────────

class _Signals(QObject):
    ready = pyqtSignal()
    error = pyqtSignal(str)


# ── Главное окно ───────────────────────────────────────────────────────────

class BrowserWindow(QMainWindow):

    def __init__(self, signals: _Signals) -> None:
        super().__init__()
        self.setWindowTitle("MurNet Browser")
        self.setMinimumSize(1080, 720)
        self._signals = signals
        self._transports: list[ObfsTransport] = []
        self._security_panel_visible = False

        # ── toolbar ─────────────────────────────────────────────────────
        bar = QToolBar("nav")
        bar.setMovable(False)
        bar.setStyleSheet("""
            QToolBar  { background: #161b22; border-bottom: 1px solid #30363d; padding: 4px; }
            QPushButton { background: #21262d; color: #e6edf3; border: 1px solid #30363d;
                          border-radius: 4px; padding: 4px 10px; font-size: 14px; }
            QPushButton:hover { background: #30363d; }
            QLineEdit { background: #21262d; color: #e6edf3; border: 1px solid #30363d;
                        border-radius: 4px; padding: 4px 8px; font-size: 13px; }
        """)
        self.addToolBar(bar)

        self._btn_back    = QPushButton("←")
        self._btn_forward = QPushButton("→")
        self._btn_reload  = QPushButton("⟳")
        self._addr        = QLineEdit()
        self._addr.setPlaceholderText("http://xxxxxxxxxxxx.murnet/")
        self._addr.setFont(QFont("Consolas", 11))

        for w in (self._btn_back, self._btn_forward, self._btn_reload):
            w.setFixedWidth(36)
            bar.addWidget(w)
        bar.addWidget(self._addr)

        # ── security button ─────────────────────────────────────────────
        self._btn_sec = QPushButton("🛡️ Security")
        self._btn_sec.setStyleSheet("""
            QPushButton { background: #238636; border-color: #2ea043; color: white; font-weight: bold; }
            QPushButton:hover { background: #2ea043; }
        """)
        self._btn_sec.clicked.connect(self._toggle_security_panel)
        bar.addWidget(self._btn_sec)

        # ── webview ──────────────────────────────────────────────────────
        profile = QWebEngineProfile.defaultProfile()
        settings = profile.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)

        self._view = QWebEngineView()
        self._view.setStyleSheet("background:#0d1117;")
        
        # ── security overlay ─────────────────────────────────────────────
        self._sec_overlay = QLabel(self._view)
        self._sec_overlay.setVisible(False)
        self._sec_overlay.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)
        self._sec_overlay.setFixedSize(280, 160)
        self._sec_overlay.move(780, 10) # Fixed position for now
        self._sec_overlay.setStyleSheet("""
            background: rgba(22, 27, 34, 0.95);
            border: 1px solid #3fb950;
            border-radius: 8px;
            color: #e6edf3;
            padding: 15px;
            font-family: 'Consolas', 'Courier New', monospace;
        """)

        self.setCentralWidget(self._view)

        # ── status bar ───────────────────────────────────────────────────
        self._status_label = QLabel("Запуск…")
        self._status_label.setStyleSheet("color:#8b949e; font-size:11px;")
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(120)
        self._progress.setMaximumHeight(14)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet("QProgressBar::chunk{background:#58a6ff;}")

        sb = QStatusBar()
        sb.setStyleSheet("background:#161b22; border-top:1px solid #30363d;")
        sb.addWidget(self._status_label)
        sb.addPermanentWidget(self._progress)
        self.setStatusBar(sb)

        # ── signals ──────────────────────────────────────────────────────
        self._btn_back.clicked.connect(self._view.back)
        self._btn_forward.clicked.connect(self._view.forward)
        self._btn_reload.clicked.connect(self._view.reload)
        self._addr.returnPressed.connect(self._navigate)

        self._view.urlChanged.connect(
            lambda u: self._addr.setText(u.toString())
        )
        self._view.titleChanged.connect(
            lambda t: self.setWindowTitle(f"{t} — MurNet Browser")
        )
        self._view.loadProgress.connect(self._progress.setValue)
        self._view.loadStarted.connect(lambda: self._progress.setVisible(True))
        self._view.loadFinished.connect(lambda _: self._progress.setVisible(False))

        self._signals.ready.connect(self._on_ready)
        self._signals.error.connect(self._on_error)

        QShortcut(QKeySequence("Ctrl+L"), self, self._focus_addr)
        QShortcut(QKeySequence("Alt+Left"),  self, self._view.back)
        QShortcut(QKeySequence("Alt+Right"), self, self._view.forward)
        QShortcut(QKeySequence("F5"),        self, self._view.reload)

        # Disable navigation until proxy is ready
        self._addr.setEnabled(False)

        # Show startup page
        self._view.setHtml(_PAGE_LOADING)

    # ── slots ─────────────────────────────────────────────────────────────

    def _on_ready(self) -> None:
        self._addr.setEnabled(True)
        self._addr.setFocus()
        self._status_label.setText(
            f"Onion ready  ·  proxy 127.0.0.1:{_PROXY_PORT}"
        )
        self._view.setHtml(_PAGE_READY)

    def _on_error(self, msg: str) -> None:
        self._status_label.setText("Ошибка запуска")
        self._view.setHtml(_PAGE_ERROR(msg))

    def _navigate(self) -> None:
        url = self._addr.text().strip()
        if not url:
            return
        if "://" not in url:
            url = "http://" + url
        self._view.load(QUrl(url))

    def _focus_addr(self) -> None:
        self._addr.setFocus()
        self._addr.selectAll()

    def _toggle_security_panel(self) -> None:
        self._security_panel_visible = not self._security_panel_visible
        self._sec_overlay.setVisible(self._security_panel_visible)
        if self._security_panel_visible:
            self._update_security_info()

    def _update_security_info(self) -> None:
        if not self._transports:
            return
        
        # Берем данные из первого транспорта (они должны быть идентичны по конфигу)
        t = self._transports[0]
        total_rejected = sum(transport.probes_rejected for transport in self._transports)
        
        html = f"""
            <div style='font-size: 14px; margin-bottom: 8px; color: #3fb950;'>🌌 MURNET SECURITY</div>
            <div style='font-size: 12px; color: #8b949e;'>MASK (SNI): <b style='color: #58a6ff;'>{t.sni}</b></div>
            <div style='font-size: 12px; color: #8b949e;'>PSK AUTH: <b style='color: #7ee787;'>ACTIVE</b></div>
            <div style='border-top: 1px solid #30363d; margin: 10px 0;'></div>
            <div style='font-size: 11px; color: #8b949e;'>PROBES REJECTED (RKN):</div>
            <div style='font-size: 22px; font-weight: bold; color: #f85149;'>{total_rejected}</div>
        """
        self._sec_overlay.setText(html)
        self._sec_overlay.adjustSize()
        # Keep it at the top right
        self._sec_overlay.move(self._view.width() - self._sec_overlay.width() - 20, 20)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "_sec_overlay"):
            self._sec_overlay.move(self._view.width() - self._sec_overlay.width() - 20, 20)


# ── MurNet async backend ───────────────────────────────────────────────────

async def _start_nodes(signals: _Signals) -> None:
    try:
        # Мы подключаемся к VDS Guard и Middle
        vds_guard_addr  = f"{_VDS_IP}:{_VDS_GUARD}"
        vds_middle_addr = f"{_VDS_IP}:{_VDS_MIDDLE}"
        client_addr     = f"127.0.0.1:{_CLIENT_PORT}"

        # Локальный клиентский узел
        cli_r = OnionRouter(client_addr)
        # Добавляем VDS узлы в список известных пиров
        cli_t = OnionTransport(cli_r, "127.0.0.1", _CLIENT_PORT,
                               peers={"Guard": vds_guard_addr, "Middle": vds_middle_addr})
        await cli_t.start()

        # Store transports in main window
        for window in QApplication.topLevelWidgets():
            if isinstance(window, BrowserWindow):
                window._transports = [cli_t]
                # Start UI refresh timer
                from PyQt6.QtCore import QTimer
                window._sec_timer = QTimer(window)
                window._sec_timer.timeout.connect(window._update_security_info)
                window._sec_timer.start(2000)

        directory = HiddenServiceDirectory()
        cli_t.hs_directory = directory

        # Принудительно добавляем наш VDS сайт в директорию
        import time as _time
        vds_hs_addr = "fgseSxh6fbMktJ1oD9mcU9ycYo4ZUzWNxf.murnet"
        vds_hs_pub  = "eba400645db5ad46fb7081b3c785e9cf2b7d7c3ccae839c8533e99d31d3293d8"
        # HS relay указывает на настоящий HS-порт VDS (9213)
        vds_hs_relay = f"{_VDS_IP}:{_VDS_HS}"
        
        directory._entries[vds_hs_addr.lower()] = {
            "pubkey":    vds_hs_pub,
            "relay":     vds_hs_relay,
            "timestamp": _time.time(),
        }

        # Load services written by hidden_service_demo.py (optional)
        _peers_file = os.path.join(os.path.dirname(__file__), ".murnet_peers.json")
        if os.path.exists(_peers_file):
            import json as _json
            try:
                data = _json.load(open(_peers_file))
                for addr, entry in data.get("services", {}).items():
                    entry["timestamp"] = _time.time()
                    directory._entries[addr] = entry
            except Exception:
                pass

        proxy = HiddenServiceClient(
            cli_r, cli_t, directory, proxy_port=_PROXY_PORT
        )
        await proxy.start()

        signals.ready.emit()

    except Exception as exc:
        signals.error.emit(str(exc))


def _thread_main(loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    loop.run_forever()


# ── entry point ───────────────────────────────────────────────────────────

def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("MurNet Browser")
    app.setStyle("Fusion")
    app.setStyleSheet("QMainWindow { background: #0d1117; }")

    signals = _Signals()
    window  = BrowserWindow(signals)
    window.show()

    loop   = asyncio.new_event_loop()
    thread = threading.Thread(target=_thread_main, args=(loop,), daemon=True)
    thread.start()
    asyncio.run_coroutine_threadsafe(_start_nodes(signals), loop)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

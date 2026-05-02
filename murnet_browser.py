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

# ── Chromium proxy flag MUST be set before QApplication ────────────────────
_PROXY_PORT  = 18888
_GUARD_PORT  = 18201
_MIDDLE_PORT = 18202
_CLIENT_PORT = 18204

sys.argv += [f"--proxy-server=http://127.0.0.1:{_PROXY_PORT}"]
sys.path.insert(0, os.path.dirname(__file__))

from PyQt6.QtCore    import QUrl, Qt, QObject, pyqtSignal
from PyQt6.QtGui     import QKeySequence, QShortcut, QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QToolBar, QLineEdit,
    QPushButton, QStatusBar, QLabel, QProgressBar,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore    import QWebEngineProfile, QWebEngineSettings

from core.onion.router        import OnionRouter
from core.onion.transport     import OnionTransport
from core.onion.hidden_service import HiddenServiceDirectory
from core.onion.hs_client     import HiddenServiceClient

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

        # ── webview ──────────────────────────────────────────────────────
        profile = QWebEngineProfile.defaultProfile()
        settings = profile.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)

        self._view = QWebEngineView()
        self._view.setStyleSheet("background:#0d1117;")
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

        # Show startup page
        self._view.setHtml(_PAGE_LOADING)

    # ── slots ─────────────────────────────────────────────────────────────

    def _on_ready(self) -> None:
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


# ── MurNet async backend ───────────────────────────────────────────────────

async def _start_nodes(signals: _Signals) -> None:
    try:
        guard_addr  = f"127.0.0.1:{_GUARD_PORT}"
        middle_addr = f"127.0.0.1:{_MIDDLE_PORT}"
        client_addr = f"127.0.0.1:{_CLIENT_PORT}"

        guard_r = OnionRouter(guard_addr)
        guard_t = OnionTransport(guard_r, "127.0.0.1", _GUARD_PORT)
        await guard_t.start()

        mid_r = OnionRouter(middle_addr)
        mid_t = OnionTransport(mid_r, "127.0.0.1", _MIDDLE_PORT,
                               peers={"Guard": guard_addr})
        await mid_t.start()

        cli_r = OnionRouter(client_addr)
        cli_t = OnionTransport(cli_r, "127.0.0.1", _CLIENT_PORT,
                               peers={"Guard": guard_addr, "Middle": middle_addr})
        await cli_t.start()

        directory = HiddenServiceDirectory()
        for t in (cli_t, guard_t, mid_t):
            t.hs_directory = directory

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

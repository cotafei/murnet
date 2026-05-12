# MurNet Browser (Rust)

Минималистичный браузер для `.murnet` сайтов на Rust + системный WebView.

## Архитектура

```
┌─────────────────────────────────┐    ┌──────────────────────────┐
│   murnet_browser (Rust)         │    │  murnet_proxy.py         │
│   ┌──────────────────────────┐  │    │                          │
│   │  tao window              │  │    │  Onion client            │
│   │  └─ wry WebView (Edge)   │──┼───▶│  HTTP → 127.0.0.1:18888  │
│   │     proxy → 127.0.0.1:18888  │    │  └→ Guard:9211           │
│   └──────────────────────────┘  │    │     └→ Middle:9212       │
└─────────────────────────────────┘    │        └→ HS:9213 → site │
                                       └──────────────────────────┘
```

UI и сетевая часть **разделены**:
- **Rust-бинарь** — только окно + WebView (системный Edge/WebKit), без Python в зависимостях.
- **`murnet_proxy.py`** — onion-клиент, поднимает HTTP-прокси на `127.0.0.1:18888`.

## Зачем

Сравнение с `murnet_browser.py` (PyQt6):

| Метрика            | PyQt6        | Rust + wry   |
|--------------------|--------------|--------------|
| Размер бинаря      | ~200 МБ      | ~5–10 МБ     |
| Старт              | ~3 с         | <200 мс      |
| RAM (idle)         | ~250 МБ      | ~30–50 МБ    |
| Зависимости        | Python+Qt    | только OS    |
| Бандлит Chromium   | Да           | Нет (берёт системный WebView2) |

## Сборка

Установи Rust ([rustup.rs](https://rustup.rs)), потом:

```powershell
cd D:\kai\03_Projects\MURNET\browser_rs
cargo build --release
```

Бинарь: `target\release\murnet_browser.exe`.

## Запуск

В двух терминалах:

```powershell
# Терминал 1 — onion прокси (Python)
cd D:\kai\03_Projects\MURNET
python murnet_proxy.py

# Терминал 2 — браузер (Rust)
cd D:\kai\03_Projects\MURNET\browser_rs
cargo run --release
```

Или запусти готовый `target\release\murnet_browser.exe` напрямую.

В адресную строку вбей `.murnet` адрес. Например:
```
http://fgsesxh6fbmktj1od9mcu9ycyo4zuzwnxf.murnet/
```

## Горячие клавиши

| Клавиша      | Действие        |
|--------------|-----------------|
| `Ctrl+L`     | Адресная строка |
| `Enter`      | Перейти         |
| `Alt+←/→`    | Назад / вперёд  |
| `F5`         | Обновить        |

## Зависимости системы

- **Windows 10/11** — WebView2 Runtime (preinstalled на свежих сборках; иначе [скачать](https://developer.microsoft.com/microsoft-edge/webview2/))
- **macOS** — встроенный WKWebView (ничего ставить не надо)
- **Linux** — `webkit2gtk-4.1` (`apt install libwebkit2gtk-4.1-dev` или через пакмен дистрибутива)

## Что дальше (TODO)

- [ ] Запускать `murnet_proxy.py` как child process из Rust (`std::process::Command`) при старте, убивать при выходе
- [ ] IPC между shell и Rust (Cmd+T для новой вкладки, читать `probes_rejected` из транспорта)
- [ ] Native toolbar вместо HTML shell (через `tao::menu`) — сэкономит iframe и cross-origin граничные кейсы
- [ ] Переписать onion client на Rust (`tokio` + `chacha20poly1305`) — тогда proxy.py не нужен, всё в одном бинаре

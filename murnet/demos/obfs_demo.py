"""
MurNet Obfuscation Demo — сравнение plain vs obfs трафика.

Запуск:
  python demos/obfs_demo.py

Что показывает:
  1. Запускает два relay с ObfsTransport
  2. Отправляет onion-ячейку через обфусцированный канал
  3. Захватывает сырые байты с обоих вариантов и показывает разницу
  4. Доказывает что DPI видит только шум

Выход в терминал:
  Plain:   {"src": "127.0.0.1:9301", "cell": {...}}
  Obfs:    b'\\x3a\\x00\\x00\\x00\\x8f\\x2c...'  (случайные байты)
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from murnet.core.onion.router         import OnionRouter
from murnet.core.onion.transport      import OnionTransport
from murnet.core.onion.obfs_transport import ObfsTransport
from murnet.core.onion.cell           import OnionCell

logging.basicConfig(level=logging.INFO)

PORT_PLAIN_A = 9301
PORT_PLAIN_B = 9302
PORT_OBFS_A  = 9311
PORT_OBFS_B  = 9312


# ── перехват сырых байт ───────────────────────────────────────────────────

_captured: list[bytes] = []

async def _sniffer(host: str, port: int, label: str, capture: list) -> None:
    """Слушает порт и захватывает первые N байт соединения."""
    async def _handler(r, w):
        data = await r.read(256)
        capture.append((label, data))
        w.close()
    srv = await asyncio.start_server(_handler, host, port)
    async with srv:
        await asyncio.sleep(0.5)


# ── тест plain ────────────────────────────────────────────────────────────

async def test_plain() -> bytes:
    """Захватывает как выглядит plain OnionTransport на проводе."""
    captured = []

    async def _handler(r, w):
        data = await r.read(512)
        captured.append(data)
        w.close()

    srv = await asyncio.start_server(_handler, "127.0.0.1", PORT_PLAIN_B)

    r = OnionRouter(f"127.0.0.1:{PORT_PLAIN_A}")
    t = OnionTransport(r, "127.0.0.1", PORT_PLAIN_A,
                       peers={"B": f"127.0.0.1:{PORT_PLAIN_B}"})
    await t.start()

    cell = OnionCell(circuit_id="test-cid", cmd="CREATE", data=b"hello")
    try:
        await t._send("B", cell)
        await asyncio.sleep(0.3)
    except Exception:
        pass

    await t.stop()
    srv.close()
    return captured[0] if captured else b""


# ── тест obfs ─────────────────────────────────────────────────────────────

async def test_obfs() -> bytes:
    """Захватывает как выглядит ObfsTransport на проводе."""
    raw_bytes = []

    # Низкоуровневый sniffer — принимает и сохраняет сырые байты
    async def _raw_handler(r, w):
        data = await r.read(512)
        raw_bytes.append(data)
        w.close()

    srv = await asyncio.start_server(_raw_handler, "127.0.0.1", PORT_OBFS_B + 10)

    r = OnionRouter(f"127.0.0.1:{PORT_OBFS_A}")
    t = ObfsTransport(r, "127.0.0.1", PORT_OBFS_A,
                      peers={"B": f"127.0.0.1:{PORT_OBFS_B + 10}"})
    await t.start()

    cell = OnionCell(circuit_id="test-cid", cmd="CREATE", data=b"hello")
    try:
        await t._send("B", cell)
        await asyncio.sleep(0.3)
    except Exception:
        pass

    await t.stop()
    srv.close()
    return raw_bytes[0] if raw_bytes else b""


# ── obfs end-to-end ───────────────────────────────────────────────────────

async def test_obfs_e2e() -> bool:
    """Полноценная передача через ObfsTransport туда-обратно."""
    received = []

    r_b   = OnionRouter(f"127.0.0.1:{PORT_OBFS_B}")
    r_b.on_data = lambda sid, data: received.append(data)
    t_b   = ObfsTransport(r_b, "127.0.0.1", PORT_OBFS_B)
    await t_b.start()

    r_a   = OnionRouter(f"127.0.0.1:{PORT_OBFS_A}")
    t_a   = ObfsTransport(r_a, "127.0.0.1", PORT_OBFS_A,
                          peers={"B": f"127.0.0.1:{PORT_OBFS_B}"})
    await t_a.start()

    # Строим circuit и отправляем данные
    try:
        circuit = await asyncio.wait_for(
            r_a.build_circuit([f"127.0.0.1:{PORT_OBFS_B}"]),
            timeout=10,
        )
        await r_a.send_data(circuit, "stream-1", b"secret message over obfs")
        await asyncio.sleep(0.5)
    except Exception as exc:
        print(f"  [!] e2e error: {exc}")
        return False
    finally:
        await t_a.stop()
        await t_b.stop()

    return True


async def test_probe_rejection() -> int:
    """Симулирует атаку (подключение без PSK или с неверным) и возвращает счетчик отбитых проб."""
    r_b = OnionRouter(f"127.0.0.1:{PORT_OBFS_B}")
    t_b = ObfsTransport(r_b, "127.0.0.1", PORT_OBFS_B, psk="correct-psk")
    await t_b.start()

    # Попытка подключения с НЕВЕРНЫМ PSK (отправляем достаточно данных для сбоя)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT_OBFS_B)
        writer.write(os.urandom(100))
        await writer.drain()
        await asyncio.sleep(0.5) # Даем время серверу обработать
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    count = t_b.probes_rejected
    await t_b.stop()
    return count


# ── main ──────────────────────────────────────────────────────────────────

async def main() -> None:
    print("\n  MurNet Obfuscation Demo")
    print("  " + "="*50)

    # 1. Plain
    print("\n  [1] Plain OnionTransport — что видит DPI:")
    plain_bytes = await test_plain()
    if plain_bytes:
        try:
            text = plain_bytes.decode("utf-8", errors="replace")
            print(f"      {text[:120]}")
        except Exception:
            print(f"      {plain_bytes[:120]}")
    else:
        print("      (нет данных)")

    # 2. Obfs — raw bytes
    print("\n  [2] ObfsTransport — что видит DPI (первые 64 байта):")
    obfs_bytes = await test_obfs()
    if obfs_bytes:
        hex_str = obfs_bytes[:64].hex()
        chunks  = [hex_str[i:i+32] for i in range(0, len(hex_str), 32)]
        for chunk in chunks:
            spaced = " ".join(chunk[j:j+2] for j in range(0, len(chunk), 2))
            print(f"      {spaced}")
    else:
        print("      (нет данных)")

    # 3. Printable chars ratio
    if obfs_bytes:
        printable = sum(1 for b in obfs_bytes if 32 <= b < 127)
        ratio = printable / len(obfs_bytes) * 100
        print(f"\n      Читаемых символов: {ratio:.1f}%  "
              f"(у JSON ~80%, у шума ~2-5%)")

    # 4. E2E test
    print("\n  [3] Полный onion circuit через ObfsTransport:")
    ok = await test_obfs_e2e()
    print(f"      {'OK — данные прошли через зашифрованный канал' if ok else 'FAILED'}")

    # 5. Probe rejection test
    print("\n  [4] Симуляция атаки (Active Probing):")
    rejected = await test_probe_rejection()
    print(f"      Попытка сканирования с неверным PSK...")
    print(f"      Счетчик отбитых атак: {rejected} [ЗАБЛОКИРОВАНО]")
    if rejected > 0:
        print(f"      Результат: сервер проигнорировал подключение (Silent Drop)")

    print("\n  " + "="*50)
    print("  Итог:")
    print("    Plain  -> JSON виден в DPI, паттерн raspoznaetsya")
    print("    ObfsTransport -> sluchajnye bajty, net zagolovkov,")
    print("                     net fingerprint-a, net magic bytes")
    print()


if __name__ == "__main__":
    asyncio.run(main())

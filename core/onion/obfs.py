"""
ObfsStream — обфускация трафика MurNet.

Для наблюдателя (DPI/провайдер) соединение выглядит как поток случайных байт:

  Handshake:
    → 32 байта (X25519 pubkey клиента, неотличимы от шума)
    ← 32 байта (X25519 pubkey сервера, неотличимы от шума)
    Оба вычисляют общий ключ через X25519 + HKDF-SHA256.
    Нет magic bytes, нет version field, нет имени протокола.

  Фрейм данных:
    [4 байта LE: len(ciphertext)]
    [12 байт: случайный nonce]
    [N байт: ChaCha20-Poly1305(payload + random_padding)]

    payload = [2 байта LE: data_len] + data
    padding = os.urandom(rand 0..255)

  Почему это работает:
    - Нет распознаваемого TLS ClientHello
    - Нет JSON / текстовых заголовков
    - Каждый фрейм уникален (новый nonce)
    - Размеры фреймов варьируются (padding)
    - Активный пробник не может отличить от любого AEAD-протокола
"""
from __future__ import annotations

import asyncio
import os
import struct
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


_MAX_FRAME = 65535   # максимальный размер payload


class ObfsStream:
    """
    Обфусцированный bidirectional stream поверх asyncio StreamReader/Writer.

    Использование:
        stream = ObfsStream(reader, writer, is_server=False)
        await stream.handshake()
        stream.write(data)
        await stream.drain()
        data = await stream.read()
    """

    __slots__ = (
        "_reader", "_writer", "_is_server",
        "_send_aead", "_recv_aead",
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_server: bool = False,
    ) -> None:
        self._reader    = reader
        self._writer    = writer
        self._is_server = is_server
        self._send_aead: Optional[ChaCha20Poly1305] = None
        self._recv_aead: Optional[ChaCha20Poly1305] = None

    # ── handshake ─────────────────────────────────────────────────────────

    async def handshake(self) -> None:
        """X25519 key exchange. Клиент пишет первым."""
        priv  = X25519PrivateKey.generate()
        my_pk = priv.public_key().public_bytes_raw()  # 32 bytes

        if not self._is_server:
            self._writer.write(my_pk)
            await self._writer.drain()
            peer_pk_bytes = await self._reader.readexactly(32)
        else:
            peer_pk_bytes = await self._reader.readexactly(32)
            self._writer.write(my_pk)
            await self._writer.drain()

        peer_pk = X25519PublicKey.from_public_bytes(peer_pk_bytes)
        shared  = priv.exchange(peer_pk)

        # Детерминированная соль из обоих pubkey-ов
        if not self._is_server:
            salt = my_pk + peer_pk_bytes
        else:
            salt = peer_pk_bytes + my_pk

        def _derive(info: bytes) -> bytes:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=info,
            ).derive(shared)

        # Два разных ключа для каждого направления
        key_c2s = _derive(b"murnet-obfs-v1-c2s")
        key_s2c = _derive(b"murnet-obfs-v1-s2c")

        if not self._is_server:
            self._send_aead = ChaCha20Poly1305(key_c2s)
            self._recv_aead = ChaCha20Poly1305(key_s2c)
        else:
            self._send_aead = ChaCha20Poly1305(key_s2c)
            self._recv_aead = ChaCha20Poly1305(key_c2s)

    # ── write ─────────────────────────────────────────────────────────────

    def write(self, data: bytes) -> None:
        """Зашифровать и поставить в буфер writer-а."""
        assert self._send_aead, "handshake not done"
        nonce   = os.urandom(12)
        pad_len = os.urandom(1)[0]                       # 0..255 байт padding
        plain   = struct.pack("<H", len(data)) + data + os.urandom(pad_len)
        ct      = self._send_aead.encrypt(nonce, plain, None)
        self._writer.write(struct.pack("<I", len(ct)) + nonce + ct)

    async def drain(self) -> None:
        await self._writer.drain()

    # ── read ──────────────────────────────────────────────────────────────

    async def read(self) -> bytes:
        """Прочитать и расшифровать один фрейм. Возвращает payload без padding."""
        assert self._recv_aead, "handshake not done"
        hdr      = await self._reader.readexactly(4)
        ct_len   = struct.unpack("<I", hdr)[0]
        nonce    = await self._reader.readexactly(12)
        ct       = await self._reader.readexactly(ct_len)
        plain    = self._recv_aead.decrypt(nonce, ct, None)
        data_len = struct.unpack("<H", plain[:2])[0]
        return plain[2 : 2 + data_len]

    # ── passthrough ───────────────────────────────────────────────────────

    def is_closing(self) -> bool:
        return self._writer.is_closing()

    def close(self) -> None:
        try:
            self._writer.close()
        except Exception:
            pass

    def get_extra_info(self, key: str, default=None):
        return self._writer.get_extra_info(key, default)

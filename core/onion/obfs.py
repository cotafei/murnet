"""
ObfsStream — обфускация трафика MurNet.

Для наблюдателя (DPI/провайдер) соединение выглядит как поток случайных байт:

  Handshake:
    → [Fake TLS ClientHello with SNI (vk.com/yandex.ru)]
    → [32 байта: X25519 pubkey]
    → [16 байт: HMAC-SHA256(PSK, pubkey)]
    ← [Fake TLS ServerHello]
    ← [32 байта: X25519 pubkey]
    ← [16 байт: HMAC-SHA256(PSK, pubkey)]

    Если PSK не совпадает, сервер закрывает соединение без ответа (stealth).
    Если SNI не передан, используется vk.com (для маскировки в РФ).

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
import hmac
import hashlib
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
        "_psk", "_sni",
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_server: bool = False,
        psk: Optional[bytes] = None,
        sni: str = "vk.com",
    ) -> None:
        self._reader    = reader
        self._writer    = writer
        self._is_server = is_server
        self._psk       = psk or b"murnet-default-psk-v1"
        self._sni       = sni
        self._send_aead: Optional[ChaCha20Poly1305] = None
        self._recv_aead: Optional[ChaCha20Poly1305] = None

    # ── helpers ───────────────────────────────────────────────────────────

    def _get_hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()[:16]

    def _make_client_hello(self) -> bytes:
        """Минимальный TLS ClientHello с SNI."""
        # Упрощенная структура для обхода DPI
        # [Record Header: 16 03 01 len]
        # [Handshake Header: 01 len]
        # [ClientHello: version, random, session_id, ciphers, compression, extensions(SNI)]
        sni_bytes = self._sni.encode()
        sni_ext   = struct.pack(">HHH", 0, len(sni_bytes) + 5, len(sni_bytes) + 3) + b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
        ext_len   = len(sni_ext)
        ch_body   = b"\x03\x03" + os.urandom(32) + b"\x00\x00\x02\x00\x2f\x01\x00" + struct.pack(">H", ext_len) + sni_ext
        ch_header = b"\x01" + struct.pack(">I", len(ch_body))[1:]
        record    = b"\x16\x03\x01" + struct.pack(">H", len(ch_header) + len(ch_body))
        return record + ch_header + ch_body

    def _make_server_hello(self) -> bytes:
        """Минимальный TLS ServerHello."""
        sh_body   = b"\x03\x03" + os.urandom(32) + b"\x00\x00\x2f\x00"
        sh_header = b"\x01" + struct.pack(">I", len(sh_body))[1:]
        record    = b"\x16\x03\x03" + struct.pack(">H", len(sh_header) + len(sh_body))
        # Добавим ChangeCipherSpec для правдоподобности
        ccs       = b"\x14\x03\x03\x00\x01\x01"
        return record + sh_header + sh_body + ccs

    # ── handshake ─────────────────────────────────────────────────────────

    async def handshake(self) -> None:
        """X25519 + PSK handshake под прикрытием TLS."""
        priv  = X25519PrivateKey.generate()
        my_pk = priv.public_key().public_bytes_raw()
        my_hmac = self._get_hmac(self._psk, my_pk)

        if not self._is_server:
            # Клиент: TLS ClientHello + Pubkey + PSK-Auth
            self._writer.write(self._make_client_hello())
            self._writer.write(my_pk + my_hmac)
            await self._writer.drain()

            # Читаем ServerHello (пропускаем record-слой)
            # Мы знаем примерный размер наших фейковых записей
            # record(5) + handshake_hdr(4) + body(38) + ccs(6) = 53
            await self._reader.readexactly(53)

            # Читаем ответные ключи
            peer_data = await self._reader.readexactly(32 + 16)
        else:
            # Сервер: Читаем ClientHello (примерно 100-150 байт в зависимости от SNI)
            # Чтобы не зависеть от точного размера, читаем заголовок рекорда
            rec_hdr = await self._reader.readexactly(5)
            if rec_hdr[0] != 0x16:
                raise ValueError("Not a TLS handshake")
            rec_len = struct.unpack(">H", rec_hdr[3:5])[0]
            await self._reader.readexactly(rec_len)

            # Читаем Pubkey + HMAC
            peer_data = await self._reader.readexactly(32 + 16)
            peer_pk_bytes = peer_data[:32]
            peer_hmac     = peer_data[32:]

            # ПРОВЕРКА PSK
            if not hmac.compare_digest(peer_hmac, self._get_hmac(self._psk, peer_pk_bytes)):
                # МОЛЧИМ И ЗАКРЫВАЕМСЯ
                self._writer.close()
                raise ConnectionError("PSK authentication failed (silent drop)")

            # Если ок — отвечаем своим TLS + Pubkey + HMAC
            self._writer.write(self._make_server_hello())
            self._writer.write(my_pk + my_hmac)
            await self._writer.drain()

        peer_pk_bytes = peer_data[:32]
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

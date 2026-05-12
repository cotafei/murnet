"""
ObfsStream — обфускация трафика MurNet (wire protocol v2).

Для DPI соединение выглядит как поток случайных байт без TLS-сигнатуры
(TLS-маска отключена в v2 — RKN DPI её резал на нестандартных портах).

Handshake (raw X25519 + HMAC, no TLS wrapper):
    → [32 B: X25519 pubkey] || [16 B: nonce] || [16 B: HMAC(PSK, pk || nonce || zero16)]
    ← [32 B: X25519 pubkey] || [16 B: nonce] || [16 B: HMAC(PSK, pk || nonce || client_nonce)]

  Server's HMAC binds client_nonce → защита от server impersonation.
  Replay detection — на уровне ObfsTransport (передаётся через check_nonce_fn):
  сервер запоминает виденные client_nonce в LRU-set с TTL, повтор → reject.

  Bad PSK → server adds 50–550ms random jitter, then silent close.
  Это убирает timing distinguisher между "wrong PSK" и "slow network".

Frame (data):
    [4 B LE: len(ciphertext)]    — capped at _MAX_FRAME + overhead
    [12 B: random nonce]
    [N B: ChaCha20-Poly1305(payload + random_padding)]

    payload = [2 B LE: data_len] || data || urandom(0..255)
"""
from __future__ import annotations

import asyncio
import hmac
import hashlib
import os
import struct
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


_MAX_FRAME = 65535          # максимальный размер payload
_NONCE_LEN_HANDSHAKE = 16   # bytes — handshake replay-protection nonce
_JITTER_MIN_S       = 0.05  # минимум timing-jitter перед silent close
_JITTER_RANGE_S     = 0.5   # диапазон сверх минимума (итого 50–550ms)


# C1 fix: callback тип для проверки nonce на replay
# Передаётся в server-mode ObfsStream; возвращает True если nonce свежий.
NonceChecker = Callable[[bytes], bool]


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
        "_check_nonce_fn",
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_server: bool = False,
        psk: Optional[bytes] = None,
        sni: str = "vk.com",
        check_nonce_fn: Optional[NonceChecker] = None,
    ) -> None:
        self._reader    = reader
        self._writer    = writer
        self._is_server = is_server
        self._psk       = psk or b"murnet-default-psk-v1"
        self._sni       = sni
        self._send_aead: Optional[ChaCha20Poly1305] = None
        self._recv_aead: Optional[ChaCha20Poly1305] = None
        # C1: server-side replay check (returns False if nonce already seen)
        self._check_nonce_fn = check_nonce_fn

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
        """X25519 + PSK handshake with replay protection (v2).

        Wire (each side):
            pubkey (32B)  ||  nonce (16B)  ||  HMAC-SHA256(PSK, pubkey || nonce || peer_nonce)[:16]

        Client sends without peer_nonce (uses zeros — first message).
        Server's HMAC binds the client's nonce → replay of a recorded
        client message yields a fresh server response, but the attacker
        cannot construct a new server reply, so they cannot complete an
        active relay/impersonation.

        Session keys are derived from BOTH nonces, guaranteeing
        per-session uniqueness even when ephemeral keys collide (they
        won't, but defense in depth).

        On HMAC failure the server adds a 50-500ms random jitter before
        closing the socket — defeats the timing distinguisher between
        "bad PSK" and "slow network".
        """
        priv  = X25519PrivateKey.generate()
        my_pk = priv.public_key().public_bytes_raw()
        my_nonce = os.urandom(_NONCE_LEN_HANDSHAKE)

        if not self._is_server:
            # Client speaks first — no peer_nonce yet, use zeros.
            zero_peer_nonce = b"\x00" * _NONCE_LEN_HANDSHAKE
            my_hmac = self._get_hmac(self._psk, my_pk + my_nonce + zero_peer_nonce)
            self._writer.write(my_pk + my_nonce + my_hmac)
            await self._writer.drain()
            peer_data = await self._reader.readexactly(32 + _NONCE_LEN_HANDSHAKE + 16)
            peer_pk_bytes = peer_data[:32]
            peer_nonce    = peer_data[32 : 32 + _NONCE_LEN_HANDSHAKE]
            peer_hmac     = peer_data[32 + _NONCE_LEN_HANDSHAKE :]

            # Server's HMAC must bind OUR nonce — proves freshness.
            expected = self._get_hmac(self._psk, peer_pk_bytes + peer_nonce + my_nonce)
            if not hmac.compare_digest(peer_hmac, expected):
                self._writer.close()
                raise ConnectionError("server handshake auth failed")
        else:
            # Server reads first.
            peer_data = await self._reader.readexactly(32 + _NONCE_LEN_HANDSHAKE + 16)
            peer_pk_bytes = peer_data[:32]
            peer_nonce    = peer_data[32 : 32 + _NONCE_LEN_HANDSHAKE]
            peer_hmac     = peer_data[32 + _NONCE_LEN_HANDSHAKE :]

            # Server-side validation. All failures go through the same
            # jittered close to defeat the timing distinguisher between
            # "bad PSK", "replay", "bad pubkey" and "slow network". (W5)
            handshake_ok = True
            fail_reason  = "handshake failed"
            try:
                zero_peer_nonce = b"\x00" * _NONCE_LEN_HANDSHAKE
                expected = self._get_hmac(
                    self._psk, peer_pk_bytes + peer_nonce + zero_peer_nonce
                )
                if not hmac.compare_digest(peer_hmac, expected):
                    handshake_ok = False
                    fail_reason  = "handshake failed"   # don't leak "PSK" to logs (N3)

                # C1: replay protection — has the server seen this nonce before?
                if handshake_ok and self._check_nonce_fn is not None:
                    if not self._check_nonce_fn(peer_nonce):
                        handshake_ok = False
                        fail_reason  = "handshake failed"  # same opaque message

                # X25519 sanity check before exchange — invalid pubkey path
                # must also go through the jitter, not fast-fail. (W5)
                if handshake_ok:
                    try:
                        _peer_pk_obj = X25519PublicKey.from_public_bytes(peer_pk_bytes)
                    except Exception:
                        handshake_ok = False
                        fail_reason  = "handshake failed"
            except Exception:
                handshake_ok = False

            if not handshake_ok:
                # W1 fix: cancellation-safe close. Always close the writer
                # even if the sleep is cancelled by an outer wait_for timeout.
                jitter = _JITTER_MIN_S + os.urandom(1)[0] / 256.0 * _JITTER_RANGE_S
                try:
                    await asyncio.sleep(jitter)
                finally:
                    try:
                        self._writer.close()
                    except Exception:
                        pass
                raise ConnectionError(fail_reason)

            # Reply with HMAC that includes peer_nonce → binds session.
            my_hmac = self._get_hmac(self._psk, my_pk + my_nonce + peer_nonce)
            self._writer.write(my_pk + my_nonce + my_hmac)
            await self._writer.drain()

        peer_pk = X25519PublicKey.from_public_bytes(peer_pk_bytes)
        shared  = priv.exchange(peer_pk)

        # KDF salt includes both nonces → per-session uniqueness.
        if not self._is_server:
            salt = my_pk + peer_pk_bytes + my_nonce + peer_nonce
        else:
            salt = peer_pk_bytes + my_pk + peer_nonce + my_nonce

        def _derive(info: bytes) -> bytes:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=info,
            ).derive(shared)

        # Bumped info constants → v2 protocol; v1 peers can't decrypt v2 cells
        # (intentional — forces simultaneous upgrade, no silent fallback).
        key_c2s = _derive(b"murnet-obfs-v2-c2s")
        key_s2c = _derive(b"murnet-obfs-v2-s2c")

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
        # F10 fix: cap frame size to prevent memory-bomb DoS
        if ct_len > _MAX_FRAME + 17:   # +12 (nonce) +16 (tag) +pad +len_hdr
            raise ValueError(f"frame too large: {ct_len} > {_MAX_FRAME}")
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

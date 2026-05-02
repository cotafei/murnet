"""
MurNet Hidden Service — .murnet адреса поверх onion routing.

Адрес формируется из Ed25519 публичного ключа:
  Ed25519 pubkey → Blake2b-160 → Base58Check → "<addr>.murnet"

Пример: 3xK9mPqRsTuVwXyZ2aHL4Fk.murnet

Жизненный цикл:
  1. HiddenServiceIdentity — генерирует/загружает ключ, выдаёт .murnet адрес
  2. HiddenServiceAnnounce — периодически анонсирует сервис через gossip
  3. HiddenServiceRouter  — принимает входящие onion-соединения, форвардит на localhost:port
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from core.identity.crypto import base58_encode, blake2b_hash

logger = logging.getLogger("murnet.hidden_service")

_VERSION_BYTE = b"\x60"   # 0x60 → адреса начинаются с буквы "m" в Base58
_ANNOUNCE_EVERY = 30.0    # секунд между анонсами
_ANNOUNCE_TTL   = 4       # gossip-хопов


# ─────────────────────────────────────────────────────────────────────────────
# Адрес
# ─────────────────────────────────────────────────────────────────────────────

def pubkey_to_murnet_addr(public_bytes: bytes) -> str:
    """
    Ed25519 pubkey (32 bytes) → Base58Check .murnet адрес.

    Формат (аналогично Bitcoin P2PKH):
      versioned = VERSION_BYTE + blake2b_160(pubkey)
      checksum  = blake2b_256(blake2b_256(versioned))[:4]
      addr      = base58(versioned + checksum) + ".murnet"
    """
    hash160   = blake2b_hash(public_bytes, digest_size=20)
    versioned = _VERSION_BYTE + hash160
    checksum  = blake2b_hash(blake2b_hash(versioned), digest_size=4)
    return base58_encode(versioned + checksum) + ".murnet"


def addr_to_raw(addr: str) -> str:
    """Убирает суффикс .murnet если есть."""
    return addr.removesuffix(".murnet")


# ─────────────────────────────────────────────────────────────────────────────
# Идентичность сервиса
# ─────────────────────────────────────────────────────────────────────────────

class HiddenServiceIdentity:
    """
    Keypair + .murnet адрес для одного скрытого сервиса.

    Параметры
    ----------
    key_file : str | Path, optional
        Путь к PEM-файлу с приватным ключом.
        Если файл не существует — генерируется новый ключ и сохраняется.
    """

    def __init__(self, key_file: Optional[str | Path] = None) -> None:
        if key_file and Path(key_file).exists():
            self._private = self._load(key_file)
        else:
            self._private = ed25519.Ed25519PrivateKey.generate()
            if key_file:
                self._save(key_file)

        pub_bytes   = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_bytes = pub_bytes
        self.address      = pubkey_to_murnet_addr(pub_bytes)

    # ── ключи ────────────────────────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    @staticmethod
    def verify(public_bytes: bytes, data: bytes, signature: bytes) -> bool:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            pub.verify(signature, data)
            return True
        except Exception:
            return False

    # ── сериализация ─────────────────────────────────────────────────────────

    def _save(self, path: str | Path) -> None:
        pem = self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        Path(path).write_bytes(pem)
        os.chmod(path, 0o600)

    @staticmethod
    def _load(path: str | Path) -> ed25519.Ed25519PrivateKey:
        pem = Path(path).read_bytes()
        return serialization.load_pem_private_key(pem, password=None)

    def __repr__(self) -> str:
        return f"HiddenServiceIdentity({self.address})"


# ─────────────────────────────────────────────────────────────────────────────
# Анонс через gossip
# ─────────────────────────────────────────────────────────────────────────────

class HiddenServiceAnnounce:
    """
    Периодически рассылает анонс сервиса через OnionTransport gossip.

    Анонс-пакет (поверх обычного gossip-поля):
      {
        "src": "<relay_addr>",
        "hs_announce": {
          "addr":      "<base58>.murnet",
          "pubkey":    "<hex>",
          "relay":     "<host:port>",   # entry-relay к сервису
          "timestamp": <float>,
          "sig":       "<hex>"          # Ed25519(addr+relay+timestamp)
        },
        "ttl": N
      }
    """

    def __init__(
        self,
        identity: HiddenServiceIdentity,
        transport,
        relay: str,
    ) -> None:
        self._id       = identity
        self._transport = transport
        self._relay     = relay
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def broadcast_now(self) -> None:
        await self._broadcast()

    async def _loop(self) -> None:
        while True:
            await self._broadcast()
            await asyncio.sleep(_ANNOUNCE_EVERY)

    async def _broadcast(self) -> None:
        ts      = time.time()
        payload = f"{self._id.address}|{self._relay}|{ts:.3f}".encode()
        sig     = self._id.sign(payload)

        packet = {
            "src": self._relay,
            "hs_announce": {
                "addr":      self._id.address,
                "pubkey":    self._id.public_bytes.hex(),
                "relay":     self._relay,
                "timestamp": ts,
                "sig":       sig.hex(),
            },
            "ttl": _ANNOUNCE_TTL,
        }

        await self._transport._broadcast_raw(packet)
        logger.debug("[hs] анонс отправлен: %s", self._id.address)


# ─────────────────────────────────────────────────────────────────────────────
# Директория скрытых сервисов
# ─────────────────────────────────────────────────────────────────────────────

class HiddenServiceDirectory:
    """
    Хранит известные .murnet сервисы полученные через gossip.

    Запись:
      addr → {"pubkey": hex, "relay": "host:port", "timestamp": float}
    """

    def __init__(self) -> None:
        self._entries: dict[str, dict] = {}

    def handle_announce(self, packet: dict) -> bool:
        """
        Верифицирует и сохраняет анонс.
        Возвращает True если запись новая/обновлённая.
        """
        hs = packet.get("hs_announce", {})
        addr      = hs.get("addr", "")
        pubkey_hex = hs.get("pubkey", "")
        relay     = hs.get("relay", "")
        ts        = float(hs.get("timestamp", 0))
        sig_hex   = hs.get("sig", "")

        if not all([addr, pubkey_hex, relay, sig_hex]):
            return False

        # Проверяем что адрес соответствует публичному ключу
        try:
            pub_bytes = bytes.fromhex(pubkey_hex)
            expected  = pubkey_to_murnet_addr(pub_bytes)
            if expected != addr:
                logger.warning("[hs] addr/pubkey mismatch: %s", addr)
                return False
        except Exception:
            return False

        # Проверяем подпись
        try:
            payload = f"{addr}|{relay}|{ts:.3f}".encode()
            sig     = bytes.fromhex(sig_hex)
            if not HiddenServiceIdentity.verify(pub_bytes, payload, sig):
                logger.warning("[hs] bad signature: %s", addr)
                return False
        except Exception:
            return False

        # Принимаем только свежие (не старше 10 минут)
        if time.time() - ts > 600:
            return False

        existing = self._entries.get(addr)
        if existing and existing["timestamp"] >= ts:
            return False

        self._entries[addr.lower()] = {"pubkey": pubkey_hex, "relay": relay, "timestamp": ts}
        logger.info("[hs] сервис обновлён: %s → %s", addr, relay)
        return True

    def resolve(self, addr: str) -> Optional[str]:
        """Возвращает relay-адрес для .murnet адреса или None."""
        entry = self._entries.get(addr.lower())
        if not entry:
            return None
        if time.time() - entry["timestamp"] > 600:
            self._entries.pop(addr.lower(), None)
            return None
        return entry["relay"]

    def list_all(self) -> list[dict]:
        now = time.time()
        return [
            {"addr": a, **v}
            for a, v in self._entries.items()
            if now - v["timestamp"] <= 600
        ]

    def __len__(self) -> int:
        return len(self.list_all())

"""
MurNet v6.2 — Encrypted Keystore

Хранит приватный ключ узла зашифрованным паролем.
Использует Argon2id для деривации ключа шифрования и AES-256-GCM для защиты данных.

Принцип: нет пароля — нет доступа к узлу.  Восстановление не предусмотрено.

Формат файла (JSON, права 0o600)::

    {
        "version": 2,
        "salt":       "<base64, 32 байта>",
        "nonce":      "<base64, 12 байт>",
        "ciphertext": "<base64, зашифрованный private key>"
    }

Параметры Argon2id (консервативные, но не парализующие UI):
    time_cost=3, memory_cost=65536 (64 MB), parallelism=4
    — примерно 1–3 секунды на современном CPU.
"""

from __future__ import annotations

import base64
import json
import os
import random
import time
from typing import Optional

# Внутренние зависимости
from core.identity.crypto import secure_random_bytes, derive_key_argon2

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


_VERSION = 2
_SALT_SIZE = 32        # байт
_NONCE_SIZE = 12       # байт (AES-GCM standard)
_MIN_PASSWORD_LEN = 8  # минимальная длина пароля
_WRONG_PWD_DELAY = 0.5 # базовая задержка при неверном пароле (сек) + random jitter


class KeystoreError(Exception):
    """Базовое исключение хранилища."""


class WrongPasswordError(KeystoreError):
    """Неверный пароль — расшифровка не удалась."""
    def __str__(self) -> str:
        return "Неверный пароль. Доступ к узлу невозможен."


class KeystoreNotFoundError(KeystoreError):
    """Файл хранилища не существует."""


class WeakPasswordError(KeystoreError):
    """Пароль слишком короткий."""
    def __str__(self) -> str:
        return f"Пароль должен содержать не менее {_MIN_PASSWORD_LEN} символов."


# ---------------------------------------------------------------------------


class EncryptedKeystore:
    """
    Шифрованное хранилище приватного ключа узла.

    Использование
    -------------
    Первый запуск (создание)::

        ks = EncryptedKeystore("./data")
        ks.create(identity.to_bytes(), password="мой_пароль_123")

    Последующие запуски (разблокировка)::

        ks = EncryptedKeystore("./data")
        key_bytes = ks.load("мой_пароль_123")   # WrongPasswordError если неверный

    Проверка существования::

        if ks.exists():
            # первый запуск
    """

    def __init__(self, data_dir: str) -> None:
        if not _HAS_CRYPTO:
            raise KeystoreError("cryptography library required: pip install cryptography")
        self._path = os.path.join(data_dir, "identity.key.enc")
        self._data_dir = data_dir

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        """Возвращает True, если зашифрованный файл уже существует."""
        return os.path.isfile(self._path)

    def create(self, key_bytes: bytes, password: str) -> None:
        """
        Зашифровать и сохранить ключевые байты.

        Raises
        ------
        WeakPasswordError
            Если пароль короче _MIN_PASSWORD_LEN символов.
        """
        if len(password) < _MIN_PASSWORD_LEN:
            raise WeakPasswordError()

        salt = secure_random_bytes(_SALT_SIZE)
        nonce = secure_random_bytes(_NONCE_SIZE)

        enc_key, _ = derive_key_argon2(password.encode("utf-8"), salt)
        aesgcm = AESGCM(enc_key)
        ciphertext = aesgcm.encrypt(nonce, key_bytes, None)

        payload = {
            "version":    _VERSION,
            "salt":       base64.b64encode(salt).decode(),
            "nonce":      base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

        os.makedirs(self._data_dir, exist_ok=True)
        # Записываем с ограничением прав (только владелец)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(payload).encode())
        finally:
            os.close(fd)

    def load(self, password: str) -> bytes:
        """
        Расшифровать и вернуть ключевые байты.

        Raises
        ------
        KeystoreNotFoundError
            Файл не найден.
        WrongPasswordError
            Пароль неверный (AES-GCM authentication tag не совпал).
            Перед исключением добавляется случайная задержка (_WRONG_PWD_DELAY +
            jitter до 0.3 сек), чтобы затруднить локальный перебор пароля.
        """
        if not self.exists():
            raise KeystoreNotFoundError(f"Keystore not found: {self._path}")

        try:
            with open(self._path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise KeystoreError(f"Cannot read keystore: {exc}") from exc

        # Version migration (future-proofing)
        version = payload.get("version", 1)
        if version == 1:
            payload = self._migrate_v1_to_v2(payload)
        elif version != _VERSION:
            raise KeystoreError(f"Unsupported keystore version: {version}")

        try:
            salt = base64.b64decode(payload["salt"])
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
        except (KeyError, Exception) as exc:
            raise KeystoreError(f"Corrupted keystore: {exc}") from exc

        # Derive key into a bytearray for explicit zeroing after use
        enc_key_bytes, _ = derive_key_argon2(password.encode("utf-8"), salt)
        enc_key = bytearray(enc_key_bytes)
        del enc_key_bytes

        aesgcm = AESGCM(bytes(enc_key))
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except (InvalidTag, Exception):
            # Constant-time delay to resist local brute-force timing attacks
            time.sleep(_WRONG_PWD_DELAY + random.uniform(0.0, 0.3))
            raise WrongPasswordError()
        finally:
            # Zero out derived key material from memory (best-effort on CPython)
            for i in range(len(enc_key)):
                enc_key[i] = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _migrate_v1_to_v2(payload: dict) -> dict:
        """
        Migrate a version-1 keystore payload to version-2 format in memory.

        Version 1 was an experimental layout that stored the nonce concatenated
        inside the ciphertext field instead of as a separate key.  This method
        splits them apart and returns a v2-compatible dict.

        The migrated payload is NOT written back to disk here — the caller
        should re-create the file with change_password() to fully upgrade.
        """
        try:
            raw = base64.b64decode(payload["ciphertext"])
            # v1 format: first 12 bytes = nonce, rest = ciphertext+tag
            nonce = raw[:12]
            ciphertext = raw[12:]
            return {
                "version":    2,
                "salt":       payload["salt"],
                "nonce":      base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
        except Exception as exc:
            raise KeystoreError(f"Cannot migrate v1 keystore: {exc}") from exc

    def change_password(self, old_password: str, new_password: str) -> None:
        """
        Изменить пароль: расшифровать старым, зашифровать новым.

        Raises
        ------
        WrongPasswordError   — если старый пароль неверный
        WeakPasswordError    — если новый пароль слишком короткий
        """
        key_bytes = self.load(old_password)  # raises WrongPasswordError if wrong
        # Удаляем старый файл, записываем новый (create() создаст его заново)
        os.remove(self._path)
        self.create(key_bytes, new_password)

    def wipe(self) -> None:
        """
        Удалить зашифрованный файл ключа (best-effort overwrite + unlink).

        Ограничения
        -----------
        На SSD/NVMe и файловых системах с журналированием (ext4, APFS, NTFS)
        физическое уничтожение данных НЕ гарантируется:
        - SSD wear-levelling может хранить старые блоки в ячейках, недоступных
          через ФС, до следующего цикла сборки мусора.
        - Журналы ФС могут содержать копии данных из write-ahead log.
        - Copy-on-write ФС (btrfs, ZFS) хранят снапшоты.

        Для физического уничтожения используйте полное шифрование диска (LUKS,
        BitLocker, FileVault) или аппаратный сброс хранилища.
        """
        if self.exists():
            # Перезаписываем случайными байтами перед удалением (best-effort)
            size = os.path.getsize(self._path)
            try:
                with open(self._path, "wb") as fh:
                    fh.write(secure_random_bytes(max(size, 64)))
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
            os.remove(self._path)


# ---------------------------------------------------------------------------
# Утилита для CLI / Desktop
# ---------------------------------------------------------------------------

def prompt_password_cli(data_dir: str) -> str:
    """
    Интерактивный промпт пароля для CLI.

    - Если keystore ещё не существует: запрашивает пароль дважды (создание).
    - Если существует: запрашивает один раз (разблокировка).

    Возвращает введённый пароль.
    Завершает процесс при отмене (Ctrl-C / EOF).
    """
    import getpass
    import sys

    ks = EncryptedKeystore(data_dir)

    if not ks.exists():
        print("=" * 55)
        print("  Murnet — Первый запуск. Создайте пароль для узла.")
        print("  БЕЗ ЭТОГО ПАРОЛЯ ДОСТУП К УЗЛУ БУДЕТ НЕВОЗМОЖЕН.")
        print("=" * 55)
        while True:
            try:
                pw1 = getpass.getpass("  Новый пароль (мин. 8 символов): ")
                pw2 = getpass.getpass("  Подтвердите пароль:              ")
            except (KeyboardInterrupt, EOFError):
                print("\nОтменено.")
                sys.exit(0)
            if pw1 != pw2:
                print("  [!] Пароли не совпадают. Попробуйте снова.\n")
                continue
            if len(pw1) < _MIN_PASSWORD_LEN:
                print(f"  [!] Слишком короткий. Минимум {_MIN_PASSWORD_LEN} символов.\n")
                continue
            return pw1
    else:
        print("=" * 55)
        print("  Murnet — Введите пароль для разблокировки узла.")
        print("=" * 55)
        try:
            return getpass.getpass("  Пароль: ")
        except (KeyboardInterrupt, EOFError):
            print("\nОтменено.")
            sys.exit(0)

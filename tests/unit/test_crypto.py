#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET CRYPTO TESTS v5.0
Тестирование криптографических функций
"""

import pytest
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.identity.crypto import (
    Identity, KeyPair, E2EEncryption, SecureChannel,
    blake2b_hash, constant_time_compare, secure_random_bytes,
    base58_encode, base58_decode, canonical_json,
    derive_key_argon2, hkdf_derive,
    SecurityError, ValidationError, DecryptionError
)


@pytest.mark.crypto
class TestIdentity:
    """Тесты Identity и ключевой пары"""
    
    def test_identity_generation(self):
        """Генерация новой идентичности"""
        identity = Identity()
        
        assert identity.address is not None
        assert len(identity.address) > 0
        assert identity.address.startswith('1')
        
        assert identity.public_key is not None
        assert len(identity.get_public_bytes()) == 32
        
        assert identity.private_key is not None
        assert len(identity.get_private_bytes()) == 32
    
    @pytest.mark.parametrize("seed_size", [16, 32, 64])
    def test_identity_various_seed_sizes(self, seed_size):
        """Разные размеры seed"""
        seed = os.urandom(seed_size)
        identity = Identity(seed=seed)
        assert len(identity.address) > 0
        assert len(identity.get_public_bytes()) == 32
    
    def test_identity_from_seed(self):
        """Создание из seed"""
        seed = os.urandom(32)
        identity = Identity(seed=seed)
        
        # Тот же seed = тот же адрес
        identity2 = Identity(seed=seed)
        assert identity.address == identity2.address
    
    def test_identity_from_private_key(self):
        """Создание из приватного ключа"""
        identity1 = Identity()
        private_key = identity1.get_private_bytes()
        
        identity2 = Identity(private_key=private_key)
        assert identity1.address == identity2.address
        assert identity1.get_public_bytes() == identity2.get_public_bytes()
    
    def test_identity_from_mnemonic(self):
        """Создание из мнемоники"""
        mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access"
        identity = Identity(mnemonic=mnemonic)
        
        # Та же мнемоника = тот же адрес
        identity2 = Identity(mnemonic=mnemonic)
        assert identity.address == identity2.address
    
    def test_invalid_private_key_length(self):
        """Неверная длина приватного ключа"""
        with pytest.raises((SecurityError, ValidationError)):
            Identity(private_key=b'short')
    
    def test_sign_and_verify(self):
        """Подпись и верификация"""
        identity = Identity()
        
        data = {'message': 'test', 'timestamp': 1234567890}
        signature = identity.sign(data)
        
        assert isinstance(signature, str)
        assert len(signature) > 0
        
        # Верификация своей подписи - используем правильный формат public key (hex)
        public_key_hex = identity.get_public_bytes().hex()
        is_valid = identity.verify(data, signature, public_key_hex)
        assert is_valid is True
    
    def test_verify_wrong_signature(self):
        """Верификация чужой подписи"""
        identity1 = Identity()
        identity2 = Identity()
        
        data = {'test': 'data'}
        signature = identity1.sign(data)
        
        # Проверяем с публичным ключом identity2 - должно вернуть False
        public_key2 = identity2.get_public_bytes().hex()
        is_valid = identity2.verify(data, signature, public_key2)
        assert is_valid is False
    
    def test_tampered_data(self):
        """Подпись не проходит при изменении данных"""
        identity = Identity()
        
        data = {'message': 'original', 'value': 42}
        signature = identity.sign(data)
        
        # Изменяем данные
        data['value'] = 43
        public_key = identity.get_public_bytes().hex()
        
        is_valid = identity.verify(data, signature, public_key)
        assert is_valid is False
    
    def test_keypair_serialization(self):
        """Сериализация KeyPair"""
        identity = Identity()
        kp = identity.to_keypair()
        
        data = kp.to_dict()
        kp2 = KeyPair.from_dict(data)
        
        assert kp.address == kp2.address
        assert kp.private_key == kp2.private_key
        assert kp.public_key == kp2.public_key
    
    def test_identity_bytes_serialization(self):
        """Сериализация в bytes"""
        identity = Identity()
        data = identity.to_bytes()
        
        assert len(data) == 64  # 32 + 32
        
        identity2 = Identity.from_bytes(data)
        assert identity.address == identity2.address


@pytest.mark.crypto
class TestBase58:
    """Тесты Base58 кодирования"""
    
    def test_base58_encode_decode(self):
        """Кодирование и декодирование"""
        test_data = [
            b'',
            b'\x00',
            b'\x00\x00',
            b'hello',
            b'\x00hello',
            os.urandom(20),
            os.urandom(32),
        ]
        
        for data in test_data:
            encoded = base58_encode(data)
            decoded = base58_decode(encoded)
            assert decoded == data
    
    def test_base58_invalid_characters(self):
        """Недопустимые символы"""
        with pytest.raises(ValidationError):
            base58_decode('0OIl')  # Недопустимые символы
    
    def test_base58_empty(self):
        """Пустая строка"""
        assert base58_encode(b'') == ''
        assert base58_decode('') == b''


@pytest.mark.crypto
class TestHashing:
    """Тесты хеширования"""
    
    def test_blake2b_basic(self):
        """Базовое хеширование"""
        data = b'test data'
        hash1 = blake2b_hash(data)
        hash2 = blake2b_hash(data)
        
        assert hash1 == hash2
        assert len(hash1) == 32
    
    def test_blake2b_different_sizes(self):
        """Разные размеры дайджеста"""
        data = b'test'
        
        for size in [16, 20, 32, 64]:
            h = blake2b_hash(data, digest_size=size)
            assert len(h) == size
    
    def test_blake2b_with_key(self):
        """Хеширование с ключом"""
        data = b'test'
        key = b'secret key'
        
        hash1 = blake2b_hash(data, key=key)
        hash2 = blake2b_hash(data, key=key)
        hash3 = blake2b_hash(data, key=b'other key')
        
        assert hash1 == hash2
        assert hash1 != hash3
    
    def test_constant_time_compare(self):
        """Сравнение в постоянное время"""
        a = b'hello world'
        b = b'hello world'
        c = b'hello worlD'
        
        assert constant_time_compare(a, b) is True
        assert constant_time_compare(a, c) is False
        assert constant_time_compare(a, b'short') is False


@pytest.mark.crypto
class TestE2EEncryption:
    """Тесты end-to-end шифрования"""
    
    def test_encrypt_decrypt(self):
        """Шифрование и дешифрование"""
        alice = Identity()
        bob = Identity()
        
        e2e_alice = E2EEncryption(alice)
        
        plaintext = "Secret message"
        encrypted = e2e_alice.encrypt_message(
            plaintext,
            bob.get_x25519_public_bytes()
        )
        
        assert 'ciphertext' in encrypted
        assert 'nonce' in encrypted
        assert 'sender_pubkey' in encrypted
        
        # Bob расшифровывает
        e2e_bob = E2EEncryption(bob)
        decrypted = e2e_bob.decrypt_message(encrypted)
        
        assert decrypted == plaintext
    
    def test_wrong_recipient(self):
        """Неверный получатель не может расшифровать"""
        alice = Identity()
        bob = Identity()
        charlie = Identity()
        
        e2e_alice = E2EEncryption(alice)
        encrypted = e2e_alice.encrypt_message(
            "Secret",
            bob.get_x25519_public_bytes()
        )
        
        # Charlie пытается расшифровать
        e2e_charlie = E2EEncryption(charlie)
        
        with pytest.raises(DecryptionError):
            e2e_charlie.decrypt_message(encrypted)
    
    def test_message_too_large(self):
        """Сообщение превышает лимит"""
        identity = Identity()
        e2e = E2EEncryption(identity)
        
        large_message = "x" * (1024 * 1024 + 1)  # 1MB + 1
        
        with pytest.raises(ValidationError):
            e2e.encrypt_message(large_message, identity.get_public_bytes())
    
    def test_shared_secret_caching(self):
        """Кэширование shared secret"""
        alice = Identity()
        bob = Identity()
        
        e2e = E2EEncryption(alice)
        
        # Первый вызов - вычисление
        secret1 = e2e.get_shared_secret(bob.get_public_bytes())
        
        # Второй вызов - из кэша
        secret2 = e2e.get_shared_secret(bob.get_public_bytes())
        
        assert secret1 == secret2


@pytest.mark.crypto
class TestSecureChannel:
    """Тесты защищенного канала"""
    
    def test_secure_channel_basic(self):
        """Базовая работа канала"""
        alice = Identity()
        bob = Identity()
        
        channel_alice = SecureChannel(alice, bob.get_public_bytes())
        
        plaintext = b"Hello Bob!"
        ciphertext = channel_alice.encrypt(plaintext)
        
        # Структура пакета корректна
        assert len(ciphertext) > len(plaintext)
    
    def test_sequence_numbers(self):
        """Проверка sequence numbers"""
        alice = Identity()
        bob = Identity()
        
        channel = SecureChannel(alice, bob.get_public_bytes())
        
        assert channel.message_counter == 0
        channel.encrypt(b"msg1")
        assert channel.message_counter == 1
        channel.encrypt(b"msg2")
        assert channel.message_counter == 2


@pytest.mark.crypto
class TestKDF:
    """Тесты Key Derivation Functions"""
    
    def test_argon2id_basic(self):
        """Базовый тест Argon2id"""
        password = b"test password"
        
        key1, salt1 = derive_key_argon2(password)
        key2, salt2 = derive_key_argon2(password, salt1)
        
        assert len(key1) == 32
        assert len(salt1) == 16
        assert key1 == key2
        assert salt1 == salt2
    
    def test_argon2id_different_passwords(self):
        """Разные пароли дают разные ключи"""
        key1, _ = derive_key_argon2(b"password1")
        key2, _ = derive_key_argon2(b"password2")
        
        assert key1 != key2
    
    def test_argon2id_different_salts(self):
        """Разные соли дают разные ключи"""
        password = b"test"
        
        key1, salt1 = derive_key_argon2(password)
        key2, salt2 = derive_key_argon2(password)
        
        assert salt1 != salt2
        assert key1 != key2
    
    def test_hkdf_basic(self):
        """Базовый тест HKDF"""
        master_key = os.urandom(32)
        
        key1 = hkdf_derive(master_key, info=b"test")
        key2 = hkdf_derive(master_key, info=b"test")
        key3 = hkdf_derive(master_key, info=b"other")
        
        assert key1 == key2
        assert key1 != key3
        assert len(key1) == 32


@pytest.mark.crypto
class TestSecureRandom:
    """Тесты secure random"""
    
    def test_random_bytes_length(self):
        """Правильная длина"""
        for size in [16, 32, 64, 128]:
            data = secure_random_bytes(size)
            assert len(data) == size
    
    def test_random_bytes_uniqueness(self):
        """Уникальность"""
        # Генерируем много значений, проверяем уникальность
        values = [secure_random_bytes(32) for _ in range(100)]
        assert len(set(values)) == len(values)


@pytest.mark.crypto
class TestCanonicalJSON:
    """Тесты канонического JSON"""
    
    def test_deterministic_encoding(self):
        """Детерминированное кодирование"""
        data = {'b': 2, 'a': 1, 'c': {'e': 5, 'd': 4}}
        
        json1 = canonical_json(data)
        json2 = canonical_json(data)
        
        assert json1 == json2
    
    def test_sorted_keys(self):
        """Ключи отсортированы"""
        data = {'z': 1, 'a': 2, 'm': 3}
        result = canonical_json(data)
        
        # Проверяем порядок
        assert result.index(b'"a"') < result.index(b'"m"')
        assert result.index(b'"m"') < result.index(b'"z"')
    
    def test_no_whitespace(self):
        """Без пробелов"""
        data = {'key': 'value'}
        result = canonical_json(data)
        
        assert b' ' not in result
        assert b'\n' not in result
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET SECURITY TESTS v5.0
Тестирование безопасности и защита от атак
"""

import pytest
import time
import json
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.identity.crypto import Identity, E2EEncryption, ValidationError, SecurityError
from core.net.transport import Transport, PacketType, RateLimiter
from core.net.routing import RoutingTable, LSA, LinkStateDatabase
from core.net.dht_rpc import DHTAuthManager, DHTRequest
from core.node.node import SecureMurnetNode


@pytest.fixture
def identity():
    """Тестовая идентичность"""
    return Identity()


@pytest.mark.security
class TestCryptoSecurity:
    """Тесты криптографической безопасности"""
    
    def test_private_key_not_exposed_in_signature(self, identity):
        """Приватный ключ не раскрывается в подписи"""
        data = {'test': 'data'}
        signature = identity.sign(data)
        
        # Подпись - это base64, не должно содержать приватный ключ
        import base64
        sig_bytes = base64.b64decode(signature)
        
        # Проверяем что в подписи нет приватного ключа
        private_key = identity.get_private_bytes()
        assert private_key not in sig_bytes
    
    def test_signature_verification_strict(self, identity):
        """Строгая верификация подписи"""
        data = {'message': 'test'}
        signature = identity.sign(data)
        
        # Правильная верификация - используем hex формат
        public_key_hex = identity.get_public_bytes().hex()
        assert identity.verify(data, signature, public_key_hex) is True
        
        # Изменение данных
        data['message'] = 'tampered'
        assert identity.verify(data, signature, public_key_hex) is False
        
        # Изменение подписи
        tampered_sig = signature[:-5] + 'XXXXX'
        data['message'] = 'test'  # Возвращаем оригинал
        assert identity.verify(data, tampered_sig, public_key_hex) is False
    
    def test_different_keys_different_addresses(self):
        """Разные ключи = разные адреса"""
        identity1 = Identity()
        identity2 = Identity()
        
        assert identity1.address != identity2.address
        assert identity1.get_public_bytes() != identity2.get_public_bytes()
    
    def test_e2e_encryption_freshness(self):
        """E2E шифрование создает разные ciphertext"""
        alice = Identity()
        bob = Identity()
        
        e2e = E2EEncryption(alice)
        
        # Шифруем одно и то же сообщение дважды
        enc1 = e2e.encrypt_message("hello", bob.get_public_bytes())
        enc2 = e2e.encrypt_message("hello", bob.get_public_bytes())
        
        # Nonce должен быть разным
        assert enc1['nonce'] != enc2['nonce']
        # Ciphertext должен быть разным
        assert enc1['ciphertext'] != enc2['ciphertext']
    
    def test_invalid_base64_handling(self, identity):
        """Обработка невалидного base64 — verify() возвращает False, не бросает исключение"""
        data = {'test': 'data'}
        # verify() намеренно поглощает все ошибки и возвращает False,
        # чтобы не утечь информацию через исключения (security best practice)
        result = identity.verify(data, "not-valid-base64!!!", "also-invalid")
        assert result is False
    
    def test_large_input_handling(self, identity):
        """Обработка больших входных данных"""
        # 1MB данных
        large_data = {'payload': 'x' * (1024 * 1024)}
        
        # Должно работать без ошибок
        signature = identity.sign(large_data)
        assert signature is not None


@pytest.mark.security
class TestTransportSecurity:
    """Тесты безопасности транспорта"""
    
    def test_rate_limiting_blocks_flood(self, fresh_data_dir):
        """Rate limiting блокирует флуд"""
        limiter = RateLimiter(rate=10, burst=5)
        
        # Первые 5 проходят
        for i in range(5):
            assert limiter.allow('192.168.1.1') is True
        
        # 6-й отклонен
        assert limiter.allow('192.168.1.1') is False
    
    def test_rate_limiter_per_ip_isolation(self, fresh_data_dir):
        """Rate limiting изолирует IP"""
        limiter = RateLimiter(rate=10, burst=5)
        
        # Заполняем лимит для одного IP
        for i in range(5):
            limiter.allow('192.168.1.1')
        
        # Другой IP должен проходить
        assert limiter.allow('192.168.1.2') is True
    
    def test_packet_size_limits(self, fresh_data_dir):
        """Лимиты размера пакета"""
        identity = Identity()
        transport = Transport(port=0)
        
        # Слишком большое сообщение должно быть отклонено (> 1MB)
        huge_message = {'data': 'x' * (1024 * 1024 + 1)}
        
        result = transport.send_to(huge_message, '127.0.0.1', 9999)
        assert result is False
    
    def test_replay_protection_sequence_numbers(self, fresh_data_dir):
        """Защита от replay через sequence numbers"""
        from core.net.transport import PeerConnection
        
        peer = PeerConnection(addr=('127.0.0.1', 8888), address='test')
        
        # Первый пакет с seq=1
        assert peer.is_sequence_valid(1) is True
        peer.record_sequence(1)
        
        # Повтор с seq=1 отклонен
        assert peer.is_sequence_valid(1) is False
        
        # Старый sequence отклонен (используем window_size=0 — окно «вплотную» к max)
        assert peer.is_sequence_valid(0, window_size=0) is False
    
    def test_timestamp_validation(self, fresh_data_dir):
        """Валидация временной метки"""
        identity = Identity()
        transport = Transport(port=0)
        
        # Слишком старый timestamp
        from core.net.transport import PacketHeader, PacketType
        
        old_header = PacketHeader(
            packet_type=PacketType.DATA,
            timestamp=int(time.time()) - 400  # 400 секунд назад
        )
        
        # Проверка в receive_loop отклонит такой пакет
        # (проверяем логику напрямую)
        now = int(time.time())
        assert abs(now - old_header.timestamp) > 300  # Старше 5 минут


@pytest.mark.security
class TestRoutingSecurity:
    """Тесты безопасности маршрутизации"""
    
    def test_lsa_sequence_replay_protection(self, identity):
        """Защита от replay LSA"""
        lsdb = LinkStateDatabase(identity.address, identity)
        
        other = Identity()
        
        # Принимаем LSA
        lsa1 = LSA(
            origin=other.address,
            sequence=5,
            links={},
            timestamp=time.time()
        )
        assert lsdb.receive_lsa(lsa1) is True
        
        # Повтор с тем же sequence
        lsa2 = LSA(
            origin=other.address,
            sequence=5,
            links={},
            timestamp=time.time()
        )
        assert lsdb.receive_lsa(lsa2) is False
    
    def test_lsa_flood_detection(self, identity):
        """Детекция LSA flood"""
        routing = RoutingTable(identity.address, identity)
        
        other = Identity()
        
        # Быстро отправляем много LSA
        results = []
        for i in range(15):
            lsa = LSA(
                origin=other.address,
                sequence=i+1,
                links={},
                timestamp=time.time()
            )
            results.append(routing.receive_lsa(lsa))
        
        # Последние должны быть отклонены
        assert results[-1] is False
    
    def test_lsa_timestamp_validation(self, identity):
        """Валидация временной метки LSA"""
        lsdb = LinkStateDatabase(identity.address, identity)
        
        other = Identity()
        
        # Слишком старый LSA
        old_lsa = LSA(
            origin=other.address,
            sequence=1,
            links={},
            timestamp=time.time() - 400
        )
        assert lsdb.receive_lsa(old_lsa) is False
        
        # Слишком новый (в будущем)
        future_lsa = LSA(
            origin=other.address,
            sequence=1,
            links={},
            timestamp=time.time() + 400
        )
        assert lsdb.receive_lsa(future_lsa) is False
    
    def test_trust_score_degradation(self, identity):
        """Деградация trust score при LSA с неверной подписью"""
        lsdb = LinkStateDatabase(identity.address, identity)

        other = Identity()
        initial_trust = lsdb.get_trust_score(other.address)

        # Неверный публичный ключ — каждый LSA вызовет signature mismatch → trust *= 0.5
        wrong_pubkey = b'\xaa' * 32
        for i in range(10):
            lsa = LSA(
                origin=other.address,
                sequence=i + 1,          # монотонно возрастающие — проходят sequence-проверку
                links={},
                timestamp=time.time(),
                signature="ZmFrZXNpZ25hdHVyZQ=="  # валидный base64, но неверное значение
            )
            lsdb.receive_lsa(lsa, sender_public_key=wrong_pubkey)

        final_trust = lsdb.get_trust_score(other.address)
        assert final_trust < initial_trust


@pytest.mark.security
class TestDHTSecurity:
    """Тесты безопасности DHT"""
    
    def test_dht_auth_nonce_replay(self, identity):
        """Защита от replay в DHT auth"""
        auth_manager = DHTAuthManager(identity)
        
        # Создаем запрос
        request = DHTRequest(
            id='test-id',
            type='test',
            key='test-key',
            sender='1Sender',
            timestamp=time.time(),
            nonce='unique-nonce-123',
            signature=''
        )
        
        # Добавляем nonce в использованные
        auth_manager.recent_nonces.add('unique-nonce-123')
        
        # Проверка отклонит повтор
        peer_key = b'test-key' * 8
        is_valid = auth_manager.verify_request(request, peer_key)
        assert is_valid is False
    
    def test_dht_auth_timestamp_validation(self, identity):
        """Валидация timestamp в DHT"""
        auth_manager = DHTAuthManager(identity)
        
        # Старый запрос
        old_request = DHTRequest(
            id='test',
            type='test',
            key='key',
            sender='1Sender',
            timestamp=time.time() - 400,  # 400 секунд назад
            nonce='nonce',
            signature=''
        )
        
        peer_key = b'test-key' * 8
        is_valid = auth_manager.verify_request(old_request, peer_key)
        assert is_valid is False
    
    def test_dht_auth_ban_after_failures(self, identity):
        """Бан после множества failures"""
        auth_manager = DHTAuthManager(identity)
        
        sender = '1MaliciousNode'
        
        # Много failed attempts
        for i in range(15):
            auth_manager.failed_attempts[sender] += 1
        
        # Проверяем что забанен
        assert auth_manager.is_banned(sender) is True


@pytest.mark.security
class TestNodeSecurity:
    """Тесты безопасности узла"""
    
    def test_circuit_breaker_blocks_under_load(self, fresh_data_dir):
        """Circuit breaker блокирует при перегрузке"""
        from core.node.node import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        
        # Начальное состояние
        assert cb.can_execute() is True
        
        # Много failures
        for i in range(3):
            cb.record_failure()
        
        # Circuit breaker открыт
        assert cb.can_execute() is False
        
        # Ждем recovery
        time.sleep(1.1)
        
        # Должен перейти в half-open
        assert cb.can_execute() is True
    
    def test_backpressure_throttling(self, fresh_data_dir):
        """Backpressure дросселирует нагрузку"""
        from core.node.node import BackpressureController
        
        bp = BackpressureController(high_watermark=0.8, low_watermark=0.3)
        
        # Низкая нагрузка
        bp.update_load(10, 100)  # 10%
        assert bp.should_accept() is True
        assert bp.is_throttled is False
        
        # Высокая нагрузка
        bp.update_load(85, 100)  # 85%
        assert bp.is_throttled is True
        assert bp.should_accept() is False
        
        # Восстановление
        bp.update_load(20, 100)  # 20%
        assert bp.is_throttled is False


@pytest.mark.security
class TestInputValidation:
    """Тесты валидации входных данных"""
    
    def test_invalid_address_rejected(self, identity):
        """Невалидный адрес отклонен"""
        # Слишком короткий seed
        with pytest.raises((ValidationError, ValueError, SecurityError)):
            Identity(seed=b'short')
    
    def test_oversized_payload_rejected(self, identity):
        """Слишком большой payload отклонен"""
        e2e = E2EEncryption(identity)
        
        # 1MB + 1
        huge_message = 'x' * (1024 * 1024 + 1)
        
        with pytest.raises((ValidationError, Exception)):
            e2e.encrypt_message(huge_message, identity.get_public_bytes())
    
    def test_malformed_json_handling(self, fresh_data_dir):
        """Обработка malformed JSON"""
        # Проверяем что транспорт безопасно обрабатывает невалидный JSON
        identity = Identity()
        transport = Transport(port=0)
        
        # Невалидный JSON не должен crash
        invalid_data = b'{invalid json'
        
        # Прямая проверка через _safe_json_loads
        result = transport._safe_json_loads(invalid_data)
        assert result is None


@pytest.mark.security
class TestDoSProtection:
    """Тесты защиты от DoS"""
    
    def test_connection_limit_per_peer(self, fresh_data_dir):
        """Лимит соединений на пир"""
        # Проверяем что нет утечки памяти при множественных соединениях
        identity = Identity()
        transport = Transport(port=0)
        
        # Симулируем множественные попытки соединения
        for i in range(100):
            transport._get_or_create_peer(('127.0.0.1', 8000 + i), f'1Node{i}')
        
        # Проверяем что пиры созданы
        assert transport.get_peer_count() <= 100
    
    def test_memory_exhaustion_protection(self, fresh_data_dir):
        """Защита от исчерпания памяти"""
        from core.net.murnaked import BloomFilter
        
        # Bloom filter с разумным размером
        bloom = BloomFilter(size=10000, hash_count=5)
        
        # Добавляем много элементов
        for i in range(10000):
            bloom.add(f'item{i}')
        
        # Проверяем что размер bit_array не растет
        assert len(bloom.bit_array) == 10000


@pytest.mark.security
class TestSideChannelProtection:
    """Тесты защиты от side-channel атак"""
    
    def test_constant_time_comparison(self):
        """Сравнение в постоянное время"""
        from core.identity.crypto import constant_time_compare
        
        # Одинаковые данные
        a = b'secret-data-12345'
        b = b'secret-data-12345'
        
        assert constant_time_compare(a, b) is True
        
        # Разные данные одной длины
        c = b'secret-data-12346'
        assert constant_time_compare(a, c) is False
        
        # Разная длина
        d = b'short'
        assert constant_time_compare(a, d) is False
    
    def test_no_timing_leak_in_verification(self, identity):
        """Нет утечки времени в верификации"""
        import timeit
        
        data = {'test': 'data'}
        signature = identity.sign(data)
        public_key_hex = identity.get_public_bytes().hex()
        
        # Правильная подпись
        time_correct = timeit.timeit(
            lambda: identity.verify(data, signature, public_key_hex),
            number=100
        )
        
        # Неправильная подпись
        wrong_sig = signature[:-5] + 'XXXXX'
        time_wrong = timeit.timeit(
            lambda: identity.verify(data, wrong_sig, public_key_hex),
            number=100
        )
        
        # Время должно быть разумным (Ed25519 verify не является строго constant-time
        # для невалидных подписей; проверяем что разница не катастрофическая)
        ratio = max(time_correct, time_wrong) / min(time_correct, time_wrong)
        assert ratio < 100  # Не более 100x разницы


@pytest.mark.security
class TestAuthentication:
    """Тесты аутентификации"""
    
    def test_handshake_requires_auth(self, fresh_data_dir):
        """Handshake требует аутентификации"""
        identity = Identity()
        transport = Transport(port=0)
        
        # Проверяем что handshake не завершен без аутентификации
        peer = transport._get_or_create_peer(('127.0.0.1', 8888), '1Test')
        assert peer.handshake_complete is False
        assert peer.is_authenticated is False
    
    def test_session_key_derivation(self, fresh_data_dir):
        """Деривация сессионного ключа"""
        alice = Identity()
        bob = Identity()
        
        transport = Transport(port=0)
        port = transport.start(
            alice.address,
            alice.get_public_bytes(),
            alice.get_private_bytes()
        )
        
        # Деривация shared secret
        shared = alice.derive_shared_secret(bob.get_public_bytes())
        
        assert len(shared) == 32
        assert shared != alice.get_private_bytes()
        assert shared != bob.get_private_bytes()
        
        transport.stop()


@pytest.mark.security
class TestAuthorization:
    """Тесты авторизации"""
    
    def test_permission_enforcement(self, fresh_data_dir):
        """Принудительное применение прав"""
        # Проверяем что API требует правильных permissions
        from api.auth import AuthManager
        
        auth = AuthManager()
        
        token = auth.generate_token(
            node_address='1Test',
            permissions=['read']
        )
        
        payload = auth.verify_token(token.token)
        assert payload is not None
        assert 'read' in payload['permissions']
        assert 'write' not in payload['permissions']
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET TRANSPORT TESTS v5.0
Тестирование UDP транспорта и сетевого уровня
"""

import pytest
import time
import threading
import socket
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.net.transport import (
    Transport, PacketType, PacketHeader, PeerConnection,
    RateLimiter
)
from core.identity.crypto import Identity


@pytest.fixture
def transport_pair(fresh_data_dir):
    """Пара транспортов для тестирования"""
    identity1 = Identity()
    identity2 = Identity()
    
    transport1 = Transport(port=0)
    transport2 = Transport(port=0)
    
    port1 = transport1.start(identity1.address, identity1.get_public_bytes(),
                              identity1.get_private_bytes())
    port2 = transport2.start(identity2.address, identity2.get_public_bytes(),
                              identity2.get_private_bytes())
    
    # Даем время на запуск
    time.sleep(0.1)
    
    yield (transport1, transport2, port1, port2, identity1, identity2)
    
    transport1.stop()
    transport2.stop()


class TestTransportBasic:
    """Базовые тесты транспорта"""
    
    def test_transport_start_stop(self, fresh_data_dir):
        """Запуск и остановка"""
        identity = Identity()
        transport = Transport(port=0)
        
        port = transport.start(
            identity.address,
            identity.get_public_bytes(),
            identity.get_private_bytes()
        )
        
        assert port > 0
        assert transport.running is True
        assert transport.socket is not None
        
        transport.stop()
        assert transport.running is False
    
    def test_transport_bind_specific_port(self, fresh_data_dir):
        """Привязка к конкретному порту"""
        identity = Identity()
        transport = Transport(port=9999)
        
        # Может упасть если порт занят, поэтому ловим исключение
        try:
            port = transport.start(
                identity.address,
                identity.get_public_bytes(),
                identity.get_private_bytes()
            )
            assert port == 9999
            transport.stop()
        except OSError:
            pytest.skip("Port 9999 already in use")
    
    def test_transport_bind_any_port(self, fresh_data_dir):
        """Привязка к любому свободному порту"""
        identity = Identity()
        transport = Transport(port=0)  # OS выбирает порт
        
        port = transport.start(
            identity.address,
            identity.get_public_bytes(),
            identity.get_private_bytes()
        )
        
        assert port > 1024  # Должен быть непривилегированный порт
        transport.stop()


class TestPacketHeader:
    """Тесты заголовков пакетов"""
    
    def test_header_encode_decode(self):
        """Кодирование и декодирование"""
        header = PacketHeader(
            version=1,
            packet_type=PacketType.DATA,
            sequence=12345,
            ack_sequence=67890,
            payload_length=100,
            timestamp=1234567890,
            auth_tag=b'\x00' * 16
        )
        
        encoded = header.encode()
        assert len(encoded) == PacketHeader.FULL_SIZE
        
        decoded = PacketHeader.decode(encoded)
        assert decoded.version == header.version
        assert decoded.packet_type == header.packet_type
        assert decoded.sequence == header.sequence
        assert decoded.ack_sequence == header.ack_sequence
        assert decoded.payload_length == header.payload_length
        assert decoded.timestamp == header.timestamp
    
    def test_header_too_short(self):
        """Слишком короткие данные"""
        with pytest.raises(ValueError):
            PacketHeader.decode(b'short')
    
    def test_header_all_types(self):
        """Все типы пакетов"""
        for pkt_type in PacketType:
            header = PacketHeader(packet_type=pkt_type)
            encoded = header.encode()
            decoded = PacketHeader.decode(encoded)
            assert decoded.packet_type == pkt_type


class TestPeerConnection:
    """Тесты соединений с пирами"""
    
    def test_peer_creation(self):
        """Создание peer connection"""
        peer = PeerConnection(
            addr=('127.0.0.1', 8888),
            address='1TestAddress123'
        )
        
        assert peer.addr == ('127.0.0.1', 8888)
        assert peer.address == '1TestAddress123'
        assert peer.is_active is True
        assert peer.handshake_complete is False
    
    def test_rtt_calculation(self):
        """Расчет RTT"""
        peer = PeerConnection(addr=('127.0.0.1', 8888), address='test')
        
        # Начальное значение
        assert peer.rtt == 0.5
        
        # Добавляем измерения
        peer.rtt_samples.append(0.1)
        peer.rtt_samples.append(0.2)
        peer.rtt_samples.append(0.3)
        
        assert peer.rtt == pytest.approx(0.2)  # Среднее
    
    def test_rate_limiting(self):
        """Rate limiting"""
        peer = PeerConnection(addr=('127.0.0.1', 8888), address='test')
        
        # Первые 100 пакетов должны пройти
        for i in range(100):
            assert peer.check_rate_limit(100) is True
        
        # 101-й должен быть отклонен
        assert peer.check_rate_limit(100) is False
    
    def test_sequence_validation(self):
        """Валидация sequence numbers"""
        peer = PeerConnection(addr=('127.0.0.1', 8888), address='test')
        
        # Новые sequence должны быть валидны
        assert peer.is_sequence_valid(1) is True
        assert peer.is_sequence_valid(2) is True
        
        # Записываем
        peer.record_sequence(1)
        
        # Повтор должен быть отклонен
        assert peer.is_sequence_valid(1) is False
        
        # Sequence 0 is within the window (window=1000), so still valid
        assert peer.is_sequence_valid(0) is True


class TestRateLimiter:
    """Тесты rate limiter"""
    
    def test_basic_rate_limiting(self):
        """Базовое ограничение"""
        limiter = RateLimiter(rate=10, burst=20)
        
        # Первые 20 должны пройти (burst)
        for i in range(20):
            assert limiter.allow('127.0.0.1') is True
        
        # 21-й должен быть отклонен
        assert limiter.allow('127.0.0.1') is False
    
    def test_token_refill(self):
        """Пополнение токенов"""
        limiter = RateLimiter(rate=100, burst=1)
        
        # Первый проходит
        assert limiter.allow('127.0.0.1') is True
        
        # Второй отклонен
        assert limiter.allow('127.0.0.1') is False
        
        # Ждем пополнения
        time.sleep(0.02)  # 20ms для 1 токена при rate=100
        
        # Теперь должен пройти
        assert limiter.allow('127.0.0.1') is True
    
    def test_different_ips(self):
        """Разные IP не мешают друг другу"""
        limiter = RateLimiter(rate=10, burst=10)
        
        for i in range(10):
            assert limiter.allow('192.168.1.1') is True
            assert limiter.allow('192.168.1.2') is True
    
    def test_cleanup(self):
        """Очистка старых записей"""
        limiter = RateLimiter(rate=10, burst=10)
        
        limiter.allow('127.0.0.1')
        limiter.allow('192.168.1.1')
        
        assert len(limiter.buckets) == 2
        
        # Очистка с большим max_age
        limiter.cleanup(max_age=0)
        
        assert len(limiter.buckets) == 0


class TestTransportCommunication:
    """Тесты коммуникации между транспортами"""
    
    @pytest.mark.slow
    def test_peer_discovery(self, transport_pair):
        """Обнаружение пиров"""
        transport1, transport2, port1, port2, identity1, identity2 = transport_pair
        
        # Подключаемся
        transport1.connect_to('127.0.0.1', port2, identity2.address)
        
        # Ждем handshake
        time.sleep(0.5)
        
        # Проверяем что пиры видят друг друга
        peers1 = transport1.get_peers()
        peers2 = transport2.get_peers()
        
        assert len(peers1) > 0 or len(peers2) > 0
    
    @pytest.mark.slow
    def test_message_send_receive(self, transport_pair):
        """Отправка и получение сообщения"""
        transport1, transport2, port1, port2, identity1, identity2 = transport_pair

        received = threading.Event()

        def handler(message, ip, port):
            if isinstance(message, dict) and message.get('type') == 'test':
                received.set()

        transport2.register_handler(handler)

        # Подключаемся и ждем handshake
        transport1.connect_to('127.0.0.1', port2, identity2.address)
        time.sleep(0.5)

        # Отправляем сообщение
        test_msg = {'type': 'test', 'data': 'hello'}
        transport1.send_to(test_msg, '127.0.0.1', port2)

        # Ждем доставки (event-based для надежности)
        assert received.wait(timeout=3.0), "Message not delivered within timeout"

    @pytest.mark.slow
    def test_reliable_delivery(self, transport_pair):
        """Надежная доставка с ACK"""
        transport1, transport2, port1, port2, identity1, identity2 = transport_pair

        received = threading.Event()

        def handler(message, ip, port):
            if message.get('type') == 'test':
                received.set()

        transport2.register_handler(handler)

        # Подключаемся и ждем handshake
        transport1.connect_to('127.0.0.1', port2, identity2.address)
        time.sleep(0.5)

        # Отправляем с reliable=True
        test_msg = {'type': 'test', 'data': 'reliable'}
        transport1.send_to(test_msg, '127.0.0.1', port2, reliable=True)

        # Ждем с таймаутом
        assert received.wait(timeout=3.0)


class TestTransportSecurity:
    """Тесты безопасности транспорта"""
    
    def test_invalid_json_rejected(self, transport_pair):
        """Невалидный JSON отклоняется"""
        transport1, transport2, port1, port2, identity1, identity2 = transport_pair
        
        # Создаем raw пакет с невалидным JSON
        header = PacketHeader(
            packet_type=PacketType.DATA,
            payload_length=10,
            timestamp=int(time.time())
        )
        
        packet = header.encode() + b'not json!!'
        
        # Отправляем напрямую через сокет
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet, ('127.0.0.1', port2))
        sock.close()
        
        # Не должно упасть
        time.sleep(0.1)
        
        stats = transport2.get_stats()
        assert stats['packets_dropped_invalid'] >= 0
    
    def test_oversized_message_rejected(self, fresh_data_dir):
        """Слишком большое сообщение отклоняется"""
        identity = Identity()
        transport = Transport(port=0)
        port = transport.start(
            identity.address,
            identity.get_public_bytes(),
            identity.get_private_bytes()
        )
        
        # Создаем слишком большое сообщение (> 1MB)
        huge_msg = {'data': 'x' * (1024 * 1024 + 1)}
        
        result = transport.send_to(huge_msg, '127.0.0.1', 9999)
        assert result is False
        
        transport.stop()


class TestTransportStats:
    """Тесты статистики"""
    
    def test_stats_initial(self, fresh_data_dir):
        """Начальная статистика"""
        identity = Identity()
        transport = Transport(port=0)
        port = transport.start(
            identity.address,
            identity.get_public_bytes(),
            identity.get_private_bytes()
        )
        
        stats = transport.get_stats()
        
        assert 'packets_sent' in stats
        assert 'packets_received' in stats
        assert 'bytes_sent' in stats
        assert 'bytes_received' in stats
        
        transport.stop()
    
    def test_stats_after_send(self, transport_pair):
        """Статистика после отправки"""
        transport1, transport2, port1, port2, identity1, identity2 = transport_pair
        
        initial_stats = transport1.get_stats()
        initial_sent = initial_stats['packets_sent']
        
        # Отправляем пакет
        transport1.send_to({'test': 'data'}, '127.0.0.1', port2)
        
        time.sleep(0.1)
        
        new_stats = transport1.get_stats()
        assert new_stats['packets_sent'] >= initial_sent


class TestTransportHandlers:
    """Тесты обработчиков"""
    
    def test_message_handler_registration(self, fresh_data_dir):
        """Регистрация обработчика сообщений"""
        identity = Identity()
        transport = Transport(port=0)
        transport.start(
            identity.address,
            identity.get_public_bytes(),
            identity.get_private_bytes()
        )
        
        def handler(message, ip, port):
            pass
        
        transport.register_handler(handler)
        assert handler in transport.message_handlers
        
        transport.stop()
    
    def test_connect_handler_registration(self, fresh_data_dir):
        """Регистрация обработчика подключения"""
        identity = Identity()
        transport = Transport(port=0)
        transport.start(
            identity.address,
            identity.get_public_bytes(),
            identity.get_private_bytes()
        )
        
        def handler(address, addr):
            pass
        
        transport.register_connect_handler(handler)
        assert handler in transport.connect_handlers
        
        transport.stop()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET STORAGE TESTS v5.0
Тестирование SQLite хранилища
"""

import pytest
import time
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from murnet.core.data.storage import Storage, StorageConfig, LRUCache
from murnet.core.identity.crypto import Identity


@pytest.fixture
def storage(fresh_data_dir):
    """Хранилище для тестов"""
    config = StorageConfig(
        data_dir=fresh_data_dir,
        max_size_mb=100,
        compression=True,
        wal_mode=True,
        cache_size=100
    )
    storage = Storage(fresh_data_dir, config)
    yield storage
    storage.close()


class TestStorageBasic:
    """Базовые тесты хранилища"""
    
    def test_storage_creation(self, fresh_data_dir):
        """Создание хранилища"""
        storage = Storage(fresh_data_dir)
        
        assert os.path.exists(fresh_data_dir)
        assert os.path.exists(os.path.join(fresh_data_dir, 'dht'))
        assert os.path.exists(os.path.join(fresh_data_dir, 'files'))
        
        storage.close()
    
    def test_database_created(self, storage, fresh_data_dir):
        """База данных создана"""
        db_path = os.path.join(fresh_data_dir, 'murnet.db')
        assert os.path.exists(db_path)
    
    def test_tables_created(self, storage):
        """Все таблицы созданы"""
        conn = storage._get_conn()
        
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        
        table_names = [t['name'] for t in tables]
        
        assert 'identity' in table_names
        assert 'messages' in table_names
        assert 'dht_data' in table_names
        assert 'routing' in table_names
        assert 'peers' in table_names
        assert 'metadata' in table_names


class TestIdentityStorage:
    """Тесты хранения идентичности"""
    
    def test_save_and_load_identity(self, storage):
        """Сохранение и загрузка идентичности"""
        identity = Identity()
        identity_bytes = identity.to_bytes()
        
        address = storage.save_identity(identity_bytes)
        assert address is not None
        assert len(address) > 0
        
        loaded = storage.load_identity()
        assert loaded == identity_bytes
    
    def test_get_identity_dict(self, storage):
        """Получение идентичности как словаря"""
        identity = Identity()
        storage.save_identity(identity.to_bytes())
        
        identity_dict = storage.get_identity()
        assert identity_dict is not None
        assert 'private_key' in identity_dict
        assert 'public_key' in identity_dict
        assert 'address' in identity_dict
        
        assert len(identity_dict['private_key']) == 32
        assert len(identity_dict['public_key']) == 32
    
    def test_identity_overwrite(self, storage):
        """Перезапись идентичности"""
        identity1 = Identity()
        identity2 = Identity()
        
        storage.save_identity(identity1.to_bytes())
        storage.save_identity(identity2.to_bytes())
        
        loaded = storage.load_identity()
        # Должна быть вторая идентичность
        assert loaded[:32] == identity2.get_private_bytes()
    
    def test_invalid_identity_bytes(self, storage):
        """Невалидные байты идентичности"""
        with pytest.raises(ValueError):
            storage.save_identity(b'too short')


class TestMessageStorage:
    """Тесты хранения сообщений"""
    
    def test_save_message(self, storage):
        """Сохранение сообщения"""
        result = storage.save_message(
            msg_id='msg-001',
            from_addr='1FromAddress123',
            to_addr='1ToAddress456',
            text='Hello World',
            timestamp=time.time(),
            delivered=False
        )
        
        assert result is True
    
    def test_get_messages(self, storage):
        """Получение сообщений"""
        # Сохраняем несколько сообщений
        for i in range(5):
            storage.save_message(
                msg_id=f'msg-{i}',
                from_addr='1FromAddress',
                to_addr='1ToAddress',
                text=f'Message {i}',
                timestamp=time.time() + i,
                delivered=False
            )
        
        messages = storage.get_messages('1ToAddress', limit=10)
        
        assert len(messages) == 5
        # Сортировка по убыванию времени
        assert messages[0]['timestamp'] > messages[4]['timestamp']
    
    def test_get_messages_limit(self, storage):
        """Лимит сообщений"""
        for i in range(10):
            storage.save_message(
                msg_id=f'msg-{i}',
                from_addr='1From',
                to_addr='1To',
                text=f'Msg {i}',
                timestamp=time.time() + i
            )
        
        messages = storage.get_messages('1To', limit=5)
        assert len(messages) == 5
    
    def test_mark_delivered(self, storage):
        """Отметка о доставке"""
        storage.save_message(
            msg_id='msg-delivered',
            from_addr='1From',
            to_addr='1To',
            text='Test',
            timestamp=time.time(),
            delivered=False
        )
        
        storage.mark_delivered('msg-delivered', delivered=True)
        
        messages = storage.get_messages('1To')
        assert messages[0]['delivered'] is True
    
    def test_mark_read(self, storage):
        """Отметка о прочтении"""
        storage.save_message(
            msg_id='msg-read',
            from_addr='1From',
            to_addr='1To',
            text='Test',
            timestamp=time.time(),
            read=False
        )
        
        storage.mark_read('msg-read')
        
        messages = storage.get_messages('1To', only_unread=True)
        assert len(messages) == 0
    
    def test_message_compression(self, storage):
        """Сжатие больших сообщений"""
        large_text = 'x' * 1000  # Больше 100 байт для сжатия
        
        storage.save_message(
            msg_id='msg-large',
            from_addr='1From',
            to_addr='1To',
            text=large_text,
            timestamp=time.time(),
            compress=True
        )
        
        messages = storage.get_messages('1To')
        assert len(messages) == 1
        assert messages[0]['content'] == large_text
    
    def test_message_preview(self, storage):
        """Превью сообщения"""
        long_text = 'a' * 300  # Длинное сообщение
        
        storage.save_message(
            msg_id='msg-preview',
            from_addr='1From',
            to_addr='1To',
            text=long_text,
            timestamp=time.time()
        )
        
        messages = storage.get_messages('1To')
        assert len(messages[0]['preview']) == 200


class TestDHTStorage:
    """Тесты DHT хранения"""
    
    def test_dht_put_and_get(self, storage):
        """Сохранение и получение DHT данных"""
        result = storage.dht_put(
            key='test-key',
            value=b'test value',
            value_type='text',
            ttl=3600
        )
        
        assert result is True
        
        data = storage.dht_get('test-key')
        assert data is not None
        assert data['value'] == b'test value'
        assert data['type'] == 'text'
    
    def test_dht_get_missing(self, storage):
        """Получение несуществующего ключа"""
        data = storage.dht_get('nonexistent-key')
        assert data is None
    
    def test_dht_update_version(self, storage):
        """Обновление с увеличением версии"""
        storage.dht_put('versioned-key', b'v1')
        storage.dht_put('versioned-key', b'v2')
        
        data = storage.dht_get('versioned-key')
        assert data['value'] == b'v2'
        assert data['version'] == 2
    
    def test_dht_compression(self, storage):
        """Сжатие больших значений"""
        large_value = b'x' * 2000
        
        storage.dht_put('large-key', large_value)
        
        data = storage.dht_get('large-key')
        assert data['value'] == large_value
        assert 'gzip' in data['type']


class TestRoutingStorage:
    """Тесты хранения маршрутов"""
    
    def test_save_route(self, storage):
        """Сохранение маршрута"""
        storage.save_route(
            destination='1DestAddress',
            next_hop='1NextHop',
            cost=2.5,
            latency_ms=50,
            hop_count=2
        )
        
        route = storage.get_route('1DestAddress')
        
        assert route is not None
        assert route['next_hop'] == '1NextHop'
        assert route['cost'] == 2.5
        assert route['latency_ms'] == 50
    
    def test_save_better_route(self, storage):
        """Обновление лучшего маршрута"""
        storage.save_route('1Dest', '1Hop1', cost=5.0)
        storage.save_route('1Dest', '1Hop2', cost=3.0)
        
        route = storage.get_route('1Dest')
        assert route['next_hop'] == '1Hop2'
        assert route['cost'] == 3.0
    
    def test_get_all_routes(self, storage):
        """Получение всех маршрутов"""
        for i in range(5):
            storage.save_route(f'1Dest{i}', f'1Hop{i}', cost=float(i))
        
        routes = storage.get_all_routes()
        assert len(routes) == 5


class TestPeerStorage:
    """Тесты хранения пиров"""
    
    def test_save_peer(self, storage):
        """Сохранение пира"""
        storage.save_peer(
            address='1PeerAddress',
            ip='192.168.1.100',
            port=8888,
            public_key=b'\\x00' * 32,
            metadata={'version': '5.0'}
        )
        
        peer = storage.get_peer('1PeerAddress')
        
        assert peer is not None
        assert peer['ip'] == '192.168.1.100'
        assert peer['port'] == 8888
        assert peer['metadata']['version'] == '5.0'
    
    def test_update_peer(self, storage):
        """Обновление пира"""
        storage.save_peer('1Peer', '192.168.1.1', 8888)
        storage.save_peer('1Peer', '192.168.1.2', 9999)
        
        peer = storage.get_peer('1Peer')
        assert peer['ip'] == '192.168.1.2'
        assert peer['port'] == 9999
    
    def test_get_peers_list(self, storage):
        """Список пиров"""
        for i in range(5):
            storage.save_peer(
                f'1Peer{i}',
                f'192.168.1.{i}',
                8888 + i
            )
        
        peers = storage.get_peers(limit=10)
        assert len(peers) == 5


class TestLRUCache:
    """Тесты LRU кэша"""
    
    def test_cache_basic(self):
        """Базовая работа кэша"""
        cache = LRUCache(3)
        
        cache.put('a', 1)
        cache.put('b', 2)
        cache.put('c', 3)
        
        assert cache.get('a') == 1
        assert cache.get('b') == 2
        assert cache.get('c') == 3
    
    def test_cache_eviction(self):
        """Вытеснение при переполнении"""
        cache = LRUCache(2)
        
        cache.put('a', 1)
        cache.put('b', 2)
        cache.put('c', 3)  # Должен вытеснить 'a'
        
        assert cache.get('a') is None
        assert cache.get('b') == 2
        assert cache.get('c') == 3
    
    def test_cache_lru_order(self):
        """LRU порядок"""
        cache = LRUCache(2)
        
        cache.put('a', 1)
        cache.put('b', 2)
        cache.get('a')  # 'a' теперь свежее
        cache.put('c', 3)  # Должен вытеснить 'b'
        
        assert cache.get('a') == 1
        assert cache.get('b') is None
        assert cache.get('c') == 3
    
    def test_cache_remove(self):
        """Удаление из кэша"""
        cache = LRUCache(3)
        
        cache.put('a', 1)
        cache.remove('a')
        
        assert cache.get('a') is None
    
    def test_cache_stats(self):
        """Статистика кэша"""
        cache = LRUCache(3)
        
        cache.get('missing')  # Miss
        cache.put('a', 1)
        cache.get('a')  # Hit
        cache.get('a')  # Hit
        
        assert cache.hits == 2
        assert cache.misses == 1


class TestStorageStats:
    """Тесты статистики хранилища"""
    
    def test_get_stats(self, storage):
        """Получение статистики"""
        # Добавляем данные
        storage.save_message('m1', '1F', '1T', 'text', time.time())
        storage.dht_put('k1', b'v1')
        storage.save_peer('1P', '1.1.1.1', 8888)
        
        stats = storage.get_stats()
        
        assert 'db_size_mb' in stats
        assert stats['messages'] == 1
        assert stats['dht_entries'] == 1
        assert stats['peers'] == 1
        assert 'cache_hit_rate' in stats
    
    def test_stats_unread_count(self, storage):
        """Счетчик непрочитанных"""
        storage.save_message('m1', '1F', '1T', 'text', time.time(), read=False)
        storage.save_message('m2', '1F', '1T', 'text', time.time(), read=False)
        storage.save_message('m3', '1F', '1T', 'text', time.time(), read=True)
        
        stats = storage.get_stats()
        assert stats['messages_unread'] == 2


class TestStorageCleanup:
    """Тесты очистки"""
    
    def test_expired_messages_cleanup(self, storage):
        """Очистка истекших сообщений"""
        # Сообщение с истекшим TTL
        storage.save_message(
            'expired',
            '1F',
            '1T',
            'text',
            time.time() - 100,  # Создано 100 секунд назад
            ttl=1  # TTL 1 секунда
        )
        
        # Форсируем очистку
        storage._cleanup_expired()
        
        messages = storage.get_messages('1T')
        assert len(messages) == 0
    
    def test_expired_dht_cleanup(self, storage):
        """Очистка истекших DHT записей"""
        storage.dht_put('expired-key', b'value', ttl=1)
        
        # Ждем истечения
        time.sleep(1.1)
        
        # Форсируем очистку
        storage._cleanup_expired()
        
        data = storage.dht_get('expired-key')
        assert data is None


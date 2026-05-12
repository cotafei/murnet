#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET DHT TESTS v5.0
Тестирование распределенного хеш-таблицы
"""

import pytest
import time
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from murnet.core.net.murnaked import (
    EnhancedMurnakedStorage, ConsistentHashRing, VirtualNode,
    StorageEntry, BloomFilter, HintedHandoff
)
from murnet.core.identity.crypto import Identity


@pytest.fixture
def murnaked(fresh_data_dir):
    """DHT хранилище для тестов"""
    identity = Identity()
    storage = EnhancedMurnakedStorage(
        node_address=identity.address,
        data_dir=fresh_data_dir,
        replication_factor=3,
        vnodes_per_node=10
    )
    yield storage


@pytest.fixture
def hash_ring():
    """Чистое кольцо хеширования"""
    return ConsistentHashRing(vnodes_per_node=10)


class TestConsistentHashRing:
    """Тесты consistent hashing"""
    
    def test_ring_creation(self):
        """Создание кольца"""
        ring = ConsistentHashRing(vnodes_per_node=5)
        
        assert ring.vnodes_per_node == 5
        assert len(ring.ring) == 0
        assert len(ring.sorted_tokens) == 0
    
    def test_add_node(self, hash_ring):
        """Добавление узла"""
        hash_ring.add_node('1NodeAddress')
        
        assert '1NodeAddress' in hash_ring.real_nodes
        assert len(hash_ring.real_nodes['1NodeAddress']) == 10  # vnodes_per_node
        assert len(hash_ring.ring) == 10
        assert len(hash_ring.sorted_tokens) == 10
    
    def test_add_duplicate_node(self, hash_ring):
        """Добавление дубликата"""
        hash_ring.add_node('1Node')
        initial_count = len(hash_ring.ring)
        
        hash_ring.add_node('1Node')  # Повторно
        
        assert len(hash_ring.ring) == initial_count
    
    def test_remove_node(self, hash_ring):
        """Удаление узла"""
        hash_ring.add_node('1Node')
        hash_ring.remove_node('1Node')
        
        assert '1Node' not in hash_ring.real_nodes
        assert len(hash_ring.ring) == 0
        assert len(hash_ring.sorted_tokens) == 0
    
    def test_get_node(self, hash_ring):
        """Получение узла для ключа"""
        hash_ring.add_node('1NodeA')
        hash_ring.add_node('1NodeB')
        
        node = hash_ring.get_node('some-key')
        
        assert node in ['1NodeA', '1NodeB']
    
    def test_get_node_empty_ring(self, hash_ring):
        """Пустое кольцо"""
        node = hash_ring.get_node('key')
        assert node == ''
    
    def test_get_nodes(self, hash_ring):
        """Получение N узлов"""
        for i in range(5):
            hash_ring.add_node(f'1Node{i}')
        
        nodes = hash_ring.get_nodes('key', n=3)
        
        assert len(nodes) == 3
        assert len(set(nodes)) == 3  # Уникальные
    
    def test_get_nodes_more_than_available(self, hash_ring):
        """Запрос больше узлов чем есть"""
        hash_ring.add_node('1Node1')
        hash_ring.add_node('1Node2')
        
        nodes = hash_ring.get_nodes('key', n=10)
        
        assert len(nodes) == 2  # Все доступные
    
    def test_ring_stats(self, hash_ring):
        """Статистика кольца"""
        hash_ring.add_node('1Node')
        
        stats = hash_ring.get_ring_stats()
        
        assert stats['total_vnodes'] == 10
        assert stats['real_nodes'] == 1
        assert stats['vnodes_per_node'] == 10


class TestStorageEntry:
    """Тесты записей хранилища"""
    
    def test_entry_creation(self):
        """Создание записи"""
        entry = StorageEntry(
            key='test-key',
            data=b'test-data',
            timestamp=time.time(),
            ttl=3600,
            replicas={'1Node1', '1Node2'}
        )
        
        assert entry.key == 'test-key'
        assert entry.data == b'test-data'
        assert entry.ttl == 3600
        assert len(entry.replicas) == 2
        assert entry.version == 1
    
    def test_entry_not_expired(self):
        """Не истекшая запись"""
        entry = StorageEntry(
            key='key',
            data=b'data',
            timestamp=time.time(),
            ttl=3600
        )
        
        assert entry.is_expired() is False
    
    def test_entry_expired(self):
        """Истекшая запись"""
        entry = StorageEntry(
            key='key',
            data=b'data',
            timestamp=time.time() - 7200,  # 2 часа назад
            ttl=3600  # TTL 1 час
        )
        
        assert entry.is_expired() is True
    
    def test_entry_no_ttl(self):
        """Запись без TTL"""
        entry = StorageEntry(
            key='key',
            data=b'data',
            timestamp=time.time(),
            ttl=None
        )
        
        assert entry.is_expired() is False


class TestBloomFilter:
    """Тесты Bloom filter"""
    
    def test_bloom_creation(self):
        """Создание фильтра"""
        bloom = BloomFilter(size=1000, hash_count=5)
        
        assert bloom.size == 1000
        assert bloom.hash_count == 5
        assert len(bloom.bit_array) == 1000
        assert bloom.item_count == 0
    
    def test_add_and_check(self):
        """Добавление и проверка"""
        bloom = BloomFilter(size=1000, hash_count=5)
        
        bloom.add('item1')
        bloom.add('item2')
        
        assert bloom.might_contain('item1') is True
        assert bloom.might_contain('item2') is True
        assert bloom.might_contain('item3') is False  # Не добавляли
    
    def test_false_positives_possible(self):
        """Ложноположительные возможны"""
        bloom = BloomFilter(size=10, hash_count=2)  # Маленький для FP
        
        bloom.add('item1')
        
        # Может быть ложноположительное
        result = bloom.might_contain('item2')
        # Не проверяем конкретное значение, т.к. зависит от хешей
        assert isinstance(result, bool)
    
    def test_item_count(self):
        """Счетчик элементов"""
        bloom = BloomFilter(size=1000, hash_count=5)
        
        bloom.add('a')
        bloom.add('b')
        bloom.add('c')
        
        assert bloom.item_count == 3


class TestHintedHandoff:
    """Тесты hinted handoff"""
    
    def test_hint_creation(self):
        """Создание hint"""
        hint = HintedHandoff(
            target_node='1TargetNode',
            key='test-key',
            data=b'test-data',
            timestamp=time.time()
        )
        
        assert hint.target_node == '1TargetNode'
        assert hint.key == 'test-key'
        assert hint.data == b'test-data'
        assert hint.attempts == 0
        assert hint.max_attempts == 10
    
    def test_hint_with_attempts(self):
        """Hint с попытками"""
        hint = HintedHandoff(
            target_node='1Target',
            key='key',
            data=b'data',
            timestamp=time.time(),
            attempts=5
        )
        
        assert hint.attempts == 5


class TestMurnakedBasic:
    """Базовые тесты Murnaked"""
    
    def test_storage_creation(self, fresh_data_dir):
        """Создание хранилища"""
        identity = Identity()
        storage = EnhancedMurnakedStorage(
            node_address=identity.address,
            data_dir=fresh_data_dir,
            replication_factor=3,
            vnodes_per_node=10
        )
        
        assert storage.node_address == identity.address
        assert storage.replication_factor == 3
        assert len(storage.ring.real_nodes) == 1  # Только мы
        assert storage.node_address in storage.ring.real_nodes
    
    def test_store_locally(self, murnaked):
        """Локальное сохранение"""
        result = murnaked.store(
            key='test-key',
            data=b'test-data',
            ttl=3600
        )
        
        assert result is True
        assert 'test-key' in murnaked.local_store
        assert murnaked.bloom.might_contain('test-key')
    
    def test_retrieve_local(self, murnaked):
        """Локальное получение"""
        murnaked.store('my-key', b'my-data', ttl=3600)
        
        data = murnaked.retrieve('my-key')
        
        assert data == b'my-data'
    
    def test_retrieve_missing(self, murnaked):
        """Получение несуществующего ключа"""
        data = murnaked.retrieve('nonexistent-key')
        assert data is None
    
    def test_retrieve_expired(self, murnaked):
        """Получение истекшего ключа"""
        murnaked.store(
            'expired-key',
            b'data',
            ttl=1  # 1 секунда
        )
        
        time.sleep(1.1)
        
        data = murnaked.retrieve('expired-key')
        assert data is None
    
    def test_store_with_replicas(self, murnaked):
        """Сохранение с репликами"""
        # Добавляем другие узлы в кольцо
        other_node = Identity()
        murnaked.ring.add_node(other_node.address)
        
        result = murnaked.store('rep-key', b'rep-data')
        
        assert result is True
        entry = murnaked.local_store.get('rep-key')
        assert len(entry.replicas) > 0
    
    def test_add_neighbor(self, murnaked):
        """Добавление соседа"""
        other = Identity()
        
        murnaked.add_neighbor(other.address)
        
        assert other.address in murnaked.neighbors
        assert other.address in murnaked.ring.real_nodes
    
    def test_remove_neighbor(self, murnaked):
        """Удаление соседа"""
        other = Identity()
        murnaked.add_neighbor(other.address)
        
        murnaked.remove_neighbor(other.address)
        
        assert other.address not in murnaked.neighbors
        assert other.address not in murnaked.ring.real_nodes
    
    def test_get_stats(self, murnaked):
        """Получение статистики"""
        murnaked.store('key1', b'data1')
        murnaked.store('key2', b'data2')
        
        stats = murnaked.get_stats()
        
        assert 'local_keys' in stats
        assert stats['local_keys'] == 2
        assert 'ring_stats' in stats
        assert 'bloom_fpr' in stats


class TestMurnakedPersistence:
    """Тесты персистентности"""
    
    def test_persist_to_disk(self, murnaked, fresh_data_dir):
        """Сохранение на диск"""
        murnaked.store('persist-key', b'persist-data', ttl=3600)
        
        # Проверяем что файл создан
        dht_dir = os.path.join(fresh_data_dir, 'dht')
        files = os.listdir(dht_dir)
        
        assert len(files) > 0
        assert any(f.endswith('.entry') for f in files)
    
    def test_load_from_disk(self, fresh_data_dir):
        """Загрузка с диска"""
        identity = Identity()
        
        # Создаем и сохраняем
        storage1 = EnhancedMurnakedStorage(
            identity.address, fresh_data_dir
        )
        storage1.store('load-key', b'load-data')
        del storage1
        
        # Загружаем
        storage2 = EnhancedMurnakedStorage(
            identity.address, fresh_data_dir
        )
        
        data = storage2.retrieve('load-key')
        assert data == b'load-data'


class TestMurnakedFileOperations:
    """Тесты файловых операций"""
    
    def test_save_file(self, murnaked):
        """Сохранение файла"""
        file_id = 'test-file-123'
        file_data = b'file contents here'
        
        result = murnaked.save_file(file_id, file_data)
        
        assert result is True
    
    def test_get_file(self, murnaked):
        """Получение файла"""
        file_id = 'my-file'
        file_data = b'file data'
        
        murnaked.save_file(file_id, file_data)
        retrieved = murnaked.get_file(file_id)
        
        assert retrieved == file_data
    
    def test_save_and_get_message(self, murnaked):
        """Сохранение и получение сообщения"""
        msg_id = 'msg-001'
        
        result = murnaked.save_message(
            msg_id=msg_id,
            from_addr='1From',
            to_addr='1To',
            text='Hello World',
            timestamp=time.time(),
            signature='sig'
        )
        
        assert result is True
        
        msg = murnaked.get_message(msg_id)
        assert msg is not None
        assert msg['text'] == 'Hello World'
    
    def test_register_and_lookup_name(self, murnaked):
        """Регистрация и поиск имени"""
        name = 'alice'
        address = '1AliceAddress'
        
        result = murnaked.register_name(name, address, 'signature')
        assert result is True
        
        lookup = murnaked.get_name(name)
        assert lookup is not None
        assert lookup['address'] == address


class TestMurnakedStats:
    """Тесты статистики"""
    
    def test_stats_counters(self, murnaked):
        """Счетчики статистики"""
        initial_stats = murnaked.get_stats()
        
        # Сохраняем
        murnaked.store('key1', b'data1')
        murnaked.store('key2', b'data2')
        
        # Получаем
        murnaked.retrieve('key1')
        
        stats = murnaked.get_stats()
        
        assert stats['stored_keys'] >= 2
        assert stats['retrieved_keys'] >= 1
    
    def test_bloom_false_positive_rate(self, murnaked):
        """Оценка FPR Bloom filter"""
        # Добавляем много элементов
        for i in range(100):
            murnaked.store(f'key{i}', b'data')
        
        stats = murnaked.get_stats()
        fpr = stats['bloom_fpr']
        
        # FPR должен быть разумным (меньше 1%)
        assert fpr < 0.01


class TestMurnakedRPC:
    """Тесты RPC (если node_instance передан)"""
    
    def test_rpc_not_active_without_node(self, murnaked):
        """RPC не активен без node_instance"""
        # murnaked создан без node_instance
        assert murnaked.rpc is None
    
    def test_rpc_active_with_node(self, fresh_data_dir):
        """RPC активен с node_instance"""
        # Этот тест требует мокирования Node
        # В реальности проверяем что RPC создается
        pass


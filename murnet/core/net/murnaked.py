#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
УЛУЧШЕННЫЙ MURNAKED DHT v5.0 - С РЕАЛЬНОЙ СЕТЕВОЙ RPC
- Consistent Hashing
- Virtual Nodes  
- Anti-Entropy Repair
- Bloom Filters
- РЕАЛЬНАЯ СЕТЕВАЯ DHT RPC
"""

import hashlib
import time
import os
import json
import threading
import random
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict

from murnet.core.net.dht_rpc import DHTRPCManager, DHTMessageType


def bisect_right(a, x):
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] <= x:
            lo = mid + 1
        else:
            hi = mid
    return lo


@dataclass
class VirtualNode:
    vnode_id: str
    real_node: str
    token: int


@dataclass
class StorageEntry:
    key: str
    data: bytes
    timestamp: float
    version: int = 1
    ttl: Optional[int] = None
    replicas: Set[str] = field(default_factory=set)

    def is_expired(self) -> bool:
        if self.ttl is None:
            return False
        return time.time() - self.timestamp > self.ttl


class ConsistentHashRing:
    """Кольцо консистентного хеширования"""

    def __init__(self, vnodes_per_node: int = 10):
        self.vnodes_per_node = vnodes_per_node
        self.ring: Dict[int, VirtualNode] = {}
        self.sorted_tokens: List[int] = []
        self.real_nodes: Dict[str, List[VirtualNode]] = defaultdict(list)
        self.lock = threading.RLock()

    def _hash(self, key: str) -> int:
        return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16)

    def add_node(self, node_id: str):
        with self.lock:
            if node_id in self.real_nodes:
                return

            for i in range(self.vnodes_per_node):
                vnode_id = f"{node_id}#{i}"
                token = self._hash(vnode_id)

                while token in self.ring:
                    token = (token + 1) % (2**32)

                vnode = VirtualNode(
                    vnode_id=vnode_id,
                    real_node=node_id,
                    token=token
                )

                self.ring[token] = vnode
                self.real_nodes[node_id].append(vnode)

            self._rebuild_sorted_tokens()

    def remove_node(self, node_id: str):
        with self.lock:
            if node_id not in self.real_nodes:
                return

            for vnode in self.real_nodes[node_id]:
                if vnode.token in self.ring:
                    del self.ring[vnode.token]

            del self.real_nodes[node_id]
            self._rebuild_sorted_tokens()

    def _rebuild_sorted_tokens(self):
        self.sorted_tokens = sorted(self.ring.keys())

    def get_node(self, key: str) -> str:
        with self.lock:
            if not self.sorted_tokens:
                return ""

            token = self._hash(key)
            idx = bisect_right(self.sorted_tokens, token)
            if idx >= len(self.sorted_tokens):
                idx = 0

            vnode = self.ring[self.sorted_tokens[idx]]
            return vnode.real_node

    def get_nodes(self, key: str, n: int = 3) -> List[str]:
        with self.lock:
            if not self.sorted_tokens:
                return []

            token = self._hash(key)
            nodes = []
            seen = set()

            idx = bisect_right(self.sorted_tokens, token)

            while len(nodes) < n and len(nodes) < len(self.real_nodes):
                if idx >= len(self.sorted_tokens):
                    idx = 0

                vnode = self.ring[self.sorted_tokens[idx]]

                if vnode.real_node not in seen:
                    nodes.append(vnode.real_node)
                    seen.add(vnode.real_node)

                idx += 1

            return nodes

    def get_ring_stats(self) -> Dict:
        with self.lock:
            return {
                'total_vnodes': len(self.ring),
                'real_nodes': len(self.real_nodes),
                'vnodes_per_node': self.vnodes_per_node,
                'ring_coverage': len(self.ring) / (2**32) * 100
            }


class BloomFilter:
    def __init__(self, size: int = 10000, hash_count: int = 5):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [0] * size
        self.item_count = 0

    def _hashes(self, item: str) -> List[int]:
        hashes = []
        for i in range(self.hash_count):
            hash_val = int(hashlib.sha256(f"{item}:{i}".encode()).hexdigest(), 16)
            hashes.append(hash_val % self.size)
        return hashes

    def add(self, item: str):
        for pos in self._hashes(item):
            self.bit_array[pos] = 1
        self.item_count += 1

    def might_contain(self, item: str) -> bool:
        return all(self.bit_array[pos] for pos in self._hashes(item))


@dataclass
class HintedHandoff:
    target_node: str
    key: str
    data: bytes
    timestamp: float
    attempts: int = 0
    max_attempts: int = 10


class AntiEntropyService:
    def __init__(self, storage):
        self.storage = storage
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._repair_loop, daemon=True)
        self.thread.start()

    def _repair_loop(self):
        while self.running:
            time.sleep(60)
            try:
                self._check_local_data()
            except Exception as e:
                print(f"Anti-entropy error: {e}")

    def _check_local_data(self):
        expired = []
        for key, entry in self.storage.local_store.items():
            if entry.is_expired():
                expired.append(key)

        for key in expired:
            del self.storage.local_store[key]


class EnhancedMurnakedStorage:
    """Улучшенное DHT хранилище с реальной сетевой RPC"""

    def __init__(self, node_address: str, data_dir: str, 
                 replication_factor: int = 3,
                 vnodes_per_node: int = 10,
                 node_instance=None):  # <-- ДОБАВЛЕН node_instance
        self.node_address = node_address
        self.data_dir = data_dir
        self.replication_factor = replication_factor
        self.node = node_instance  # <-- Сохраняем ссылку на Node

        self.ring = ConsistentHashRing(vnodes_per_node)
        self.ring.add_node(node_address)

        self.local_store: Dict[str, StorageEntry] = {}
        self.store_lock = threading.RLock()

        self.bloom = BloomFilter(size=100000)
        self.hints: List[HintedHandoff] = []
        self.hints_lock = threading.Lock()

        self.anti_entropy = AntiEntropyService(self)
        self.neighbors: Set[str] = set()

        # RPC менеджер (инициализируется если есть node_instance)
        self.rpc: Optional[DHTRPCManager] = None
        if node_instance:
            self.rpc = DHTRPCManager(node_instance, self)

        self.stats = {
            'stored_keys': 0,
            'retrieved_keys': 0,
            'replicated_keys': 0,
            'repaired_keys': 0,
            'hinted_handoffs': 0,
            'bloom_checks': 0,
            'bloom_false_positives': 0,
            'rpc_requests': 0,
            'rpc_responses': 0,
        }

        self._load_from_disk()
        self.anti_entropy.start()
        threading.Thread(target=self._hint_delivery_loop, daemon=True).start()

    def store(self, key: str, data: bytes, 
              ttl: Optional[int] = None,
              context: Optional[Dict] = None) -> bool:
        """Сохранить данные в DHT (локально + репликация)"""

        nodes = self.ring.get_nodes(key, self.replication_factor)

        entry = StorageEntry(
            key=key,
            data=data,
            timestamp=time.time(),
            ttl=ttl,
            replicas=set(nodes)
        )

        # Сохраняем локально если мы в списке
        if self.node_address in nodes:
            with self.store_lock:
                self.local_store[key] = entry
                self.bloom.add(key)

            self._persist_to_disk(key, entry)
            self.stats['stored_keys'] += 1

        # Реплицируем на другие ноды
        for node in nodes:
            if node != self.node_address:
                success = self._replicate_to(node, key, entry)

                if not success:
                    # Hinted handoff
                    with self.hints_lock:
                        self.hints.append(HintedHandoff(
                            target_node=node,
                            key=key,
                            data=data,
                            timestamp=time.time()
                        ))
                    self.stats['hinted_handoffs'] += 1

        return True

    def retrieve(self, key: str) -> Optional[bytes]:
        """Получить данные из DHT (локально или по сети)"""
        self.stats['bloom_checks'] += 1

        # Пробуем локально
        with self.store_lock:
            entry = self.local_store.get(key)

            if entry and not entry.is_expired():
                self.stats['retrieved_keys'] += 1
                return entry.data
            elif entry and entry.is_expired():
                del self.local_store[key]

        # Пробуем по сети
        nodes = self.ring.get_nodes(key, self.replication_factor)

        for node in nodes:
            if node == self.node_address:
                continue

            data = self._request_from_node(node, key)
            if data:
                # Кэшируем локально на 5 минут
                self.store(key, data, ttl=300)
                return data

        return None

    def _replicate_to(self, node: str, key: str, entry: StorageEntry) -> bool:
        """РЕАЛЬНАЯ репликация через RPC"""
        if not self.rpc:
            return False  # Нет RPC - нет репликации

        try:
            # Асинхронная репликация
            self.rpc.replicate_remote(
                node_address=node,
                key=key,
                data=entry.data,
                original_key=key
            )
            self.stats['replicated_keys'] += 1
            return True
        except Exception as e:
            print(f"❌ Replication to {node[:16]}... failed: {e}")
            return False

    def _request_from_node(self, node: str, key: str) -> Optional[bytes]:
        """РЕАЛЬНЫЙ запрос данных через RPC"""
        if not self.rpc:
            return None

        result = [None]
        event = threading.Event()

        def on_response(data: Optional[bytes]):
            result[0] = data
            event.set()

        try:
            self.rpc.retrieve_remote(
                node_address=node,
                key=key,
                callback=on_response
            )

            # Ждем ответ 5 секунд
            event.wait(timeout=5.0)

            if result[0]:
                self.stats['rpc_responses'] += 1

            return result[0]

        except Exception as e:
            print(f"❌ Retrieve from {node[:16]}... failed: {e}")
            return None

    def _persist_to_disk(self, key: str, entry: StorageEntry):
        filepath = os.path.join(self.data_dir, 'dht', f"{key}.entry")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump({
                'key': entry.key,
                'data': entry.data.hex(),
                'timestamp': entry.timestamp,
                'version': entry.version,
                'ttl': entry.ttl,
                'replicas': list(entry.replicas)
            }, f)

    def _load_from_disk(self):
        dht_dir = os.path.join(self.data_dir, 'dht')
        if not os.path.exists(dht_dir):
            return

        for filename in os.listdir(dht_dir):
            if not filename.endswith('.entry'):
                continue

            filepath = os.path.join(dht_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)

                entry = StorageEntry(
                    key=data['key'],
                    data=bytes.fromhex(data['data']),
                    timestamp=data['timestamp'],
                    version=data.get('version', 1),
                    ttl=data.get('ttl'),
                    replicas=set(data.get('replicas', []))
                )

                if not entry.is_expired():
                    self.local_store[entry.key] = entry
                    self.bloom.add(entry.key)

            except Exception as e:
                print(f"Ошибка загрузки {filename}: {e}")

    def _hint_delivery_loop(self):
        """Доставка hinted handoffs"""
        while True:
            time.sleep(30)

            with self.hints_lock:
                undelivered = []

                for hint in self.hints:
                    if hint.attempts >= hint.max_attempts:
                        continue

                    # Пробуем доставить через RPC
                    if self.rpc:
                        try:
                            self.rpc.send_hint(
                                node_address=hint.target_node,
                                key=hint.key,
                                data=hint.data
                            )
                            print(f"✅ Hint delivered: {hint.key[:16]}...")
                            continue  # Успешно - не добавляем в undelivered
                        except:
                            pass

                    hint.attempts += 1
                    undelivered.append(hint)

                self.hints = undelivered

    def add_neighbor(self, node_address: str):
        self.neighbors.add(node_address)
        self.ring.add_node(node_address)

    def remove_neighbor(self, node_address: str):
        self.neighbors.discard(node_address)
        self.ring.remove_node(node_address)

    def get_neighbors(self) -> List[str]:
        return list(self.neighbors)

    def get_stats(self) -> Dict:
        with self.store_lock:
            n = self.bloom.item_count
            m = self.bloom.size
            k = self.bloom.hash_count
            if n > 0 and m > 0:
                fpr = (1 - (1 - 1/m)**(k*n))**k
            else:
                fpr = 0.0

            return {
                **self.stats,
                'local_keys': len(self.local_store),
                'ring_stats': self.ring.get_ring_stats(),
                'bloom_fpr': fpr,
                'pending_hints': len(self.hints),
                'rpc_active': self.rpc is not None
            }

    def save_message(self, msg_id: str, from_addr: str, to_addr: str,
                    text: str, timestamp: float, signature: str) -> bool:
        data = json.dumps({
            'id': msg_id,
            'from': from_addr,
            'to': to_addr,
            'text': text,
            'timestamp': timestamp,
            'signature': signature
        }).encode()
        return self.store(f"msg:{msg_id}", data)

    def get_message(self, msg_id: str):
        data = self.retrieve(f"msg:{msg_id}")
        if data:
            return json.loads(data.decode())
        return None

    def register_name(self, name: str, address: str, signature: str) -> bool:
        data = json.dumps({
            'name': name,
            'address': address,
            'signature': signature,
            'timestamp': time.time()
        }).encode()
        return self.store(f"name:{name}", data)

    def get_name(self, name: str):
        data = self.retrieve(f"name:{name}")
        if data:
            return json.loads(data.decode())
        return None

    def save_file(self, file_id: str, data: bytes) -> bool:
        return self.store(f"file:{file_id}", data)

    def get_file(self, file_id: str):
        return self.retrieve(f"file:{file_id}")

    def update_neighbors(self, neighbors_list: list):
        for n in neighbors_list:
            addr = n.get('address', '')
            if addr:
                self.add_neighbor(addr)

    def handle_dht_response(self, message: dict):
        pass


# ============================================================================
# LEGACY WRAPPER
# ============================================================================

class MurnakedNode(EnhancedMurnakedStorage):
    """Legacy wrapper для совместимости"""

    def __init__(self, node_address: str, node_id: bytes, 
                 identity, data_dir: str, transport=None,
                 node_instance=None):  # <-- ДОБАВЛЕН node_instance
        if ':' in node_address:
            addr, port = node_address.rsplit(':', 1)
        else:
            addr, port = node_address, 8888

        super().__init__(
            node_address=node_address,
            data_dir=data_dir,
            replication_factor=3,
            vnodes_per_node=10,
            node_instance=node_instance  # <-- ПЕРЕДАЕМ
        )

        self.transport = transport
        self.identity = identity
        self.public_key = identity.get_public_bytes() if identity else b''
        self.neighbors = {}

    def start(self):
        """Запуск DHT сервисов"""
        if self.rpc:
            self.rpc.start()
            print("🔥 DHT RPC started")

    def stop(self):
        """Остановка DHT сервисов"""
        if self.rpc:
            self.rpc.stop()
        self.anti_entropy.running = False

    def save_message(self, msg_id: str, from_addr: str, to_addr: str,
                    text: str, timestamp: float, signature: str) -> bool:
        data = json.dumps({
            'id': msg_id,
            'from': from_addr,
            'to': to_addr,
            'text': text,
            'timestamp': timestamp,
            'signature': signature
        }).encode()
        return self.store(f"msg:{msg_id}", data)

    def get_message(self, msg_id: str):
        data = self.retrieve(f"msg:{msg_id}")
        if data:
            return json.loads(data.decode())
        return None

    def register_name(self, name: str, address: str, signature: str) -> bool:
        data = json.dumps({
            'name': name,
            'address': address,
            'signature': signature,
            'timestamp': time.time()
        }).encode()
        return self.store(f"name:{name}", data)

    def get_name(self, name: str):
        data = self.retrieve(f"name:{name}")
        if data:
            return json.loads(data.decode())
        return None

    def save_file(self, file_id: str, data: bytes) -> bool:
        return self.store(f"file:{file_id}", data)

    def get_file(self, file_id: str):
        return self.retrieve(f"file:{file_id}")

    def update_neighbors(self, neighbors_list: list):
        for n in neighbors_list:
            addr = n.get('address', '')
            if addr:
                self.add_neighbor(addr)
                self.neighbors[addr] = n

    def handle_dht_response(self, message: dict):
        pass
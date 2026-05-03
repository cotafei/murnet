"""
MURNET STORAGE v5.1 - Fixed API
"""

import os
import json
import time
import sqlite3
import threading
import hashlib
import zlib
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from contextlib import contextmanager
from collections import OrderedDict

from core.data.migrations import migrate as _run_migrations


@dataclass
class StorageConfig:
    data_dir: str = "./data"
    max_size_mb: int = 500
    compression: bool = True
    encryption_key: Optional[bytes] = None
    wal_mode: bool = True
    cache_size: int = 1000
    auto_vacuum: bool = True


class LRUCache:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.cache: OrderedDict = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                self.hits += 1
                return self.cache[key]
            self.misses += 1
            return None
    
    def put(self, key: str, value: Any):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)
    
    def remove(self, key: str):
        with self.lock:
            self.cache.pop(key, None)


class Storage:
    def __init__(self, data_dir: str = "./data", config: Optional[StorageConfig] = None):
        self.config = config or StorageConfig()
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "murnet.db")
        self.cache = LRUCache(self.config.cache_size if config else 1000)
        
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(os.path.join(data_dir, "dht"), exist_ok=True)
        os.makedirs(os.path.join(data_dir, "files"), exist_ok=True)
        
        self._local = threading.local()
        self._running = False

        self._init_database()
        self._apply_migrations()
        self._start_background_tasks()
    
    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None
            )
            self._local.conn.row_factory = sqlite3.Row
            if self.config.wal_mode:
                self._local.conn.execute("PRAGMA journal_mode=WAL")
                self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn
    
    @contextmanager
    def _transaction(self):
        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    
    def _init_database(self):
        with self._transaction() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS identity (
                    id INTEGER PRIMARY KEY,
                    private_key BLOB NOT NULL,
                    public_key BLOB NOT NULL,
                    address TEXT UNIQUE NOT NULL,
                    created_at REAL DEFAULT (strftime('%s','now'))
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    from_addr TEXT NOT NULL,
                    to_addr TEXT NOT NULL,
                    content BLOB,
                    content_preview TEXT,
                    timestamp REAL NOT NULL,
                    delivered INTEGER DEFAULT 0,
                    read INTEGER DEFAULT 0,
                    signature TEXT,
                    ttl INTEGER,
                    expires_at REAL,
                    compressed INTEGER DEFAULT 0
                )
            """)
            
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_addr)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL")
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dht_data (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL,
                    value_type TEXT DEFAULT 'binary',
                    version INTEGER DEFAULT 1,
                    timestamp REAL DEFAULT (strftime('%s','now')),
                    ttl INTEGER,
                    expires_at REAL,
                    replicas TEXT,
                    owner TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS routing (
                    destination TEXT PRIMARY KEY,
                    next_hop TEXT NOT NULL,
                    cost REAL DEFAULT 1.0,
                    latency_ms INTEGER,
                    last_seen REAL DEFAULT (strftime('%s','now')),
                    hop_count INTEGER DEFAULT 1,
                    stable INTEGER DEFAULT 0
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS peers (
                    address TEXT PRIMARY KEY,
                    ip TEXT,
                    port INTEGER,
                    public_key BLOB,
                    last_seen REAL DEFAULT (strftime('%s','now')),
                    trust_score REAL DEFAULT 0.5,
                    failed_attempts INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at REAL DEFAULT (strftime('%s','now'))
                )
            """)
            
            if self.config.auto_vacuum:
                conn.execute("PRAGMA auto_vacuum=INCREMENTAL")

    def _apply_migrations(self):
        """Run pending DB migrations on a fresh connection (not thread-local)."""
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            _run_migrations(conn)
        finally:
            conn.close()

    def _start_background_tasks(self):
        self._running = True
        
        def cleanup_loop():
            while self._running:
                try:
                    time.sleep(60)
                    self._cleanup_expired()
                    if self.config.auto_vacuum:
                        self._vacuum_if_needed()
                except Exception as e:
                    print(f"Cleanup error: {e}")
        
        threading.Thread(target=cleanup_loop, daemon=True).start()
    
    def _cleanup_expired(self):
        with self._transaction() as conn:
            now = time.time()
            conn.execute(
                "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,)
            )
            conn.execute(
                "DELETE FROM dht_data WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,)
            )
    
    def _vacuum_if_needed(self):
        size_mb = os.path.getsize(self.db_path) / (1024 * 1024)
        if size_mb > self.config.max_size_mb * 0.8:
            with self._transaction() as conn:
                conn.execute("VACUUM")
    
    # === Identity - ИСПРАВЛЕННЫЙ API (ripemd160 -> blake2b) ===
    
    def save_identity(self, identity_bytes: bytes):
        """
        Сохранение идентичности из сериализованных байтов.
        Формат: 32 bytes private_key + 32 bytes public_key
        """
        if len(identity_bytes) < 64:
            raise ValueError("Invalid identity bytes length")
        
        private_key = identity_bytes[:32]
        public_key = identity_bytes[32:64]
        
        # Вычисляем address из public_key используя blake2b вместо ripemd160
        # Используем тот же алгоритм, что и в crypto.py
        hash160 = hashlib.blake2b(public_key, digest_size=20).digest()
        versioned = bytes([0x00]) + hash160
        # Double blake2b для checksum (соответствует crypto.py)
        checksum = hashlib.blake2b(hashlib.blake2b(versioned).digest(), digest_size=4).digest()
        address = self._base58_encode(versioned + checksum)
        
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity (id, private_key, public_key, address) VALUES (1, ?, ?, ?)",
                (private_key, public_key, address)
            )
        
        return address
    
    def _base58_encode(self, data: bytes) -> str:
        """Base58 encoding для адресов (копия из crypto.py)"""
        if not data:
            return ""
        
        BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        
        leading_zeros = sum(1 for b in data if b == 0)
        num = int.from_bytes(data, 'big')
        result = ''
        
        while num > 0:
            num, remainder = divmod(num, 58)
            result = BASE58_ALPHABET[remainder] + result
        
        return '1' * leading_zeros + result
    
    def load_identity(self) -> Optional[bytes]:
        """Загрузка полной идентичности как bytes (private + public)"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT private_key, public_key FROM identity WHERE id = 1"
        ).fetchone()
        
        if row:
            return row['private_key'] + row['public_key']
        return None
    
    def get_identity(self) -> Optional[Dict[str, Any]]:
        """Загрузка полной идентичности как словарь"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT private_key, public_key, address FROM identity WHERE id = 1"
        ).fetchone()
        
        if row:
            return {
                'private_key': row['private_key'],
                'public_key': row['public_key'],
                'address': row['address']
            }
        return None
    
    # === Messages ===
    
    def save_message(self, msg_id: str, from_addr: str, to_addr: str,
                     text: str, timestamp: float, delivered: bool = False,
                     read: bool = False,
                     signature: Optional[str] = None, ttl: Optional[int] = None,
                     compress: bool = True) -> bool:
        try:
            content = text.encode('utf-8')
            compressed = 0

            if compress and self.config.compression and len(content) > 100:
                content = zlib.compress(content)
                compressed = 1

            preview = text[:200] if len(text) > 200 else text
            expires_at = timestamp + ttl if ttl else None

            with self._transaction() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO messages
                    (id, from_addr, to_addr, content, content_preview, timestamp,
                     delivered, read, signature, ttl, expires_at, compressed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (msg_id, from_addr, to_addr, content, preview, timestamp,
                      int(delivered), int(read), signature, ttl, expires_at, compressed))
            
            self.cache.remove(f"msgs:{to_addr}")
            return True
            
        except Exception as e:
            print(f"Save message error: {e}")
            return False
    
    def get_messages(self, address: str, limit: int = 50, 
                     only_unread: bool = False) -> List[Dict]:
        cache_key = f"msgs:{address}:{only_unread}:{limit}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        conn = self._get_conn()
        
        query = """
            SELECT id, from_addr, to_addr, content, content_preview, timestamp,
                   delivered, read, signature, compressed
            FROM messages 
            WHERE to_addr = ?
        """
        params = [address]
        
        if only_unread:
            query += " AND read = 0"
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(query, params).fetchall()
        
        messages = []
        for row in rows:
            content = row['content']
            if row['compressed']:
                try:
                    content = zlib.decompress(content)
                except:
                    pass
            
            messages.append({
                'id': row['id'],
                'from': row['from_addr'],
                'to': row['to_addr'],
                'content': content.decode('utf-8', errors='replace'),
                'preview': row['content_preview'],
                'timestamp': row['timestamp'],
                'delivered': bool(row['delivered']),
                'read': bool(row['read']),
                'signature': row['signature']
            })
        
        self.cache.put(cache_key, messages)
        return messages
    
    def mark_delivered(self, msg_id: str, delivered: bool = True):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE messages SET delivered = ? WHERE id = ?",
                (int(delivered), msg_id)
            )
    
    def mark_read(self, msg_id: str):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE messages SET read = 1 WHERE id = ?",
                (msg_id,)
            )
    
    def get_conversations(self, address: str) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT from_addr, COUNT(*) as count, MAX(timestamp) as last_time,
                   SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END) as unread
            FROM messages 
            WHERE to_addr = ?
            GROUP BY from_addr
            ORDER BY last_time DESC
        """, (address,)).fetchall()
        
        return [{
            'peer_address': row['from_addr'],
            'message_count': row['count'],
            'last_message_time': row['last_time'],
            'unread_count': row['unread'],
            'peer_name': None,
            'last_message_preview': None
        } for row in rows]
    
    # === DHT ===
    
    def dht_put(self, key: str, value: bytes, value_type: str = 'binary',
                ttl: Optional[int] = None, owner: Optional[str] = None,
                replicas: Optional[List[str]] = None) -> bool:
        try:
            if self.config.compression and len(value) > 1000:
                value = zlib.compress(value)
                value_type = f"{value_type}:gzip"
            
            expires_at = time.time() + ttl if ttl else None
            
            with self._transaction() as conn:
                conn.execute("""
                    INSERT INTO dht_data (key, value, value_type, timestamp, 
                                        ttl, expires_at, replicas, owner)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        value_type = excluded.value_type,
                        version = version + 1,
                        timestamp = excluded.timestamp,
                        ttl = excluded.ttl,
                        expires_at = excluded.expires_at,
                        replicas = excluded.replicas
                """, (key, value, value_type, time.time(), ttl, expires_at,
                      json.dumps(replicas) if replicas else None, owner))
            
            self.cache.remove(f"dht:{key}")
            return True
            
        except Exception as e:
            print(f"DHT put error: {e}")
            return False
    
    def dht_get(self, key: str) -> Optional[Dict]:
        cache_key = f"dht:{key}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM dht_data WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)",
            (key, time.time())
        ).fetchone()
        
        if not row:
            return None
        
        value = row['value']
        value_type = row['value_type']
        
        if ':gzip' in value_type:
            try:
                value = zlib.decompress(value)
            except:
                pass
        
        result = {
            'key': row['key'],
            'value': value,
            'type': value_type,
            'version': row['version'],
            'timestamp': row['timestamp'],
            'owner': row['owner'],
            'replicas': json.loads(row['replicas']) if row['replicas'] else []
        }
        
        self.cache.put(cache_key, result)
        return result
    
    # === Routing ===
    
    def save_route(self, destination: str, next_hop: str, cost: float = 1.0,
                   latency_ms: Optional[int] = None, hop_count: int = 1):
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO routing (destination, next_hop, cost, latency_ms, 
                                   hop_count, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(destination) DO UPDATE SET
                    next_hop = CASE WHEN excluded.cost < cost 
                                   THEN excluded.next_hop ELSE next_hop END,
                    cost = MIN(cost, excluded.cost),
                    latency_ms = COALESCE(excluded.latency_ms, latency_ms),
                    hop_count = CASE WHEN excluded.cost < cost 
                                    THEN excluded.hop_count ELSE hop_count END,
                    last_seen = excluded.last_seen,
                    stable = stable + 1
            """, (destination, next_hop, cost, latency_ms, hop_count, time.time()))
    
    def get_route(self, destination: str) -> Optional[Dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM routing WHERE destination = ?",
            (destination,)
        ).fetchone()
        
        if row:
            return {
                'destination': row['destination'],
                'next_hop': row['next_hop'],
                'cost': row['cost'],
                'latency_ms': row['latency_ms'],
                'last_seen': row['last_seen'],
                'hop_count': row['hop_count'],
                'stable': bool(row['stable'])
            }
        return None
    
    def get_all_routes(self) -> Dict[str, Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM routing ORDER BY cost"
        ).fetchall()
        
        return {row['destination']: {
            'next_hop': row['next_hop'],
            'cost': row['cost'],
            'hop_count': row['hop_count']
        } for row in rows}
    
    # === Peers ===
    
    def save_peer(self, address: str, ip: Optional[str] = None,
                  port: Optional[int] = None, public_key: Optional[bytes] = None,
                  metadata: Optional[Dict] = None):
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO peers (address, ip, port, public_key, last_seen, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET
                    ip = COALESCE(excluded.ip, ip),
                    port = COALESCE(excluded.port, port),
                    public_key = COALESCE(excluded.public_key, public_key),
                    last_seen = excluded.last_seen,
                    metadata = COALESCE(excluded.metadata, metadata)
            """, (address, ip, port, public_key, time.time(),
                  json.dumps(metadata) if metadata else None))
    
    def get_peer(self, address: str) -> Optional[Dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM peers WHERE address = ?",
            (address,)
        ).fetchone()
        
        if row:
            return {
                'address': row['address'],
                'ip': row['ip'],
                'port': row['port'],
                'public_key': row['public_key'],
                'last_seen': row['last_seen'],
                'trust_score': row['trust_score'],
                'failed_attempts': row['failed_attempts'],
                'metadata': json.loads(row['metadata']) if row['metadata'] else {}
            }
        return None
    
    def get_peers(self, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM peers ORDER BY last_seen DESC LIMIT ?",
            (limit,)
        ).fetchall()
        
        return [{
            'address': row['address'],
            'ip': row['ip'],
            'port': row['port'],
            'last_seen': row['last_seen'],
            'trust_score': row['trust_score']
        } for row in rows]
    
    # === Stats ===
    
    def get_stats(self) -> Dict:
        conn = self._get_conn()
        
        return {
            'db_size_mb': round(os.path.getsize(self.db_path) / (1024 * 1024), 2),
            'messages': conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
            'messages_unread': conn.execute(
                "SELECT COUNT(*) FROM messages WHERE read = 0"
            ).fetchone()[0],
            'dht_entries': conn.execute("SELECT COUNT(*) FROM dht_data").fetchone()[0],
            'routes': conn.execute("SELECT COUNT(*) FROM routing").fetchone()[0],
            'peers': conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0],
            'cache_hit_rate': self.cache.hits / max(1, self.cache.hits + self.cache.misses)
        }
    
    def close(self):
        self._running = False
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
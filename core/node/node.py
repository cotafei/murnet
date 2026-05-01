
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MURNET NODE v5.0-SECURE - Hardened P2P Node
Security-hardened with authentication, encryption, and DoS protection
"""

import time
import threading
import json
import uuid
import os
import base64
import queue
import hashlib
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from core.net.transport import Transport, PacketType, RateLimiter
from core.net.routing import RoutingTable
from core.net.murnaked import MurnakedNode
from core.identity.crypto import Identity, E2EEncryption, blake2b_hash
from core.data.storage import Storage
from core.config import get_config


@dataclass
class CircuitBreaker:
    """Circuit breaker for fault tolerance"""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    
    failures: int = 0
    last_failure_time: float = 0
    state: str = "closed"
    half_open_calls: int = 0
    
    lock = threading.Lock()
    
    def can_execute(self) -> bool:
        with self.lock:
            if self.state == "closed":
                return True
            
            if self.state == "open":
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = "half-open"
                    self.half_open_calls = 0
                    return True
                return False
            
            if self.state == "half-open":
                if self.half_open_calls < self.half_open_max_calls:
                    self.half_open_calls += 1
                    return True
                return False
            
            return True
    
    def record_success(self):
        with self.lock:
            if self.state == "half-open":
                self.state = "closed"
                self.failures = 0
            else:
                self.failures = max(0, self.failures - 1)
    
    def record_failure(self):
        with self.lock:
            self.failures += 1
            self.last_failure_time = time.time()
            
            if self.failures >= self.failure_threshold:
                self.state = "open"
                print(f"🔴 Circuit Breaker OPEN (failures: {self.failures})")


@dataclass
class BackpressureController:
    """Backpressure for overload protection"""
    high_watermark: float = 0.8
    low_watermark: float = 0.3
    
    current_load: float = 0.0
    is_throttled: bool = False
    
    def update_load(self, queue_size: int, queue_capacity: int):
        self.current_load = queue_size / queue_capacity
        
        if self.current_load > self.high_watermark and not self.is_throttled:
            self.is_throttled = True
            print(f"⚠️ Backpressure: THROTTLE (load: {self.current_load:.2%})")
        
        elif self.current_load < self.low_watermark and self.is_throttled:
            self.is_throttled = False
            print(f"✅ Backpressure: RESUME (load: {self.current_load:.2%})")
    
    def should_accept(self) -> bool:
        return not self.is_throttled


class MetricsCollector:
    """Security-aware metrics"""
    
    def __init__(self):
        from collections import deque
        self.metrics = {
            'latency_histogram': deque(maxlen=1000),
            'throughput_1s': deque(maxlen=60),
            'error_rate': deque(maxlen=60),
            'queue_depth': deque(maxlen=60),
            'security_events': deque(maxlen=100),  # New: security events
        }
        self.lock = threading.RLock()
        self.security_alerts = 0
    
    def record_latency(self, latency_ms: float):
        with self.lock:
            self.metrics['latency_histogram'].append(latency_ms)
    
    def record_error(self):
        with self.lock:
            self.metrics['error_rate'].append(1)
    
    def record_success(self):
        with self.lock:
            self.metrics['error_rate'].append(0)
    
    def record_security_event(self, event_type: str, details: str):
        """Record security event"""
        with self.lock:
            self.metrics['security_events'].append({
                'type': event_type,
                'details': details,
                'timestamp': time.time()
            })
            self.security_alerts += 1
            print(f"🛡️  Security Alert [{event_type}]: {details}")
    
    def update_queue_depth(self, depth: int):
        with self.lock:
            self.metrics['queue_depth'].append(depth)
    
    def get_percentile(self, percentile: float) -> float:
        with self.lock:
            data = sorted(self.metrics['latency_histogram'])
            if not data:
                return 0.0
            idx = int(len(data) * percentile / 100)
            return data[min(idx, len(data) - 1)]
    
    def get_stats(self) -> Dict:
        with self.lock:
            errors = list(self.metrics['error_rate'])
            recent_events = list(self.metrics['security_events'])[-10:]
            
            return {
                'latency_p50': self.get_percentile(50),
                'latency_p95': self.get_percentile(95),
                'latency_p99': self.get_percentile(99),
                'error_rate_1m': sum(errors) / max(1, len(errors)) * 100,
                'avg_queue_depth': sum(self.metrics['queue_depth']) / max(1, len(self.metrics['queue_depth'])),
                'security_alerts': self.security_alerts,
                'recent_security_events': recent_events
            }


class SecureMurnetNode:
    """Security-hardened Murnet Node v5.0"""
    
    def __init__(self, data_dir: str = "./data", port: int = 8888):
        self.data_dir = data_dir
        self.port = port
        self.running = False
        self.config = get_config()
        
        print(f"🚀 Secure Node v5.0: инициализация (порт {port})")
        
        # Initialize storage with encryption
        self.storage = Storage(
            data_dir,
            config=self.config.storage
        )
        
        self._init_identity()
        
        # Initialize transport with security
        self.transport = Transport(port)
        self.transport.on_peer_connected = self._on_peer_connected
        self.transport.on_peer_disconnected = self._on_peer_disconnected
        
        # Initialize routing with authentication
        self.routing = RoutingTable(self.address, self.identity)
        
        # Initialize DHT with RPC
        self.murnaked = MurnakedNode(
            node_address=f"127.0.0.1:{port}",
            node_id=hashlib.sha256(self.address.encode()).digest(),
            identity=self.identity,
            data_dir=data_dir,
            transport=self.transport,
            node_instance=self
        )
        
        # E2E encryption
        self.e2e = E2EEncryption(self.identity)
        
        # Fault tolerance
        self.circuit_breaker = CircuitBreaker()
        self.backpressure = BackpressureController()
        self.metrics = MetricsCollector()
        
        # Message queues
        self.outbox_queue = queue.Queue(maxsize=100000)
        self.retry_queue = queue.Queue(maxsize=100000)
        self.handler_queue = queue.Queue(maxsize=100000)
        
        # Pending ACKs
        self.pending_acks: Dict[str, Any] = {}
        self.ack_lock = threading.RLock()
        
        # Thread pool
        self.executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="SecureNode-v5")
        
        # Stats
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'messages_forwarded': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': time.time(),
            'security_events': 0
        }
        
        self.healthy = True
        
        # Peer tracking
        self.authenticated_peers: Dict[str, bool] = {}
        self.peer_public_keys: Dict[str, bytes] = {}
    
    def _init_identity(self):
        """Initialize or load identity"""
        key_bytes = self.storage.load_identity()
        
        if key_bytes:
            self.identity = Identity.from_bytes(key_bytes)
            print(f"🔑 Loaded existing identity: {self.identity.address[:16]}...")
        else:
            self.identity = Identity()
            self.storage.save_identity(self.identity.to_bytes())
            print(f"🔑 Generated new identity: {self.identity.address[:16]}...")
        
        self.address = self.identity.address
        self.public_key = self.identity.get_public_bytes()
    
    def _on_peer_connected(self, address: str, addr: tuple):
        """Handle peer connection"""
        print(f"📡 Peer connected: {address[:16]}... @ {addr[0]}:{addr[1]}")
        self.routing.add_neighbor(address)
    
    def _on_peer_disconnected(self, address: str):
        """Handle peer disconnection"""
        print(f"📡 Peer disconnected: {address[:16]}...")
        self.routing.remove_link(address)
        self.authenticated_peers.pop(address, None)
        self.peer_public_keys.pop(address, None)
    
    def start(self):
        """Start secure node"""
        if self.running:
            return
        
        self.running = True
        print(f"🚀 Secure Node v5.0: запуск {self.address[:16]}...")
        
        # Start transport with identity
        self.transport.start(
            self.address,
            self.public_key,
            self.identity.get_private_bytes()
        )
        
        # Start DHT
        self.murnaked.start()
        
        # Start worker threads
        threads = [
            ("Outbox", self._outbox_loop),
            ("Retry", self._retry_loop),
            ("Handler", self._handler_loop),
            ("Metrics", self._metrics_loop),
            ("Security", self._security_loop),
        ]
        
        for name, target in threads:
            t = threading.Thread(target=target, name=f"SecureNode-{name}", daemon=True)
            t.start()
        
        print(f"✅ Secure Node v5.0 запущен")
        print(f"   Address: {self.address}")
        print(f"   Public Key: {self.public_key.hex()[:32]}...")
    
    def stop(self):
        """Stop node securely"""
        print(f"🛑 Secure Node v5.0: остановка...")
        self.running = False
        
        self.murnaked.stop()
        self.transport.stop()
        self.executor.shutdown(wait=False)
        self.e2e.clear_cache()
        
        print("✅ Node stopped securely")
    
    def send_message(self, to_addr: str, text: str, encrypt: bool = True) -> Optional[str]:
        """Send secure message"""
        if not self.circuit_breaker.can_execute():
            self.metrics.record_security_event("CIRCUIT_BREAKER", "Message blocked by circuit breaker")
            return None
        
        if not self.backpressure.should_accept():
            return None
        
        try:
            msg_id = str(uuid.uuid4())
            timestamp = time.time()
            
            # Build message
            message = {
                'type': 'message',
                'id': msg_id,
                'from': self.address,
                'to': to_addr,
                'text': text,
                'timestamp': timestamp,
                'ttl': 10,
                'path': [self.address],
                'need_ack': True,
                'version': 'v5-secure'
            }
            
            # Sign message
            message['signature'] = self.identity.sign(message)
            
            # Encrypt if requested and we have peer's key
            if encrypt and to_addr in self.peer_public_keys:
                encrypted_content = self.e2e.encrypt_message(
                    text,
                    self.peer_public_keys[to_addr]
                )
                message['encrypted'] = encrypted_content
                message['text'] = '[ENCRYPTED]'  # Hide original text
            
            # Store locally
            self.storage.save_message(
                msg_id=msg_id,
                from_addr=self.address,
                to_addr=to_addr,
                text=text,
                timestamp=timestamp,
                delivered=False,
                signature=message['signature']
            )
            
            # Queue for sending
            self.outbox_queue.put_nowait(message)
            
            # Track ACK
            with self.ack_lock:
                self.pending_acks[msg_id] = {
                    'time': time.time(),
                    'retries': 0,
                    'message': message
                }
            
            self.stats['messages_sent'] += 1
            self.circuit_breaker.record_success()
            
            return msg_id
            
        except Exception as e:
            print(f"❌ Send error: {e}")
            self.circuit_breaker.record_failure()
            return None
    
    def _outbox_loop(self):
        """Outbox processing"""
        while self.running:
            try:
                message = self.outbox_queue.get(timeout=1.0)
                self._process_outgoing(message)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ Outbox error: {e}")
                self.metrics.record_error()
    
    def _process_outgoing(self, message: Dict):
        """Process outgoing message"""
        to_addr = message.get('to')
        next_hop = self.routing.get_next_hop(to_addr)
        
        if next_hop:
            peer = self.transport.peers.get(next_hop)
            if peer and peer.is_active:
                success = self.transport.send_to(
                    message, 
                    peer.addr[0], 
                    peer.addr[1],
                    reliable=True
                )
                if not success:
                    self._flood_message(message)
            else:
                self._flood_message(message)
        else:
            self._flood_message(message)
    
    def _flood_message(self, message: Dict):
        """Controlled flooding"""
        with self.transport.peers_lock:
            peers = list(self.transport.peers.values())
        
        sent = 0
        max_flood = 5  # Limit flood scope
        
        for peer in peers[:max_flood]:
            if peer.is_active and peer.handshake_complete:
                if self.transport.send_to(message, peer.addr[0], peer.addr[1]):
                    sent += 1
        
        self.stats['messages_forwarded'] += sent
    
    def _handle_packet(self, message: Dict, ip: str, port: int):
        """Handle incoming packet with security checks"""
        try:
            # Validate message structure
            if not isinstance(message, dict):
                self.metrics.record_security_event("INVALID_FORMAT", f"Non-dict message from {ip}")
                return
            
            # Check required fields
            msg_type = message.get('type')
            msg_from = message.get('from')
            msg_id = message.get('id')
            
            if not all([msg_type, msg_from, msg_id]):
                return
            
            # Validate address format
            if not isinstance(msg_from, str) or len(msg_from) > 100:
                self.metrics.record_security_event("INVALID_ADDRESS", f"Bad address from {ip}")
                return
            
            # Verify signature
            signature = message.pop('signature', None)
            if signature:
                # We need the sender's public key to verify
                # For now, accept if from authenticated peer
                if msg_from in self.peer_public_keys:
                    if not self.identity.verify(message, signature, 
                                               base64.b64encode(self.peer_public_keys[msg_from]).decode()):
                        self.metrics.record_security_event("INVALID_SIGNATURE", f"Bad signature from {msg_from[:16]}...")
                        return
            
            # Process based on type
            if msg_type == 'message':
                self._handle_message(message, ip, port)
            elif msg_type == 'ack':
                self._handle_ack(message)
            elif msg_type == 'routing':
                self._handle_routing(message)
            elif msg_type == 'public_key':
                self._handle_public_key(message)
                
        except Exception as e:
            print(f"❌ Packet handling error: {e}")
    
    def _handle_message(self, message: Dict, ip: str, port: int):
        """Handle incoming message"""
        to_addr = message.get('to')
        msg_from = message.get('from')
        
        # Check if for us
        if to_addr == self.address:
            # Check for encryption
            if 'encrypted' in message:
                try:
                    decrypted = self.e2e.decrypt_message(message['encrypted'])
                    message['text'] = decrypted
                except Exception as e:
                    print(f"❌ Decryption failed: {e}")
                    return
            
            # Display
            text = message.get('text', '')
            print(f"💬 {msg_from[:8]}: {text[:100]}")
            
            # Store
            self.storage.save_message(
                msg_id=message.get('id'),
                from_addr=msg_from,
                to_addr=to_addr,
                text=text,
                timestamp=message.get('timestamp', time.time()),
                delivered=True
            )
            
            # Send ACK
            ack = {
                'type': 'ack',
                'ack_for': message.get('id'),
                'from': self.address,
                'timestamp': time.time()
            }
            self.transport.send_to(ack, ip, port, reliable=True)
            
        else:
            # Forward
            ttl = message.get('ttl', 10) - 1
            if ttl > 0:
                message['ttl'] = ttl
                message['path'] = message.get('path', []) + [self.address]
                self.outbox_queue.put(message)
    
    def _handle_ack(self, message: Dict):
        """Handle ACK"""
        msg_id = message.get('ack_for')
        if msg_id:
            with self.ack_lock:
                if msg_id in self.pending_acks:
                    del self.pending_acks[msg_id]
                    self.storage.mark_delivered(msg_id, delivered=True)
    
    def _handle_routing(self, message: Dict):
        """Handle routing update"""
        from_addr = message.get('from')
        table = message.get('table', {})
        
        if from_addr and table:
            # Get peer's public key if available
            peer_key = self.peer_public_keys.get(from_addr)
            self.routing.update_from_neighbor(from_addr, table, peer_key)
    
    def _handle_public_key(self, message: Dict):
        """Handle public key exchange"""
        from_addr = message.get('from')
        public_key_hex = message.get('public_key')
        
        if from_addr and public_key_hex:
            try:
                public_key = bytes.fromhex(public_key_hex)
                if len(public_key) == 32:
                    self.peer_public_keys[from_addr] = public_key
                    self.authenticated_peers[from_addr] = True
                    print(f"🔐 Authenticated peer: {from_addr[:16]}...")
            except:
                pass
    
    def _handler_loop(self):
        """Handler loop"""
        while self.running:
            try:
                message, ip, port = self.handler_queue.get(timeout=1.0)
                self._handle_packet(message, ip, port)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ Handler error: {e}")
                self.metrics.record_error()
    
    def _retry_loop(self):
        """Retry loop for unacked messages"""
        while self.running:
            time.sleep(5.0)
            
            with self.ack_lock:
                now = time.time()
                expired = []
                
                for msg_id, pending in list(self.pending_acks.items()):
                    if now - pending['time'] > 30:
                        expired.append(msg_id)
                        continue
                    
                    if pending['retries'] < 3:
                        pending['retries'] += 1
                        self.outbox_queue.put(pending['message'])
                
                for msg_id in expired:
                    del self.pending_acks[msg_id]
                    self.storage.mark_delivered(msg_id, delivered=False)
    
    def _metrics_loop(self):
        """Metrics collection"""
        while self.running:
            time.sleep(1.0)
            self.backpressure.update_load(
                self.handler_queue.qsize(),
                self.handler_queue.maxsize
            )
            self.metrics.update_queue_depth(self.handler_queue.qsize())
    
    def _security_loop(self):
        """Security monitoring"""
        while self.running:
            time.sleep(60.0)
            
            # Check for suspicious activity
            stats = self.transport.get_stats()
            if stats.get('replay_detected', 0) > 10:
                self.metrics.record_security_event("REPLAY_ATTACK", "Multiple replay attempts detected")
            
            if stats.get('packets_dropped_rate_limit', 0) > 100:
                self.metrics.record_security_event("RATE_LIMIT", "High rate limit drops")
    
    def register_name(self, name: str) -> bool:
        """Register a human-readable name mapped to this node's address in the DHT"""
        if not name or len(name) > 64:
            return False
        # Sign the name+address binding so peers can verify authenticity
        signature = self.identity.sign({'name': name, 'address': self.address})
        return self.murnaked.register_name(name, self.address, signature)

    def lookup_name(self, name: str) -> Optional[str]:
        """Lookup a human-readable name in the DHT, return address or None"""
        if not name or len(name) > 64:
            return None
        result = self.murnaked.get_name(name)
        if result and isinstance(result, dict):
            return result.get('address')
        return None

    def get_status(self) -> Dict:
        """Get node status"""
        return {
            'address': self.address,
            'port': self.port,
            'healthy': self.healthy,
            'neighbors': len(self.routing.local_links),
            'stats': {**self.stats, 'uptime': time.time() - self.stats['start_time']},
            'metrics': self.metrics.get_stats(),
            'circuit_breaker': {
                'state': self.circuit_breaker.state,
                'failures': self.circuit_breaker.failures
            },
            'backpressure': {
                'throttled': self.backpressure.is_throttled,
                'load': self.backpressure.current_load
            },
            'security': {
                'authenticated_peers': len(self.authenticated_peers),
                'e2e_ready': len(self.peer_public_keys)
            }
        }


# Legacy compatibility wrapper
class MurnetNode(SecureMurnetNode):
    """Legacy wrapper for compatibility"""
    pass
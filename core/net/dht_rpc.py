#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET DHT RPC v5.0-SECURE - Authenticated DHT Operations
HMAC authentication, request signing, replay protection - SECURITY FIXES APPLIED
"""

import time
import threading
import hashlib
import json
import uuid
import hmac
from typing import Dict, List, Optional, Callable, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import queue

from core.identity.crypto import blake2b_hash, constant_time_compare, canonical_json, Identity


class DHTMessageType:
    """Authenticated DHT message types"""
    STORE = "dht_store"
    STORE_ACK = "dht_store_ack"
    RETRIEVE = "dht_get"
    RETRIEVE_ACK = "dht_get_ack"
    REPLICATE = "dht_rep"
    HINT = "dht_hint"
    PING = "dht_ping"
    PONG = "dht_pong"
    SYNC = "dht_sync"
    SYNC_ACK = "dht_sync_ack"


@dataclass
class DHTRequest:
    """Authenticated DHT request"""
    id: str
    type: str
    key: str
    data: Optional[bytes] = None
    ttl: Optional[int] = None
    replicas: List[str] = field(default_factory=list)
    sender: str = ""  # address отправителя
    timestamp: float = field(default_factory=time.time)
    signature: str = ""  # HMAC signature
    nonce: str = ""  # Anti-replay nonce


@dataclass  
class DHTResponse:
    """DHT response"""
    request_id: str
    success: bool
    data: Optional[bytes] = None
    error: Optional[str] = None
    from_node: str = ""
    timestamp: float = field(default_factory=time.time)
    signature: str = ""  # HMAC signature


@dataclass
class PendingDHTRequest:
    """Pending request with retry state"""
    request: DHTRequest
    callback: Optional[Callable[[DHTResponse], None]]
    sent_time: float
    retries: int = 0
    max_retries: int = 3


class DHTAuthManager:
    """Manages authentication for DHT operations with strict verification"""
    
    def __init__(self, node_identity):
        self.identity = node_identity
        self.peer_keys: Dict[str, bytes] = {}  # address -> shared secret
        self.key_lock = threading.RLock()
        self.recent_nonces: set = set()  # Anti-replay
        self.nonce_lock = threading.Lock()
        self.max_nonce_age = 300  # 5 minutes
        self.failed_attempts: Dict[str, int] = defaultdict(int)
        self.banned_peers: set = set()  # Ban list for repeated failures
        
    def get_shared_key(self, peer_address: str, peer_public_key: bytes) -> bytes:
        """Get or derive shared key with peer"""
        with self.key_lock:
            if peer_address in self.peer_keys:
                return self.peer_keys[peer_address]
            
            # Derive shared secret using X25519
            key = self.identity.derive_shared_secret(peer_public_key)
            self.peer_keys[peer_address] = key
            return key
    
    def sign_request(self, request: DHTRequest, peer_key: bytes) -> str:
        """Sign DHT request with HMAC-SHA3-256"""
        # Build canonical representation
        data = {
            'id': request.id,
            'type': request.type,
            'key': request.key,
            'sender': request.sender,
            'timestamp': int(request.timestamp),
            'nonce': request.nonce or uuid.uuid4().hex[:16]
        }
        
        if request.data:
            # Hash large data separately
            data['data_hash'] = blake2b_hash(request.data, digest_size=32).hex()
        
        message = canonical_json(data)
        signature = hmac.new(peer_key, message, hashlib.sha3_256).hexdigest()[:32]
        return signature
    
    # SECURITY FIX: Реальная верификация вместо заглушки
    def verify_request(self, request: DHTRequest, peer_key: bytes) -> bool:
        """Verify DHT request signature with strict checks"""
        # Check nonce replay
        with self.nonce_lock:
            if request.nonce in self.recent_nonces:
                print(f"🛡️  Replay attack detected from {request.sender[:16]}...")
                return False
            self.recent_nonces.add(request.nonce)
            
            # Cleanup old nonces periodically
            if len(self.recent_nonces) > 10000:
                self.recent_nonces = set(list(self.recent_nonces)[-5000:])
        
        # Check timestamp
        if abs(time.time() - request.timestamp) > self.max_nonce_age:
            print(f"🛡️  Expired request from {request.sender[:16]}...")
            return False
        
        # Reconstruct and verify signature
        expected_sig = self.sign_request(request, peer_key)
        if not constant_time_compare(request.signature.encode(), expected_sig.encode()):
            self.failed_attempts[request.sender] += 1
            if self.failed_attempts[request.sender] > 10:
                self.banned_peers.add(request.sender)
                print(f"🚫 Banned peer {request.sender[:16]}... for signature failures")
            return False
        
        # Reset failed attempts on success
        if request.sender in self.failed_attempts:
            del self.failed_attempts[request.sender]
        
        return True
    
    def sign_response(self, response: DHTResponse, peer_key: bytes) -> str:
        """Sign DHT response"""
        data = {
            'request_id': response.request_id,
            'success': response.success,
            'timestamp': int(response.timestamp),
            'from_node': response.from_node
        }
        
        if response.data:
            data['data_hash'] = blake2b_hash(response.data, digest_size=32).hex()
        
        message = canonical_json(data)
        signature = hmac.new(peer_key, message, hashlib.sha3_256).hexdigest()[:32]
        return signature
    
    def verify_response(self, response: DHTResponse, peer_key: bytes) -> bool:
        """Verify DHT response"""
        expected_sig = self.sign_response(response, peer_key)
        return constant_time_compare(response.signature.encode(), expected_sig.encode())
    
    def is_banned(self, peer_address: str) -> bool:
        """Check if peer is banned"""
        return peer_address in self.banned_peers or self.failed_attempts.get(peer_address, 0) > 10


class DHTRPCManager:
    """Secure RPC manager for DHT - SECURITY FIXES APPLIED"""

    def __init__(self, node_instance, murnaked_storage):
        self.node = node_instance
        self.storage = murnaked_storage
        self.transport = node_instance.transport
        self.routing = node_instance.routing
        
        # Authentication
        self.auth = DHTAuthManager(node_instance.identity)
        
        # Pending requests
        self.pending: Dict[str, PendingDHTRequest] = {}
        self.pending_lock = threading.RLock()
        
        # Handlers
        self.handlers: Dict[str, Callable[[Dict, str, int], None]] = {
            DHTMessageType.STORE: self._handle_store,
            DHTMessageType.RETRIEVE: self._handle_retrieve,
            DHTMessageType.REPLICATE: self._handle_replicate,
            DHTMessageType.HINT: self._handle_hint,
            DHTMessageType.PING: self._handle_ping,
            DHTMessageType.SYNC: self._handle_sync,
        }
        
        # Rate limiting
        self.request_counts: Dict[str, List[float]] = defaultdict(list)
        self.rate_lock = threading.Lock()
        self.max_requests_per_minute = 60
        
        # Stats
        self.stats = {
            'requests_sent': 0,
            'requests_received': 0,
            'requests_auth_failed': 0,
            'responses_sent': 0,
            'responses_received': 0,
            'timeouts': 0,
            'retries': 0,
            'rate_limited': 0,
        }
        
        self.running = False
        self.cleanup_thread: Optional[threading.Thread] = None

    def start(self):
        """Start RPC manager"""
        if self.running:
            return
        
        self.running = True
        self.transport.register_handler(self._on_dht_message)
        
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="DHT-RPC-Cleanup",
            daemon=True
        )
        self.cleanup_thread.start()
        
        print("🔥 Secure DHT RPC Manager started")

    def stop(self):
        """Stop RPC manager"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2.0)

    def _check_rate_limit(self, node_address: str) -> bool:
        """Check if node is within rate limit"""
        with self.rate_lock:
            now = time.time()
            
            # Cleanup old entries
            self.request_counts[node_address] = [
                t for t in self.request_counts[node_address]
                if now - t < 60
            ]
            
            # Check limit
            if len(self.request_counts[node_address]) >= self.max_requests_per_minute:
                self.stats['rate_limited'] += 1
                return False
            
            self.request_counts[node_address].append(now)
            return True

    def _on_dht_message(self, message: Dict, ip: str, port: int):
        """Handle incoming DHT message with authentication"""
        msg_type = message.get('dht_type')
        
        if not msg_type:
            return
        
        sender = message.get('dht_sender', '')
        
        # Check if banned
        if self.auth.is_banned(sender):
            return
        
        # Rate limiting
        if not self._check_rate_limit(sender):
            return
        
        self.stats['requests_received'] += 1
        
        # SECURITY FIX: Verify authentication for ALL messages except PING
        if msg_type != DHTMessageType.PING:
            if not self._verify_message_auth(message, sender):
                self.stats['requests_auth_failed'] += 1
                print(f"🛡️  Auth failed for {msg_type} from {sender[:16]}...")
                return
        
        handler = self.handlers.get(msg_type)
        if handler:
            try:
                handler(message, ip, port)
            except Exception as e:
                print(f"❌ DHT handler error ({msg_type}): {e}")
        elif msg_type.endswith('_ack'):
            self._handle_response(message)

    # SECURITY FIX: Реальная верификация вместо return True
    def _verify_message_auth(self, message: Dict, sender: str) -> bool:
        """Verify message authentication with strict checks"""
        # Get peer's public key from storage
        peer_info = self.node.storage.get_peer(sender)
        if not peer_info:
            print(f"🛡️  Unknown peer: {sender[:16]}...")
            return False
        
        public_key = peer_info.get('public_key')
        if not public_key:
            print(f"🛡️  No public key for peer: {sender[:16]}...")
            return False
        
        # Get or derive shared key
        try:
            peer_key = self.auth.get_shared_key(sender, public_key)
        except Exception as e:
            print(f"🛡️  Key derivation failed for {sender[:16]}...: {e}")
            return False
        
        # Build request object
        request = DHTRequest(
            id=message.get('dht_id', ''),
            type=message.get('dht_type', ''),
            key=message.get('dht_key', ''),
            data=bytes.fromhex(message['dht_data']) if message.get('dht_data') else None,
            ttl=message.get('dht_ttl'),
            sender=sender,
            timestamp=message.get('dht_timestamp', 0),
            signature=message.get('dht_signature', ''),
            nonce=message.get('dht_nonce', '')
        )
        
        # Verify signature
        return self.auth.verify_request(request, peer_key)

    def _resolve_node(self, node_address: str) -> Optional[Tuple[str, int]]:
        """Resolve node address to IP:port"""
        # Check active peers
        for peer in self.transport.get_peers():
            if peer.get('address') == node_address:
                return (peer['ip'], peer['port'])
        
        # Check routing table
        route = self.node.storage.get_route(node_address)
        if route:
            next_hop = route.get('next_hop')
            if next_hop:
                return self._resolve_node(next_hop)
        
        return None

    def store_remote(self, node_address: str, key: str, data: bytes,
                     ttl: Optional[int] = None,
                     callback: Optional[Callable[[bool], None]] = None) -> str:
        """Send authenticated STORE request"""
        # Get peer info and key
        peer_info = self.node.storage.get_peer(node_address)
        if not peer_info or not peer_info.get('public_key'):
            print(f"⚠️  Cannot authenticate to {node_address[:16]}...")
            if callback:
                callback(False)
            return ""
        
        peer_key = self.auth.get_shared_key(
            node_address, 
            peer_info['public_key']
        )
        
        # Generate nonce
        nonce = uuid.uuid4().hex[:16]
        
        request = DHTRequest(
            id=str(uuid.uuid4()),
            type=DHTMessageType.STORE,
            key=key,
            data=data,
            ttl=ttl,
            sender=self.node.address,
            nonce=nonce
        )
        
        # Sign request
        request.signature = self.auth.sign_request(request, peer_key)
        
        def response_callback(response: DHTResponse):
            if callback:
                callback(response.success)
        
        self._send_request(node_address, request, response_callback, peer_key)
        self.stats['requests_sent'] += 1
        
        return request.id

    def retrieve_remote(self, node_address: str, key: str,
                        callback: Optional[Callable[[Optional[bytes]], None]] = None) -> str:
        """Send authenticated RETRIEVE request"""
        peer_info = self.node.storage.get_peer(node_address)
        if not peer_info or not peer_info.get('public_key'):
            if callback:
                callback(None)
            return ""
        
        peer_key = self.auth.get_shared_key(
            node_address,
            peer_info['public_key']
        )
        
        nonce = uuid.uuid4().hex[:16]
        
        request = DHTRequest(
            id=str(uuid.uuid4()),
            type=DHTMessageType.RETRIEVE,
            key=key,
            sender=self.node.address,
            nonce=nonce
        )
        
        request.signature = self.auth.sign_request(request, peer_key)
        
        def response_callback(response: DHTResponse):
            if callback:
                callback(response.data if response.success else None)
        
        self._send_request(node_address, request, response_callback, peer_key)
        self.stats['requests_sent'] += 1
        
        return request.id
    
    def replicate_remote(self, node_address: str, key: str, data: bytes,
                        original_key: str) -> bool:
        """Send REPLICATE request"""
        peer_info = self.node.storage.get_peer(node_address)
        if not peer_info or not peer_info.get('public_key'):
            return False
        
        peer_key = self.auth.get_shared_key(
            node_address,
            peer_info['public_key']
        )
        
        nonce = uuid.uuid4().hex[:16]
        
        request = DHTRequest(
            id=str(uuid.uuid4()),
            type=DHTMessageType.REPLICATE,
            key=key,
            data=data,
            sender=self.node.address,
            nonce=nonce
        )
        
        request.signature = self.auth.sign_request(request, peer_key)
        
        def dummy_callback(response):
            pass
        
        self._send_request(node_address, request, dummy_callback, peer_key)
        return True
    
    def send_hint(self, node_address: str, key: str, data: bytes) -> bool:
        """Send hinted handoff"""
        peer_info = self.node.storage.get_peer(node_address)
        if not peer_info or not peer_info.get('public_key'):
            return False
        
        peer_key = self.auth.get_shared_key(
            node_address,
            peer_info['public_key']
        )
        
        nonce = uuid.uuid4().hex[:16]
        
        request = DHTRequest(
            id=str(uuid.uuid4()),
            type=DHTMessageType.HINT,
            key=key,
            data=data,
            sender=self.node.address,
            nonce=nonce
        )
        
        request.signature = self.auth.sign_request(request, peer_key)
        
        def dummy_callback(response):
            pass
        
        self._send_request(node_address, request, dummy_callback, peer_key)
        return True

    def _send_request(self, node_address: str, request: DHTRequest,
                      callback: Optional[Callable[[DHTResponse], None]],
                      peer_key: bytes):
        """Send request to node"""
        peer_info = self._resolve_node(node_address)
        
        if not peer_info:
            print(f"⚠️  Cannot resolve node: {node_address[:16]}...")
            if callback:
                callback(DHTResponse(
                    request_id=request.id,
                    success=False,
                    error="Node not found"
                ))
            return
        
        ip, port = peer_info
        
        # Serialize request
        message = {
            'dht_type': request.type,
            'dht_id': request.id,
            'dht_key': request.key,
            'dht_data': request.data.hex() if request.data else None,
            'dht_ttl': request.ttl,
            'dht_sender': request.sender,
            'dht_timestamp': request.timestamp,
            'dht_signature': request.signature,
            'dht_nonce': request.nonce,
        }
        
        # Store pending
        if callback:
            with self.pending_lock:
                self.pending[request.id] = PendingDHTRequest(
                    request=request,
                    callback=callback,
                    sent_time=time.time()
                )
        
        # Send
        success = self.transport.send_to(message, ip, port, reliable=True)
        
        if not success and callback:
            with self.pending_lock:
                self.pending.pop(request.id, None)
            callback(DHTResponse(
                request_id=request.id,
                success=False,
                error="Send failed"
            ))

    def _handle_response(self, message: Dict):
        """Handle incoming response"""
        request_id = message.get('dht_request_id')
        
        with self.pending_lock:
            pending = self.pending.pop(request_id, None)
        
        if not pending:
            return
        
        self.stats['responses_received'] += 1
        
        # Build response
        response = DHTResponse(
            request_id=request_id,
            success=message.get('dht_success', False),
            data=bytes.fromhex(message['dht_data']) if message.get('dht_data') else None,
            error=message.get('dht_error'),
            from_node=message.get('dht_sender', ''),
            timestamp=time.time(),
            signature=message.get('dht_signature', '')
        )
        
        # Verify response if we have peer key
        peer_info = self.node.storage.get_peer(response.from_node)
        if peer_info and peer_info.get('public_key'):
            try:
                peer_key = self.auth.get_shared_key(
                    response.from_node,
                    peer_info['public_key']
                )
                if not self.auth.verify_response(response, peer_key):
                    print(f"⚠️  Response signature verification failed: {request_id}")
                    if pending.callback:
                        pending.callback(DHTResponse(
                            request_id=request_id,
                            success=False,
                            error="Signature verification failed"
                        ))
                    return
            except Exception as e:
                print(f"⚠️  Response verification error: {e}")
        
        # Call callback
        if pending.callback:
            try:
                pending.callback(response)
            except Exception as e:
                print(f"❌ DHT callback error: {e}")

    def _handle_store(self, message: Dict, ip: str, port: int):
        """Handle authenticated STORE"""
        key = message.get('dht_key')
        data_hex = message.get('dht_data')
        ttl = message.get('dht_ttl')
        sender = message.get('dht_sender')
        request_id = message.get('dht_id')
        
        success = False
        if key and data_hex:
            try:
                # Validate key format
                if not isinstance(key, str) or len(key) > 256:
                    raise ValueError("Invalid key format")
                
                # Validate data size
                data = bytes.fromhex(data_hex)
                if len(data) > 10 * 1024 * 1024:  # 10MB max
                    raise ValueError("Data too large")
                
                success = self.storage.store(
                    key=key,
                    data=data,
                    ttl=ttl,
                    context={'from': sender, 'replica': True}
                )
            except Exception as e:
                print(f"❌ Store error: {e}")
        
        self._send_ack(ip, port, request_id, success, key=key)

    def _handle_retrieve(self, message: Dict, ip: str, port: int):
        """Handle RETRIEVE"""
        key = message.get('dht_key')
        request_id = message.get('dht_id')
        
        data = None
        success = False
        
        if key and isinstance(key, str) and len(key) <= 256:
            entry = self.storage.local_store.get(key)
            if entry and not entry.is_expired():
                data = entry.data
                success = True
        
        self._send_ack(ip, port, request_id, success, data=data, key=key)

    def _handle_replicate(self, message: Dict, ip: str, port: int):
        """Handle REPLICATE"""
        key = message.get('dht_key')
        data_hex = message.get('dht_data')
        ttl = message.get('dht_ttl')
        
        if key and data_hex:
            try:
                data = bytes.fromhex(data_hex)
                if len(data) <= 10 * 1024 * 1024:
                    self.storage.store(key=key, data=data, ttl=ttl)
                    self.stats['responses_sent'] += 1
            except Exception as e:
                print(f"❌ Replicate error: {e}")

    def _handle_hint(self, message: Dict, ip: str, port: int):
        """Handle hinted handoff"""
        key = message.get('dht_key')
        data_hex = message.get('dht_data')
        target_node = message.get('dht_target')
        
        if key and data_hex and target_node:
            try:
                data = bytes.fromhex(data_hex)
                with self.storage.hints_lock:
                    from core.murnaked import HintedHandoff
                    self.storage.hints.append(HintedHandoff(
                        target_node=target_node,
                        key=key,
                        data=data,
                        timestamp=time.time()
                    ))
            except Exception as e:
                print(f"❌ Hint error: {e}")

    def _handle_ping(self, message: Dict, ip: str, port: int):
        """Handle PING"""
        request_id = message.get('dht_id')
        
        response = {
            'dht_type': DHTMessageType.PONG,
            'dht_request_id': request_id,
            'dht_success': True,
            'dht_sender': self.node.address,
            'dht_timestamp': time.time()
        }
        
        self.transport.send_to(response, ip, port, reliable=False)
        self.stats['responses_sent'] += 1

    def _handle_sync(self, message: Dict, ip: str, port: int):
        """Handle SYNC"""
        request_id = message.get('dht_id')
        self._send_ack(ip, port, request_id, True)

    def _send_ack(self, ip: str, port: int, request_id: str, 
                  success: bool, data: Optional[bytes] = None,
                  key: Optional[str] = None, error: Optional[str] = None):
        """Send ACK response with signature"""
        # Get peer info for signing
        peer_addr = None
        peer_key = None
        
        for peer in self.transport.get_peers():
            if peer['ip'] == ip and peer['port'] == port:
                peer_addr = peer['address']
                break
        
        if peer_addr:
            peer_info = self.node.storage.get_peer(peer_addr)
            if peer_info and peer_info.get('public_key'):
                try:
                    peer_key = self.auth.get_shared_key(
                        peer_addr,
                        peer_info['public_key']
                    )
                except:
                    pass
        
        response = {
            'dht_type': DHTMessageType.STORE_ACK,
            'dht_request_id': request_id,
            'dht_success': success,
            'dht_data': data.hex() if data else None,
            'dht_key': key,
            'dht_error': error,
            'dht_sender': self.node.address,
            'dht_timestamp': time.time()
        }
        
        # Sign response if we have peer key
        if peer_key:
            resp_obj = DHTResponse(
                request_id=request_id,
                success=success,
                data=data,
                from_node=self.node.address
            )
            response['dht_signature'] = self.auth.sign_response(resp_obj, peer_key)
        
        self.transport.send_to(response, ip, port, reliable=True)
        self.stats['responses_sent'] += 1

    def _cleanup_loop(self):
        """Cleanup expired requests and nonces"""
        while self.running:
            time.sleep(5.0)
            
            now = time.time()
            timeout = 10.0
            
            with self.pending_lock:
                expired = []
                
                for req_id, pending in list(self.pending.items()):
                    if now - pending.sent_time > timeout:
                        expired.append(req_id)
                        
                        if pending.retries < pending.max_retries:
                            pending.retries += 1
                            pending.sent_time = now
                            
                            peer_info = self._resolve_node(pending.request.sender)
                            if peer_info:
                                ip, port = peer_info
                                
                                # Get peer key for resend
                                peer_storage = self.node.storage.get_peer(pending.request.sender)
                                peer_key = None
                                if peer_storage and peer_storage.get('public_key'):
                                    try:
                                        peer_key = self.auth.get_shared_key(
                                            pending.request.sender,
                                            peer_storage['public_key']
                                        )
                                    except:
                                        continue
                                
                                message = {
                                    'dht_type': pending.request.type,
                                    'dht_id': pending.request.id,
                                    'dht_key': pending.request.key,
                                    'dht_data': pending.request.data.hex() if pending.request.data else None,
                                    'dht_sender': self.node.address,
                                    'dht_signature': pending.request.signature,
                                    'dht_nonce': pending.request.nonce,
                                }
                                self.transport.send_to(message, ip, port, reliable=True)
                                self.stats['retries'] += 1
                        else:
                            if pending.callback:
                                try:
                                    pending.callback(DHTResponse(
                                        request_id=req_id,
                                        success=False,
                                        error="Timeout"
                                    ))
                                except:
                                    pass
                            self.stats['timeouts'] += 1
                
                for req_id in expired:
                    if req_id in self.pending:
                        del self.pending[req_id]
            
            # Cleanup rate limiters
            with self.rate_lock:
                stale = [
                    addr for addr, times in self.request_counts.items()
                    if not times or now - times[-1] > 300
                ]
                for addr in stale:
                    del self.request_counts[addr]

    def get_stats(self) -> Dict:
        """Get RPC stats"""
        with self.pending_lock:
            pending_count = len(self.pending)
        
        return {
            **self.stats,
            'pending_requests': pending_count,
        }

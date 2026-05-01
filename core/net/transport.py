import socket
import threading
import time
import json
import struct
import random
import hashlib
import hmac
from typing import Dict, List, Optional, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import queue

from core.identity.crypto import blake2b_hash, secure_random_bytes, constant_time_compare


class PacketType(Enum):
    PING = 0x01
    PONG = 0x02
    HELLO = 0x03
    ACK = 0x04
    DATA = 0x10
    DATA_FRAG = 0x11
    AUTH = 0x20  # New: Authentication packet


@dataclass
class PacketHeader:
    """Packet header with authentication tag"""
    version: int = 1
    packet_type: PacketType = PacketType.DATA
    sequence: int = 0
    ack_sequence: int = 0
    payload_length: int = 0
    timestamp: int = 0  # Unix timestamp for replay protection
    auth_tag: bytes = field(default_factory=lambda: b'\x00' * 16)
    
    STRUCT_FORMAT = '!BBIIHII'
    SIZE = 20  # Without auth_tag (struct.calcsize('!BBIIHII') == 20)
    FULL_SIZE = 36  # With 16-byte auth_tag
    
    def encode(self) -> bytes:
        return struct.pack(
            self.STRUCT_FORMAT,
            self.version,
            self.packet_type.value,
            self.sequence,
            self.ack_sequence,
            self.payload_length,
            self.timestamp,
            0  # Reserved
        ) + self.auth_tag
    
    @classmethod
    def decode(cls, data: bytes) -> 'PacketHeader':
        if len(data) < cls.FULL_SIZE:
            raise ValueError("Packet too short")
        
        vals = struct.unpack(cls.STRUCT_FORMAT, data[:cls.SIZE])
        return cls(
            version=vals[0],
            packet_type=PacketType(vals[1]),
            sequence=vals[2],
            ack_sequence=vals[3],
            payload_length=vals[4],
            timestamp=vals[5],
            auth_tag=data[cls.SIZE:cls.FULL_SIZE]
        )


@dataclass 
class PeerConnection:
    """Enhanced peer connection with security state"""
    addr: Tuple[str, int]
    address: str
    public_key: Optional[bytes] = None
    session_key: Optional[bytes] = None
    
    # Sequence tracking for replay protection
    next_send_seq: int = field(default_factory=lambda: random.randint(1, 1000000))
    next_expected_seq: int = 1
    received_sequences: Set[int] = field(default_factory=set)  # Sliding window
    max_received_seq: int = 0
    
    # Reliability
    unacked_packets: Dict[int, Tuple[bytes, float]] = field(default_factory=dict)
    rtt_samples: deque = field(default_factory=lambda: deque(maxlen=10))
    
    # Security
    last_seen: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    failed_attempts: int = 0
    handshake_complete: bool = False
    is_active: bool = True
    is_authenticated: bool = False  # New: explicit auth state
    
    # Rate limiting
    packet_times: deque = field(default_factory=lambda: deque(maxlen=200))
    
    @property
    def rtt(self) -> float:
        if not self.rtt_samples:
            return 0.5
        return sum(self.rtt_samples) / len(self.rtt_samples)
    
    @property
    def smooth_rtt(self) -> float:
        if len(self.rtt_samples) < 2:
            return self.rtt
        alpha = 0.125
        srtt = self.rtt_samples[0]
        for sample in list(self.rtt_samples)[1:]:
            srtt = (1 - alpha) * srtt + alpha * sample
        return srtt
    
    def check_rate_limit(self, max_pps: int = 100) -> bool:
        """Check if peer is within rate limit"""
        now = time.time()
        # Remove old entries (> 1 second)
        while self.packet_times and now - self.packet_times[0] > 1.0:
            self.packet_times.popleft()
        
        self.packet_times.append(now)
        return len(self.packet_times) <= max_pps
    
    def is_sequence_valid(self, seq: int, window_size: int = 1000) -> bool:
        """Check if sequence number is valid (not replay)"""
        # Too old
        if seq < self.max_received_seq - window_size:
            return False
        
        # Already received
        if seq in self.received_sequences:
            return False
        
        return True
    
    def record_sequence(self, seq: int, window_size: int = 1000):
        """Record received sequence number"""
        self.received_sequences.add(seq)
        
        if seq > self.max_received_seq:
            self.max_received_seq = seq
        
        # Cleanup old sequences
        cutoff = self.max_received_seq - window_size
        self.received_sequences = {s for s in self.received_sequences if s > cutoff}


class RateLimiter:
    """Token bucket rate limiter per IP"""
    
    def __init__(self, rate: int = 100, burst: int = 200):
        self.rate = rate  # tokens per second
        self.burst = burst  # max tokens
        self.buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_update)
        self.lock = threading.RLock()
    
    def allow(self, ip: str) -> bool:
        """Check if request from IP is allowed"""
        with self.lock:
            now = time.time()
            
            if ip not in self.buckets:
                self.buckets[ip] = (self.burst, now)
            
            tokens, last_update = self.buckets[ip]
            
            # Add tokens based on time passed
            elapsed = now - last_update
            tokens = min(self.burst, tokens + elapsed * self.rate)
            
            if tokens >= 1:
                tokens -= 1
                self.buckets[ip] = (tokens, now)
                return True
            else:
                self.buckets[ip] = (tokens, now)
                return False
    
    def cleanup(self, max_age: float = 60.0):
        """Remove stale entries"""
        with self.lock:
            now = time.time()
            stale = [ip for ip, (_, last) in self.buckets.items()
                    if now - last >= max_age]
            for ip in stale:
                del self.buckets[ip]


class Transport:
    """Hardened UDP transport - SECURITY FIXES APPLIED"""
    
    MAX_PACKET_SIZE = 1400
    MAX_PAYLOAD = MAX_PACKET_SIZE - PacketHeader.FULL_SIZE - 32  # Auth tag overhead
    FRAGMENT_SIZE = 1200
    RETRANSMIT_BASE = 0.2
    MAX_RETRANSMITS = 5
    
    # Security limits - NEW: Enhanced limits
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB max message
    MAX_JSON_DEPTH = 10  # Max nesting depth
    MAX_JSON_LENGTH = 1024 * 1024  # 1MB max JSON
    RATE_LIMIT_PPS = 100  # Packets per second per peer
    GLOBAL_RATE_LIMIT = 10000  # Global packets per second
    REPLAY_WINDOW = 300  # 5 minutes replay protection
    
    def __init__(self, port: int = 0, bind_host: str = '0.0.0.0'):
        self.port = port
        self.bind_host = bind_host
        self.socket: Optional[socket.socket] = None
        self.running = False
        
        # Peers
        self.peers: Dict[str, PeerConnection] = {}
        self.peers_by_addr: Dict[Tuple[str, int], str] = {}
        self.peers_lock = threading.RLock()
        
        # Rate limiting
        self.rate_limiter = RateLimiter(rate=100, burst=200)
        self.global_rate_limiter = RateLimiter(rate=self.GLOBAL_RATE_LIMIT, burst=self.GLOBAL_RATE_LIMIT * 2)
        
        # Handlers
        self.message_handlers: List[Callable] = []
        self.connect_handlers: List[Callable] = []
        
        # Queues
        self.send_queue: queue.Queue = queue.Queue(maxsize=10000)
        
        # Stats
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'packets_retransmitted': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_dropped_rate_limit': 0,
            'packets_dropped_invalid': 0,
            'replay_detected': 0,
            'errors': 0
        }
        self.stats_lock = threading.Lock()
        
        # Threads
        self._threads: List[threading.Thread] = []
        self.on_peer_connected: Optional[Callable] = None
        self.on_peer_disconnected: Optional[Callable] = None
        
        # Node identity
        self._node_address = ""
        self._public_key = b""
        self._private_key = b""
        self._x25519_public_key = b""  # X25519 public key for ECDH
    
    def start(self, node_address: str = "", public_key: bytes = b"",
              private_key: bytes = b"") -> int:
        """Start transport with identity"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        
        # Set timeout for clean shutdown
        self.socket.settimeout(1.0)
        
        self.socket.bind((self.bind_host, self.port))
        self.port = self.socket.getsockname()[1]
        
        self.running = True
        self._node_address = node_address
        self._public_key = public_key
        self._private_key = private_key

        # Pre-compute X25519 public key for ECDH in HELLO packets
        if private_key:
            try:
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                _x25519_priv = X25519PrivateKey.from_private_bytes(private_key)
                self._x25519_public_key = _x25519_priv.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
            except Exception:
                self._x25519_public_key = public_key  # Fallback
        
        # Start threads
        self._threads = [
            threading.Thread(target=self._receive_loop, name="Transport-Recv", daemon=True),
            threading.Thread(target=self._send_loop, name="Transport-Send", daemon=True),
            threading.Thread(target=self._retransmit_loop, name="Transport-Retx", daemon=True),
            threading.Thread(target=self._keepalive_loop, name="Transport-Keepalive", daemon=True),
            threading.Thread(target=self._cleanup_loop, name="Transport-Cleanup", daemon=True),
        ]
        
        for t in self._threads:
            t.start()
        
        print(f"🚀 Secure Transport started on {self.bind_host}:{self.port}")
        return self.port
    
    def stop(self):
        """Stop transport gracefully"""
        print("🛑 Stopping secure transport...")
        self.running = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        for t in self._threads:
            t.join(timeout=2.0)
        
        print("✅ Transport stopped")
    
    def register_handler(self, handler: Callable[[dict, str, int], None]):
        self.message_handlers.append(handler)
    
    def register_connect_handler(self, handler: Callable[[str, Tuple[str, int]], None]):
        self.connect_handlers.append(handler)
    
    def _get_or_create_peer(self, addr: Tuple[str, int], 
                           address: Optional[str] = None) -> Optional[PeerConnection]:
        with self.peers_lock:
            if address and address in self.peers:
                peer = self.peers[address]
                if peer.addr != addr:
                    self.peers_by_addr.pop(peer.addr, None)
                    peer.addr = addr
                    self.peers_by_addr[addr] = address
                return peer
            
            if addr in self.peers_by_addr:
                return self.peers[self.peers_by_addr[addr]]
            
            if address:
                peer = PeerConnection(addr=addr, address=address)
                self.peers[address] = peer
                self.peers_by_addr[addr] = address
                return peer
            
            return None
    
    # SECURITY FIX: Убрано использование приватного ключа в HMAC
    def _compute_auth_tag(self, header_bytes: bytes, payload: bytes, 
                         peer_key: Optional[bytes] = None) -> bytes:
        """Compute authentication tag using HMAC-BLAKE2b
        
        SECURITY FIX: Never use private key for HMAC!
        """
        # SECURITY FIX: Если нет peer_key, возвращаем нулевой тег (неаутентифицированный)
        # Никогда не используем приватный ключ!
        if peer_key is None:
            return b'\x00' * 16  # Только для неаутентифицированных пакетов (HELLO)
        
        # HMAC using Blake2b
        mac_data = header_bytes + payload
        return blake2b_hash(mac_data, key=peer_key, digest_size=16)
    
    def _verify_auth_tag(self, header: PacketHeader, payload: bytes,
                        peer: PeerConnection) -> bool:
        """Verify packet authentication"""
        if not peer.session_key and not peer.public_key:
            # Not authenticated yet - allow HELLO packets only
            return header.packet_type == PacketType.HELLO
        
        key = peer.session_key or peer.public_key
        expected = self._compute_auth_tag(
            header.encode()[:PacketHeader.SIZE], 
            payload, 
            key
        )
        
        return constant_time_compare(header.auth_tag, expected)
    
    def _receive_loop(self):
        """Main receive loop with security checks"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(2048)
                
                # Global rate limit
                if not self.global_rate_limiter.allow(addr[0]):
                    with self.stats_lock:
                        self.stats['packets_dropped_rate_limit'] += 1
                    continue
                
                # Minimum size check
                if len(data) < PacketHeader.FULL_SIZE:
                    continue
                
                try:
                    header = PacketHeader.decode(data)
                    payload = data[PacketHeader.FULL_SIZE:]
                except:
                    with self.stats_lock:
                        self.stats['packets_dropped_invalid'] += 1
                    continue
                
                # Validate payload length
                if len(payload) != header.payload_length:
                    with self.stats_lock:
                        self.stats['packets_dropped_invalid'] += 1
                    continue
                
                # Replay protection - check timestamp
                now = int(time.time())
                if abs(now - header.timestamp) > self.REPLAY_WINDOW:
                    with self.stats_lock:
                        self.stats['replay_detected'] += 1
                    continue
                
                self._handle_packet(header, payload, addr)
                
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    raise
                break
            except Exception as e:
                with self.stats_lock:
                    self.stats['errors'] += 1
                print(f"Receive error: {e}")
    
    def _handle_packet(self, header: PacketHeader, payload: bytes, addr: Tuple[str, int]):
        """Handle received packet with security checks"""
        with self.stats_lock:
            self.stats['packets_received'] += 1
            self.stats['bytes_received'] += len(payload)
        
        # Get or create peer
        peer = self._get_or_create_peer(addr)
        
        if peer:
            # Per-peer rate limiting
            if not peer.check_rate_limit(self.RATE_LIMIT_PPS):
                peer.failed_attempts += 1
                if peer.failed_attempts > 10:
                    peer.is_active = False
                return
            
            # Sequence validation (replay protection)
            if not peer.is_sequence_valid(header.sequence):
                with self.stats_lock:
                    self.stats['replay_detected'] += 1
                return
            
            peer.record_sequence(header.sequence)
            peer.last_seen = time.time()
            peer.packets_received += 1
            peer.bytes_received += len(payload)
            
            # Verify authentication
            if not self._verify_auth_tag(header, payload, peer):
                peer.failed_attempts += 1
                return
            
            # Process ACK
            if header.ack_sequence > 0:
                self._process_ack(peer, header.ack_sequence)
        
        # Handle by type
        if header.packet_type == PacketType.HELLO:
            self._handle_hello(payload, addr)
        elif header.packet_type == PacketType.PING:
            self._send_pong(addr, header.sequence)
        elif header.packet_type == PacketType.PONG:
            if peer and header.sequence in peer.unacked_packets:
                _, sent_time = peer.unacked_packets.pop(header.sequence)
                peer.rtt_samples.append(time.time() - sent_time)
        elif header.packet_type == PacketType.DATA:
            self._handle_data(peer, header, payload, addr)
        elif header.packet_type == PacketType.AUTH:
            self._handle_auth(peer, payload, addr)
    
    def _handle_hello(self, payload: bytes, addr: Tuple[str, int]):
        """Handle handshake with strict validation"""
        try:
            # SECURITY FIX: Limit payload size
            if len(payload) > 1024:
                return
            
            # SECURITY FIX: Safe JSON parsing with limits
            message = self._safe_json_loads(payload)
            if message is None:
                return
            
            # Validate required fields
            address = message.get('address')
            public_key_hex = message.get('public_key')
            
            if not address or not public_key_hex:
                return
            
            # Validate address format
            if not isinstance(address, str) or len(address) > 100:
                return
            
            # Validate public key
            try:
                public_key = bytes.fromhex(public_key_hex)
                if len(public_key) != 32:
                    return
            except:
                return

            # Network authentication token check (Layer 3 — Network Secret)
            from core.net.network_auth import verify_network_token, is_configured as _net_ok
            if _net_ok():
                _nn = message.get('net_nonce')
                _nt = message.get('net_token')
                if not _nn or not _nt:
                    return  # Missing token → reject silently
                try:
                    _nonce = bytes.fromhex(_nn)
                    _token = bytes.fromhex(_nt)
                    _ts = int(message.get('timestamp', 0))
                    if not verify_network_token(_nonce, _ts, _token):
                        return  # Bad token → reject silently
                except Exception:
                    return

            # Create/update peer
            peer = self._get_or_create_peer(addr, address)
            if peer:
                peer.public_key = public_key
                peer.handshake_complete = True
                
                # Derive session key
                if self._private_key:
                    from core.identity.crypto import Identity
                    temp_id = Identity(private_key=self._private_key)
                    peer.session_key = temp_id.derive_shared_secret(public_key)
                
                # Send our hello
                self._send_hello(addr)
                
                # Notify handlers
                for handler in self.connect_handlers:
                    try:
                        handler(address, addr)
                    except:
                        pass

                # Notify on_peer_connected callback (set by SecureMurnetNode)
                if self.on_peer_connected:
                    try:
                        self.on_peer_connected(address, addr)
                    except Exception:
                        pass
                        
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"Hello handling error: {e}")
    
    # SECURITY FIX: Safe JSON parsing with depth limit
    def _safe_json_loads(self, data: bytes, max_depth: int = 10) -> Optional[dict]:
        """Safely parse JSON with depth limit"""
        try:
            # Check size before parsing
            if len(data) > self.MAX_JSON_LENGTH:
                print(f"JSON payload too large: {len(data)} bytes")
                return None
            
            message = json.loads(data.decode('utf-8'))
            
            # Check depth
            def check_depth(obj, depth=0):
                if depth > max_depth:
                    raise ValueError("JSON too deeply nested")
                if isinstance(obj, dict):
                    for v in obj.values():
                        check_depth(v, depth + 1)
                elif isinstance(obj, list):
                    for v in obj:
                        check_depth(v, depth + 1)
            
            check_depth(message)
            return message
            
        except Exception as e:
            print(f"JSON parsing error: {e}")
            return None
    
    def _handle_data(self, peer: Optional[PeerConnection], 
                    header: PacketHeader, payload: bytes, addr: Tuple[str, int]):
        """Handle data packet with strict validation"""
        if not peer or not peer.handshake_complete:
            return
        
        # Send ACK
        self._send_ack(addr, header.sequence)
        
        try:
            # SECURITY FIX: Safe JSON parsing with limits
            if len(payload) > self.MAX_MESSAGE_SIZE:
                print(f"Payload too large: {len(payload)}")
                return
            
            message = self._safe_json_loads(payload)
            if message is None:
                return
            
            # Validate message fields
            msg_from = message.get('from')
            if msg_from and isinstance(msg_from, str) and len(msg_from) <= 100:
                if msg_from != peer.address:
                    with self.peers_lock:
                        if msg_from in self.peers:
                            old_peer = self.peers.pop(msg_from)
                            self.peers_by_addr.pop(old_peer.addr, None)
                        self.peers[msg_from] = peer
                        peer.address = msg_from
                        self.peers_by_addr[addr] = msg_from
            
            # Call handlers
            for handler in self.message_handlers:
                try:
                    handler(message, addr[0], addr[1])
                except Exception as e:
                    print(f"Handler error: {e}")
                    
        except Exception as e:
            print(f"Data handling error: {e}")
    
    def _handle_auth(self, peer: Optional[PeerConnection], payload: bytes, 
                    addr: Tuple[str, int]):
        """Handle authentication packet"""
        # Additional authentication logic can go here
        pass
    
    def _send_loop(self):
        """Send loop"""
        while self.running:
            try:
                item = self.send_queue.get(timeout=0.1)
                addr, data, packet_type, reliable = item
                self._send_packet(addr, data, packet_type, reliable)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Send loop error: {e}")
    
    def _send_packet(self, addr: Tuple[str, int], payload: bytes,
                    packet_type: PacketType = PacketType.DATA,
                    reliable: bool = True) -> int:
        """Send packet with authentication"""
        peer = None
        with self.peers_lock:
            if addr in self.peers_by_addr:
                peer = self.peers[self.peers_by_addr[addr]]
        
        seq = 0
        if peer:
            seq = peer.next_send_seq
            peer.next_send_seq += 1
        
        # Build header
        header = PacketHeader(
            version=1,
            packet_type=packet_type,
            sequence=seq,
            payload_length=len(payload),
            timestamp=int(time.time()),
            auth_tag=b'\x00' * 16  # Placeholder
        )
        
        # Compute auth tag - SECURITY FIX: never use private key
        key = peer.session_key if peer else None
        header.auth_tag = self._compute_auth_tag(
            header.encode()[:PacketHeader.SIZE],
            payload,
            key
        )
        
        packet = header.encode() + payload
        
        try:
            self.socket.sendto(packet, addr)
            
            with self.stats_lock:
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
            
            if peer:
                peer.packets_sent += 1
                peer.bytes_sent += len(packet)
                if reliable and seq > 0:
                    peer.unacked_packets[seq] = (packet, time.time())
            
            return seq
            
        except Exception as e:
            with self.stats_lock:
                self.stats['errors'] += 1
            print(f"Send error: {e}")
            return 0
    
    def _retransmit_loop(self):
        """Retransmit loop with exponential backoff"""
        while self.running:
            time.sleep(0.05)
            now = time.time()
            
            with self.peers_lock:
                peers = list(self.peers.values())
            
            for peer in peers:
                if not peer.is_active:
                    continue
                
                for seq, (packet, sent_time) in list(peer.unacked_packets.items()):
                    # Exponential backoff
                    rto = peer.smooth_rtt * (2 ** min(peer.failed_attempts, 4))
                    rto = max(rto, 0.1)
                    rto = min(rto, 30.0)  # Cap at 30 seconds
                    
                    if now - sent_time > rto:
                        if peer.failed_attempts < self.MAX_RETRANSMITS:
                            try:
                                self.socket.sendto(packet, peer.addr)
                                peer.unacked_packets[seq] = (packet, now)
                                with self.stats_lock:
                                    self.stats['packets_retransmitted'] += 1
                            except Exception as e:
                                print(f"Retransmit error: {e}")
                        else:
                            # Max retries exceeded
                            del peer.unacked_packets[seq]
                            peer.failed_attempts += 1
                
                # Cleanup old unacked
                cutoff = now - 60
                peer.unacked_packets = {
                    seq: (pkt, t) for seq, (pkt, t) in peer.unacked_packets.items()
                    if t > cutoff
                }
    
    def _keepalive_loop(self):
        """Keepalive with timeout detection"""
        while self.running:
            time.sleep(15)
            now = time.time()
            
            with self.peers_lock:
                peers = list(self.peers.items())
            
            for address, peer in peers:
                # Timeout detection
                if now - peer.last_seen > 60:
                    print(f"Peer {address[:16]}... timed out")
                    peer.is_active = False
                    if self.on_peer_disconnected:
                        self.on_peer_disconnected(address)
                    continue
                
                # Send keepalive if idle
                if now - peer.last_seen > 10:
                    self._send_ping(peer.addr)
    
    def _cleanup_loop(self):
        """Periodic cleanup tasks"""
        while self.running:
            time.sleep(60)
            
            # Cleanup rate limiters
            self.rate_limiter.cleanup()
            self.global_rate_limiter.cleanup()
            
            # Cleanup stale peers
            with self.peers_lock:
                stale = [
                    addr for addr, peer in self.peers.items()
                    if not peer.is_active and time.time() - peer.last_seen > 300
                ]
                for addr in stale:
                    peer = self.peers.pop(addr, None)
                    if peer:
                        self.peers_by_addr.pop(peer.addr, None)
    
    def _send_ping(self, addr: Tuple[str, int]):
        """Send ping"""
        payload = struct.pack('!d', time.time())
        self._send_packet(addr, payload, PacketType.PING, reliable=False)
    
    def _send_pong(self, addr: Tuple[str, int], ping_seq: int):
        """Send pong"""
        payload = struct.pack('!I', ping_seq)
        self.send_queue.put((addr, payload, PacketType.PONG, False))
    
    def _send_ack(self, addr: Tuple[str, int], sequence: int):
        """Send ACK"""
        payload = struct.pack('!I', sequence)
        self.send_queue.put((addr, payload, PacketType.ACK, False))
    
    def _process_ack(self, peer: PeerConnection, ack_seq: int):
        """Process ACK"""
        if ack_seq in peer.unacked_packets:
            _, sent_time = peer.unacked_packets.pop(ack_seq)
            peer.rtt_samples.append(time.time() - sent_time)
            peer.failed_attempts = max(0, peer.failed_attempts - 1)
    
    def _send_hello(self, addr: Tuple[str, int]):
        """Send hello packet"""
        # Send X25519 public key (not Ed25519) so ECDH session keys match on both sides
        x25519_key = self._x25519_public_key or self._public_key
        hello_data = {
            'version': '5.0-secure',
            'address': self._node_address,
            'public_key': x25519_key.hex() if x25519_key else '',
            'timestamp': int(time.time()),
            'capabilities': ['auth', 'encrypt', 'compress']
        }

        # Network authentication token (Layer 3 — Network Secret)
        import os as _os
        from core.net.network_auth import make_network_token, is_configured as _net_ok
        if _net_ok():
            _nonce = _os.urandom(32)
            _token = make_network_token(_nonce, hello_data['timestamp'])
            hello_data['net_nonce'] = _nonce.hex()
            hello_data['net_token'] = _token.hex()

        payload = json.dumps(hello_data, ensure_ascii=False).encode('utf-8')
        self._send_packet(addr, payload, PacketType.HELLO, reliable=False)
    
    def connect_to(self, ip: str, port: int, address: Optional[str] = None) -> bool:
        """Connect to peer"""
        addr = (ip, port)
        
        if address:
            self._get_or_create_peer(addr, address)
        
        self._send_hello(addr)
        return True
    
    def send_to(self, message: dict, ip: str, port: int, 
                reliable: bool = True) -> bool:
        """Send message to address"""
        try:
            # SECURITY FIX: Validate message size before serialization
            payload = json.dumps(message, ensure_ascii=False).encode('utf-8')
            
            if len(payload) > self.MAX_MESSAGE_SIZE:
                print(f"Message too large: {len(payload)} bytes")
                return False
            
            if len(payload) > self.MAX_PAYLOAD:
                print(f"Message too large for single packet: {len(payload)} bytes")
                return False
            
            self.send_queue.put(((ip, port), payload, PacketType.DATA, reliable))
            return True
            
        except Exception as e:
            print(f"Send error: {e}")
            return False
    
    def send_to_peer(self, message: dict, address: str, 
                    reliable: bool = True) -> bool:
        """Send message to peer by address"""
        with self.peers_lock:
            peer = self.peers.get(address)
        
        if not peer or not peer.is_active:
            return False
        
        return self.send_to(message, peer.addr[0], peer.addr[1], reliable)
    
    def broadcast(self, message: dict, reliable: bool = False) -> int:
        """Broadcast to all peers"""
        with self.peers_lock:
            peers = list(self.peers.values())
        
        sent = 0
        for peer in peers:
            if peer.is_active and peer.handshake_complete:
                if self.send_to(message, peer.addr[0], peer.addr[1], reliable):
                    sent += 1
        
        return sent
    
    def get_peers(self) -> List[Dict]:
        """Get peer list"""
        with self.peers_lock:
            return [{
                'address': p.address,
                'ip': p.addr[0],
                'port': p.addr[1],
                'rtt': p.rtt,
                'last_seen': p.last_seen,
                'handshake_complete': p.handshake_complete,
                'is_active': p.is_active,
                'is_authenticated': p.is_authenticated,
                'failed_attempts': p.failed_attempts
            } for p in self.peers.values()]
    
    def get_peer_count(self) -> int:
        """Get active peer count"""
        with self.peers_lock:
            return sum(1 for p in self.peers.values() if p.is_active)
    
    def get_stats(self) -> Dict:
        """Get transport stats"""
        with self.stats_lock:
            return dict(self.stats)

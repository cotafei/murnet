"""
MURNET ROUTING v5.0-SECURE - Authenticated Link-State
Signed LSAs, replay protection, secure path computation
"""

import time
import threading
import heapq
import hmac
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

from core.identity.crypto import blake2b_hash, canonical_json


class LinkState(Enum):
    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"


@dataclass
class Link:
    neighbor: str = ""
    cost: float = 1.0
    bandwidth: float = 1000.0
    latency: float = 0.0
    loss_rate: float = 0.0
    state: LinkState = LinkState.UP
    last_updated: float = field(default_factory=time.time)
    
    def effective_cost(self) -> float:
        if self.state == LinkState.DOWN:
            return float('inf')
        cost = self.cost
        cost += self.loss_rate * 10
        cost += self.latency / 10
        cost *= (1 + (1000 - self.bandwidth) / 1000)
        return cost


@dataclass
class LSA:
    """Link State Advertisement with authentication"""
    origin: str
    sequence: int
    links: Dict[str, Link]
    timestamp: float
    ttl: int = 3600
    signature: str = ""  # HMAC signature
    hash_chain: str = ""  # For tamper detection
    
    def is_fresh(self) -> bool:
        return time.time() - self.timestamp < self.ttl
    
    def compute_hash(self, key: bytes) -> str:
        """Compute hash for signature verification"""
        def _serialize_link(link) -> dict:
            d = link.__dict__.copy()
            if hasattr(d.get('state'), 'value'):
                d['state'] = d['state'].value
            d.pop('last_updated', None)  # exclude volatile field from hash
            return d

        data = {
            'origin': self.origin,
            'sequence': self.sequence,
            'links': {k: _serialize_link(v) for k, v in self.links.items()},
            'timestamp': int(self.timestamp),
            'ttl': self.ttl
        }
        message = canonical_json(data)
        return blake2b_hash(message, key=key, digest_size=16).hex()


@dataclass
class Path:
    destination: str
    next_hops: List[str]
    cost: float
    segments: List[str] = field(default_factory=list)
    bandwidth: float = 0.0
    is_protected: bool = False
    backup_path: Optional[List[str]] = None
    trust_score: float = 1.0


class LinkStateDatabase:
    """Secure link-state database with authenticated updates"""
    
    def __init__(self, own_address: str, identity=None):
        self.own_address = own_address
        self.identity = identity
        self.lsdb: Dict[str, LSA] = {}
        self.lsdb_lock = threading.RLock()
        self.graph: Dict[str, Dict[str, Link]] = defaultdict(dict)
        self.sequence_numbers: Dict[str, int] = defaultdict(int)
        
        # Security
        self.received_sequences: Dict[str, Set[int]] = defaultdict(set)
        self.max_sequence_window = 1000
        self.trust_scores: Dict[str, float] = defaultdict(lambda: 0.5)
        
    def originate_lsa(self, links: Dict[str, Link]) -> LSA:
        """Create and sign LSA"""
        self.sequence_numbers[self.own_address] += 1
        
        lsa = LSA(
            origin=self.own_address,
            sequence=self.sequence_numbers[self.own_address],
            links=links,
            timestamp=time.time()
        )
        
        # Sign if we have identity
        if self.identity:
            # Use node's private key for signing
            key = self.identity.get_private_bytes()
            lsa.signature = lsa.compute_hash(key)
        
        with self.lsdb_lock:
            self.lsdb[self.own_address] = lsa
            self._update_graph()
        
        return lsa
    
    def receive_lsa(self, lsa: LSA, sender_public_key: Optional[bytes] = None) -> bool:
        """Receive and verify LSA"""
        with self.lsdb_lock:
            # Check sequence freshness
            if not self._is_sequence_valid(lsa.origin, lsa.sequence):
                return False
            
            # Verify timestamp
            if abs(time.time() - lsa.timestamp) > 300:  # 5 minutes
                return False
            
            # Verify signature if available
            if lsa.signature and sender_public_key:
                expected = lsa.compute_hash(sender_public_key)
                if not hmac.compare_digest(lsa.signature.encode(), expected.encode()):
                    # Signature mismatch - possible attack
                    self.trust_scores[lsa.origin] *= 0.5
                    return False
            
            existing = self.lsdb.get(lsa.origin)
            
            if existing and existing.sequence >= lsa.sequence:
                return False
            
            # Record sequence
            self.received_sequences[lsa.origin].add(lsa.sequence)
            self._cleanup_sequences(lsa.origin)
            
            self.lsdb[lsa.origin] = lsa
            self._update_graph()
            
            # Increase trust for valid update
            self.trust_scores[lsa.origin] = min(1.0, self.trust_scores[lsa.origin] + 0.1)
            
            return True
    
    def _is_sequence_valid(self, origin: str, sequence: int) -> bool:
        """Check if sequence number is valid (not replay)"""
        if sequence in self.received_sequences[origin]:
            return False
        
        max_seq = max(self.received_sequences[origin]) if self.received_sequences[origin] else 0
        if sequence < max_seq - self.max_sequence_window:
            return False
        
        return True
    
    def _cleanup_sequences(self, origin: str):
        """Cleanup old sequence numbers"""
        if len(self.received_sequences[origin]) > self.max_sequence_window:
            sorted_seqs = sorted(self.received_sequences[origin])
            self.received_sequences[origin] = set(sorted_seqs[-self.max_sequence_window:])
    
    def _update_graph(self):
        """Rebuild network graph from LSDB"""
        self.graph = defaultdict(dict)
        
        for lsa in self.lsdb.values():
            if not lsa.is_fresh():
                continue
            
            # Check trust score
            if self.trust_scores[lsa.origin] < 0.1:
                continue  # Ignore untrusted nodes
            
            for neighbor, link in lsa.links.items():
                self.graph[lsa.origin][neighbor] = link
                if lsa.origin not in self.graph[neighbor]:
                    self.graph[neighbor][lsa.origin] = Link(
                        neighbor=lsa.origin,
                        cost=link.cost,
                        bandwidth=link.bandwidth,
                        latency=link.latency
                    )
    
    def get_neighbors(self, node: str) -> Dict[str, Link]:
        with self.lsdb_lock:
            return dict(self.graph.get(node, {}))
    
    def get_trust_score(self, node: str) -> float:
        return self.trust_scores.get(node, 0.5)


class DijkstraEngine:
    """Secure path computation"""
    
    def __init__(self, lsdb: LinkStateDatabase):
        self.lsdb = lsdb
        
    def compute(self, source: str, min_trust: float = 0.3) -> Dict[str, Path]:
        """Compute paths with trust filtering"""
        with self.lsdb.lsdb_lock:
            graph = dict(self.lsdb.graph)
        
        if source not in graph:
            return {}
        
        distances: Dict[str, float] = {source: 0.0}
        predecessors: Dict[str, Set[str]] = defaultdict(set)
        visited: Set[str] = set()
        
        pq = [(0.0, source)]
        
        while pq:
            dist, current = heapq.heappop(pq)
            
            if current in visited:
                continue
            visited.add(current)
            
            # Check trust score
            if self.lsdb.get_trust_score(current) < min_trust:
                continue
            
            for neighbor, link in graph.get(current, {}).items():
                if neighbor in visited:
                    continue
                
                cost = link.effective_cost()
                if cost == float('inf'):
                    continue
                
                new_dist = dist + cost
                
                if neighbor not in distances or new_dist < distances[neighbor]:
                    distances[neighbor] = new_dist
                    predecessors[neighbor] = {current}
                    heapq.heappush(pq, (new_dist, neighbor))
                    
                elif abs(new_dist - distances[neighbor]) < 0.001:
                    predecessors[neighbor].add(current)
        
        paths = {}
        for dest, cost in distances.items():
            if dest == source:
                continue
            
            next_hops = self._find_next_hops(source, dest, predecessors, graph)
            segments = self._build_path(source, dest, predecessors)
            
            paths[dest] = Path(
                destination=dest,
                next_hops=next_hops,
                cost=cost,
                segments=segments,
                bandwidth=self._estimate_bandwidth(segments, graph),
                trust_score=self.lsdb.get_trust_score(dest)
            )
        
        return paths
    
    def _find_next_hops(self, source: str, dest: str, 
                       predecessors: Dict[str, Set[str]],
                       graph: Dict) -> List[str]:
        """Find next hops for ECMP"""
        next_hops = set()
        
        def traverse(node: str, visited: Set[str]):
            if node == source:
                return
            if node in visited:
                return
            visited.add(node)
            
            for pred in predecessors.get(node, set()):
                if pred == source:
                    next_hops.add(node)
                else:
                    traverse(pred, visited)
        
        traverse(dest, set())
        return list(next_hops)
    
    def _build_path(self, source: str, dest: str, 
                   predecessors: Dict[str, Set[str]]) -> List[str]:
        """Build path from predecessors"""
        path = [dest]
        current = dest
        
        while current != source:
            preds = predecessors.get(current, set())
            if not preds:
                break
            current = min(preds)  # Deterministic
            path.append(current)
        
        return list(reversed(path))
    
    def _estimate_bandwidth(self, path: List[str], graph: Dict) -> float:
        """Estimate path bandwidth"""
        if len(path) < 2:
            return 0.0
        
        min_bw = float('inf')
        for i in range(len(path) - 1):
            link = graph.get(path[i], {}).get(path[i+1])
            if link:
                min_bw = min(min_bw, link.bandwidth)
        
        return min_bw if min_bw != float('inf') else 0.0


class RoutingTable:
    """Secure routing table with authenticated updates"""
    
    def __init__(self, own_address: str, identity=None):
        self.own_address = own_address
        self.identity = identity
        self.lsdb = LinkStateDatabase(own_address, identity)
        self.dijkstra = DijkstraEngine(self.lsdb)
        
        self.paths: Dict[str, Path] = {}
        self.paths_lock = threading.RLock()
        
        self.local_links: Dict[str, Link] = {}
        self.ecmp_counters: Dict[str, int] = defaultdict(int)
        
        self.route_changes = 0
        self.last_recompute = 0
        
        self.routes: Dict[str, float] = {}
        self.max_hops: int = 10
        
        # Security
        self.attack_detection: Dict[str, Dict] = defaultdict(lambda: {
            'lsa_flood_count': 0,
            'last_lsa_time': 0,
            'suspicious_changes': 0
        })
    
    def add_link(self, neighbor: str, cost: float = 1.0, 
                bandwidth: float = 1000.0, latency: float = 0.0):
        """Add local link"""
        self.local_links[neighbor] = Link(
            neighbor=neighbor,
            cost=cost,
            bandwidth=bandwidth,
            latency=latency
        )
        self._originate_lsa()
    
    def add_neighbor(self, address: str):
        """Add neighbor"""
        self.add_link(address, cost=1.0)
        self.routes[address] = 1
    
    def remove_link(self, neighbor: str):
        """Remove link"""
        if neighbor in self.local_links:
            del self.local_links[neighbor]
            self._originate_lsa()
    
    def _originate_lsa(self):
        """Originate LSA with signing"""
        self.lsdb.originate_lsa(self.local_links)
        self.recompute()
    
    def receive_lsa(self, lsa: LSA, sender_public_key: Optional[bytes] = None) -> bool:
        """Receive LSA with attack detection"""
        # Flood detection
        now = time.time()
        detection = self.attack_detection[lsa.origin]
        
        if now - detection['last_lsa_time'] < 1.0:
            detection['lsa_flood_count'] += 1
            if detection['lsa_flood_count'] > 10:
                print(f"⚠️ LSA flood detected from {lsa.origin[:16]}...")
                return False
        else:
            detection['lsa_flood_count'] = 0
        
        detection['last_lsa_time'] = now
        
        # Process LSA
        is_new = self.lsdb.receive_lsa(lsa, sender_public_key)
        if is_new:
            self.recompute()
        
        return is_new
    
    def recompute(self):
        """Recompute routing table"""
        with self.paths_lock:
            new_paths = self.dijkstra.compute(self.own_address, min_trust=0.3)
            
            if new_paths != self.paths:
                self.route_changes += 1
                self.last_recompute = time.time()
            
            self.paths = new_paths
            self.routes = {dest: path.cost for dest, path in self.paths.items()}
    
    def get_next_hop(self, destination: str) -> Optional[str]:
        """Get next hop with ECMP"""
        with self.paths_lock:
            path = self.paths.get(destination)
            
            if not path or not path.next_hops:
                return None
            
            if len(path.next_hops) == 1:
                return path.next_hops[0]
            
            # ECMP
            counter = self.ecmp_counters[destination]
            next_hop = path.next_hops[counter % len(path.next_hops)]
            self.ecmp_counters[destination] = counter + 1
            
            return next_hop
    
    def get_all_routes(self) -> Dict[str, float]:
        with self.paths_lock:
            return dict(self.routes)
    
    def update_from_neighbor(self, neighbor: str, neighbor_table: dict,
                           neighbor_public_key: Optional[bytes] = None):
        """Update from neighbor with authentication"""
        links = {}
        for dest, cost in neighbor_table.items():
            if dest != self.own_address:
                links[dest] = Link(neighbor=dest, cost=float(cost))
        
        lsa = LSA(
            origin=neighbor,
            sequence=1,
            links=links,
            timestamp=time.time()
        )
        
        self.receive_lsa(lsa, neighbor_public_key)
        
        for dest, cost in neighbor_table.items():
            self.routes[dest] = cost
    
    def is_neighbor(self, address: str) -> bool:
        return address in self.local_links
    
    def get_stats(self) -> Dict:
        with self.paths_lock:
            return {
                'own_address': self.own_address,
                'paths_count': len(self.paths),
                'route_changes': self.route_changes,
                'last_recompute': self.last_recompute,
                'lsdb_size': len(self.lsdb.lsdb),
                'ecmp_paths': sum(1 for p in self.paths.values() if len(p.next_hops) > 1),
                'avg_trust_score': sum(self.lsdb.trust_scores.values()) / max(1, len(self.lsdb.trust_scores)),
                'attack_alerts': sum(1 for d in self.attack_detection.values() if d['lsa_flood_count'] > 5)
            }
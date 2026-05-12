"""
Circuit state for MurNet Onion Router.

Originator side: CircuitOrigin — ordered list of hops with their keys.
Relay side:      CircuitManager — forward/backward routing table.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class HopState:
    """One hop in an originator-side circuit."""
    peer_addr:  str    # MurNet address of this relay
    circuit_id: str    # circuit_id on the leg originator→this relay
    key:        bytes  # 32-byte session key shared with this relay


@dataclass
class CircuitOrigin:
    """
    Originator-side circuit.

    hops[0] = guard (first relay)
    hops[-1] = exit  (last relay)
    """
    id:   str             = field(default_factory=lambda: str(uuid.uuid4()))
    hops: List[HopState]  = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def first_peer(self) -> str:
        return self.hops[0].peer_addr

    @property
    def first_cid(self) -> str:
        return self.hops[0].circuit_id


@dataclass
class RelayEntry:
    """
    Relay-side routing entry for one circuit leg.

    upstream:   side closer to originator
    downstream: side closer to exit (None when this relay is the exit)
    key:        32-byte session key shared with originator for this leg
    """
    key:             bytes
    upstream_peer:   Optional[str]   # None when we ARE the originator
    upstream_cid:    str
    downstream_peer: Optional[str]   = None
    downstream_cid:  Optional[str]   = None


class CircuitManager:
    """Relay-side table: maps any circuit_id → RelayEntry."""

    def __init__(self) -> None:
        self._by_cid: Dict[str, RelayEntry] = {}

    def add(self, entry: RelayEntry) -> None:
        self._by_cid[entry.upstream_cid] = entry
        if entry.downstream_cid:
            self._by_cid[entry.downstream_cid] = entry

    def get(self, cid: str) -> Optional[RelayEntry]:
        return self._by_cid.get(cid)

    def remove(self, cid: str) -> None:
        entry = self._by_cid.pop(cid, None)
        if not entry:
            return
        other = (
            entry.downstream_cid
            if cid == entry.upstream_cid
            else entry.upstream_cid
        )
        self._by_cid.pop(other, None)

    def set_downstream(self, upstream_cid: str, peer: str, cid: str) -> None:
        entry = self._by_cid.get(upstream_cid)
        if not entry:
            raise KeyError(f"Unknown circuit {upstream_cid!r}")
        entry.downstream_peer = peer
        entry.downstream_cid  = cid
        self._by_cid[cid]     = entry

    def __len__(self) -> int:
        seen = set()
        for e in self._by_cid.values():
            seen.add(id(e))
        return len(seen)

"""
Relay directory — in-memory registry of known onion relay nodes.

Populated via gossip: each relay periodically announces itself to neighbours,
neighbours forward the announcement (TTL-limited).  No central server needed.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List


_DEFAULT_TTL = 300  # seconds a relay entry stays valid without a refresh


@dataclass
class RelayInfo:
    addr:      str
    name:      str
    timestamp: float = field(default_factory=time.time)
    ttl:       int   = _DEFAULT_TTL

    def is_alive(self) -> bool:
        return time.time() - self.timestamp < self.ttl

    def to_dict(self) -> dict:
        return {"addr": self.addr, "name": self.name,
                "timestamp": self.timestamp, "ttl": self.ttl}

    @classmethod
    def from_dict(cls, d: dict) -> "RelayInfo":
        return cls(addr=d["addr"], name=d["name"],
                   timestamp=d.get("timestamp", time.time()),
                   ttl=d.get("ttl", _DEFAULT_TTL))


class RelayDirectory:
    def __init__(self) -> None:
        self._relays: Dict[str, RelayInfo] = {}

    def announce(self, info: RelayInfo) -> bool:
        """Add or refresh a relay.  Returns True if this is a new/updated entry."""
        existing = self._relays.get(info.addr)
        if existing and existing.timestamp >= info.timestamp:
            return False
        self._relays[info.addr] = info
        return True

    def alive(self, exclude: List[str] | None = None) -> List[RelayInfo]:
        """Return all live relays, optionally excluding some addresses."""
        excl = set(exclude or [])
        return [r for r in self._relays.values() if r.is_alive() and r.addr not in excl]

    def pick(self, n: int, exclude: List[str] | None = None) -> List[str]:
        """Pick n random relay addresses.  Raises if not enough relays available."""
        pool = self.alive(exclude)
        if len(pool) < n:
            raise RuntimeError(
                f"Need {n} relays, only {len(pool)} known. "
                "Wait for gossip or add more --peer entries."
            )
        return [r.addr for r in random.sample(pool, n)]

    def __len__(self) -> int:
        return sum(1 for r in self._relays.values() if r.is_alive())

    def __repr__(self) -> str:
        relays = self.alive()
        names = ", ".join(r.name or r.addr for r in relays)
        return f"RelayDirectory({len(relays)} alive: {names})"

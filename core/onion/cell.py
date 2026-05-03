"""
Onion Cell — wire format for MurNet Onion Router.

Each cell is a dict compatible with the MurNet VPN message system.
The "oc_ver" field identifies it as an onion cell.

Cell commands:
  CREATE      — Originator → relay 1. Payload: originator's ephemeral X25519 pubkey.
  CREATED     — Relay 1 → originator. Payload: relay's ephemeral X25519 pubkey.
  RELAY_FWD   — Any direction toward exit. Payload: layered ciphertext (one layer per hop).
  RELAY_BACK  — Any direction toward originator. Payload: layered ciphertext added per hop.
  DESTROY     — Tear down a circuit leg.

Circuit IDs:
  Each leg of the circuit has its own circuit_id.
  Originator ←cid_1→ R1 ←cid_2→ R2 ←cid_3→ R3
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from enum import Enum


ONION_VERSION = 1


class OnionCmd(str, Enum):
    CREATE    = "OC_CREATE"
    CREATED   = "OC_CREATED"
    RELAY_FWD = "OC_RELAY_FWD"
    RELAY_BACK = "OC_RELAY_BACK"
    DESTROY   = "OC_DESTROY"


@dataclass
class OnionCell:
    cmd: OnionCmd
    circuit_id: str
    data: bytes = b""

    def to_dict(self) -> dict:
        return {
            "oc_ver": ONION_VERSION,
            "cmd": self.cmd.value,
            "cid": self.circuit_id,
            "data": base64.b64encode(self.data).decode() if self.data else "",
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OnionCell":
        raw = d.get("data", "")
        return cls(
            cmd=OnionCmd(d["cmd"]),
            circuit_id=d["cid"],
            data=base64.b64decode(raw) if raw else b"",
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, s: str) -> "OnionCell":
        return cls.from_dict(json.loads(s))


def is_onion_cell(payload: dict) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("oc_ver") == ONION_VERSION
        and "cmd" in payload
        and "cid" in payload
    )

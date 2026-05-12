"""
MurNet v6.1 canonical message schema.

Version 6.1 introduces typed dataclass messages with Ed25519 signature support,
Blake2b-derived NodeIDs, and a unified parse_message factory. All wire messages
carry a 'v' field set to '6.1'; from_dict() rejects any other version string.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from hashlib import blake2b
from uuid import uuid4


PROTOCOL_VERSION = "6.1"


class MessageType(str, Enum):
    HELLO = "HELLO"
    BYE = "BYE"
    PING = "PING"
    PONG = "PONG"
    DATA = "DATA"
    ACK = "ACK"
    NACK = "NACK"
    DHT_FIND_NODE = "DHT_FIND_NODE"
    DHT_FOUND_NODES = "DHT_FOUND_NODES"
    DHT_STORE = "DHT_STORE"
    DHT_FIND_VALUE = "DHT_FIND_VALUE"
    DHT_VALUE = "DHT_VALUE"
    LSA = "LSA"
    ROUTE_REQUEST = "ROUTE_REQUEST"
    ROUTE_REPLY = "ROUTE_REPLY"
    NAME_REGISTER = "NAME_REGISTER"
    NAME_LOOKUP = "NAME_LOOKUP"
    NAME_RESPONSE = "NAME_RESPONSE"


class ProtocolError(Exception):
    pass


@dataclass
class MurMessage:
    type: MessageType
    sender_id: str
    version: str = PROTOCOL_VERSION
    msg_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time.time)
    ttl: int = 64
    signature: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode()

    def canonical_bytes(self) -> bytes:
        d = {k: v for k, v in self.to_dict().items() if k != "signature"}
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_dict(cls, d: dict) -> "MurMessage":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        return cls(
            type=MessageType(d["type"]),
            sender_id=d["sender_id"],
            version=d.get("version", PROTOCOL_VERSION),
            msg_id=d.get("msg_id", str(uuid4())),
            timestamp=d.get("timestamp", time.time()),
            ttl=d.get("ttl", 64),
            signature=d.get("signature", ""),
        )

    @classmethod
    def from_bytes(cls, b: bytes) -> "MurMessage":
        try:
            d = json.loads(b)
        except json.JSONDecodeError as e:
            raise ProtocolError(f"Invalid JSON: {e}") from e
        return cls.from_dict(d)


def _base_fields(d: dict) -> dict:
    return dict(
        type=MessageType(d["type"]),
        sender_id=d["sender_id"],
        version=d.get("version", PROTOCOL_VERSION),
        msg_id=d.get("msg_id", str(uuid4())),
        timestamp=d.get("timestamp", time.time()),
        ttl=d.get("ttl", 64),
        signature=d.get("signature", ""),
    )


@dataclass
class HelloMsg(MurMessage):
    type: MessageType = field(default=MessageType.HELLO, init=False)
    x25519_pubkey: str = ""
    ed25519_pubkey: str = ""
    listen_port: int = 0
    node_version: str = PROTOCOL_VERSION

    @classmethod
    def from_dict(cls, d: dict) -> "HelloMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            x25519_pubkey=d.get("x25519_pubkey", ""),
            ed25519_pubkey=d.get("ed25519_pubkey", ""),
            listen_port=d.get("listen_port", 0),
            node_version=d.get("node_version", PROTOCOL_VERSION),
        )


@dataclass
class DataMsg(MurMessage):
    type: MessageType = field(default=MessageType.DATA, init=False)
    payload: str = ""
    encoding: str = "json"
    target_id: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "DataMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            payload=d.get("payload", ""),
            encoding=d.get("encoding", "json"),
            target_id=d.get("target_id", ""),
        )


@dataclass
class AckMsg(MurMessage):
    type: MessageType = field(default=MessageType.ACK, init=False)
    ack_id: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "AckMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            ack_id=d.get("ack_id", ""),
        )


@dataclass
class DhtFindNodeMsg(MurMessage):
    type: MessageType = field(default=MessageType.DHT_FIND_NODE, init=False)
    target_id: str = ""
    k: int = 20

    @classmethod
    def from_dict(cls, d: dict) -> "DhtFindNodeMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            target_id=d.get("target_id", ""),
            k=d.get("k", 20),
        )


@dataclass
class DhtFoundNodesMsg(MurMessage):
    type: MessageType = field(default=MessageType.DHT_FOUND_NODES, init=False)
    request_id: str = ""
    nodes: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "DhtFoundNodesMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            request_id=d.get("request_id", ""),
            nodes=d.get("nodes", []),
        )


@dataclass
class DhtStoreMsg(MurMessage):
    type: MessageType = field(default=MessageType.DHT_STORE, init=False)
    key: str = ""
    value: str = ""
    value_ttl: int = 86400

    @classmethod
    def from_dict(cls, d: dict) -> "DhtStoreMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            key=d.get("key", ""),
            value=d.get("value", ""),
            value_ttl=d.get("value_ttl", 86400),
        )


@dataclass
class DhtFindValueMsg(MurMessage):
    type: MessageType = field(default=MessageType.DHT_FIND_VALUE, init=False)
    key: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "DhtFindValueMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            key=d.get("key", ""),
        )


@dataclass
class DhtValueMsg(MurMessage):
    type: MessageType = field(default=MessageType.DHT_VALUE, init=False)
    request_id: str = ""
    key: str = ""
    value: str = ""
    found: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "DhtValueMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            request_id=d.get("request_id", ""),
            key=d.get("key", ""),
            value=d.get("value", ""),
            found=d.get("found", False),
        )


@dataclass
class LsaMsg(MurMessage):
    type: MessageType = field(default=MessageType.LSA, init=False)
    origin_id: str = ""
    seq: int = 0
    links: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "LsaMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            origin_id=d.get("origin_id", ""),
            seq=d.get("seq", 0),
            links=d.get("links", []),
        )


@dataclass
class NameRegisterMsg(MurMessage):
    type: MessageType = field(default=MessageType.NAME_REGISTER, init=False)
    name: str = ""
    node_id: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "NameRegisterMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            name=d.get("name", ""),
            node_id=d.get("node_id", ""),
        )


@dataclass
class NameLookupMsg(MurMessage):
    type: MessageType = field(default=MessageType.NAME_LOOKUP, init=False)
    name: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "NameLookupMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            name=d.get("name", ""),
        )


@dataclass
class NameResponseMsg(MurMessage):
    type: MessageType = field(default=MessageType.NAME_RESPONSE, init=False)
    name: str = ""
    node_id: str = ""
    found: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "NameResponseMsg":
        if d.get("v", d.get("version")) != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {d.get('v', d.get('version'))!r}")
        b = _base_fields(d)
        return cls(
            sender_id=b["sender_id"], version=b["version"], msg_id=b["msg_id"],
            timestamp=b["timestamp"], ttl=b["ttl"], signature=b["signature"],
            name=d.get("name", ""),
            node_id=d.get("node_id", ""),
            found=d.get("found", False),
        )


_TYPE_MAP: dict[MessageType, type] = {
    MessageType.HELLO: HelloMsg,
    MessageType.DATA: DataMsg,
    MessageType.ACK: AckMsg,
    MessageType.DHT_FIND_NODE: DhtFindNodeMsg,
    MessageType.DHT_FOUND_NODES: DhtFoundNodesMsg,
    MessageType.DHT_STORE: DhtStoreMsg,
    MessageType.DHT_FIND_VALUE: DhtFindValueMsg,
    MessageType.DHT_VALUE: DhtValueMsg,
    MessageType.LSA: LsaMsg,
    MessageType.NAME_REGISTER: NameRegisterMsg,
    MessageType.NAME_LOOKUP: NameLookupMsg,
    MessageType.NAME_RESPONSE: NameResponseMsg,
}


def parse_message(data: bytes) -> MurMessage:
    try:
        d = json.loads(data)
    except json.JSONDecodeError as e:
        raise ProtocolError(f"Invalid JSON: {e}") from e
    if "type" not in d:
        raise ProtocolError("Missing 'type' field")
    version = d.get("v", d.get("version"))
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"Unsupported protocol version: {version!r}")
    try:
        msg_type = MessageType(d["type"])
    except ValueError as e:
        raise ProtocolError(f"Unknown message type: {d['type']!r}") from e
    cls = _TYPE_MAP.get(msg_type)
    if cls is None:
        return MurMessage.from_dict(d)
    return cls.from_dict(d)


def make_node_id(public_key_bytes: bytes) -> str:
    return blake2b(public_key_bytes, digest_size=32).hexdigest()

"""MurNet — decentralized onion-routed P2P network."""

__version__ = "6.2.1"
__author__ = "MurNet Dev"

from murnet.core.identity.crypto import (
    Identity,
    SignatureError,
    canonical_json,
    base58_encode,
    base58_decode,
)
from murnet.core.node.node import SecureMurnetNode as MurnetNode
from murnet.core.net.transport import Transport, PacketType
from murnet.core.net.routing import RoutingTable
from murnet.core.data.storage import Storage
from murnet.core.net.murnaked import MurnakedNode
from murnet.core.config import MurnetConfig, get_config, set_config

from murnet.mobile.battery import BatteryOptimizer, PowerState
from murnet.mobile.network import MobileNetworkManager, NetworkType
from murnet.mobile.sync import SyncManager, SyncPriority

from murnet.api.server import MurnetAPIServer
from murnet.api.auth import AuthManager, MobileAuthManager
from murnet.api.models import (
    MessageType,
    NodeStatus,
    SendMessageRequest,
    NodeInfo,
    MessageInfo,
    ConversationInfo,
    FullStatusResponse,
)

__all__ = [
    "MurnetNode",
    "Identity",
    "Transport",
    "PacketType",
    "RoutingTable",
    "Storage",
    "MurnakedNode",
    "MurnetConfig",
    "get_config",
    "set_config",
    "BatteryOptimizer",
    "PowerState",
    "MobileNetworkManager",
    "NetworkType",
    "SyncManager",
    "SyncPriority",
    "MurnetAPIServer",
    "AuthManager",
    "MobileAuthManager",
    "SignatureError",
    "canonical_json",
    "base58_encode",
    "base58_decode",
    "MessageType",
    "NodeStatus",
    "SendMessageRequest",
    "NodeInfo",
    "MessageInfo",
    "ConversationInfo",
    "FullStatusResponse",
]

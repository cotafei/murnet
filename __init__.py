__version__ = "5.0.0"
__author__ = "Murnet Dev"

# Core exports
from core.identity.crypto import Identity, SignatureError, canonical_json, base58_encode, base58_decode
from core.node.node import SecureMurnetNode as MurnetNode
from core.net.transport import Transport, PacketType
from core.net.routing import RoutingTable
from core.data.storage import Storage
from core.net.murnaked import MurnakedNode
from core.config import MurnetConfig, get_config, set_config

# Mobile exports
from mobile.battery import BatteryOptimizer, PowerState
from mobile.network import MobileNetworkManager, NetworkType
from mobile.sync import SyncManager, SyncPriority

# API exports
from api.server import MurnetAPIServer
from api.auth import AuthManager, MobileAuthManager
from api.models import (
    MessageType, NodeStatus, SendMessageRequest, NodeInfo,
    MessageInfo, ConversationInfo, FullStatusResponse
)

__all__ = [
    'MurnetNode',
    'Identity',
    'Transport',
    'PacketType',
    'RoutingTable',
    'Storage',
    'MurnakedNode',
    'MurnetConfig',
    'get_config',
    'set_config',
    'BatteryOptimizer',
    'PowerState',
    'MobileNetworkManager',
    'NetworkType',
    'SyncManager',
    'SyncPriority',
    'MurnetAPIServer',
    'AuthManager',
    'MobileAuthManager',
    'SignatureError',
    'canonical_json',
    'base58_encode',
    'base58_decode',
]
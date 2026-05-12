"""
MURNET API MODELS v5.0
Pydantic models for REST API and WebSocket
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator
from enum import Enum


class MessageType(str, Enum):
    """Типы сообщений"""
    TEXT = "text"
    FILE = "file"
    SYSTEM = "system"
    ENCRYPTED = "encrypted"


class NodeStatus(str, Enum):
    """Статус узла"""
    ONLINE = "online"
    SYNCING = "syncing"
    OFFLINE = "offline"
    ERROR = "error"
    BATTERY_SAVING = "battery_saving"


# ==================== REQUEST MODELS ====================

class SendMessageRequest(BaseModel):
    """Запрос на отправку сообщения"""
    to_address: str = Field(..., description="Адрес получателя", min_length=10)
    content: str = Field(..., description="Текст сообщения", max_length=10000)
    message_type: MessageType = MessageType.TEXT
    ttl: Optional[int] = Field(86400, description="Время жизни в секундах")
    encrypt: bool = Field(True, description="Шифровать сообщение")
    
    @field_validator('to_address')
    @classmethod
    def validate_address(cls, v):
        if not v.startswith('1') or len(v) < 20:
            raise ValueError('Invalid Murnet address format')
        return v


class RegisterNameRequest(BaseModel):
    """Запрос на регистрацию имени"""
    name: str = Field(..., min_length=3, max_length=32, pattern=r'^[a-zA-Z0-9_-]+$')
    public: bool = Field(True, description="Публично ли имя")


class LookupNameRequest(BaseModel):
    """Запрос на поиск имени"""
    name: str = Field(..., min_length=1, max_length=32)


class ConnectPeerRequest(BaseModel):
    """Запрос на подключение к пиру"""
    ip: str = Field(..., description="IP адрес")
    port: int = Field(8888, ge=1, le=65535)
    address: Optional[str] = Field(None, description="Известный адрес узла")


class FileUploadRequest(BaseModel):
    """Запрос на загрузку файла"""
    to_address: Optional[str] = Field(None, description="Адрес получателя или None для хранения")
    filename: str = Field(..., max_length=255)
    content_type: Optional[str] = None
    ttl: int = Field(604800, description="7 дней по умолчанию")  # 7 days


class ConfigUpdateRequest(BaseModel):
    """Запрос на обновление конфигурации"""
    section: Literal["network", "storage", "mobile", "api"]
    key: str
    value: Any


# ==================== RESPONSE MODELS ====================

class ApiResponse(BaseModel):
    """Базовый ответ API"""
    success: bool
    message: Optional[str] = None
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MessageResponse(ApiResponse):
    """Ответ с ID сообщения"""
    message_id: Optional[str] = None
    estimated_delivery: Optional[datetime] = None


class MessageInfo(BaseModel):
    """Информация о сообщении"""
    id: str
    from_address: str
    to_address: str
    content_preview: str
    timestamp: float
    delivered: bool
    read: bool
    message_type: MessageType


class ConversationInfo(BaseModel):
    """Информация о диалоге"""
    peer_address: str
    peer_name: Optional[str] = None
    last_message_time: float
    message_count: int
    unread_count: int
    last_message_preview: Optional[str] = None


class NodeInfo(BaseModel):
    """Информация об узле"""
    address: str
    public_key: str
    status: NodeStatus
    version: str = "5.0"
    uptime_seconds: int
    
    # Сеть
    peers_count: int
    connections_active: int
    
    # Хранилище
    storage_used_mb: float
    storage_total_mb: float
    messages_count: int
    
    # DHT
    dht_entries: int
    dht_neighbors: int
    
    # Мобильное
    battery_optimized: bool = False
    sync_pending: int = 0


class PeerInfo(BaseModel):
    """Информация о пире"""
    address: str
    ip: str
    port: int
    rtt_ms: Optional[float] = None
    last_seen: float
    handshake_complete: bool
    is_active: bool
    trust_score: float = 0.5


class RouteInfo(BaseModel):
    """Информация о маршруте"""
    destination: str
    next_hop: str
    cost: float
    hop_count: int
    latency_ms: Optional[int] = None
    stable: bool = False


class DHTStats(BaseModel):
    """Статистика DHT"""
    local_keys: int
    stored_keys: int
    retrieved_keys: int
    replicated_keys: int
    ring_coverage_percent: float
    pending_hints: int


class NetworkStats(BaseModel):
    """Сетевые метрики"""
    packets_sent: int
    packets_received: int
    packets_retransmitted: int
    bytes_sent: int
    bytes_received: int
    avg_rtt_ms: Optional[float] = None
    packet_loss_percent: float = 0.0


class StorageStats(BaseModel):
    """Статистика хранилища"""
    db_size_mb: float
    messages_total: int
    messages_unread: int
    dht_entries: int
    routes: int
    peers: int
    cache_hit_rate: float


class SystemStats(BaseModel):
    """Системные метрики"""
    cpu_percent: Optional[float] = None
    memory_used_mb: Optional[float] = None
    memory_total_mb: Optional[float] = None
    disk_used_mb: Optional[float] = None
    disk_total_mb: Optional[float] = None
    battery_percent: Optional[int] = None  # Для мобильных
    is_charging: Optional[bool] = None


class FullStatusResponse(ApiResponse):
    """Полный статус системы"""
    node: NodeInfo
    network: NetworkStats
    storage: StorageStats
    dht: DHTStats
    system: Optional[SystemStats] = None
    
    # Мобильное
    sync_status: Optional[Dict[str, Any]] = None
    battery_saver_active: bool = False


# ==================== WEBSOCKET MODELS ====================

class WSMessageType(str, Enum):
    """Типы WebSocket сообщений"""
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    MESSAGE_NEW = "message_new"
    MESSAGE_DELIVERED = "message_delivered"
    PEER_CONNECTED = "peer_connected"
    PEER_DISCONNECTED = "peer_disconnected"
    SYNC_START = "sync_start"
    SYNC_COMPLETE = "sync_complete"
    ERROR = "error"
    PING = "ping"
    PONG = "pong"


class WebSocketMessage(BaseModel):
    """WebSocket сообщение"""
    type: WSMessageType
    payload: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    node_address: Optional[str] = None


class WSAuthMessage(BaseModel):
    """Аутентификация WebSocket"""
    token: str
    node_address: str
    client_type: Literal["android", "ios", "web", "desktop"] = "android"


# ==================== MOBILE MODELS ====================

class SyncStatus(BaseModel):
    """Статус синхронизации"""
    syncing: bool
    pending_uploads: int
    pending_downloads: int
    last_sync: Optional[float] = None
    next_sync: Optional[float] = None
    sync_on_wifi_only: bool = True


class BatteryStatus(BaseModel):
    """Статус батареи"""
    level_percent: int
    is_charging: bool
    saver_enabled: bool
    estimated_remaining_minutes: Optional[int] = None


class MobileConfigResponse(BaseModel):
    """Мобильная конфигурация"""
    battery_optimization: bool
    background_sync: bool
    sync_interval_seconds: int
    max_background_data_mb: int
    aggressive_sleep: bool
    adaptive_intervals: bool
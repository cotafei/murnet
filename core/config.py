"""
MURNET CONFIG v5.1 - Production Ready
"""

import os
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class NetworkConfig:
    bind_host: str = "0.0.0.0"
    port: int = 8888
    max_packet_size: int = 1400
    udp_buffer_size: int = 2097152
    nat_traversal: bool = True
    upnp_enabled: bool = False
    bootstrap_nodes: List[str] = field(default_factory=list)
    mobile_keepalive_interval: int = 30
    mobile_batch_size: int = 10


@dataclass
class StorageConfig:
    data_dir: str = "./data"
    max_size_mb: int = 500
    compression: bool = True
    wal_mode: bool = True
    cache_size: int = 1000
    auto_vacuum: bool = True
    mobile_max_size_mb: int = 100
    mobile_cache_size: int = 100
    aggressive_cleanup: bool = False


@dataclass
class DHTConfig:
    replication_factor: int = 3
    vnodes_per_node: int = 10
    ttl_default: int = 86400
    repair_interval: int = 60
    lazy_replication: bool = False
    sync_interval_mobile: int = 300


@dataclass
class APIConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8080
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    jwt_secret: Optional[str] = None
    jwt_expire_hours: int = 24
    max_upload_size: int = 50 * 1024 * 1024
    ws_ping_interval: int = 20
    ws_ping_timeout: int = 10


@dataclass
class SecurityConfig:
    encryption_at_rest: bool = True
    require_auth: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    max_message_size: int = 10 * 1024 * 1024
    allowed_algorithms: List[str] = field(default_factory=lambda: ["Ed25519"])


@dataclass
class MobileConfig:
    battery_optimization: bool = True
    background_sync: bool = True
    sync_on_wifi_only: bool = False
    data_saver_mode: bool = False
    aggressive_sleep: bool = False
    adaptive_intervals: bool = True


@dataclass
class VDSConfig:
    systemd_integration: bool = False
    docker_mode: bool = False
    monitoring_enabled: bool = True
    log_rotation: bool = True
    max_log_size_mb: int = 100
    max_log_files: int = 5
    prometheus_port: Optional[int] = None


@dataclass
class MurnetConfig:
    network: NetworkConfig = field(default_factory=NetworkConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    dht: DHTConfig = field(default_factory=DHTConfig)
    api: APIConfig = field(default_factory=APIConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    mobile: MobileConfig = field(default_factory=MobileConfig)
    vds: VDSConfig = field(default_factory=VDSConfig)
    
    debug: bool = False
    log_level: str = "INFO"
    node_name: Optional[str] = None
    
    @classmethod
    def from_file(cls, path: str) -> 'MurnetConfig':
        path = Path(path)
        if not path.exists():
            return cls()
        
        with open(path, 'r') as f:
            data = json.load(f)
        
        return cls._from_dict(data)
    
    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> 'MurnetConfig':
        return cls(
            network=NetworkConfig(**data.get('network', {})),
            storage=StorageConfig(**data.get('storage', {})),
            dht=DHTConfig(**data.get('dht', {})),
            api=APIConfig(**data.get('api', {})),
            security=SecurityConfig(**data.get('security', {})),
            mobile=MobileConfig(**data.get('mobile', {})),
            vds=VDSConfig(**data.get('vds', {})),
            debug=data.get('debug', False),
            log_level=data.get('log_level', 'INFO'),
            node_name=data.get('node_name')
        )
    
    def to_file(self, path: str):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        data = asdict(self)
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def apply_profile(self, profile: str):
        if profile == "mobile":
            self._apply_mobile_profile()
        elif profile == "vds":
            self._apply_vds_profile()
        elif profile == "desktop":
            self._apply_desktop_profile()
    
    def _apply_mobile_profile(self):
        self.storage.max_size_mb = self.storage.mobile_max_size_mb
        self.storage.cache_size = self.storage.mobile_cache_size
        self.storage.aggressive_cleanup = True
        self.dht.lazy_replication = True
        self.mobile.battery_optimization = True
        self.mobile.aggressive_sleep = True
        self.network.mobile_keepalive_interval = 60
        self.api.host = "127.0.0.1"
    
    def _apply_vds_profile(self):
        self.api.host = "0.0.0.0"
        self.vds.systemd_integration = True
        self.vds.monitoring_enabled = True
        self.storage.max_size_mb = 2000
        self.network.upnp_enabled = False
        self.dht.replication_factor = 5
    
    def _apply_desktop_profile(self):
        pass


_config: Optional[MurnetConfig] = None


def get_config() -> MurnetConfig:
    global _config
    if _config is None:
        for path in ['./murnet.json', '~/.murnet/config.json', '/etc/murnet/config.json']:
            expanded = Path(path).expanduser()
            if expanded.exists():
                _config = MurnetConfig.from_file(str(expanded))
                break
        else:
            _config = MurnetConfig()
    return _config


def set_config(config: MurnetConfig):
    global _config
    _config = config

"""
MURNET MOBILE NETWORK v5.0
Адаптация под мобильные сети (3G/4G/5G/WiFi switching)
"""

import time
import threading
from dataclasses import dataclass
from typing import Optional, Dict, Callable
from enum import Enum
import socket


class NetworkType(Enum):
    """Тип сети"""
    UNKNOWN = "unknown"
    WIFI = "wifi"
    MOBILE_5G = "5g"
    MOBILE_4G = "4g"
    MOBILE_3G = "3g"
    MOBILE_2G = "2g"
    OFFLINE = "offline"


@dataclass
class NetworkQuality:
    """Качество соединения"""
    network_type: NetworkType
    rtt_ms: float
    bandwidth_kbps: float
    packet_loss: float
    is_metered: bool  # Платная сеть
    is_roaming: bool


class MobileNetworkManager:
    """
    Управление мобильным сетевым стеком
    - Определение типа сети
    - Адаптация параметров под качество
    - Обработка переключения WiFi <-> Mobile
    """
    
    def __init__(self, node_instance):
        self.node = node_instance
        self.config = node_instance.config
        
        self.current_network = NetworkType.UNKNOWN
        self.quality = NetworkQuality(
            network_type=NetworkType.UNKNOWN,
            rtt_ms=1000,
            bandwidth_kbps=100,
            packet_loss=0.0,
            is_metered=False,
            is_roaming=False
        )
        
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        self.callbacks: Dict[NetworkType, list] = {nt: [] for nt in NetworkType}
        self._last_network_check = 0
        
        # Параметры адаптации
        self.adaptive_params = {
            NetworkType.WIFI: {
                'packet_size': 1400,
                'keepalive_interval': 30,
                'batch_size': 50,
                'parallel_connections': 5
            },
            NetworkType.MOBILE_5G: {
                'packet_size': 1400,
                'keepalive_interval': 45,
                'batch_size': 30,
                'parallel_connections': 3
            },
            NetworkType.MOBILE_4G: {
                'packet_size': 1200,
                'keepalive_interval': 60,
                'batch_size': 20,
                'parallel_connections': 2
            },
            NetworkType.MOBILE_3G: {
                'packet_size': 800,
                'keepalive_interval': 120,
                'batch_size': 10,
                'parallel_connections': 1
            },
            NetworkType.MOBILE_2G: {
                'packet_size': 500,
                'keepalive_interval': 300,
                'batch_size': 5,
                'parallel_connections': 1
            }
        }
    
    def start(self):
        """Запуск мониторинга сети"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="NetworkMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        print("📡 Network monitor started")
    
    def stop(self):
        """Остановка мониторинга"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
    
    def _monitor_loop(self):
        """Цикл мониторинга"""
        while self.running:
            try:
                self._detect_network_type()
                self._measure_quality()
                self._apply_adaptive_params()
                time.sleep(10)  # Проверка каждые 10 секунд
            except Exception as e:
                print(f"Network monitor error: {e}")
                time.sleep(30)
    
    def _detect_network_type(self) -> NetworkType:
        """Определение типа сети"""
        # На Android можно использовать ConnectivityManager
        # Здесь эвристика по RTT и bandwidth
        
        try:
            # Проверка WiFi (обычно низкий RTT, высокая пропускная способность)
            if self.quality.rtt_ms < 20 and self.quality.bandwidth_kbps > 10000:
                new_type = NetworkType.WIFI
            elif self.quality.bandwidth_kbps > 50000:
                new_type = NetworkType.MOBILE_5G
            elif self.quality.bandwidth_kbps > 10000:
                new_type = NetworkType.MOBILE_4G
            elif self.quality.bandwidth_kbps > 1000:
                new_type = NetworkType.MOBILE_3G
            elif self.quality.bandwidth_kbps > 0:
                new_type = NetworkType.MOBILE_2G
            else:
                new_type = NetworkType.OFFLINE
            
            if new_type != self.current_network:
                old_type = self.current_network
                self.current_network = new_type
                self._on_network_change(old_type, new_type)
            
            return new_type
            
        except Exception as e:
            print(f"Network detection error: {e}")
            return NetworkType.UNKNOWN
    
    def _measure_quality(self):
        """Измерение качества соединения"""
        try:
            # Измеряем RTT до ближайших пиров
            rtts = []
            for peer in self.node.transport.get_peers()[:3]:
                if peer.get('rtt'):
                    rtts.append(peer['rtt'])
            
            if rtts:
                self.quality.rtt_ms = sum(rtts) / len(rtts) * 1000  # в мс
            
            # Оценка bandwidth (эвристика)
            if hasattr(self.node.transport, 'stats'):
                stats = self.node.transport.stats
                duration = time.time() - self.node.stats['start_time']
                if duration > 0:
                    bytes_per_sec = stats['bytes_received'] / duration
                    self.quality.bandwidth_kbps = (bytes_per_sec * 8) / 1000
            
            # Packet loss
            if hasattr(self.node.transport, 'stats'):
                stats = self.node.transport.stats
                total = stats['packets_sent'] + stats['packets_received']
                if total > 0:
                    self.quality.packet_loss = stats['packets_retransmitted'] / total
            
        except Exception as e:
            print(f"Quality measurement error: {e}")
    
    def _on_network_change(self, old_type: NetworkType, new_type: NetworkType):
        """Обработка смены сети"""
        print(f"📡 Network changed: {old_type.value} -> {new_type.value}")
        
        # Уведомляем callbacks
        for callback in self.callbacks.get(new_type, []):
            try:
                callback(old_type, new_type)
            except Exception as e:
                print(f"Network callback error: {e}")
        
        # Специальная обработка
        if new_type == NetworkType.OFFLINE:
            self._handle_offline()
        elif old_type == NetworkType.OFFLINE:
            self._handle_back_online()
        
        if new_type in [NetworkType.MOBILE_3G, NetworkType.MOBILE_2G]:
            self._handle_slow_network()
        
        if self.quality.is_metered or self.quality.is_roaming:
            self._handle_metered_connection()
    
    def _apply_adaptive_params(self):
        """Применение адаптивных параметров"""
        params = self.adaptive_params.get(self.current_network)
        if not params:
            return
        
        # Применяем к транспорту
        if hasattr(self.node.transport, 'MAX_PACKET_SIZE'):
            self.node.transport.MAX_PACKET_SIZE = params['packet_size']
        
        if hasattr(self.node.transport, 'set_keepalive_interval'):
            self.node.transport.set_keepalive_interval(params['keepalive_interval'])
        
        # Batch size для синхронизации
        if hasattr(self.node, 'sync_manager'):
            self.node.sync_manager.batch_size = params['batch_size']
    
    def _handle_offline(self):
        """Обработка потери соединения"""
        print("📡 OFFLINE: Queueing messages for later")
        
        # Переключаемся в offline mode
        if hasattr(self.node, 'set_offline_mode'):
            self.node.set_offline_mode(True)
    
    def _handle_back_online(self):
        """Обработка восстановления соединения"""
        print("📡 BACK ONLINE: Syncing queued messages")
        
        if hasattr(self.node, 'set_offline_mode'):
            self.node.set_offline_mode(False)
        
        # Форсируем синхронизацию
        if hasattr(self.node, 'sync_manager'):
            self.node.sync_manager.force_sync()
    
    def _handle_slow_network(self):
        """Обработка медленной сети"""
        print("📡 SLOW NETWORK: Reducing traffic")
        
        # Уменьшаем размер пакетов
        if hasattr(self.node.transport, 'MAX_PACKET_SIZE'):
            self.node.transport.MAX_PACKET_SIZE = 800
        
        # Отключаем не критичные фоновые задачи
        if hasattr(self.node.murnaked, 'anti_entropy'):
            self.node.murnaked.anti_entropy.running = False
    
    def _handle_metered_connection(self):
        """Обработка платного соединения"""
        print("📡 METERED CONNECTION: Minimizing data usage")
        
        if self.config.mobile.sync_on_wifi_only:
            # Отключаем синхронизацию
            if hasattr(self.node, 'sync_manager'):
                self.node.sync_manager.pause()
    
    def should_upload_file(self, file_size: int) -> bool:
        """Проверка, стоит ли загружать файл в текущей сети"""
        if self.current_network == NetworkType.WIFI:
            return True
        
        if self.quality.is_metered and self.config.mobile.data_saver_mode:
            return False
        
        # На 3G/2G не загружаем большие файлы
        if self.current_network in [NetworkType.MOBILE_3G, NetworkType.MOBILE_2G]:
            return file_size < 1024 * 1024  # < 1MB
        
        return True
    
    def get_recommended_quality(self) -> str:
        """Рекомендуемое качество медиа"""
        if self.current_network == NetworkType.WIFI:
            return "high"
        elif self.current_network == NetworkType.MOBILE_5G:
            return "high"
        elif self.current_network == NetworkType.MOBILE_4G:
            return "medium"
        else:
            return "low"
    
    def register_callback(self, network_type: NetworkType, callback: Callable):
        """Регистрация callback на смену сети"""
        self.callbacks[network_type].append(callback)
    
    def get_status(self) -> Dict:
        """Статус сети"""
        return {
            'current_network': self.current_network.value,
            'rtt_ms': round(self.quality.rtt_ms, 2),
            'bandwidth_kbps': round(self.quality.bandwidth_kbps, 2),
            'packet_loss': round(self.quality.packet_loss, 4),
            'is_metered': self.quality.is_metered,
            'is_roaming': self.quality.is_roaming,
            'adaptive_params': self.adaptive_params.get(self.current_network, {})
        }

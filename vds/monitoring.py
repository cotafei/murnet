
"""
MURNET MONITORING v6.0
Prometheus metrics and health checks for VDS
"""

import time
import threading
from typing import Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import json


try:
    from prometheus_client import Counter, Gauge, Histogram, Info, start_http_server
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass
class MetricValue:
    name: str
    value: float
    labels: Dict[str, str]
    timestamp: float


class MetricsCollector:
    """
    Сбор метрик для мониторинга
    - Prometheus integration
    - Custom metrics
    - Health checks
    """
    
    def __init__(self, node_instance, port: int = 9090):
        self.node = node_instance
        self.port = port
        self.running = False
        
        # Prometheus metrics
        self.metrics = {}
        if HAS_PROMETHEUS:
            self._init_prometheus_metrics()
        
        # Custom metrics storage
        self.custom_metrics: Dict[str, list] = {}
        self.metrics_lock = threading.Lock()
        
        # Health checks
        self.health_checks: Dict[str, Callable] = {}
        
        # Сбор метрик
        self.collector_thread: Optional[threading.Thread] = None
    
    def _init_prometheus_metrics(self):
        """Инициализация Prometheus метрик"""
        self.metrics['node_info'] = Info('murnet_node', 'Node information')
        
        self.metrics['messages_sent'] = Counter(
            'murnet_messages_sent_total',
            'Total messages sent',
            ['type']
        )
        self.metrics['messages_received'] = Counter(
            'murnet_messages_received_total',
            'Total messages received',
            ['type']
        )
        
        self.metrics['peers_connected'] = Gauge(
            'murnet_peers_connected',
            'Number of connected peers'
        )
        self.metrics['dht_entries'] = Gauge(
            'murnet_dht_entries',
            'Number of DHT entries'
        )
        self.metrics['storage_size'] = Gauge(
            'murnet_storage_size_bytes',
            'Storage size in bytes'
        )
        
        self.metrics['message_latency'] = Histogram(
            'murnet_message_latency_seconds',
            'Message delivery latency',
            buckets=[.001, .005, .01, .025, .05, .1, .25, .5, 1.0, 2.5, 5.0]
        )
        
        self.metrics['bandwidth_usage'] = Gauge(
            'murnet_bandwidth_bytes',
            'Bandwidth usage',
            ['direction']  # in, out
        )
    
    def start(self):
        """Запуск сервера метрик"""
        if self.running:
            return
        
        self.running = True
        
        if HAS_PROMETHEUS:
            try:
                start_http_server(self.port)
                print(f"[metrics] Prometheus metrics on port {self.port}")
            except Exception as e:
                print(f"Failed to start Prometheus server: {e}")
        
        # Запуск сбора метрик
        self.collector_thread = threading.Thread(
            target=self._collect_loop,
            name="MetricsCollector",
            daemon=True
        )
        self.collector_thread.start()
    
    def stop(self):
        """Остановка"""
        self.running = False
        if self.collector_thread:
            self.collector_thread.join(timeout=2.0)
    
    def _collect_loop(self):
        """Цикл сбора метрик"""
        while self.running:
            try:
                self._update_metrics()
                time.sleep(15)  # Сбор каждые 15 секунд
            except Exception as e:
                print(f"Metrics collection error: {e}")
                time.sleep(60)
    
    def _update_metrics(self):
        """Обновление метрик"""
        if not HAS_PROMETHEUS:
            return
        
        # Node info
        self.metrics['node_info'].info({
            'version': '6.0',
            'address': self.node.address[:16] + '...'
        })
        
        # Peers
        peers = self.node.transport.get_peer_count()
        self.metrics['peers_connected'].set(peers)
        
        # DHT
        dht_stats = self.node.murnaked.get_stats()
        self.metrics['dht_entries'].set(dht_stats.get('local_keys', 0))
        
        # Storage
        storage_stats = self.node.storage.get_stats()
        self.metrics['storage_size'].set(
            storage_stats.get('db_size_mb', 0) * 1024 * 1024
        )
        
        # Bandwidth
        transport_stats = self.node.transport.get_stats()
        self.metrics['bandwidth_usage'].labels(direction='in').set(
            transport_stats.get('bytes_received', 0)
        )
        self.metrics['bandwidth_usage'].labels(direction='out').set(
            transport_stats.get('bytes_sent', 0)
        )
    
    def record_message_sent(self, msg_type: str = "text"):
        """Запись отправки сообщения"""
        if HAS_PROMETHEUS:
            self.metrics['messages_sent'].labels(type=msg_type).inc()
    
    def record_message_received(self, msg_type: str = "text"):
        """Запись получения сообщения"""
        if HAS_PROMETHEUS:
            self.metrics['messages_received'].labels(type=msg_type).inc()
    
    def record_latency(self, seconds: float):
        """Запись задержки"""
        if HAS_PROMETHEUS:
            self.metrics['message_latency'].observe(seconds)
    
    def add_custom_metric(self, name: str, value: float, labels: Optional[Dict] = None):
        """Добавление кастомной метрики"""
        with self.metrics_lock:
            if name not in self.custom_metrics:
                self.custom_metrics[name] = []
            
            self.custom_metrics[name].append(MetricValue(
                name=name,
                value=value,
                labels=labels or {},
                timestamp=time.time()
            ))
            
            # Храним только последние 1000 значений
            if len(self.custom_metrics[name]) > 1000:
                self.custom_metrics[name] = self.custom_metrics[name][-1000:]
    
    def register_health_check(self, name: str, check_func: Callable):
        """Регистрация health check"""
        self.health_checks[name] = check_func
    
    def health_check(self) -> Dict:
        """Выполнение всех health checks"""
        results = {
            'status': 'healthy',
            'checks': {},
            'timestamp': time.time()
        }
        
        for name, check in self.health_checks.items():
            try:
                check_result = check()
                results['checks'][name] = {
                    'status': 'pass' if check_result else 'fail',
                    'healthy': check_result
                }
                if not check_result:
                    results['status'] = 'unhealthy'
            except Exception as e:
                results['checks'][name] = {
                    'status': 'error',
                    'error': str(e)
                }
                results['status'] = 'unhealthy'
        
        # Базовые проверки
        results['checks']['node_running'] = {
            'status': 'pass' if self.node.running else 'fail',
            'healthy': self.node.running
        }
        
        results['checks']['storage_accessible'] = {
            'status': 'pass',
            'healthy': True  # TODO: реальная проверка
        }
        
        return results
    
    def get_metrics_snapshot(self) -> Dict:
        """Снимок всех метрик"""
        return {
            'prometheus_available': HAS_PROMETHEUS,
            'custom_metrics': {
                name: [
                    {'value': mv.value, 'labels': mv.labels, 'ts': mv.timestamp}
                    for mv in values[-100:]  # Последние 100
                ]
                for name, values in self.custom_metrics.items()
            },
            'health': self.health_check()
        }


class HealthServer:
    """
    HTTP сервер для health checks (если не используется Prometheus)
    """
    
    def __init__(self, metrics_collector: MetricsCollector, port: int = 8081):
        self.metrics = metrics_collector
        self.port = port
        self.running = False
    
    def start(self):
        """Запуск простого HTTP сервера"""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/health':
                        health = self.metrics.health_check()
                        status = 200 if health['status'] == 'healthy' else 503
                        self._send_json(health, status)
                    elif self.path == '/metrics':
                        snapshot = self.metrics.get_metrics_snapshot()
                        self._send_json(snapshot)
                    else:
                        self.send_error(404)
                
                def _send_json(self, data, status=200):
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(data).encode())
                
                def log_message(self, format, *args):
                    pass  # Тихий режим
            
            server = HTTPServer(('0.0.0.0', self.port), Handler)
            self.running = True
            
            threading.Thread(target=server.serve_forever, daemon=True).start()
            print(f"[health] Health server on port {self.port}")
            
        except Exception as e:
            print(f"Failed to start health server: {e}")


def collect_async_transport_stats(transport) -> Dict:
    """Build stats dict from an AsyncTransport instance.

    AsyncTransport does not expose get_stats(), so we derive equivalent
    figures from get_peers() instead.
    """
    try:
        peers = transport.get_peers()
    except Exception:
        peers = []

    peer_count = len(peers)
    bytes_received = 0
    bytes_sent = 0

    for peer in peers:
        # Peer objects may carry per-peer counters; use them when available.
        bytes_received += getattr(peer, 'bytes_received', 0)
        bytes_sent += getattr(peer, 'bytes_sent', 0)

    return {
        'peer_count': peer_count,
        'bytes_received': bytes_received,
        'bytes_sent': bytes_sent,
    }


class HealthChecker:
    """Perform structured health checks against a running node."""

    def check_node(self, node) -> Dict:
        """Return ``{"healthy": bool, "checks": {...}}`` for *node*.

        Each entry in ``checks`` has the shape ``{"ok": bool, "detail": str}``.
        The top-level ``healthy`` flag is ``True`` only when every check passes.
        """
        checks = {}

        # 1. Is the node process/loop actually running?
        node_running = bool(getattr(node, 'running', False))
        checks['node_running'] = {
            'ok': node_running,
            'detail': 'node.running is True' if node_running else 'node.running is False or missing',
        }

        # 2. Does the node have at least one connected peer?
        try:
            peers = node.transport.get_peers()
            peers_count = len(peers)
            has_peers = peers_count > 0
            checks['has_peers'] = {
                'ok': has_peers,
                'detail': f'{peers_count} peer(s) connected',
            }
        except Exception as exc:
            checks['has_peers'] = {
                'ok': False,
                'detail': f'could not retrieve peers: {exc}',
            }

        # 3. Is storage reachable?
        try:
            node.storage.get_stats()
            checks['storage_ok'] = {
                'ok': True,
                'detail': 'storage.get_stats() succeeded',
            }
        except Exception as exc:
            checks['storage_ok'] = {
                'ok': False,
                'detail': f'storage.get_stats() raised: {exc}',
            }

        # 4. Is the DHT reachable?
        try:
            node.murnaked.get_stats()
            checks['dht_ok'] = {
                'ok': True,
                'detail': 'murnaked.get_stats() succeeded',
            }
        except Exception as exc:
            checks['dht_ok'] = {
                'ok': False,
                'detail': f'murnaked.get_stats() raised: {exc}',
            }

        healthy = all(c['ok'] for c in checks.values())
        return {'healthy': healthy, 'checks': checks}

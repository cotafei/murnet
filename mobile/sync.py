
"""
MURNET SYNC MANAGER v5.0
Фоновая синхронизация для мобильных устройств
"""

import time
import threading
import queue
from dataclasses import dataclass
from typing import Optional, List, Dict, Callable
from enum import Enum


class SyncPriority(Enum):
    """Приоритет синхронизации"""
    CRITICAL = 1  # Сообщения, ACK
    HIGH = 2      # Имена, маршруты
    NORMAL = 3    # DHT repair
    LOW = 4       # Статистика, логи
    BACKGROUND = 5  # Prefetch


@dataclass
class SyncTask:
    """Задача синхронизации"""
    id: str
    priority: SyncPriority
    operation: str
    data: Dict
    created_at: float
    retry_count: int = 0
    max_retries: int = 3


class SyncManager:
    """
    Менеджер фоновой синхронизации
    - Приоритетная очередь задач
    - Batch processing
    - Conflict resolution
    - Offline queue
    """
    
    def __init__(self, node_instance):
        self.node = node_instance
        self.config = node_instance.config
        
        self.running = False
        self.paused = False
        self.interval = 30  # секунд
        
        # Очереди
        self.task_queue: queue.PriorityQueue = queue.PriorityQueue()
        self.offline_queue: List[SyncTask] = []
        self.completed_tasks: Dict[str, SyncTask] = {}
        
        self.sync_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        
        self.batch_size = 20
        self.last_sync = 0
        self.sync_count = 0
        
        # Callbacks
        self.on_sync_start: Optional[Callable] = None
        self.on_sync_complete: Optional[Callable] = None
        self.on_sync_error: Optional[Callable] = None
    
    def start(self):
        """Запуск менеджера синхронизации"""
        if self.running:
            return
        
        self.running = True
        self.sync_thread = threading.Thread(
            target=self._sync_loop,
            name="SyncManager",
            daemon=True
        )
        self.sync_thread.start()
        print("🔄 Sync manager started")
    
    def stop(self):
        """Остановка"""
        self.running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5.0)
    
    def pause(self):
        """Пауза (например, при платном соединении)"""
        self.paused = True
        print("🔄 Sync paused")
    
    def resume(self):
        """Возобновление"""
        self.paused = False
        print("🔄 Sync resumed")
    
    def set_interval(self, seconds: int):
        """Установка интервала синхронизации"""
        self.interval = seconds
    
    def queue_task(self, operation: str, data: Dict, 
                   priority: SyncPriority = SyncPriority.NORMAL) -> str:
        """
        Добавление задачи в очередь
        
        Args:
            operation: Тип операции (send_message, dht_put, etc.)
            data: Данные операции
            priority: Приоритет
        
        Returns:
            ID задачи
        """
        import uuid
        task_id = str(uuid.uuid4())
        
        task = SyncTask(
            id=task_id,
            priority=priority,
            operation=operation,
            data=data,
            created_at=time.time()
        )
        
        # PriorityQueue: (priority, timestamp, task)
        # Lower number = higher priority
        self.task_queue.put((priority.value, task.created_at, task))
        
        return task_id
    
    def _sync_loop(self):
        """Основной цикл синхронизации"""
        while self.running:
            try:
                if self.paused:
                    time.sleep(5)
                    continue
                
                # Проверяем, пора ли синхронизироваться
                if time.time() - self.last_sync < self.interval:
                    time.sleep(1)
                    continue
                
                # Проверяем батарею
                if hasattr(self.node, 'battery_optimizer'):
                    if not self.node.battery_optimizer.should_sync_now():
                        time.sleep(10)
                        continue
                
                self._perform_sync()
                
            except Exception as e:
                print(f"Sync loop error: {e}")
                if self.on_sync_error:
                    self.on_sync_error(e)
                time.sleep(10)
    
    def _perform_sync(self):
        """Выполнение синхронизации"""
        if self.on_sync_start:
            self.on_sync_start()
        
        self.last_sync = time.time()
        
        # Собираем batch задач
        batch = []
        try:
            while len(batch) < self.batch_size:
                priority, timestamp, task = self.task_queue.get(timeout=0.1)
                batch.append(task)
        except queue.Empty:
            pass
        
        if not batch:
            # Нет задач в очереди - синхронизируем стандартные данные
            self._sync_standard_data()
            return
        
        print(f"🔄 Syncing {len(batch)} tasks")
        
        # Группируем по типу для эффективности
        by_operation = {}
        for task in batch:
            if task.operation not in by_operation:
                by_operation[task.operation] = []
            by_operation[task.operation].append(task)
        
        # Выполняем
        for operation, tasks in by_operation.items():
            try:
                self._execute_batch(operation, tasks)
            except Exception as e:
                print(f"Batch execution error ({operation}): {e}")
                # Возвращаем в очередь с retry
                for task in tasks:
                    if task.retry_count < task.max_retries:
                        task.retry_count += 1
                        self.task_queue.put((task.priority.value, time.time(), task))
                    else:
                        # Max retries - сохраняем в offline queue
                        self.offline_queue.append(task)
        
        self.sync_count += 1
        
        if self.on_sync_complete:
            self.on_sync_complete(len(batch))
        
        # Отмечаем синхронизацию для battery optimizer
        if hasattr(self.node, 'battery_optimizer'):
            self.node.battery_optimizer.mark_synced()
    
    def _execute_batch(self, operation: str, tasks: List[SyncTask]):
        """Выполнение batch операций"""
        if operation == "send_message":
            for task in tasks:
                self.node.send_message(
                    to_addr=task.data['to'],
                    text=task.data['text']
                )
        
        elif operation == "dht_put":
            for task in tasks:
                self.node.murnaked.store(
                    key=task.data['key'],
                    data=task.data['value']
                )
        
        elif operation == "register_name":
            for task in tasks:
                self.node.register_name(task.data['name'])
        
        elif operation == "mark_delivered":
            for task in tasks:
                self.node.storage.mark_delivered(task.data['msg_id'])
    
    def _sync_standard_data(self):
        """Синхронизация стандартных данных (без задач в очереди)"""
        # 1. Проверяем новые сообщения
        messages = self.node.storage.get_messages(self.node.address, limit=10)
        
        # 2. Обновляем маршруты
        if hasattr(self.node.routing, 'recompute'):
            self.node.routing.recompute()
        
        # 3. DHT anti-entropy (если не в saver mode)
        if hasattr(self.node.murnaked, 'anti_entropy'):
            if hasattr(self.node, 'battery_optimizer'):
                if self.node.battery_optimizer.current_state.value not in ['critical', 'saver']:
                    pass  # Anti-entropy запускается сам по таймеру
    
    def force_sync(self):
        """Форсированная синхронизация"""
        self.last_sync = 0  # Сбрасываем таймер
        # Пробуждаем поток
        if self.sync_thread and self.sync_thread.is_alive():
            pass  # Цикл сам проверит условие
    
    def get_pending_count(self) -> int:
        """Количество ожидающих задач"""
        return self.task_queue.qsize() + len(self.offline_queue)
    
    def get_status(self) -> Dict:
        """Статус синхронизации"""
        return {
            'running': self.running,
            'paused': self.paused,
            'interval': self.interval,
            'last_sync': self.last_sync,
            'next_sync': self.last_sync + self.interval if self.last_sync else None,
            'pending_tasks': self.get_pending_count(),
            'completed_tasks': len(self.completed_tasks),
            'offline_queue_size': len(self.offline_queue),
            'sync_count': self.sync_count
        }


class ConflictResolver:
    """
    Разрешение конфликтов при синхронизации
    (Last-Write-Wins с векторными часами)
    """
    
    def __init__(self):
        self.vector_clocks: Dict[str, Dict[str, int]] = {}
    
    def update_clock(self, node_id: str, key: str):
        """Обновление векторных часов"""
        if key not in self.vector_clocks:
            self.vector_clocks[key] = {}
        
        if node_id not in self.vector_clocks[key]:
            self.vector_clocks[key][node_id] = 0
        
        self.vector_clocks[key][node_id] += 1
    
    def resolve(self, key: str, local_data: Dict, remote_data: Dict) -> Dict:
        """
        Разрешение конфликта
        Возвращает данные которые должны быть сохранены
        """
        local_ts = local_data.get('timestamp', 0)
        remote_ts = remote_data.get('timestamp', 0)
        
        # Простое LWW (Last Write Wins)
        if remote_ts > local_ts:
            return remote_data
        else:
            return local_data
    
    def merge(self, key: str, local_data: Dict, remote_data: Dict) -> Dict:
        """
        Слияние данных (для поддерживающих merge типов)
        """
        # Для сообщений - объединяем списки
        if isinstance(local_data.get('items'), list):
            merged = set(local_data['items'])
            merged.update(remote_data.get('items', []))
            return {'items': list(merged), 'timestamp': time.time()}
        
        # По умолчанию - LWW
        return self.resolve(key, local_data, remote_data)


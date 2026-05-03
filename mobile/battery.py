
"""
MURNET BATTERY OPTIMIZATION v5.0
Оптимизация энергопотребления для мобильных устройств
"""

import time
import threading
from dataclasses import dataclass
from typing import Optional, Callable, Dict, List
from enum import Enum
import psutil


class PowerState(Enum):
    """Состояние питания"""
    NORMAL = "normal"
    SAVER = "saver"
    CRITICAL = "critical"
    CHARGING = "charging"


@dataclass
class BatteryInfo:
    """Информация о батарее"""
    percent: int
    is_charging: bool
    power_plugged: bool
    estimated_remaining: Optional[int]  # минуты
    saver_enabled: bool


class BatteryOptimizer:
    """
    Оптимизатор батареи для Murnet
    - Адаптивные интервалы синхронизации
    - Batch processing сообщений
    - Aggressive sleep mode
    """
    
    def __init__(self, node_instance):
        self.node = node_instance
        self.config = node_instance.config
        
        self.current_state = PowerState.NORMAL
        self.battery_info: Optional[BatteryInfo] = None
        
        self.normal_interval = 30      # 30 секунд
        self.saver_interval = 300      # 5 минут
        self.critical_interval = 900   # 15 минут
        
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        self.callbacks: Dict[PowerState, List[Callable]] = {
            state: [] for state in PowerState
        }
        
        self._last_sync = 0
        self._pending_messages: List[Dict] = []
        self._pending_lock = threading.Lock()
    
    def start(self):
        """Запуск мониторинга батареи"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="BatteryMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        print("🔋 Battery optimizer started")
    
    def stop(self):
        """Остановка мониторинга"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
    
    def _monitor_loop(self):
        """Цикл мониторинга"""
        while self.running:
            try:
                self._check_battery()
                self._apply_optimizations()
                time.sleep(60)  # Проверка каждую минуту
            except Exception as e:
                print(f"Battery monitor error: {e}")
                time.sleep(60)
    
    def _check_battery(self):
        """Проверка состояния батареи"""
        try:
            battery = psutil.sensors_battery()
            
            if battery is None:
                # Десктоп без батареи
                self.battery_info = BatteryInfo(
                    percent=100,
                    is_charging=True,
                    power_plugged=True,
                    estimated_remaining=None,
                    saver_enabled=False
                )
                self.current_state = PowerState.CHARGING
                return
            
            self.battery_info = BatteryInfo(
                percent=battery.percent,
                is_charging=battery.power_plugged,
                power_plugged=battery.power_plugged,
                estimated_remaining=battery.secsleft // 60 if battery.secsleft != psutil.POWER_TIME_UNLIMITED else None,
                saver_enabled=battery.percent < 20 and not battery.power_plugged
            )
            
            # Определение состояния
            if battery.power_plugged:
                new_state = PowerState.CHARGING
            elif battery.percent <= 10:
                new_state = PowerState.CRITICAL
            elif battery.percent <= 20 or self.battery_info.saver_enabled:
                new_state = PowerState.SAVER
            else:
                new_state = PowerState.NORMAL
            
            # Уведомление об изменении состояния
            if new_state != self.current_state:
                old_state = self.current_state
                self.current_state = new_state
                self._on_state_change(old_state, new_state)
                
        except Exception as e:
            print(f"Battery check error: {e}")
    
    def _on_state_change(self, old_state: PowerState, new_state: PowerState):
        """Обработка смены состояния питания"""
        print(f"🔋 Power state: {old_state.value} -> {new_state.value}")
        
        # Вызываем зарегистрированные callbacks
        for callback in self.callbacks.get(new_state, []):
            try:
                callback(old_state, new_state)
            except Exception as e:
                print(f"Battery callback error: {e}")
        
        # Применяем настройки
        if new_state == PowerState.CRITICAL:
            self._enable_critical_mode()
        elif new_state == PowerState.SAVER:
            self._enable_saver_mode()
        elif new_state == PowerState.CHARGING:
            self._enable_normal_mode()
    
    def _enable_critical_mode(self):
        """Режим критического заряда"""
        print("🪫 CRITICAL: Suspending non-essential operations")
        
        # Останавливаем фоновую синхронизацию
        if hasattr(self.node, 'sync_manager'):
            self.node.sync_manager.set_interval(self.critical_interval)
        
        # Уменьшаем частоту keepalive
        if hasattr(self.node.transport, 'set_keepalive_interval'):
            self.node.transport.set_keepalive_interval(300)
        
        # Отключаем DHT repair
        if hasattr(self.node.murnaked, 'anti_entropy'):
            self.node.murnaked.anti_entropy.running = False
    
    def _enable_saver_mode(self):
        """Режим экономии энергии"""
        print("🔋 SAVER: Reducing activity")
        
        if hasattr(self.node, 'sync_manager'):
            self.node.sync_manager.set_interval(self.saver_interval)
        
        if hasattr(self.node.transport, 'set_keepalive_interval'):
            self.node.transport.set_keepalive_interval(120)
    
    def _enable_normal_mode(self):
        """Нормальный режим"""
        print("⚡ NORMAL: Full operation")
        
        if hasattr(self.node, 'sync_manager'):
            self.node.sync_manager.set_interval(self.normal_interval)
        
        if hasattr(self.node.transport, 'set_keepalive_interval'):
            self.node.transport.set_keepalive_interval(30)
        
        if hasattr(self.node.murnaked, 'anti_entropy'):
            self.node.murnaked.anti_entropy.running = True
    
    def _apply_optimizations(self):
        """Применение текущих оптимизаций"""
        if not self.config.mobile.battery_optimization:
            return
        
        # Batch processing накопленных сообщений
        if self.current_state in [PowerState.SAVER, PowerState.CRITICAL]:
            self._flush_pending_messages()
    
    def queue_message(self, message: Dict) -> bool:
        """
        Добавление сообщения в очередь (batch processing)
        Возвращает True если сообщение добавлено, False если отправлено сразу
        """
        if not self.config.mobile.battery_optimization:
            return False
        
        if self.current_state == PowerState.NORMAL or self.current_state == PowerState.CHARGING:
            return False  # Отправляем сразу
        
        with self._pending_lock:
            self._pending_messages.append(message)
            
            # Если накопилось много сообщений - отправляем
            if len(self._pending_messages) >= 10:
                self._flush_pending_messages()
        
        return True
    
    def _flush_pending_messages(self):
        """Отправка накопленных сообщений одним batch"""
        with self._pending_lock:
            messages = self._pending_messages.copy()
            self._pending_messages.clear()
        
        if messages:
            print(f"📤 Flushing {len(messages)} batched messages")
            for msg in messages:
                if hasattr(self.node, 'send_message'):
                    self.node.send_message(
                        to_addr=msg['to'],
                        text=msg['text']
                    )
    
    def get_current_interval(self) -> int:
        """Получение текущего интервала синхронизации"""
        if self.current_state == PowerState.CRITICAL:
            return self.critical_interval
        elif self.current_state == PowerState.SAVER:
            return self.saver_interval
        else:
            return self.normal_interval
    
    def should_sync_now(self) -> bool:
        """Проверка, нужна ли синхронизация сейчас"""
        interval = self.get_current_interval()
        return time.time() - self._last_sync >= interval
    
    def mark_synced(self):
        """Отметить что синхронизация выполнена"""
        self._last_sync = time.time()
    
    def register_callback(self, state: PowerState, callback: Callable):
        """Регистрация callback на изменение состояния"""
        self.callbacks[state].append(callback)
    
    def get_status(self) -> Dict:
        """Статус оптимизатора"""
        return {
            'state': self.current_state.value,
            'battery_percent': self.battery_info.percent if self.battery_info else None,
            'is_charging': self.battery_info.is_charging if self.battery_info else None,
            'saver_enabled': self.battery_info.saver_enabled if self.battery_info else None,
            'current_interval': self.get_current_interval(),
            'pending_messages': len(self._pending_messages),
            'last_sync': self._last_sync
        }


class AdaptiveScheduler:
    """
    Адаптивный планировщик задач
    Подстраивается под состояние батареи и сети
    """
    
    def __init__(self, battery_optimizer: BatteryOptimizer):
        self.battery = battery_optimizer
        self.tasks: Dict[str, Dict] = {}
        self.lock = threading.Lock()
    
    def schedule(self, task_id: str, func: Callable, 
                 interval: int, priority: int = 5):
        """
        Планирование периодической задачи
        priority: 1-10 (1 - highest, всегда выполняется)
        """
        with self.lock:
            self.tasks[task_id] = {
                'func': func,
                'interval': interval,
                'priority': priority,
                'last_run': 0,
                'thread': None
            }
        
        # Запускаем
        self._run_task(task_id)
    
    def _run_task(self, task_id: str):
        """Выполнение задачи с учётом приоритета"""
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                return
            
            # Проверяем приоритет и состояние батареи
            if task['priority'] > 3 and self.battery.current_state in [
                PowerState.CRITICAL, PowerState.SAVER
            ]:
                # Откладываем низкоприоритетные задачи
                delay = self.battery.get_current_interval()
            else:
                delay = task['interval']
            
            def runner():
                time.sleep(delay)
                try:
                    task['func']()
                    task['last_run'] = time.time()
                except Exception as e:
                    print(f"Task {task_id} error: {e}")
                finally:
                    self._run_task(task_id)  # Reschedule
            
            task['thread'] = threading.Thread(target=runner, daemon=True)
            task['thread'].start()
    
    def cancel(self, task_id: str):
        """Отмена задачи"""
        with self.lock:
            task = self.tasks.pop(task_id, None)
            if task and task['thread']:
                # Thread не убить, просто удаляем из списка
                pass


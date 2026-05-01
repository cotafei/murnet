# Мобильная оптимизация — Murnet v6.1

> **Дисклеймер.** Мобильные оптимизаторы являются частью экспериментального
> студенческого проекта. Реализация не тестировалась на реальных мобильных
> устройствах в production-условиях.

---

## Обзор

Модуль `mobile/` содержит три независимых компонента для адаптации работы
Murnet на устройствах с ограниченными ресурсами:

```
mobile/
├── battery.py   — адаптация к уровню заряда батареи
├── network.py   — адаптация к типу и качеству сети
├── sync.py      — приоритетная очередь задач синхронизации
└── push.py      — push-уведомления через FCM / APNs / кастомный провайдер
```

---

## 1. BatteryOptimizer (`battery.py`)

Отслеживает уровень заряда и состояние зарядки, изменяя поведение узла
для минимизации энергопотребления.

### Состояния питания

| Состояние | Условие | Интервал синхронизации |
|-----------|---------|----------------------|
| `CHARGING` | Устройство заряжается | 30 секунд |
| `NORMAL` | Заряд > 30% | 60 секунд |
| `SAVER` | Заряд 15–30% | 120 секунд |
| `CRITICAL` | Заряд < 15% | 900 секунд |

### Поведение в режимах экономии

**SAVER и CRITICAL:**
- Исходящие сообщения не отправляются мгновенно — накапливаются в буфере
- Буфер сбрасывается при достижении порога или смене состояния (например, при подключении зарядки)
- Уменьшается частота keepalive-пакетов

**CRITICAL (дополнительно):**
- Отключается DHT repair
- Приостанавливаются фоновые задачи anti-entropy
- Отключается DHT-репликация (только чтение)

### API

```python
from mobile.battery import BatteryOptimizer, PowerState

optimizer = BatteryOptimizer()
state = optimizer.get_power_state()       # → PowerState.NORMAL
interval = optimizer.get_sync_interval()  # → 60 (секунд)
optimizer.flush_pending_messages()         # Принудительно отправить накопленные
```

---

## 2. MobileNetworkManager (`network.py`)

Определяет тип и качество сетевого соединения, адаптируя параметры транспорта.

### Определение типа сети (RTT-эвристика)

Тип сети определяется по измеренному RTT до внешнего хоста:

| Тип | RTT | Характеристики |
|-----|-----|----------------|
| `WIFI` | < 20 мс | Максимальный MTU, частый keepalive (30 с) |
| `4G` | 20–80 мс | Стандартный MTU, keepalive 60 с |
| `3G` | 80–200 мс | Уменьшенный MTU, keepalive 120 с |
| `2G` | > 200 мс | Минимальный MTU, keepalive 300 с, только критичные задачи |

### Адаптивные параметры

**WiFi:**
- Максимальный размер пакета (до лимита протокола)
- Частая фоновая синхронизация
- Разрешена загрузка больших файлов

**3G:**
- Уменьшенный размер пакета
- Редкий keepalive
- Фоновые задачи приостанавливаются

**2G:**
- Минимальный MTU
- Только доставка срочных сообщений
- Запрет на загрузку файлов

### Платные соединения (Metered)

Если сеть определена как платная и в настройках включён режим `wifi_only`,
синхронизация DHT и фоновые задачи приостанавливаются.

### Офлайн-режим

При потере соединения исходящие сообщения помещаются в офлайн-очередь.
При восстановлении связи очередь автоматически отправляется с учётом приоритетов.

### API

```python
from mobile.network import MobileNetworkManager, NetworkType

manager = MobileNetworkManager()
net_type = manager.get_network_type()    # → NetworkType.WIFI
is_metered = manager.is_metered()        # → False
manager.queue_offline_message(msg)       # Добавить в офлайн-очередь
manager.flush_offline_queue()            # Отправить накопленные сообщения
```

---

## 3. SyncManager (`sync.py`)

Управляет очередью фоновых задач с приоритетами и экспоненциальным backoff.

### Приоритеты задач

| Приоритет | Значение | Пример |
|-----------|----------|--------|
| `CRITICAL` | 0 | Доставка срочного сообщения |
| `HIGH` | 1 | Повторная отправка после ACK-таймаута |
| `NORMAL` | 2 | Стандартная синхронизация DHT |
| `LOW` | 3 | Обновление LSA |
| `BACKGROUND` | 4 | Anti-entropy, DHT repair |

### Экспоненциальный backoff

При сбое задача возвращается в очередь с увеличивающейся задержкой:

```
retry_delay = base_delay * 2^attempt   (максимум: 300 секунд)
```

| Попытка | Задержка |
|---------|----------|
| 1 | 5 с |
| 2 | 10 с |
| 3 | 20 с |
| 4 | 40 с |
| 5+ | 300 с (максимум) |

### Офлайн-очередь

Задачи, исчерпавшие все попытки при отсутствии сети, сохраняются в
отдельную офлайн-очередь. При следующем успешном подключении они
автоматически возобновляются начиная с `NORMAL`-приоритета.

### API

```python
from mobile.sync import SyncManager, SyncPriority, SyncTask

sync = SyncManager()

async def my_task():
    # ... логика
    pass

task = SyncTask(
    task_id="unique-id",
    priority=SyncPriority.HIGH,
    coroutine=my_task(),
    max_retries=3
)
sync.schedule(task)
```

---

## 4. PushManager (`push.py`)

Обеспечивает доставку push-уведомлений на мобильные устройства через внешние
провайдеры (FCM, APNs) или пользовательскую интеграцию.

### PushProvider

| Значение | Описание |
|----------|----------|
| `NONE` | Push-уведомления отключены |
| `FCM` | Firebase Cloud Messaging (Android и web) |
| `APNS` | Apple Push Notification Service (iOS / macOS) |
| `CUSTOM` | Произвольный HTTP-провайдер |

### DeviceRegistry

Хранит соответствие `device_token → node_address` и персистирует реестр в
JSON-файл на диске. Позволяет регистрировать токены с указанием платформы
(`android`, `ios`, `web`) и удалять устаревшие записи.

### PushManager

| Метод | Описание |
|-------|----------|
| `send(notification)` | Отправить произвольное `PushNotification` |
| `notify_new_message(from_addr, to_addr, preview)` | Сформировать и отправить уведомление о новом сообщении |
| `get_stats()` | Вернуть словарь со статистикой (sent, failed, pending) |

### API

```python
from mobile.push import PushManager, PushConfig, PushProvider, DeviceRegistry, PushNotification

registry = DeviceRegistry("./data/devices.json")
registry.register("1AbcNode...", "fcm_token_xyz", "android")

config = PushConfig(provider=PushProvider.FCM, fcm_server_key="key-xxx")
push = PushManager(config, registry)
push.notify_new_message(from_addr="1Alice...", to_addr="1AbcNode...", preview="Hello!")
```

---

## Взаимодействие компонентов

```
BatteryOptimizer ──► sync_interval
         │
         ▼
MobileNetworkManager ──► network_type, is_metered
         │
         ▼
SyncManager ──► priority queue ──► задачи синхронизации
         │
         ▼
PushManager ──► DeviceRegistry ──► FCM / APNs / CUSTOM
```

`SecureMurnetNode` опрашивает `BatteryOptimizer` и `MobileNetworkManager`
при каждом цикле синхронизации и передаёт актуальные параметры в `SyncManager`.
При получении нового входящего сообщения узел вызывает
`PushManager.notify_new_message()`, который через `DeviceRegistry` определяет
токен адресата и отправляет уведомление через настроенный провайдер.

---

## Конфигурация

Параметры мобильных оптимизаторов задаются в `config.yaml`:

```yaml
mobile:
  battery:
    enabled: true
    critical_threshold: 15    # % заряда для режима CRITICAL
    saver_threshold: 30       # % заряда для режима SAVER
  network:
    wifi_only_mode: false     # Запрет синхронизации на платных сетях
    rtt_probe_interval: 60    # Интервал измерения RTT (секунд)
  sync:
    max_queue_size: 1000      # Максимум задач в очереди
    offline_queue_persist: true # Сохранять офлайн-очередь на диск
```

---

## Известные ограничения

- Определение типа сети через RTT является эвристикой и может давать
  ошибочные результаты в сетях с переменной латентностью.
- Определение состояния батареи зависит от библиотеки `psutil`, которая
  работает корректно не на всех мобильных платформах.
- На Android/iOS нативные API для батареи и сети недоступны из Python —
  необходима обёртка на стороне нативного приложения.

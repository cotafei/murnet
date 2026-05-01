# Развёртывание на VDS — Murnet v6.1

> **Дисклеймер.** Данное руководство описывает развёртывание экспериментального
> студенческого проекта. Перед выходом в публичную сеть убедитесь в актуальности
> всех зависимостей и настройте firewall. Мурнет не прошёл аудит безопасности.

---

## Требования к серверу

- Ubuntu 22.04 / Debian 12 (или совместимые)
- Python 3.11+
- 512 МБ RAM минимум (рекомендуется 1 ГБ+)
- 10 ГБ свободного места на диске

**Открытые порты:**

| Порт | Протокол | Назначение |
|------|----------|------------|
| 8888 | UDP | P2P транспорт |
| 8080 | TCP | REST API (только для доверенных сетей) |
| 9090 | TCP | Prometheus метрики (только для мониторинга) |

---

## Быстрый старт (без Docker)

```bash
# 1. Клонировать репозиторий
git clone https://github.com/cotafei/MurNet.git
cd MurNet

# 2. Создать виртуальное окружение
python3 -m venv venv
source venv/bin/activate

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Запустить узел
python cli.py --port 8888 --data-dir /var/lib/murnet
```

---

## Скрипты (`scripts/`)

v6.1 включает набор готовых скриптов для управления узлом.

```bash
# Генерация config.yaml (интерактивно)
python scripts/generate_config.py --output /etc/murnet/config.yaml

# Деплой на VDS (устанавливает systemd-сервис)
sudo bash scripts/deploy.sh

# Резервное копирование (хранит 7 последних архивов)
bash scripts/backup.sh --data-dir /var/lib/murnet --backup-dir /backup/murnet

# Проверка состояния узла через REST API
python scripts/node_status.py --url http://127.0.0.1:8080
```

---

## Развёртывание через Docker

### Генерация конфигов

```bash
python -c "from vds.docker import DockerGenerator; DockerGenerator.generate_all()"
```

Создаёт:
- `Dockerfile`
- `docker-compose.yml`
- `monitoring/` — конфиги Prometheus и Grafana

### Запуск

```bash
# Только узел
docker-compose up -d

# Узел + стек мониторинга (Prometheus + Grafana)
docker-compose --profile monitoring up -d
```

### Управление

```bash
# Просмотр логов
docker-compose logs -f murnet

# Перезапуск
docker-compose restart murnet

# Остановка
docker-compose down

# Обновление
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Volumes

| Volume | Путь в контейнере | Назначение |
|--------|-------------------|------------|
| `murnet-data` | `/var/lib/murnet` | SQLite БД, ключи |
| `murnet-logs` | `/var/log/murnet` | Файлы логов |

---

## Развёртывание через systemd

### Генерация и установка

```bash
# Генерировать systemd-файлы
python -c "from vds.systemd import SystemdManager; SystemdManager.generate_all()"

# Запустить установку (требуется sudo)
sudo bash install.sh
```

Скрипт `install.sh` выполняет:
1. Создаёт пользователя `murnet`
2. Создаёт директории `/opt/murnet`, `/var/lib/murnet`, `/var/log/murnet`
3. Устанавливает зависимости в виртуальное окружение `/opt/murnet/venv`
4. Копирует systemd-юниты: `murnet.service`, `murnet-maintenance.service`, `murnet-maintenance.timer`
5. Настраивает logrotate
6. Генерирует базовый конфиг в `/etc/murnet/config.yaml`
7. Добавляет правила UFW
8. Включает и запускает сервисы

### Управление сервисом

```bash
# Статус
sudo systemctl status murnet

# Запуск / остановка / перезапуск
sudo systemctl start murnet
sudo systemctl stop murnet
sudo systemctl restart murnet

# Логи в реальном времени
sudo journalctl -u murnet -f

# Последние 100 строк логов
sudo journalctl -u murnet -n 100 --no-pager
```

### Файл сервиса (пример)

```ini
[Unit]
Description=Murnet P2P Node v6.1
After=network.target

[Service]
Type=simple
User=murnet
WorkingDirectory=/opt/murnet
ExecStart=/opt/murnet/venv/bin/python cli.py \
    --port 8888 \
    --data-dir /var/lib/murnet
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

## Конфигурация (`/etc/murnet/config.yaml`)

```yaml
node:
  port: 8888
  api_port: 8080
  api_host: "127.0.0.1"    # Для публичного доступа: "0.0.0.0"
  data_dir: "/var/lib/murnet"
  log_level: "INFO"

network:
  max_peers: 50
  ping_interval: 30         # секунд
  peer_timeout: 120         # секунд

api:
  enabled: true
  jwt_secret: "generate-a-strong-random-secret-here"
  token_ttl: 86400          # 24 часа

dht:
  replication_factor: 3
  bootstrap_nodes: []       # Список "ip:port" начальных узлов
```

---

## Мониторинг (Prometheus + Grafana)

Метрики доступны на `http://127.0.0.1:9090/metrics` в формате Prometheus.

**Доступные метрики:**

| Метрика | Тип | Описание |
|---------|-----|----------|
| `murnet_messages_sent_total` | counter | Всего отправленных сообщений |
| `murnet_messages_received_total` | counter | Всего полученных сообщений |
| `murnet_peers_connected` | gauge | Текущее число пиров |
| `murnet_dht_entries` | gauge | Записи в DHT |
| `murnet_storage_size_bytes` | gauge | Размер БД |
| `murnet_message_latency_seconds` | histogram | Латентность доставки |
| `murnet_bandwidth_bytes` | gauge | Трафик (метки: `direction="in"\|"out"`) |
| `murnet_security_events_total` | counter | События безопасности |

### Настройка Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'murnet'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

### Grafana

Импортируйте дашборд из `monitoring/grafana-dashboard.json` после запуска стека.
По умолчанию Grafana доступна на `http://localhost:3000` (admin/admin).

---

## Безопасность VDS

### Firewall (UFW)

```bash
# Разрешить P2P (UDP)
sudo ufw allow 8888/udp

# API — только из локальной сети (не публично!)
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp

# Метрики — только для системы мониторинга
sudo ufw allow from 10.0.0.0/8 to any port 9090 proto tcp

# Запретить всё остальное
sudo ufw default deny incoming
sudo ufw enable
```

### Reverse proxy для API (Nginx + SSL)

Если API должен быть доступен из интернета, используйте Nginx с TLS:

```nginx
server {
    listen 443 ssl;
    server_name murnet.example.com;

    ssl_certificate     /etc/letsencrypt/live/murnet.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/murnet.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name murnet.example.com;
    return 301 https://$host$request_uri;
}
```

### Права доступа к файлам

```bash
# Конфиг с JWT-секретом — только для пользователя murnet
chmod 600 /etc/murnet/config.yaml
chown murnet:murnet /etc/murnet/config.yaml

# Директория с ключами
chmod 700 /var/lib/murnet
chown murnet:murnet /var/lib/murnet
```

---

## Обновление узла

```bash
cd /opt/murnet

# Остановить сервис
sudo systemctl stop murnet

# Получить обновления
git pull origin main

# Обновить зависимости
source venv/bin/activate
pip install -r requirements.txt

# Запустить сервис
sudo systemctl start murnet
sudo systemctl status murnet
```

---

## Резервное копирование

Все данные хранятся в `/var/lib/murnet`. Минимальный бэкап:

```bash
# Автоматическое резервное копирование (хранит 7 последних)
bash scripts/backup.sh --data-dir /var/lib/murnet --backup-dir /backup/murnet

# Восстановить вручную
sudo systemctl stop murnet
sudo tar xzf /backup/murnet/murnet_20260101_120000.tar.gz -C /
sudo systemctl start murnet
```

---

## Диагностика

```bash
# Проверить, что узел слушает UDP-порт
ss -ulnp | grep 8888

# Проверить API
curl http://127.0.0.1:8080/health

# Статус через скрипт (требует JWT)
python scripts/node_status.py --url http://127.0.0.1:8080

# Проверить метрики
curl http://127.0.0.1:9090/metrics | grep murnet

# Посмотреть активные соединения
ss -s
```

# Развёртывание на VDS — Murnet v6.2

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
| 8888 | UDP | P2P транспорт (Kademlia) |
| 9001-9003 | TCP | Onion транспорт (Relay) |
| 8080 | TCP | REST API (только для доверенных сетей) |

---

## Быстрый старт (v6.2+)

Теперь MurNet можно устанавливать как обычный Python-пакет.

```bash
# 1. Установить из PyPI
pip install murnet

# 2. Или из исходников
git clone https://github.com/cotafei/MurNet.git
cd MurNet
pip install -e .

# 3. Запустить relay-ноду
murnet-node --bind 0.0.0.0:9001 --name MyRelay --announce
```

---

## NAT и VDS

На VDS с публичным IP система автоматически определит тип NAT как `open` через STUN. 
UPnP на серверах обычно не поддерживается и не требуется.

```bash
# Проверить статус NAT при старте
murnet-node --bind 0.0.0.0:9001
# [INFO] STUN: public_addr=80.93.52.15:9001 nat_type=open
```

---

## Скрипты (`scripts/`)

```bash
# Деплой на VDS (устанавливает systemd-сервис)
sudo bash scripts/deploy.sh

# Проверка состояния узла через REST API
murnet-node --status
```

---

## Развёртывание через Docker

### Запуск

```bash
docker-compose up -d
```

### Volumes

| Volume | Путь в контейнере | Назначение |
|--------|-------------------|------------|
| `murnet-data` | `/var/lib/murnet` | SQLite БД, ключи |

---

## Развёртывание через systemd

### Управление сервисом

```bash
# Статус
sudo systemctl status murnet

# Логи в реальном времени
sudo journalctl -u murnet -f
```

---

## Безопасность VDS

### Firewall (UFW)

```bash
# Разрешить P2P (UDP)
sudo ufw allow 8888/udp

# Разрешить Onion (TCP)
sudo ufw allow 9001/tcp

# Запретить всё остальное
sudo ufw default deny incoming
sudo ufw enable
```

---

## Обновление узла

```bash
pip install --upgrade murnet
sudo systemctl restart murnet
```

---

## Диагностика

```bash
# Проверить порты
ss -tulpn | grep -E "8888|9001"

# Проверить анонс в сети
murnet-node --list-relays
```

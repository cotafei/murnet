"""
MURNET TEST CONFIGURATION
Общие фикстуры и настройки для всех тестов
"""

import pytest
import tempfile
import shutil
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Добавляем корень проекта в путь
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(scope="session")
def test_data_dir():
    """Временная директория для данных тестов"""
    temp_dir = tempfile.mkdtemp(prefix="murnet_test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def fresh_data_dir(test_data_dir):
    """Свежая директория для каждого теста"""
    subdir = tempfile.mkdtemp(dir=test_data_dir)
    yield subdir
    shutil.rmtree(subdir, ignore_errors=True)


@pytest.fixture
def mock_network_timeout():
    """Уменьшенные таймауты для тестов"""
    return 0.1


@pytest.fixture
def sample_keys():
    """Тестовые ключи"""
    return {
        'private_key': bytes([i % 256 for i in range(32)]),
        'public_key': bytes([i % 256 for i in range(32, 64)]),
        'address': '1MurnetTestAddress123456789'
    }


@pytest.fixture
def identity():
    """Тестовая идентичность"""
    from murnet.core.identity.crypto import Identity
    return Identity()


@pytest.fixture
def murnaked(fresh_data_dir, identity):
    """DHT хранилище для тестов"""
    from murnet.core.net.murnaked import EnhancedMurnakedStorage
    storage = EnhancedMurnakedStorage(
        node_address=identity.address,
        data_dir=fresh_data_dir,
        replication_factor=3,
        vnodes_per_node=10
    )
    yield storage


@pytest.fixture
def hash_ring():
    """Чистое кольцо хеширования"""
    from murnet.core.net.murnaked import ConsistentHashRing
    return ConsistentHashRing(vnodes_per_node=10)


@pytest.fixture
def routing_table(identity):
    """Таблица маршрутизации"""
    from murnet.core.net.routing import RoutingTable
    return RoutingTable(identity.address, identity)


@pytest.fixture
def lsdb(identity):
    """Link-state database"""
    from murnet.core.net.routing import LinkStateDatabase
    return LinkStateDatabase(identity.address, identity)


@pytest.fixture
def storage(fresh_data_dir):
    """Хранилище для тестов"""
    from murnet.core.data.storage import Storage, StorageConfig
    config = StorageConfig(
        data_dir=fresh_data_dir,
        max_size_mb=100,
        compression=True,
        wal_mode=True,
        cache_size=100
    )
    storage = Storage(fresh_data_dir, config)
    yield storage
    storage.close()


@pytest.fixture
def transport_pair(fresh_data_dir):
    """Пара транспортов для тестирования"""
    from murnet.core.net.transport import Transport
    from murnet.core.identity.crypto import Identity
    import time
    
    identity1 = Identity()
    identity2 = Identity()
    
    transport1 = Transport(port=0)
    transport2 = Transport(port=0)
    
    port1 = transport1.start(identity1.address, identity1.get_public_bytes(),
                              identity1.get_private_bytes())
    port2 = transport2.start(identity2.address, identity2.get_public_bytes(),
                              identity2.get_private_bytes())
    
    # Даем время на запуск
    time.sleep(0.1)
    
    yield (transport1, transport2, port1, port2, identity1, identity2)
    
    transport1.stop()
    transport2.stop()


@pytest.fixture
def mock_battery_critical():
    """Мок критического заряда батареи"""
    with patch('psutil.sensors_battery') as mock:
        mock.return_value = Mock(
            percent=5,
            power_plugged=False,
            secsleft=300
        )
        yield mock


@pytest.fixture  
def mock_wifi_network():
    """Мок WiFi сети"""
    with patch('mobile.network.MobileNetworkManager._detect_network_type') as mock:
        from murnet.mobile.network import NetworkType
        mock.return_value = NetworkType.WIFI
        yield mock


# Пропуск тестов если нет опциональных зависимостей
def pytest_configure(config):
    """Настройка меток"""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "network: marks tests as requiring network")
    config.addinivalue_line("markers", "security: marks tests as security tests")
    config.addinivalue_line("markers", "crypto: marks tests as crypto tests")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "performance: marks tests as performance tests")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")


def pytest_collection_modifyitems(config, items):
    """Автоматическое добавление маркеров по имени файла"""
    for item in items:
        # Автоматически маркируем по имени файла
        if "security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        elif "performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        elif "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "crypto" in item.nodeid:
            item.add_marker(pytest.mark.crypto)
        else:
            item.add_marker(pytest.mark.unit)
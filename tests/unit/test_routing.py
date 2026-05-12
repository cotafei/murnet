#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET ROUTING TESTS v5.0
Тестирование link-state маршрутизации
"""

import pytest
import time
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from murnet.core.net.routing import (
    RoutingTable, LinkStateDatabase, DijkstraEngine,
    Link, LSA, Path, LinkState
)
from murnet.core.identity.crypto import Identity


@pytest.fixture
def identity():
    """Тестовая идентичность"""
    return Identity()


@pytest.fixture
def routing_table(identity):
    """Таблица маршрутизации"""
    return RoutingTable(identity.address, identity)


@pytest.fixture
def lsdb(identity):
    """Link-state database"""
    return LinkStateDatabase(identity.address, identity)


class TestLink:
    """Тесты связей"""
    
    def test_link_creation(self):
        """Создание связи"""
        link = Link(
            neighbor='1NeighborAddress',
            cost=2.0,
            bandwidth=1000.0,
            latency=50.0,
            loss_rate=0.01
        )
        
        assert link.neighbor == '1NeighborAddress'
        assert link.cost == 2.0
        assert link.bandwidth == 1000.0
        assert link.latency == 50.0
        assert link.loss_rate == 0.01
        assert link.state == LinkState.UP
    
    def test_effective_cost_calculation(self):
        """Расчет эффективной стоимости"""
        link = Link(
            neighbor='test',
            cost=1.0,
            bandwidth=1000.0,
            latency=0.0,
            loss_rate=0.0
        )
        
        # Базовая стоимость
        assert link.effective_cost() == 1.0
        
        # С потерями
        link.loss_rate = 0.1
        cost_with_loss = link.effective_cost()
        assert cost_with_loss > 1.0
        
        # С задержкой
        link.latency = 100.0
        cost_with_latency = link.effective_cost()
        assert cost_with_latency > cost_with_loss
    
    def test_down_link_infinite_cost(self):
        """Недоступная связь имеет бесконечную стоимость"""
        link = Link(neighbor='test', state=LinkState.DOWN)
        assert link.effective_cost() == float('inf')


class TestLSA:
    """Тесты Link State Advertisements"""
    
    def test_lsa_creation(self, identity):
        """Создание LSA"""
        links = {
            '1Peer1': Link(neighbor='1Peer1', cost=1.0),
            '1Peer2': Link(neighbor='1Peer2', cost=2.0)
        }
        
        lsa = LSA(
            origin=identity.address,
            sequence=1,
            links=links,
            timestamp=time.time()
        )
        
        assert lsa.origin == identity.address
        assert lsa.sequence == 1
        assert len(lsa.links) == 2
    
    def test_lsa_freshness(self, identity):
        """Проверка свежести LSA"""
        fresh_lsa = LSA(
            origin=identity.address,
            sequence=1,
            links={},
            timestamp=time.time()
        )
        
        assert fresh_lsa.is_fresh() is True
        
        old_lsa = LSA(
            origin=identity.address,
            sequence=1,
            links={},
            timestamp=time.time() - 4000  # Старше TTL
        )
        
        assert old_lsa.is_fresh() is False
    
    def test_lsa_hash_computation(self, identity):
        """Вычисление хеша LSA"""
        lsa = LSA(
            origin=identity.address,
            sequence=1,
            links={'1Peer': Link(neighbor='1Peer')},
            timestamp=time.time()
        )
        
        key = identity.get_private_bytes()
        hash1 = lsa.compute_hash(key)
        hash2 = lsa.compute_hash(key)
        
        assert hash1 == hash2
        assert len(hash1) == 32  # hex of 16 bytes


class TestLinkStateDatabase:
    """Тесты LSDB"""
    
    def test_originate_lsa(self, lsdb, identity):
        """Создание собственного LSA"""
        links = {
            '1Peer1': Link(neighbor='1Peer1', cost=1.0),
            '1Peer2': Link(neighbor='1Peer2', cost=2.0)
        }
        
        lsa = lsdb.originate_lsa(links)
        
        assert lsa.origin == identity.address
        assert lsa.sequence == 1
        assert '1Peer1' in lsa.links
        
        # Следующий LSA имеет увеличенный sequence
        lsa2 = lsdb.originate_lsa(links)
        assert lsa2.sequence == 2
    
    def test_receive_fresh_lsa(self, lsdb, identity):
        """Прием свежего LSA"""
        other_identity = Identity()
        
        lsa = LSA(
            origin=other_identity.address,
            sequence=1,
            links={'1Peer': Link(neighbor='1Peer')},
            timestamp=time.time(),
            signature=''  # Без подписи для простоты
        )
        
        result = lsdb.receive_lsa(lsa)
        assert result is True
        
        # LSA сохранен
        assert other_identity.address in lsdb.lsdb
    
    def test_receive_stale_lsa(self, lsdb):
        """Прием устаревшего LSA"""
        other_identity = Identity()
        
        # Сначала принимаем свежий
        lsa1 = LSA(
            origin=other_identity.address,
            sequence=2,
            links={},
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa1)
        
        # Потом пытаемся принять старый
        lsa2 = LSA(
            origin=other_identity.address,
            sequence=1,
            links={},
            timestamp=time.time()
        )
        
        result = lsdb.receive_lsa(lsa2)
        assert result is False
    
    def test_receive_duplicate_lsa(self, lsdb):
        """Прием дубликата LSA"""
        other_identity = Identity()
        
        lsa = LSA(
            origin=other_identity.address,
            sequence=1,
            links={},
            timestamp=time.time()
        )
        
        lsdb.receive_lsa(lsa)
        result = lsdb.receive_lsa(lsa)  # Тот же sequence
        
        assert result is False
    
    def test_sequence_replay_protection(self, lsdb):
        """Защита от replay sequence"""
        other_identity = Identity()
        
        # Принимаем LSA
        lsa = LSA(
            origin=other_identity.address,
            sequence=5,
            links={},
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa)
        
        # Пытаемся принять тот же sequence снова
        lsa2 = LSA(
            origin=other_identity.address,
            sequence=5,
            links={},
            timestamp=time.time()
        )
        
        result = lsdb.receive_lsa(lsa2)
        assert result is False
    
    def test_timestamp_validation(self, lsdb):
        """Валидация временной метки"""
        other_identity = Identity()
        
        # Слишком старый LSA
        old_lsa = LSA(
            origin=other_identity.address,
            sequence=1,
            links={},
            timestamp=time.time() - 400  # Старше 5 минут
        )
        
        result = lsdb.receive_lsa(old_lsa)
        assert result is False
        
        # Слишком новый (в будущем)
        future_lsa = LSA(
            origin=other_identity.address,
            sequence=1,
            links={},
            timestamp=time.time() + 400
        )
        
        result = lsdb.receive_lsa(future_lsa)
        assert result is False
    
    def test_graph_rebuild(self, lsdb):
        """Перестроение графа"""
        # Добавляем несколько LSA
        for i in range(3):
            identity = Identity()
            links = {
                f'1Peer{j}': Link(neighbor=f'1Peer{j}', cost=float(j+1))
                for j in range(2)
            }
            lsa = LSA(
                origin=identity.address,
                sequence=1,
                links=links,
                timestamp=time.time()
            )
            lsdb.receive_lsa(lsa)
        
        # Проверяем что граф построен
        assert len(lsdb.graph) > 0
    
    def test_trust_score_update(self, lsdb):
        """Обновление trust score"""
        other_identity = Identity()
        
        initial_trust = lsdb.get_trust_score(other_identity.address)
        assert initial_trust == 0.5  # Default
        
        # Принимаем валидный LSA
        lsa = LSA(
            origin=other_identity.address,
            sequence=1,
            links={},
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa)
        
        new_trust = lsdb.get_trust_score(other_identity.address)
        assert new_trust > initial_trust


class TestDijkstraEngine:
    """Тесты алгоритма Дейкстры"""
    
    def test_simple_path_computation(self, identity):
        """Простой расчет пути"""
        lsdb = LinkStateDatabase(identity.address, identity)
        
        # Создаем топологию: A -- B -- C
        # Где A - это identity.address
        identity_b = Identity()
        identity_c = Identity()
        
        # LSA для B
        lsa_b = LSA(
            origin=identity_b.address,
            sequence=1,
            links={
                identity.address: Link(neighbor=identity.address, cost=1.0),
                identity_c.address: Link(neighbor=identity_c.address, cost=1.0)
            },
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa_b)
        
        # LSA для C
        lsa_c = LSA(
            origin=identity_c.address,
            sequence=1,
            links={
                identity_b.address: Link(neighbor=identity_b.address, cost=1.0)
            },
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa_c)
        
        # Запускаем Дейкстру
        dijkstra = DijkstraEngine(lsdb)
        paths = dijkstra.compute(identity.address)
        
        assert identity_b.address in paths
        assert identity_c.address in paths
        
        # Путь до B стоит 1
        assert paths[identity_b.address].cost == 1.0
        
        # Путь до C стоит 2 (через B)
        assert paths[identity_c.address].cost == 2.0
    
    def test_ecmp_paths(self, identity):
        """Equal Cost Multi-Path"""
        lsdb = LinkStateDatabase(identity.address, identity)
        
        identity_b = Identity()
        identity_c = Identity()
        identity_d = Identity()
        
        # Топология с ECMP: A - B - D и A - C - D
        lsa_b = LSA(
            origin=identity_b.address,
            sequence=1,
            links={
                identity.address: Link(cost=1.0),
                identity_d.address: Link(cost=1.0)
            },
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa_b)
        
        lsa_c = LSA(
            origin=identity_c.address,
            sequence=1,
            links={
                identity.address: Link(cost=1.0),
                identity_d.address: Link(cost=1.0)
            },
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa_c)
        
        lsa_d = LSA(
            origin=identity_d.address,
            sequence=1,
            links={
                identity_b.address: Link(cost=1.0),
                identity_c.address: Link(cost=1.0)
            },
            timestamp=time.time()
        )
        lsdb.receive_lsa(lsa_d)
        
        dijkstra = DijkstraEngine(lsdb)
        paths = dijkstra.compute(identity.address)
        
        path_to_d = paths[identity_d.address]
        assert path_to_d.cost == 2.0
        assert len(path_to_d.next_hops) == 2  # Два ECMP next-hop
    
    def test_unreachable_destination(self, identity):
        """Недостижимое назначение"""
        lsdb = LinkStateDatabase(identity.address, identity)
        
        dijkstra = DijkstraEngine(lsdb)
        paths = dijkstra.compute(identity.address)
        
        # Только себя знаем
        assert len(paths) == 0


class TestRoutingTable:
    """Тесты таблицы маршрутизации"""
    
    def test_add_link(self, routing_table):
        """Добавление связи"""
        routing_table.add_link('1Neighbor', cost=1.0, bandwidth=1000.0)
        
        assert '1Neighbor' in routing_table.local_links
        assert routing_table.local_links['1Neighbor'].cost == 1.0
    
    def test_add_neighbor(self, routing_table):
        """Добавление соседа"""
        routing_table.add_neighbor('1Neighbor')
        
        assert routing_table.is_neighbor('1Neighbor')
        assert routing_table.routes.get('1Neighbor') == 1.0
    
    def test_remove_link(self, routing_table):
        """Удаление связи"""
        routing_table.add_link('1Neighbor')
        routing_table.remove_link('1Neighbor')
        
        assert '1Neighbor' not in routing_table.local_links
        assert not routing_table.is_neighbor('1Neighbor')
    
    def test_get_next_hop(self, routing_table, identity):
        """Получение next hop"""
        # Добавляем прямого соседа
        routing_table.add_neighbor('1Neighbor')
        
        next_hop = routing_table.get_next_hop('1Neighbor')
        assert next_hop == '1Neighbor'
    
    def test_get_next_hop_nonexistent(self, routing_table):
        """Next hop для недостижимого назначения"""
        next_hop = routing_table.get_next_hop('1Unknown')
        assert next_hop is None
    
    def test_get_all_routes(self, routing_table):
        """Получение всех маршрутов"""
        routing_table.add_neighbor('1Neighbor1')
        routing_table.add_neighbor('1Neighbor2')
        
        routes = routing_table.get_all_routes()
        
        assert '1Neighbor1' in routes
        assert '1Neighbor2' in routes
    
    def test_receive_lsa_with_attack_detection(self, routing_table, identity):
        """Прием LSA с детекцией атак"""
        other_identity = Identity()
        
        # Нормальный LSA
        lsa = LSA(
            origin=other_identity.address,
            sequence=1,
            links={},
            timestamp=time.time()
        )
        
        result = routing_table.receive_lsa(lsa)
        assert result is True
    
    def test_lsa_flood_detection(self, routing_table, identity):
        """Детекция flood LSA"""
        other_identity = Identity()
        
        # Быстро отправляем много LSA
        for i in range(15):
            lsa = LSA(
                origin=other_identity.address,
                sequence=i+1,
                links={},
                timestamp=time.time()
            )
            result = routing_table.receive_lsa(lsa)
        
        # Последние должны быть отклонены
        assert result is False
    
    def test_ecmp_counter(self, routing_table, identity):
        """ECMP балансировка"""
        # Создаем ECMP ситуацию
        identity_b = Identity()
        identity_c = Identity()
        
        # Добавляем прямых соседей
        routing_table.add_link(identity_b.address, cost=1.0)
        routing_table.add_link(identity_c.address, cost=1.0)
        
        # Симулируем получение LSA с ECMP
        lsa_b = LSA(
            origin=identity_b.address,
            sequence=1,
            links={'1Dest': Link(cost=1.0)},
            timestamp=time.time()
        )
        lsa_c = LSA(
            origin=identity_c.address,
            sequence=1,
            links={'1Dest': Link(cost=1.0)},
            timestamp=time.time()
        )
        
        routing_table.receive_lsa(lsa_b)
        routing_table.receive_lsa(lsa_c)
        
        # Проверяем что ECMP работает
        routes = routing_table.get_all_routes()
        if '1Dest' in routes:
            # Вызываем несколько раз для проверки round-robin
            next_hops = [routing_table.get_next_hop('1Dest') for _ in range(4)]
            # Должны получить оба next-hop
            assert len(set(next_hops)) > 1
    
    def test_get_stats(self, routing_table):
        """Получение статистики"""
        routing_table.add_neighbor('1Neighbor')
        
        stats = routing_table.get_stats()
        
        assert 'own_address' in stats
        assert 'paths_count' in stats
        assert 'lsdb_size' in stats
        assert stats['own_address'] == routing_table.own_address


class TestPath:
    """Тесты путей"""
    
    def test_path_creation(self):
        """Создание пути"""
        path = Path(
            destination='1Dest',
            next_hops=['1NextHop'],
            cost=2.5,
            segments=['1A', '1B', '1Dest'],
            bandwidth=1000.0
        )
        
        assert path.destination == '1Dest'
        assert path.cost == 2.5
        assert len(path.segments) == 3
        assert path.bandwidth == 1000.0
    
    def test_path_with_backup(self):
        """Путь с резервным"""
        path = Path(
            destination='1Dest',
            next_hops=['1Primary'],
            cost=2.0,
            segments=['1A', '1Dest'],
            backup_path=['1A', '1Backup', '1Dest'],
            is_protected=True
        )
        
        assert path.is_protected is True
        assert path.backup_path is not None


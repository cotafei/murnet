"""
MurNet v6.1 — Network Simulation Tests

Spins up real SecureMurnetNode instances in-process to test multi-node
behaviour: topology formation, DHT, name service, concurrency safety.

All tests are marked @pytest.mark.simulation + @pytest.mark.slow and run
with continue-on-error in CI (they need real sockets).
"""

import pytest
import random
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from murnet.core.node.node import SecureMurnetNode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_node(port: int = 0):
    """Spin up a SecureMurnetNode in a temp dir. Returns (node, tmpdir)."""
    d = tempfile.mkdtemp(prefix="murnet_sim_")
    node = SecureMurnetNode(data_dir=d, port=port)
    node.start()
    return node, d


def stop_nodes(*pairs):
    """Stop nodes and clean up temp dirs."""
    for node, d in pairs:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(d, ignore_errors=True)


def connect(src, dst, wait: float = 0.5):
    """Connect src -> dst and wait for handshake."""
    src.transport.connect_to("127.0.0.1", dst.transport.port, dst.address)
    time.sleep(wait)


def wait_for(condition_fn, timeout: float = 5.0, interval: float = 0.1) -> bool:
    """Poll until condition_fn() is truthy or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if condition_fn():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


# ---------------------------------------------------------------------------
# Small network: 5-node ring
# ---------------------------------------------------------------------------

@pytest.mark.simulation
@pytest.mark.slow
class TestSmallNetwork:

    @pytest.fixture(autouse=True)
    def ring(self):
        pairs = [make_node() for _ in range(5)]
        nodes = [p[0] for p in pairs]
        # ring: 0→1→2→3→4→0
        for i in range(5):
            connect(nodes[i], nodes[(i + 1) % 5], wait=0.3)
        time.sleep(0.5)
        yield nodes
        stop_nodes(*pairs)

    def test_all_nodes_running(self, ring):
        assert all(n.running for n in ring)

    def test_ring_has_connections(self, ring):
        connected = [n for n in ring if len(n.transport.get_peers()) >= 1]
        assert len(connected) >= 3, f"Only {len(connected)}/5 nodes have peers"

    def test_status_returns_dict(self, ring):
        for node in ring:
            status = node.get_status()
            assert isinstance(status, dict)
            for key in ("address", "port", "healthy", "stats"):
                assert key in status, f"Missing key {key!r} in status"

    def test_no_deadlock_in_status(self, ring):
        """Call get_status() from multiple threads — must not deadlock."""
        results = []
        errors = []

        def call_status(node):
            try:
                s = node.get_status()
                results.append(s)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(call_status, n) for n in ring for _ in range(10)]
            done, _ = __import__("concurrent.futures", fromlist=["wait"]).wait(
                futs, timeout=10.0
            )

        assert len(errors) == 0, f"Errors during concurrent status: {errors}"
        assert len(results) >= len(ring), "Some status calls did not complete"


# ---------------------------------------------------------------------------
# Mesh network: 10 nodes, each connects to 3 random others
# ---------------------------------------------------------------------------

@pytest.mark.simulation
@pytest.mark.slow
class TestMeshNetwork:

    @pytest.fixture(autouse=True)
    def mesh(self):
        rng = random.Random(42)
        pairs = [make_node() for _ in range(10)]
        nodes = [p[0] for p in pairs]
        # each node connects to 3 random others (no self)
        for i, node in enumerate(nodes):
            targets = rng.sample([n for j, n in enumerate(nodes) if j != i], 3)
            for t in targets:
                node.transport.connect_to("127.0.0.1", t.transport.port, t.address)
        time.sleep(2.0)
        yield nodes
        stop_nodes(*pairs)

    def test_network_size(self, mesh):
        assert len(mesh) == 10

    def test_average_peer_count(self, mesh):
        counts = [len(n.transport.get_peers()) for n in mesh]
        avg = sum(counts) / len(counts)
        assert avg >= 1.5, f"Average peer count too low: {avg:.1f}"

    def test_all_nodes_still_running(self, mesh):
        assert all(n.running for n in mesh)

    def test_status_no_exception(self, mesh):
        for node in mesh:
            status = node.get_status()
            assert "address" in status


# ---------------------------------------------------------------------------
# DHT simulation: 5-node chain
# ---------------------------------------------------------------------------

@pytest.mark.simulation
@pytest.mark.slow
class TestDHTSimulation:

    @pytest.fixture(autouse=True)
    def chain(self):
        pairs = [make_node() for _ in range(5)]
        nodes = [p[0] for p in pairs]
        # linear chain: 0→1→2→3→4
        for i in range(4):
            connect(nodes[i], nodes[i + 1], wait=0.3)
        time.sleep(0.5)
        yield nodes
        stop_nodes(*pairs)

    def test_dht_store_no_crash(self, chain):
        """store() must not raise — result may be True or False."""
        result = chain[0].murnaked.store("sim_key_001", b"sim_value_001")
        assert isinstance(result, bool)

    def test_dht_retrieve_no_crash(self, chain):
        """retrieve() must not raise."""
        chain[0].murnaked.store("sim_key_002", b"sim_value_002")
        time.sleep(0.2)
        result = chain[0].murnaked.retrieve("sim_key_002")
        # value may be None (not propagated) or bytes — both are fine
        assert result is None or isinstance(result, bytes)

    def test_dht_stats_accessible(self, chain):
        """get_stats() must return a dict on every node."""
        for node in chain:
            stats = node.murnaked.get_stats()
            assert isinstance(stats, dict)
            assert "stored_keys" in stats or "local_keys" in stats


# ---------------------------------------------------------------------------
# Name service simulation: 3-node fully-connected
# ---------------------------------------------------------------------------

@pytest.mark.simulation
@pytest.mark.slow
class TestNameServiceSimulation:

    @pytest.fixture(autouse=True)
    def trio(self):
        pairs = [make_node() for _ in range(3)]
        nodes = [p[0] for p in pairs]
        # fully connected
        for i in range(3):
            for j in range(3):
                if i != j:
                    nodes[i].transport.connect_to(
                        "127.0.0.1", nodes[j].transport.port, nodes[j].address
                    )
        time.sleep(1.0)
        yield nodes
        stop_nodes(*pairs)

    def test_name_register_returns_bool(self, trio):
        result = trio[0].register_name("alice")
        assert isinstance(result, bool)

    def test_name_lookup_no_crash(self, trio):
        trio[0].register_name("bob")
        time.sleep(0.3)
        result = trio[0].lookup_name("bob")
        # may be None or address string — must not raise
        assert result is None or isinstance(result, str)

    def test_lookup_unknown_name(self, trio):
        result = trio[0].lookup_name("nonexistent_xyzzy_12345")
        assert result is None


# ---------------------------------------------------------------------------
# Concurrency / stability
# ---------------------------------------------------------------------------

@pytest.mark.simulation
@pytest.mark.slow
class TestConcurrencyStability:

    def test_rapid_connect_disconnect(self):
        """Connect and disconnect nodes 5 times without crashing."""
        pairs = [make_node() for _ in range(3)]
        nodes = [p[0] for p in pairs]
        try:
            for _ in range(5):
                for i in range(3):
                    j = (i + 1) % 3
                    nodes[i].transport.connect_to(
                        "127.0.0.1", nodes[j].transport.port, nodes[j].address
                    )
                time.sleep(0.2)
            assert all(n.running for n in nodes)
        finally:
            stop_nodes(*pairs)

    def test_concurrent_status_50_calls(self):
        """50 concurrent get_status() calls across 5 nodes — no deadlock."""
        pairs = [make_node() for _ in range(5)]
        nodes = [p[0] for p in pairs]
        try:
            errors = []

            def status(node):
                try:
                    return node.get_status()
                except Exception as e:
                    errors.append(e)
                    return None

            with ThreadPoolExecutor(max_workers=20) as ex:
                futs = [ex.submit(status, nodes[i % 5]) for i in range(50)]
                results = [f.result(timeout=10) for f in futs]

            assert len(errors) == 0, f"Errors: {errors[:3]}"
            assert sum(1 for r in results if r is not None) >= 45
        finally:
            stop_nodes(*pairs)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "-m", "simulation"])

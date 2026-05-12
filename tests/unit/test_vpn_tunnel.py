"""
Unit tests for core/vpn/tunnel.py — TunnelManager and Circuit.
"""
import asyncio
import base64
import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from murnet.core.vpn.tunnel import TunnelManager, Circuit, CircuitState, _CONNECT_TIMEOUT


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

class MockSyncNode:
    """Mimics SecureMurnetNode (sync send_vpn)."""
    def __init__(self, address="sync-node-addr"):
        self.address = address
        self.extra_handlers = {}
        self.sent: list = []

    def send_vpn(self, to_addr: str, payload: dict) -> bool:
        self.sent.append((to_addr, payload))
        return True


class MockAsyncNode:
    """Mimics AsyncMurnetNode (async send_vpn)."""
    def __init__(self, address="async-node-addr"):
        self.address = address
        self.extra_handlers = {}
        self.sent: list = []

    async def send_vpn(self, to_addr: str, payload: dict) -> bool:
        self.sent.append((to_addr, payload))
        return True


@pytest.fixture
def sync_node():
    return MockSyncNode()


@pytest.fixture
def async_node():
    return MockAsyncNode()


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def run(coro, loop=None):
    if loop is None:
        loop = asyncio.new_event_loop()
    return loop.run_until_complete(coro)


# ---------------------------------------------------------------------------
# TunnelManager initialization
# ---------------------------------------------------------------------------

class TestTunnelManagerInit:
    def test_sync_node_sets_threadsafe_handler(self, sync_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(sync_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)
        # Sync node → threadsafe bridge
        assert not asyncio.iscoroutinefunction(sync_node.extra_handlers["vpn"])
        loop.close()

    def test_async_node_sets_coroutine_handler(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)
        # Async node → coroutine handler
        assert asyncio.iscoroutinefunction(async_node.extra_handlers["vpn"])
        loop.close()

    def test_stop_clears_handler(self, sync_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(sync_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)
        mgr.stop()
        assert "vpn" not in sync_node.extra_handlers
        loop.close()


# ---------------------------------------------------------------------------
# Circuit state machine
# ---------------------------------------------------------------------------

class TestCircuit:
    def test_initial_state_is_connecting(self):
        c = Circuit(id="x", dst_host="h", dst_port=80, exit_peer="ep")
        assert c.state == CircuitState.CONNECTING

    def test_connected_event_not_set_initially(self):
        c = Circuit(id="x", dst_host="h", dst_port=80, exit_peer="ep")
        assert not c.connected_event.is_set()

    def test_recv_queue_empty_initially(self):
        c = Circuit(id="x", dst_host="h", dst_port=80, exit_peer="ep")
        assert c.recv_queue.empty()


# ---------------------------------------------------------------------------
# Client-side: connect() + message dispatch
# ---------------------------------------------------------------------------

class TestClientConnect:
    def test_connect_creates_circuit_and_sends_connect_msg(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        async def _test():
            async def _auto_respond():
                await asyncio.sleep(0.05)
                if mgr._circuits:
                    c_id = list(mgr._circuits.keys())[0]
                    await mgr._dispatch({"type": "CONNECTED", "circuit": c_id}, "exit-addr")

            asyncio.ensure_future(_auto_respond())
            return await mgr.connect("google.com", 443)

        circuit = run(_test(), loop)
        assert circuit.state == CircuitState.CONNECTED
        assert circuit.dst_host == "google.com"
        assert circuit.dst_port == 443
        assert any(p[1]["type"] == "CONNECT" for p in async_node.sent)
        connect_msg = next(p[1] for p in async_node.sent if p[1]["type"] == "CONNECT")
        assert connect_msg["dst_host"] == "google.com"
        assert connect_msg["dst_port"] == 443
        loop.close()

    def test_connect_times_out_if_no_response(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        async def _test():
            with patch("core.vpn.tunnel._CONNECT_TIMEOUT", 0.05):
                with pytest.raises(ConnectionError):
                    await mgr.connect("nowhere.invalid", 9999)

        run(_test(), loop)
        loop.close()

    def test_connect_raises_on_error_response(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        async def _test():
            async def _auto_error():
                await asyncio.sleep(0.02)
                c_id = list(mgr._circuits.keys())[0]
                await mgr._dispatch(
                    {"type": "ERROR", "circuit": c_id, "msg": "Connection refused"},
                    "exit-addr",
                )
            asyncio.ensure_future(_auto_error())
            with pytest.raises(ConnectionError, match="Connection refused"):
                await mgr.connect("closed.host", 80)

        run(_test(), loop)
        loop.close()


# ---------------------------------------------------------------------------
# Client-side: DATA and CLOSE dispatch
# ---------------------------------------------------------------------------

class TestClientDispatch:
    def _make_connected_circuit(self, mgr, circuit_id="c1"):
        c = Circuit(id=circuit_id, dst_host="h", dst_port=80, exit_peer="ep",
                    state=CircuitState.CONNECTED)
        c.connected_event.set()
        mgr._circuits[circuit_id] = c
        return c

    def test_data_message_puts_bytes_in_recv_queue(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)
        c = self._make_connected_circuit(mgr)

        raw = b"hello world"
        run(mgr._dispatch({
            "type": "DATA",
            "circuit": c.id,
            "data": base64.b64encode(raw).decode(),
        }, "exit-addr"), loop)

        assert not c.recv_queue.empty()
        assert c.recv_queue.get_nowait() == raw
        loop.close()

    def test_close_message_sets_eof_sentinel(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)
        c = self._make_connected_circuit(mgr)

        run(mgr._dispatch({"type": "CLOSE", "circuit": c.id}, "exit-addr"), loop)

        assert c.state == CircuitState.CLOSED
        assert c.closed_event.is_set()
        # EOF sentinel
        assert c.recv_queue.get_nowait() == b""
        loop.close()

    def test_data_for_unknown_circuit_ignored(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)
        # Should not raise
        run(mgr._dispatch({
            "type": "DATA",
            "circuit": "nonexistent-id",
            "data": base64.b64encode(b"x").decode(),
        }, "exit-addr"), loop)
        loop.close()


# ---------------------------------------------------------------------------
# Client-side: send_data and close_circuit
# ---------------------------------------------------------------------------

class TestSendData:
    def test_send_data_sends_vpn_messages(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        c = Circuit(id="c1", dst_host="h", dst_port=80, exit_peer="exit-addr",
                    state=CircuitState.CONNECTED)
        mgr._circuits[c.id] = c

        async def _test():
            await mgr.send_data(c, b"hello")
            await asyncio.sleep(0.05)  # let scheduled coroutine execute

        run(_test(), loop)
        data_msgs = [p[1] for p in async_node.sent if p[1]["type"] == "DATA"]
        assert len(data_msgs) == 1
        assert base64.b64decode(data_msgs[0]["data"]) == b"hello"
        loop.close()

    def test_send_data_chunks_large_payload(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        c = Circuit(id="c1", dst_host="h", dst_port=80, exit_peer="exit-addr",
                    state=CircuitState.CONNECTED)
        mgr._circuits[c.id] = c

        big = os.urandom(9000)  # > 8192 chunk size

        async def _test():
            await mgr.send_data(c, big)
            await asyncio.sleep(0.05)

        run(_test(), loop)
        data_msgs = [p[1] for p in async_node.sent if p[1]["type"] == "DATA"]
        assert len(data_msgs) == 2
        reassembled = b"".join(base64.b64decode(m["data"]) for m in data_msgs)
        assert reassembled == big
        loop.close()

    def test_send_data_noop_when_not_connected(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        c = Circuit(id="c1", dst_host="h", dst_port=80, exit_peer="exit-addr",
                    state=CircuitState.CONNECTING)

        async def _test():
            await mgr.send_data(c, b"hello")
            await asyncio.sleep(0.02)

        run(_test(), loop)
        assert not any(p[1]["type"] == "DATA" for p in async_node.sent)
        loop.close()

    def test_close_circuit_sends_close_msg(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        c = Circuit(id="c1", dst_host="h", dst_port=80, exit_peer="exit-addr",
                    state=CircuitState.CONNECTED)
        mgr._circuits[c.id] = c

        async def _test():
            mgr.close_circuit(c)
            await asyncio.sleep(0.05)  # let run_coroutine_threadsafe coroutine execute

        run(_test(), loop)
        assert c.state == CircuitState.CLOSED
        assert c.id not in mgr._circuits
        close_msgs = [p[1] for p in async_node.sent if p[1]["type"] == "CLOSE"]
        assert len(close_msgs) == 1
        loop.close()

    def test_close_circuit_idempotent(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_peer="exit-addr")
        run(mgr.start(loop), loop)

        c = Circuit(id="c1", dst_host="h", dst_port=80, exit_peer="exit-addr",
                    state=CircuitState.CONNECTED)
        mgr._circuits[c.id] = c

        async def _test():
            mgr.close_circuit(c)
            mgr.close_circuit(c)  # second call should be no-op
            await asyncio.sleep(0.05)

        run(_test(), loop)
        close_msgs = [p[1] for p in async_node.sent if p[1]["type"] == "CLOSE"]
        assert len(close_msgs) == 1
        loop.close()


# ---------------------------------------------------------------------------
# Exit-node side: CONNECT handling
# ---------------------------------------------------------------------------

class TestExitNodeConnect:
    def test_connect_to_unreachable_host_sends_error(self, async_node):
        loop = asyncio.new_event_loop()
        mgr = TunnelManager(async_node, exit_mode=True)
        run(mgr.start(loop), loop)

        run(mgr._dispatch({
            "type": "CONNECT",
            "circuit": "c1",
            "dst_host": "127.0.0.1",
            "dst_port": 1,  # almost certainly not listening
        }, "client-addr"), loop)

        # Give the task a moment to complete
        run(asyncio.sleep(0.2), loop)

        error_msgs = [p[1] for p in async_node.sent if p[1]["type"] == "ERROR"]
        assert len(error_msgs) == 1
        assert error_msgs[0]["circuit"] == "c1"
        loop.close()

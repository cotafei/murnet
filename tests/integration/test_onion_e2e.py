"""
Integration tests — end-to-end onion routing with in-process fake network.

All routers run in the same asyncio event loop. The fake network delivers
cells synchronously via direct router.handle_cell() calls, eliminating any
real UDP/TCP layer.

Test scenarios:
  1. 1-hop circuit: originator → exit, data flows both ways
  2. 3-hop circuit: originator → guard → middle → exit, data flows both ways
  3. Privacy: guard cannot read exit's traffic; middle cannot identify originator
  4. Multiple concurrent circuits
  5. DESTROY tears down relay entries
"""
import asyncio
import json
import os
import pytest

from murnet.core.onion.cell import OnionCell, OnionCmd
from murnet.core.onion.router import OnionRouter


# ──────────────────────────────────────────────────────────────────────────────
# In-process fake network
# ──────────────────────────────────────────────────────────────────────────────

class FakeNetwork:
    """
    Routes cells between OnionRouters by address.
    Records every delivered cell for later inspection.
    """

    def __init__(self):
        self._routers: dict[str, OnionRouter] = {}
        self.log: list[tuple[str, str, OnionCell]] = []  # (from, to, cell)

    def register(self, router: OnionRouter) -> None:
        self._routers[router.addr] = router

    def make_send_fn(self, from_addr: str):
        async def _send(to_addr: str, cell: OnionCell) -> None:
            self.log.append((from_addr, to_addr, cell))
            target = self._routers.get(to_addr)
            if target:
                await target.handle_cell(cell, from_addr)
        return _send

    def wire(self, *routers: OnionRouter) -> None:
        for r in routers:
            self.register(r)
            r.send_fn = self.make_send_fn(r.addr)


def make_routers(names: list[str], net: FakeNetwork) -> dict[str, OnionRouter]:
    routers = {name: OnionRouter(name) for name in names}
    net.wire(*routers.values())
    return routers


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def net():
    return FakeNetwork()


@pytest.fixture
def routers_1hop(net):
    return make_routers(["orig", "exit"], net), net


@pytest.fixture
def routers_3hop(net):
    return make_routers(["orig", "guard", "middle", "exit"], net), net


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.asyncio
async def test_1hop_circuit_build(routers_1hop):
    r, net = routers_1hop
    circuit = await r["orig"].build_circuit(["exit"])
    assert circuit.depth == 1
    assert circuit.hops[0].peer_addr == "exit"
    assert len(circuit.hops[0].key) == 32
    assert len(r["exit"]._relays) == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_1hop_data_forward(routers_1hop):
    r, net = routers_1hop
    received = []
    r["exit"].on_data = lambda sid, data: received.append(data)

    circuit = await r["orig"].build_circuit(["exit"])
    await r["orig"].send_data(circuit, "stream-1", b"hello from orig")

    assert received == [b"hello from orig"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_1hop_data_backward(routers_1hop):
    """Exit echoes data back; originator receives it via the stream queue."""
    r, net = routers_1hop
    circuit = await r["orig"].build_circuit(["exit"])
    q = r["orig"]._streams.setdefault("s1", asyncio.Queue())

    await r["orig"].send_data(circuit, "s1", b"ping")

    data = await asyncio.wait_for(q.get(), timeout=2.0)
    assert data == b"ping"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_3hop_circuit_build(routers_3hop):
    r, net = routers_3hop
    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])
    assert circuit.depth == 3
    assert [h.peer_addr for h in circuit.hops] == ["guard", "middle", "exit"]
    for hop in circuit.hops:
        assert len(hop.key) == 32
        assert hop.key != b"\x00" * 32


@pytest.mark.integration
@pytest.mark.asyncio
async def test_3hop_data_forward(routers_3hop):
    r, net = routers_3hop
    received = []
    r["exit"].on_data = lambda sid, d: received.append(d)

    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])
    payload = b"secret payload through 3 hops"
    await r["orig"].send_data(circuit, "s1", payload)

    assert received == [payload]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_3hop_data_backward(routers_3hop):
    r, net = routers_3hop
    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])
    q = r["orig"]._streams.setdefault("s1", asyncio.Queue())

    await r["orig"].send_data(circuit, "s1", b"round-trip")

    data = await asyncio.wait_for(q.get(), timeout=2.0)
    assert data == b"round-trip"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_privacy_guard_cannot_read_exit_traffic(routers_3hop):
    """
    Guard decrypts one K1 layer. The remaining payload must still be opaque
    (i.e. the guard must NOT be able to call json.loads on the inner bytes
    and get the plaintext message).
    """
    r, net = routers_3hop
    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])

    guard_entry = r["guard"]._relays.get(circuit.hops[0].circuit_id)
    assert guard_entry is not None

    from murnet.core.onion.hop_key import hop_decrypt, hop_encrypt
    secret_msg = b"TOP SECRET - guard should not see this"
    await r["orig"].send_data(circuit, "s1", secret_msg)

    # What guard actually sees arriving: find the RELAY_FWD cell it received
    guard_cells = [
        cell for (frm, to, cell) in net.log
        if to == "guard" and cell.cmd == OnionCmd.RELAY_FWD
    ]
    assert guard_cells, "Guard should have received a RELAY_FWD"

    raw_at_guard = guard_cells[-1].data
    # Guard can strip its own layer
    guard_inner = hop_decrypt(guard_entry.key, raw_at_guard)
    inner_dict  = json.loads(guard_inner)
    assert inner_dict["cmd"] == "RELAY_NEXT"

    # But the nested payload is still opaque to the guard
    nested_bytes = bytes.fromhex("") or __import__("base64").b64decode(inner_dict["payload"])
    assert secret_msg not in nested_bytes


@pytest.mark.integration
@pytest.mark.asyncio
async def test_privacy_middle_cannot_identify_originator(routers_3hop):
    """
    Middle node only knows its upstream (guard) and downstream (exit).
    It does not learn the originator's address.
    """
    r, net = routers_3hop
    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])

    middle_entry = r["middle"]._relays.get(circuit.hops[1].circuit_id)
    assert middle_entry is not None

    # Middle's upstream is guard, not orig
    assert middle_entry.upstream_peer == "guard"
    assert middle_entry.upstream_peer != "orig"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_privacy_exit_does_not_know_originator(routers_3hop):
    """Exit only knows middle as its peer."""
    r, net = routers_3hop
    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])

    exit_entry = r["exit"]._relays.get(circuit.hops[2].circuit_id)
    assert exit_entry is not None
    assert exit_entry.upstream_peer == "middle"
    assert exit_entry.upstream_peer != "orig"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_circuit_hop_keys_are_independent(routers_3hop):
    """Each hop has a unique session key — no two hops share the same key."""
    r, _ = routers_3hop
    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])
    keys = [h.key for h in circuit.hops]
    assert len(set(keys)) == len(keys), "All hop keys must be distinct"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_multiple_concurrent_circuits(net):
    """Two circuits built on the same nodes operate independently."""
    r = make_routers(["orig1", "orig2", "relay1", "relay2", "exit"], net)

    c1 = await r["orig1"].build_circuit(["relay1", "exit"])
    c2 = await r["orig2"].build_circuit(["relay2", "exit"])

    recv1, recv2 = [], []
    r["exit"].on_data = lambda sid, d: (recv1 if sid == "s1" else recv2).append(d)

    await r["orig1"].send_data(c1, "s1", b"from-orig1")
    await r["orig2"].send_data(c2, "s2", b"from-orig2")

    assert recv1 == [b"from-orig1"]
    assert recv2 == [b"from-orig2"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_destroy_cleans_relay_entries(routers_1hop):
    r, _ = routers_1hop
    circuit = await r["orig"].build_circuit(["exit"])
    assert len(r["exit"]._relays) == 1

    await r["orig"].destroy_circuit(circuit)
    assert len(r["exit"]._relays) == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_large_payload_3hop(routers_3hop):
    """64 KB payload through a 3-hop circuit."""
    r, _ = routers_3hop
    received = []
    r["exit"].on_data = lambda sid, d: received.append(d)

    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])
    big = os.urandom(65_536)
    await r["orig"].send_data(circuit, "s1", big)
    assert received == [big]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_multiple_messages_same_circuit(routers_3hop):
    r, _ = routers_3hop
    received = []
    r["exit"].on_data = lambda sid, d: received.append(d)

    circuit = await r["orig"].build_circuit(["guard", "middle", "exit"])
    for i in range(5):
        await r["orig"].send_data(circuit, "s1", f"msg-{i}".encode())

    assert received == [f"msg-{i}".encode() for i in range(5)]

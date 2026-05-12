"""
Integration tests — OnionTransport startup with mocked STUN/UPnP.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from murnet.core.net.stun import StunResult
from murnet.core.onion.router import OnionRouter
from murnet.core.onion.transport import OnionTransport


def _make_transport(self_name: str = "test-node") -> OnionTransport:
    router = MagicMock(spec=OnionRouter)
    router.addr = "127.0.0.1:19999"
    t = OnionTransport(
        router=router,
        bind_host="127.0.0.1",
        bind_port=19999,
        self_name=self_name,
    )
    return t


# ── UPnP path ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_upnp_success():
    """UPnP succeeds → public_addr set, announce loop started."""
    t = _make_transport()

    async def _fake_discover_nat(self):
        self.public_addr = "1.2.3.4:19999"
        self.nat_type    = "open"
        self.upnp_active = True

    with patch.object(OnionTransport, "_discover_nat", _fake_discover_nat), \
         patch("asyncio.start_server", new=AsyncMock(return_value=MagicMock())), \
         patch("asyncio.create_task") as mock_task:
        await t.start()

    assert t.public_addr  == "1.2.3.4:19999"
    assert t.upnp_active  is True
    mock_task.assert_called_once()   # announce loop started


@pytest.mark.asyncio
async def test_start_stun_cone():
    """STUN cone NAT → public_addr set, announce loop started."""
    t = _make_transport()

    async def _fake_discover_nat(self):
        self.public_addr = "5.6.7.8:19999"
        self.nat_type    = "cone"

    with patch.object(OnionTransport, "_discover_nat", _fake_discover_nat), \
         patch("asyncio.start_server", new=AsyncMock(return_value=MagicMock())), \
         patch("asyncio.create_task") as mock_task:
        await t.start()

    assert t.public_addr == "5.6.7.8:19999"
    mock_task.assert_called_once()


@pytest.mark.asyncio
async def test_start_symmetric_nat_client_only():
    """Symmetric NAT → public_addr=None, announce loop NOT started."""
    t = _make_transport()

    async def _fake_discover_nat(self):
        self.public_addr = None
        self.nat_type    = "symmetric"

    with patch.object(OnionTransport, "_discover_nat", _fake_discover_nat), \
         patch("asyncio.start_server", new=AsyncMock(return_value=MagicMock())), \
         patch("asyncio.create_task") as mock_task:
        await t.start()

    assert t.public_addr is None
    mock_task.assert_not_called()


@pytest.mark.asyncio
async def test_start_no_self_name_no_announce():
    """Node without self_name never announces regardless of NAT."""
    t = _make_transport(self_name=None)

    async def _fake_discover_nat(self):
        self.public_addr = "9.9.9.9:19999"
        self.nat_type    = "open"

    with patch.object(OnionTransport, "_discover_nat", _fake_discover_nat), \
         patch("asyncio.start_server", new=AsyncMock(return_value=MagicMock())), \
         patch("asyncio.create_task") as mock_task:
        await t.start()

    mock_task.assert_not_called()


@pytest.mark.asyncio
async def test_stop_releases_upnp():
    """stop() calls delete_port_mapping when UPnP was active."""
    t = _make_transport()
    t.upnp_active = True
    upnp_mock = MagicMock()
    upnp_mock.delete_port_mapping = AsyncMock(return_value=True)
    t._upnp = upnp_mock
    t._server = MagicMock()
    t._server.close = MagicMock()
    t._server.wait_closed = AsyncMock()

    await t.stop()

    upnp_mock.delete_port_mapping.assert_awaited_once_with(19999, "TCP")
    assert t.upnp_active is False

"""
Unit tests for murnet.core.net.upnp — mocked SSDP + SOAP.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from murnet.core.net.upnp import (
    UPnPClient,
    _find_control_url,
    _xml_value,
    _soap,
    _strip_ns,
)


# ── XML helpers ───────────────────────────────────────────────────────────────

_DESCRIPTION_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <controlURL>/upnp/control/WANIPConn1</controlURL>
        <eventSubURL>/upnp/event/WANIPConn1</eventSubURL>
        <SCPDURL>/upnp/WANIPConn1.xml</SCPDURL>
      </service>
    </serviceList>
  </device>
</root>"""

_EXT_IP_RESP = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="...">
      <NewExternalIPAddress>203.0.113.5</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>"""

_ADD_MAP_RESP = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMappingResponse xmlns:u="..."/>
  </s:Body>
</s:Envelope>"""

_DEL_MAP_RESP = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:DeletePortMappingResponse xmlns:u="..."/>
  </s:Body>
</s:Envelope>"""


def test_find_control_url():
    result = _find_control_url(_DESCRIPTION_XML)
    assert result is not None
    ctrl, svc = result
    assert "WANIPConn1" in ctrl
    assert "WANIPConnection:1" in svc


def test_find_control_url_missing():
    assert _find_control_url("<root></root>") is None


def test_find_control_url_malformed():
    assert _find_control_url("not xml at all <<<") is None


def test_xml_value():
    assert _xml_value(_EXT_IP_RESP, "NewExternalIPAddress") == "203.0.113.5"
    assert _xml_value(_EXT_IP_RESP, "NoSuchTag") is None


def test_strip_ns():
    assert _strip_ns("{urn:schemas-upnp-org:device-1-0}root") == "root"
    assert _strip_ns("root") == "root"


def test_soap_builder():
    body, action_hdr = _soap(
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "GetExternalIPAddress",
        "",
    )
    assert "GetExternalIPAddress" in body
    assert "WANIPConnection:1" in body
    assert "GetExternalIPAddress" in action_hdr


# ── UPnPClient integration ────────────────────────────────────────────────────

def _make_client_with_ctrl() -> UPnPClient:
    """Return a UPnPClient pre-configured as if discover() already ran."""
    client = UPnPClient()
    client._location  = "http://192.168.1.1:49000/rootDesc.xml"
    client._ctrl_url  = "http://192.168.1.1:49000/upnp/control/WANIPConn1"
    client._service   = "urn:schemas-upnp-org:service:WANIPConnection:1"
    return client


@pytest.mark.asyncio
async def test_get_external_ip():
    client = _make_client_with_ctrl()
    with patch.object(client, "_soap_post", new=AsyncMock(return_value=_EXT_IP_RESP)):
        ip = await client.get_external_ip()
    assert ip == "203.0.113.5"


@pytest.mark.asyncio
async def test_add_port_mapping_success():
    client = _make_client_with_ctrl()

    async def _fake_soap(action, args):
        if action == "GetExternalIPAddress":
            return _EXT_IP_RESP
        if action == "AddPortMapping":
            return _ADD_MAP_RESP
        return None

    with patch.object(client, "_soap_post", side_effect=_fake_soap), \
         patch.object(client, "_local_ip", new=AsyncMock(return_value="192.168.1.100")):
        ok = await client.add_port_mapping(9001, 9001, "TCP")

    assert ok is True


@pytest.mark.asyncio
async def test_add_port_mapping_failure():
    client = _make_client_with_ctrl()
    with patch.object(client, "_soap_post", new=AsyncMock(return_value=None)), \
         patch.object(client, "_local_ip", new=AsyncMock(return_value="192.168.1.100")):
        ok = await client.add_port_mapping(9001, 9001, "TCP")
    assert ok is False


@pytest.mark.asyncio
async def test_delete_port_mapping_success():
    client = _make_client_with_ctrl()
    with patch.object(client, "_soap_post", new=AsyncMock(return_value=_DEL_MAP_RESP)):
        ok = await client.delete_port_mapping(9001, "TCP")
    assert ok is True


@pytest.mark.asyncio
async def test_delete_port_mapping_failure():
    client = _make_client_with_ctrl()
    with patch.object(client, "_soap_post", new=AsyncMock(return_value="<error/>")):
        ok = await client.delete_port_mapping(9001, "TCP")
    assert ok is False


@pytest.mark.asyncio
async def test_soap_post_without_discover():
    """Calling _soap_post before discover() returns None gracefully."""
    client = UPnPClient()
    result = await client._soap_post("SomeAction", "")
    assert result is None


@pytest.mark.asyncio
async def test_discover_no_ssdp_response():
    """discover() returns None when SSDP times out."""
    client = UPnPClient()

    async def _no_ssdp(timeout=3.0):
        return None

    # Patch the asyncio datagram endpoint to simulate no response
    with patch("asyncio.get_running_loop") as mock_loop:
        loop = MagicMock()
        mock_loop.return_value = loop
        fut = MagicMock()
        fut.done.return_value = False
        loop.create_future.return_value = fut

        transport = MagicMock()
        loop.create_datagram_endpoint = AsyncMock(return_value=(transport, None))

        # asyncio.shield + wait_for will time out
        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await client.discover(timeout=0.01)

    assert result is None

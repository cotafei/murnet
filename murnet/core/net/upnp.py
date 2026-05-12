"""
UPnP IGD port mapping — asyncio, aiohttp + stdlib xml.

Flow:
  1. SSDP M-SEARCH → discover IGD location URL
  2. HTTP GET description XML → parse WANIPConnection control URL
  3. SOAP AddPortMapping / DeletePortMapping / GetExternalIPAddress
"""
from __future__ import annotations

import asyncio
import logging
import socket
import xml.etree.ElementTree as ET
from typing import Literal, Optional

import aiohttp

logger = logging.getLogger("murnet.net.upnp")

_SSDP_ADDR   = "239.255.255.250"
_SSDP_PORT   = 1900
_SSDP_MX     = 2
_SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    f"MX: {_SSDP_MX}\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
).encode()

_SERVICE_TYPES = [
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]

_SOAP_ENVELOPE = (
    '<?xml version="1.0"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    "<s:Body>{body}</s:Body>"
    "</s:Envelope>"
)

_LEASE = 3600

Protocol = Literal["TCP", "UDP"]


# ── SSDP ──────────────────────────────────────────────────────────────────────

class _SsdpProto(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future) -> None:
        self._fut = fut

    def datagram_received(self, data: bytes, addr) -> None:
        if self._fut.done():
            return
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.upper().startswith("LOCATION:"):
                self._fut.set_result(line.split(":", 1)[1].strip())
                return

    def error_received(self, exc: Exception) -> None:
        if not self._fut.done():
            self._fut.set_exception(exc)

    def connection_lost(self, exc) -> None:
        if not self._fut.done():
            self._fut.cancel()


# ── XML helpers ───────────────────────────────────────────────────────────────

def _strip_ns(tag: str) -> str:
    """Remove XML namespace from a tag string."""
    return tag.split("}")[-1] if "}" in tag else tag


def _find_control_url(xml_text: str) -> Optional[tuple[str, str]]:
    """
    Parse UPnP device description XML.
    Returns (controlURL, serviceType) for the first matching WAN service.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    for elem in root.iter():
        if _strip_ns(elem.tag) == "service":
            stype = ""
            ctrl  = ""
            for child in elem:
                tag = _strip_ns(child.tag)
                if tag == "serviceType":
                    stype = (child.text or "").strip()
                elif tag == "controlURL":
                    ctrl = (child.text or "").strip()
            for st in _SERVICE_TYPES:
                if st.lower() in stype.lower() and ctrl:
                    return ctrl, stype
    return None


def _xml_value(xml_text: str, tag: str) -> Optional[str]:
    """Extract the text of the first element matching *tag* (ignoring namespace)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    for elem in root.iter():
        if _strip_ns(elem.tag) == tag:
            return (elem.text or "").strip() or None
    return None


# ── SOAP builder ──────────────────────────────────────────────────────────────

def _soap(service: str, action: str, args: str) -> tuple[str, str]:
    """Return (body_xml, SOAPAction_header_value)."""
    inner = (
        f'<u:{action} xmlns:u="{service}">'
        f"{args}"
        f"</u:{action}>"
    )
    return _SOAP_ENVELOPE.format(body=inner), f'"{service}#{action}"'


# ── public API ────────────────────────────────────────────────────────────────

class UPnPClient:
    """
    UPnP IGD client for discovering and managing port mappings.

    Usage::

        client = UPnPClient()
        loc = await client.discover()
        if loc:
            ip = await client.get_external_ip()
            ok = await client.add_port_mapping(9001, 9001, "TCP")
    """

    def __init__(self) -> None:
        self._location:    Optional[str] = None
        self._ctrl_url:    Optional[str] = None
        self._service:     Optional[str] = None

    # ── discover ──────────────────────────────────────────────────────────────

    async def discover(self, timeout: float = 3.0) -> Optional[str]:
        """
        SSDP M-SEARCH for an IGD.
        Returns the description URL or None if no device found within *timeout*.
        """
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[str] = loop.create_future()

        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SsdpProto(fut),
                family=socket.AF_INET,
                allow_broadcast=True,
            )
        except OSError as exc:
            logger.debug("SSDP socket error: %s", exc)
            return None

        try:
            transport.sendto(_SSDP_SEARCH, (_SSDP_ADDR, _SSDP_PORT))
            location = await asyncio.wait_for(asyncio.shield(fut), timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            logger.debug("SSDP: no IGD responded within %.1fs", timeout)
            return None
        except Exception as exc:
            logger.debug("SSDP error: %s", exc)
            return None
        finally:
            transport.close()
            if not fut.done():
                fut.cancel()

        self._location = location
        logger.debug("UPnP: IGD at %s", location)

        # Fetch description to get control URL
        await self._fetch_description(location)
        return location

    async def _fetch_description(self, location: str) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(location, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    xml_text = await resp.text()
        except Exception as exc:
            logger.debug("UPnP: fetch description failed: %s", exc)
            return

        parsed = _find_control_url(xml_text)
        if not parsed:
            logger.debug("UPnP: no WANIPConnection service in description")
            return

        ctrl, svc = parsed
        # Make absolute URL if relative
        if ctrl.startswith("/"):
            from urllib.parse import urlparse
            p = urlparse(location)
            ctrl = f"{p.scheme}://{p.netloc}{ctrl}"
        elif not ctrl.startswith("http"):
            from urllib.parse import urljoin
            ctrl = urljoin(location, ctrl)

        self._ctrl_url = ctrl
        self._service  = svc
        logger.debug("UPnP: control URL %s (%s)", ctrl, svc)

    # ── SOAP actions ──────────────────────────────────────────────────────────

    async def _soap_post(self, action: str, args: str) -> Optional[str]:
        if not self._ctrl_url or not self._service:
            logger.debug("UPnP: not discovered yet — call discover() first")
            return None

        body, soap_action = _soap(self._service, action, args)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._ctrl_url,
                    data=body.encode("utf-8"),
                    headers={
                        "Content-Type": 'text/xml; charset="utf-8"',
                        "SOAPAction":   soap_action,
                    },
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return await resp.text()
        except Exception as exc:
            logger.debug("UPnP SOAP %s failed: %s", action, exc)
            return None

    async def add_port_mapping(
        self,
        external_port: int,
        internal_port: int,
        protocol: Protocol,
        description: str = "MurNet",
    ) -> bool:
        """
        Map *external_port* on the WAN side to *internal_port* on this host.
        Uses the LAN IP obtained from the outbound socket to the IGD.
        """
        internal_host = await self._local_ip()
        args = (
            f"<NewRemoteHost></NewRemoteHost>"
            f"<NewExternalPort>{external_port}</NewExternalPort>"
            f"<NewProtocol>{protocol}</NewProtocol>"
            f"<NewInternalPort>{internal_port}</NewInternalPort>"
            f"<NewInternalClient>{internal_host}</NewInternalClient>"
            f"<NewEnabled>1</NewEnabled>"
            f"<NewPortMappingDescription>{description}</NewPortMappingDescription>"
            f"<NewLeaseDuration>{_LEASE}</NewLeaseDuration>"
        )
        resp = await self._soap_post("AddPortMapping", args)
        ok = resp is not None and "AddPortMappingResponse" in resp
        if ok:
            logger.info("UPnP: mapped %s %s→%d (internal %d)",
                        protocol, await self.get_external_ip(), external_port, internal_port)
        else:
            logger.debug("UPnP: AddPortMapping failed (response: %s)",
                         (resp or "")[:200])
        return ok

    async def delete_port_mapping(
        self,
        external_port: int,
        protocol: Protocol,
    ) -> bool:
        """Remove a previously added port mapping."""
        args = (
            f"<NewRemoteHost></NewRemoteHost>"
            f"<NewExternalPort>{external_port}</NewExternalPort>"
            f"<NewProtocol>{protocol}</NewProtocol>"
        )
        resp = await self._soap_post("DeletePortMapping", args)
        ok = resp is not None and "DeletePortMappingResponse" in resp
        if ok:
            logger.info("UPnP: released %s mapping on port %d", protocol, external_port)
        return ok

    async def get_external_ip(self) -> Optional[str]:
        """Return the WAN IP address reported by the IGD."""
        resp = await self._soap_post("GetExternalIPAddress", "")
        if resp is None:
            return None
        return _xml_value(resp, "NewExternalIPAddress")

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _local_ip(self) -> str:
        """Determine the LAN IP used to reach the IGD."""
        if self._location:
            from urllib.parse import urlparse
            host = urlparse(self._location).hostname or "8.8.8.8"
        else:
            host = "8.8.8.8"
        try:
            loop = asyncio.get_running_loop()
            # Non-blocking: create a connected UDP socket to determine outbound IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((host, 80))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except OSError:
            return "127.0.0.1"

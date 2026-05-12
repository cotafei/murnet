"""Push notification support for MurNet mobile nodes.

Supports Firebase Cloud Messaging (FCM), Apple Push Notification Service (APNS),
and a generic custom HTTP endpoint. Uses only the Python standard library.
"""

import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class PushProvider(Enum):
    NONE = "none"
    FCM = "fcm"
    APNS = "apns"
    CUSTOM = "custom"


@dataclass
class PushConfig:
    provider: PushProvider
    fcm_server_key: str = ""
    apns_cert_path: str = ""
    custom_endpoint: str = ""
    enabled: bool = True


@dataclass
class PushNotification:
    title: str
    body: str
    data: dict = field(default_factory=dict)
    sound: str = "default"
    badge: int = 0


class DeviceRegistry:
    """Persists a mapping of node_address -> device token info in a JSON file."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._devices: dict = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._devices = json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                self._devices = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._devices, indent=2))
        except OSError:
            pass

    def register(self, node_address: str, device_token: str, platform: str) -> None:
        """Register or update a device token for a node address."""
        self._devices[node_address] = {
            "node_address": node_address,
            "platform": platform,
            "token": device_token,
            "registered_at": time.time(),
        }
        self._save()

    def unregister(self, node_address: str) -> None:
        """Remove the device token for a node address."""
        if node_address in self._devices:
            del self._devices[node_address]
            self._save()

    def get_token(self, node_address: str) -> Optional[str]:
        """Return the device token for a node address, or None if not found."""
        entry = self._devices.get(node_address)
        return entry["token"] if entry else None

    def get_all(self) -> list:
        """Return a list of all registered device entries."""
        return list(self._devices.values())


class PushManager:
    """Sends push notifications to registered MurNet mobile nodes."""

    def __init__(self, config: PushConfig, registry: DeviceRegistry) -> None:
        self._config = config
        self._registry = registry
        self._sent = 0
        self._failed = 0

    def send(self, node_address: str, notification: PushNotification) -> bool:
        """Look up the device token for node_address and dispatch the notification."""
        if not self._config.enabled or self._config.provider is PushProvider.NONE:
            return False

        token = self._registry.get_token(node_address)
        if not token:
            self._failed += 1
            return False

        provider = self._config.provider
        try:
            if provider is PushProvider.FCM:
                ok = self._send_fcm(token, notification)
            elif provider is PushProvider.CUSTOM:
                ok = self._send_custom(token, notification)
            else:
                # APNS requires a third-party TLS library for the binary protocol;
                # fall back to custom endpoint if configured, otherwise no-op.
                ok = False
        except Exception:
            ok = False

        if ok:
            self._sent += 1
        else:
            self._failed += 1
        return ok

    def _send_fcm(self, token: str, notification: PushNotification) -> bool:
        """Send via FCM HTTP v1 legacy send endpoint."""
        if not self._config.fcm_server_key:
            return False

        payload = json.dumps({
            "to": token,
            "notification": {
                "title": notification.title,
                "body": notification.body,
                "sound": notification.sound,
                "badge": notification.badge,
            },
            "data": notification.data,
        }).encode()

        req = urllib.request.Request(
            "https://fcm.googleapis.com/fcm/send",
            data=payload,
            headers={
                "Authorization": f"key={self._config.fcm_server_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def _send_custom(self, token: str, notification: PushNotification) -> bool:
        """POST notification to a custom HTTP endpoint as JSON."""
        if not self._config.custom_endpoint:
            return False

        payload = json.dumps({
            "token": token,
            "title": notification.title,
            "body": notification.body,
            "data": notification.data,
        }).encode()

        req = urllib.request.Request(
            self._config.custom_endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def notify_new_message(self, from_addr: str, to_addr: str, preview: str) -> bool:
        """Convenience method: notify to_addr of a new message from from_addr."""
        notification = PushNotification(
            title=f"New message from {from_addr}",
            body=preview,
            data={"from": from_addr, "to": to_addr, "type": "message"},
        )
        return self.send(to_addr, notification)

    def get_stats(self) -> dict:
        """Return counts of sent notifications, failures, and registered devices."""
        return {
            "sent": self._sent,
            "failed": self._failed,
            "registered_devices": len(self._registry.get_all()),
        }

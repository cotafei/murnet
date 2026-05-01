#!/usr/bin/env python3
"""
Murnet Node Status Checker
Checks node health via the REST API.

Usage:
    python node_status.py [--url URL] [--token TOKEN]

Exit codes:
    0 - node healthy
    1 - node unhealthy or unreachable
"""
import argparse
import json
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import timedelta

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _request(method: str, url: str, data: dict | None = None,
             token: str | None = None, timeout: int = 10) -> dict:
    """Minimal HTTP client using only stdlib."""
    body = json.dumps(data).encode() if data is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"detail": raw or str(exc)}
        raise RuntimeError(
            f"HTTP {exc.code} from {url}: {payload.get('detail', exc.reason)}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach {url}: {exc.reason}") from exc


def get(url: str, token: str | None = None) -> dict:
    return _request("GET", url, token=token)


def post(url: str, data: dict | None = None, token: str | None = None) -> dict:
    return _request("POST", url, data=data, token=token)


# ── Formatting helpers ────────────────────────────────────────────────────────

def fmt_uptime(seconds: int | float) -> str:
    td = timedelta(seconds=int(seconds))
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def section(title: str) -> None:
    print(f"\n  {'─' * 36}")
    print(f"   {title}")
    print(f"  {'─' * 36}")


def row(label: str, value, width: int = 24) -> None:
    print(f"   {label:<{width}} {value}")


# ── Main logic ────────────────────────────────────────────────────────────────

def check_health(base_url: str) -> dict:
    """GET /health — no auth required."""
    return get(f"{base_url}/health")


def login(base_url: str) -> str:
    """POST /auth/login — returns a JWT token."""
    resp = post(f"{base_url}/auth/login")
    token = resp.get("token")
    if not token:
        raise RuntimeError(f"Login succeeded but no token in response: {resp}")
    return token


def get_network_status(base_url: str, token: str) -> dict:
    """GET /network/status — requires auth."""
    return get(f"{base_url}/network/status", token=token)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Murnet node health via the REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit code 0 = healthy, 1 = unhealthy/error",
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8080",
        metavar="URL",
        help="Base URL of the Murnet API (default: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--token",
        default=None,
        metavar="JWT",
        help="JWT bearer token. If omitted, a login attempt is made first.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="Request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    overall_healthy = True

    # ── 1. Health check ───────────────────────────────────────────────────────
    print(f"\n[Murnet Node Status]  {base_url}")

    try:
        health = check_health(base_url)
        status_str = health.get("status", "unknown")
        node_running = health.get("node_running", False)
        is_healthy = status_str == "healthy" and node_running

        section("Health  (GET /health)")
        row("Status:", status_str.upper())
        row("Node running:", "yes" if node_running else "NO")
        row("API version:", health.get("version", "?"))
        row("Uptime:", fmt_uptime(health.get("uptime", 0)))
        row("Connected peers:", health.get("peers_count", 0))

        if not is_healthy:
            overall_healthy = False
            print(f"\n  [!] Node is NOT healthy (status={status_str!r}, running={node_running})")

    except RuntimeError as exc:
        print(f"\n  [!] Health check FAILED: {exc}")
        return 1

    # ── 2. Acquire token ──────────────────────────────────────────────────────
    token = args.token
    if not token:
        try:
            token = login(base_url)
            print(f"\n  Logged in successfully (token obtained).")
        except RuntimeError as exc:
            print(f"\n  [!] Login failed: {exc}")
            print("      Use --token to supply a JWT manually.")
            overall_healthy = False
            # Still show what we have and exit
            print("\n  (Skipping /network/status — no token available)")
            return 1 if not overall_healthy else 0

    # ── 3. Network / node status ──────────────────────────────────────────────
    try:
        ns = get_network_status(base_url, token)
        node = ns.get("node", {})
        net  = ns.get("network", {})

        section("Node  (GET /network/status)")
        row("Address:", node.get("address", "?"))
        row("Status:", node.get("status", "?").upper())
        row("Version:", node.get("version", "?"))
        row("Uptime:", fmt_uptime(node.get("uptime_seconds", 0)))
        row("Active peers:", node.get("peers_count", 0))
        row("DHT entries:", node.get("dht_entries", 0))
        row("Storage used:", f"{node.get('storage_used_mb', 0):.1f} / "
            f"{node.get('storage_total_mb', 0)} MB")
        row("Messages stored:", node.get("messages_count", 0))

        section("Network traffic")
        row("Packets sent:", net.get("packets_sent", 0))
        row("Packets received:", net.get("packets_received", 0))
        row("Bytes sent:", f"{net.get('bytes_sent', 0):,}")
        row("Bytes received:", f"{net.get('bytes_received', 0):,}")

        if node.get("status", "").lower() not in ("online", "healthy"):
            overall_healthy = False

    except RuntimeError as exc:
        print(f"\n  [!] Network status check FAILED: {exc}")
        overall_healthy = False

    # ── 4. Summary ────────────────────────────────────────────────────────────
    print(f"\n  {'─' * 36}")
    if overall_healthy:
        print("  Result: HEALTHY")
    else:
        print("  Result: UNHEALTHY")
    print(f"  {'─' * 36}\n")

    return 0 if overall_healthy else 1


if __name__ == "__main__":
    sys.exit(main())

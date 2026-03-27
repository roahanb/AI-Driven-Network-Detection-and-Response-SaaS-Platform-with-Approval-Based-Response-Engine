#!/usr/bin/env python3
"""
Suricata → AI-NDR Platform live watcher.

Tails Suricata's eve.json in real-time, batches new events,
and POSTs them to the NDR platform's /upload-logs endpoint.

Usage:
    python3 ndr_watcher.py [--api http://localhost:8000] [--token JWT_TOKEN]
"""

import argparse
import json
import os
import sys
import time
import tempfile
import subprocess
import signal
import logging
from pathlib import Path
from datetime import datetime

# ─── Config ───────────────────────────────────────────────────────────────────

EVE_LOG = Path(__file__).parent / "logs" / "eve.json"
STATE_FILE = Path(__file__).parent / "logs" / ".watcher_offset"
BATCH_SIZE = 50           # max events per upload
POLL_INTERVAL = 5         # seconds between polls
UPLOAD_TIMEOUT = 30       # seconds before upload request times out

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NDR-WATCHER] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ─── Interface detection ──────────────────────────────────────────────────────

def get_active_interface() -> str:
    """Return the current default network interface (en0, en1, utun, etc.)."""
    try:
        result = subprocess.run(
            ["route", "get", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "interface:" in line:
                return line.split()[-1].strip()
    except Exception:
        pass
    return "en0"  # fallback


# ─── NDR upload ───────────────────────────────────────────────────────────────

def upload_events(events: list, api_base: str, token: str) -> bool:
    """Batch events into a temp JSONL file and POST to /upload-logs."""
    if not events:
        return True

    # Write batch as JSONL (one JSON object per line)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="suricata_batch_", delete=False
    ) as f:
        for evt in events:
            f.write(json.dumps(evt) + "\n")
        tmp_path = f.name

    try:
        import urllib.request
        import urllib.error

        with open(tmp_path, "rb") as fdata:
            content = fdata.read()

        boundary = "----NDRBoundary7MA4YWxkTrZu0gW"
        filename = f"suricata_live_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/json\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

        req = urllib.request.Request(
            f"{api_base.rstrip('/')}/upload-logs",
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=UPLOAD_TIMEOUT) as resp:
            result = json.loads(resp.read())
            incidents = result.get("incidents_found", 0)
            log.info(f"Uploaded {len(events)} events → {incidents} incidents detected")
            return True

    except Exception as e:
        log.error(f"Upload failed: {e}")
        return False
    finally:
        os.unlink(tmp_path)


# ─── EVE JSON tailer ──────────────────────────────────────────────────────────

def load_offset() -> int:
    """Load the last-read byte offset so we don't re-process old events."""
    try:
        return int(STATE_FILE.read_text().strip())
    except Exception:
        return 0


def save_offset(offset: int):
    STATE_FILE.write_text(str(offset))


def read_new_events(offset: int) -> tuple[list, int]:
    """Read new lines from eve.json since `offset`. Returns (events, new_offset)."""
    if not EVE_LOG.exists():
        return [], offset

    events = []
    new_offset = offset

    with open(EVE_LOG, "r", errors="replace") as f:
        # If file was rotated/truncated, reset
        f.seek(0, 2)
        file_size = f.tell()
        if offset > file_size:
            log.warning("EVE log rotated, resetting offset")
            offset = 0

        f.seek(offset)
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                obj = json.loads(line)
                events.append(obj)
            except json.JSONDecodeError:
                pass
        new_offset = f.tell()

    return events, new_offset


# ─── Filter relevant events ───────────────────────────────────────────────────

# Event types that carry meaningful user activity (domain names, threat signatures)
# flow/netflow are pure connection counters — dropped entirely as noise
RELEVANT_EVENT_TYPES = {"alert", "anomaly", "dns", "http", "tls", "ssh", "ftp", "smtp"}

# RFC-1918 private IP prefixes
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                     "127.", "::1", "fe80:", "fc", "fd")

def _is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES)

def _has_domain(evt: dict) -> bool:
    """Return True if this event has an application-layer domain name."""
    dns = evt.get("dns", {}) or {}
    http = evt.get("http", {}) or {}
    tls = evt.get("tls", {}) or {}
    domain = (
        http.get("hostname") or
        dns.get("rrname") or
        (dns.get("queries") or [{}])[0].get("rrname") or
        tls.get("sni") or
        evt.get("domain") or ""
    )
    return bool(domain and domain.strip())

def filter_events(events: list) -> list:
    """
    Keep only user-activity and threat events:
    - Always keep: alerts and anomalies
    - Keep: DNS/HTTP/TLS events with a domain name (shows what user is accessing)
    - Drop: flow/netflow (pure connection stats — background noise)
    - Drop: DNS/TLS/HTTP with no domain and both IPs local (mDNS, SSDP, etc.)
    """
    filtered = []
    for evt in events:
        event_type = evt.get("event_type", "")
        src = evt.get("src_ip", "")
        dst = evt.get("dest_ip", "")

        # Always keep threat alerts and anomalies
        if event_type in ("alert", "anomaly"):
            filtered.append(evt)
            continue

        if event_type not in RELEVANT_EVENT_TYPES:
            continue
        if not src or not dst:
            continue

        # For DNS/HTTP/TLS: require a domain name OR an external IP
        # This filters out local mDNS (.local), SSDP, DHCP noise
        if event_type in ("dns", "http", "tls"):
            has_external = not _is_private(dst) or not _is_private(src)
            if not _has_domain(evt) and not has_external:
                continue  # no domain + both local = noise

        # SSH/FTP/SMTP: always keep (potential lateral movement / data exfil)
        filtered.append(evt)
    return filtered


# ─── Main loop ────────────────────────────────────────────────────────────────

def login(api_base: str, email: str, password: str) -> str:
    """Login and return a fresh JWT access token."""
    import urllib.request, urllib.error
    body = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/api/v1/auth/login",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
        return data["access_token"]


def main():
    parser = argparse.ArgumentParser(description="Suricata → NDR Platform watcher")
    parser.add_argument("--api", default="http://localhost:8000", help="NDR API base URL")
    parser.add_argument("--token", default="", help="JWT access token (optional if --email/--password given)")
    parser.add_argument("--email", default="", help="NDR login email (auto-login)")
    parser.add_argument("--password", default="", help="NDR login password (auto-login)")
    parser.add_argument("--reset", action="store_true", help="Reset offset (reprocess all events)")
    args = parser.parse_args()

    # Auto-login if credentials provided (or token missing)
    token = args.token
    if not token and args.email and args.password:
        log.info(f"Logging in as {args.email}...")
        try:
            token = login(args.api, args.email, args.password)
            log.info("Login successful")
        except Exception as e:
            log.error(f"Login failed: {e}")
            sys.exit(1)
    elif not token:
        log.error("Provide --token or both --email and --password")
        sys.exit(1)

    if args.reset and STATE_FILE.exists():
        STATE_FILE.unlink()
        log.info("Offset reset — will reprocess all existing events")

    iface = get_active_interface()
    log.info(f"NDR Watcher started | API: {args.api} | Interface: {iface}")
    log.info(f"Watching: {EVE_LOG}")

    offset = load_offset()
    pending: list = []
    running = True

    def shutdown(sig, frame):
        nonlocal running
        log.info("Shutting down watcher...")
        running = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    last_iface_check = time.time()
    last_iface = iface

    while running:
        # Periodically re-check active interface (for Wi-Fi/VPN switching)
        if time.time() - last_iface_check > 30:
            current_iface = get_active_interface()
            if current_iface != last_iface:
                log.info(f"Network interface changed: {last_iface} → {current_iface}")
                last_iface = current_iface
            last_iface_check = time.time()

        # Read new events
        new_events, offset = read_new_events(offset)
        new_events = filter_events(new_events)

        if new_events:
            pending.extend(new_events)
            log.info(f"Found {len(new_events)} new events (pending: {len(pending)})")

        # Upload when batch is full or on a timer
        if len(pending) >= BATCH_SIZE or (pending and len(pending) > 0):
            batch = pending[:BATCH_SIZE]
            if upload_events(batch, args.api, token):
                pending = pending[BATCH_SIZE:]
                save_offset(offset)
            else:
                # Auto re-login on 401 if credentials available
                if args.email and args.password:
                    try:
                        token = login(args.api, args.email, args.password)
                        log.info("Token refreshed via auto-login")
                    except Exception as e:
                        log.error(f"Token refresh failed: {e}")
                log.warning("Upload failed, will retry next poll")

        time.sleep(POLL_INTERVAL)

    # Final flush
    if pending:
        log.info(f"Flushing {len(pending)} remaining events...")
        upload_events(pending, args.api, token)
        save_offset(offset)

    log.info("Watcher stopped.")


if __name__ == "__main__":
    main()

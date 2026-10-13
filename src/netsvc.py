"""Embedded network services: DNS on UDP :53 (wildcard -> PC IP) and HTTP :8080
serving assets/exploit plus a JSON status endpoint."""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

log = logging.getLogger("netsvc")

# Minimal DNS frame helpers (stdlib only — no dnslib dependency).
_DNS_FLAGS = 0x8180  # standard response, recursion available, no error
_TTL = 1


def _encode_a_response(query: bytes, ip: str) -> Optional[bytes]:
    """Compose an A answer for an A/A query; None for types we punt on (empty NOERROR)."""
    try:
        if len(query) < 12:
            return None
        qdcount = int.from_bytes(query[4:6], "big")
        # Parse the first question.
        pos = 12
        for _ in range(max(qdcount, 1)):
            while pos < len(query) and query[pos] != 0:
                pos += 1 + query[pos]
            pos += 1  # root label
            qtype, qclass = int.from_bytes(query[pos : pos + 2], "big"), int.from_bytes(
                query[pos + 2 : pos + 4], "big"
            )
            pos += 4
            break
        header = query[:2] + int(_DNS_FLAGS).to_bytes(2, "big") + (
            b"\x00\x01" + b"\x00\x00" if qtype != 1 else b"\x00\x01\x00\x01"
        ) + b"\x00\x00\x00\x00"
        question = query[12:pos]
        if qtype != 1:  # only A records; anything else gets NOERROR/empty
            return query[:2] + int(_DNS_FLAGS).to_bytes(2, "big") + \
                b"\x00\x01\x00\x00\x00\x00\x00\x00" + question
        name_ptr = b"\xc0\x0c"
        rr = name_ptr + (1).to_bytes(2, "big") + qclass.to_bytes(2, "big") + \
            _TTL.to_bytes(4, "big") + (4).to_bytes(2, "big") + \
            bytes(int(x) for x in ip.split("."))
        return header + question + rr
    except Exception as exc:  # noqa: BLE001
        log.debug("dns encode failed: %s", exc)
        return None


def port_available(port: int) -> tuple[bool, Optional[str]]:
    """Check whether a TCP port is bindable on both wildcard and loopback.

    Windows allows a wildcard bind to coexist with a more-specific
    127.0.0.1 bind (e.g. Steam's webhelper on 8080), which silently steals
    loopback traffic — so both scopes are probed.
    Returns (free, owner_hint): cause + recommended fix for the caller.
    """
    for bind_ip in ("", "127.0.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            s.settimeout(1.5)
            s.bind((bind_ip, port))
            s.close()
        except PermissionError:
            return False, "permission_denied (ports <1024 need admin/privileges)"
        except OSError as exc:
            scope = "loopback" if bind_ip else "wildcard"
            return False, f"in_use on {scope} ({exc}) - change the port in config/settings.json"
    return True, None


class DnsWildServer(threading.Thread):
    """UDP :53 server answering EVERY A query with this PC's LAN IP.

    Security: the listener answers from the LAN interface only and drops
    queries whose source address is outside the PC's own /24 unless
    wide_open=True — the embedded resolver is meant to serve the console,
    not the internet.
    """

    def __init__(self, answer_ip: str, port: int = 53, wide_open: bool = False) -> None:
        super().__init__(daemon=True, name="dns-wild")
        self.answer_ip = answer_ip
        self.port = port
        self.wide_open = wide_open
        self.sock: Optional[socket.socket] = None

    def _same_subnet(self, src_ip: str) -> bool:
        import ipaddress
        try:
            return ipaddress.ip_address(src_ip) in \
                ipaddress.ip_network(f"{self.answer_ip}/24", strict=False)
        except ValueError:
            return False

    def run(self) -> None:
        try:
            if self.sock is None:  # allow tests to inject a pre-bound socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.settimeout(1.0)
                self.sock.bind(("0.0.0.0", self.port))
            log.info("wildcard DNS listening on UDP :%d -> %s", self.port, self.answer_ip)
            while True:
                try:
                    query, addr = self.sock.recvfrom(1500)
                except socket.timeout:
                    continue
                if not self.wide_open and not self._same_subnet(addr[0]):
                    log.debug("dropping DNS query from foreign subnet %s", addr[0])
                    continue
                resp = _encode_a_response(query, self.answer_ip)
                if resp:
                    self.sock.sendto(resp, addr)
        except OSError as exc:
            log.warning("DNS server stopped (%s). Console DNS will not resolve.", exc)

    def stop(self) -> None:
        if self.sock:
            self.sock.close()


class _Status:
    """Mutable status shared with the HTTP handler."""

    def __init__(self, getter: Callable[[], Dict]) -> None:
        self.getter = getter


def make_http_server(
    exploit_dir: str,
    payload_dir: str,
    status_getter: Callable[[], Dict],
    port: int = 8080,
    bind_ip: str = "0.0.0.0",
) -> ThreadingHTTPServer:
    """HTTP host serving the exploit page, payload ELFs and /status JSON."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server API
            path = self.path.split("?")[0]
            if path in ("/status", "/status.json"):
                body = json.dumps(status_getter()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            root = payload_dir if path.startswith("/payloads/") else exploit_dir
            rel = path[len("/payloads/"):] if path.startswith("/payloads/") else (
                "index.html" if path in ("/", "") else path.lstrip("/")
            )
            full = os.path.normpath(os.path.join(root, rel))
            if not full.startswith(os.path.normpath(root) + os.sep) and \
                    not full == os.path.normpath(root):
                self.send_error(403)
                return
            ctype = {
                ".elf": "application/octet-stream", ".bin": "application/octet-stream",
                ".html": "text/html", ".js": "application/javascript",
                ".json": "application/json",
            }.get(os.path.splitext(full)[1].lower(), "application/octet-stream")
            try:
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt: str, *args: object) -> None:
            log.debug("http %s", fmt % args)

    server = ThreadingHTTPServer((bind_ip, port), Handler)
    server.daemon_threads = True
    return server

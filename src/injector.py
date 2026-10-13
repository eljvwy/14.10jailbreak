"""TCP ELF injection to the console's loaders.

Modes supported (verified against ps5-payload-dev/elfldr, see NOTES.md §2):
  raw  : raw ELF bytes over TCP :9021
  file : text line  file:/data/<name>.elf
  http : text line  http://<PC-IP>:<http-port>/payloads/<name>.elf
Every call has an explicit timeout and returns a structured result.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

log = logging.getLogger("injector")


@dataclass
class InjectResult:
    """Outcome of a single injection attempt."""

    ok: bool
    reason: str
    bytes_sent: int = 0


class Injector:
    """Send payloads to the console over the elfldr / bootstrap protocols."""

    def __init__(self, settings: Dict, ps5_ip: str) -> None:
        self.elfldr_port = int(settings.get("elfldr", {}).get("port", 9021))
        self.boot_port = int(settings.get("bootstrap_loader", {}).get("port", 9020))
        self.http_port = int(settings.get("http", {}).get("port", 8080))
        self.ps5_ip = ps5_ip
        self.timeout = 20.0

    # ---------- probes ----------
    def elfldr_open(self, port: Optional[int] = None, timeout: float = 3.0) -> bool:
        """Is a loader port open right now? (No banner protocol documented.)"""
        return _tcp_connect(self.ps5_ip, port or self.elfldr_port, timeout)

    # ---------- injection ----------
    def inject_raw(self, elf_bytes: bytes, port: Optional[int] = None) -> InjectResult:
        """Send raw ELF bytes; caller closes (loader treats EOF as end)."""
        port = port or self.elfldr_port
        try:
            sock = socket.create_connection((self.ps5_ip, port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            sock.sendall(elf_bytes)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(3.0)
            try:
                reply = sock.recv(256)  # tolerate loader reply/EOF
                if reply is None:
                    return InjectResult(False, "connection_reset")
            except (ConnectionResetError, ConnectionAbortedError):
                return InjectResult(False, "connection_reset")
            except OSError:
                pass
            sock.close()
            log.info("injected %d raw bytes to %s:%d", len(elf_bytes), self.ps5_ip, port)
            return InjectResult(True, "injected", len(elf_bytes))
        except OSError as exc:
            return InjectResult(False, f"tcp_error:{exc}")

    def inject_raw_path(self, local_path: str, port: Optional[int] = None) -> InjectResult:
        """Send a validated ELF from disk (raw mode) without caching it in memory."""
        try:
            with open(local_path, "rb") as fh:
                return self.inject_raw(fh.read(), port=port)
        except OSError as exc:
            return InjectResult(False, f"missing_file:{local_path} ({exc})")

    def inject_uri(self, uri: str, port: Optional[int] = None) -> InjectResult:
        """Send a text URI line (file:/data/x.elf or http://host:port/x.elf)."""
        port = port or self.elfldr_port
        line = uri.encode() + b"\n"
        try:
            sock = socket.create_connection((self.ps5_ip, port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            sock.sendall(line)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(3.0)
            try:
                sock.recv(256)
            except (ConnectionResetError, ConnectionAbortedError):
                return InjectResult(False, "connection_reset")
            except OSError:
                pass
            sock.close()
            log.info("injected URI %s to %s:%d", uri, self.ps5_ip, port)
            return InjectResult(True, "injected", len(line))
        except OSError as exc:
            return InjectResult(False, f"tcp_error:{exc}")

    def inject_http(self, payload_name: str, pc_ip: str) -> InjectResult:
        """Preferred mode: console pulls the ELF from this PC over HTTP."""
        uri = f"http://{pc_ip}:{self.http_port}/payloads/{payload_name}"
        return self.inject_uri(uri)

    # ---------- liveness ----------
    def console_responsive(self, timeout: float = 3.0) -> bool:
        """Console considered responsive while either loader port still opens."""
        return self.elfldr_open(self.elfldr_port) or self.elfldr_open(self.boot_port)

    def wait_port(self, port: int, timeout: float, poll: float = 1.0,
                  cancel: Optional[threading.Event] = None) -> bool:
        """Block (polling) until port opens, timeout elapses, or cancel is set."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cancel is not None and cancel.is_set():
                return False
            if self.elfldr_open(port):
                return True
            time.sleep(poll)
        return False


def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

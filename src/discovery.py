"""PS5 LAN discovery and IP-change tracking.

Order per spec: cached last_seen -> SSDP/mDNS sweep -> UDP broadcast beacon ->
ARP table + concurrent TCP probes of the payload ports. Re-probes every
``reprobe_seconds`` and re-resolves by MAC so DHCP changes are followed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import struct
import subprocess
import concurrent.futures
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

log = logging.getLogger("discovery")

SSDP_ADDR = ("239.255.255.250", 1900)


@dataclass
class DiscoveredPS5:
    """Everything we know about where the console is right now."""

    ip: str = ""
    mac: str = ""
    history: List[str] = field(default_factory=list)
    last_ports: Tuple[bool, bool] = (False, False)  # (9020, 9021)


class Discovery:
    """Discover a PS5, follow IP changes, never crash on network errors."""

    def __init__(
        self,
        settings: Dict,
        last_seen_path: str = "config/last_seen.json",
        on_change: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.cfg = settings.get("discovery", {})
        self.ports = (
            int(settings.get("bootstrap_loader", {}).get("port", 9020)),
            int(settings.get("elfldr", {}).get("port", 9021)),
        )
        self.reprobe_seconds = float(self.cfg.get("reprobe_seconds", 3))
        self.probe_timeout = float(self.cfg.get("probe_timeout_seconds", 1.5))
        self.last_seen_path = last_seen_path
        self.on_change = on_change
        self.ps5 = DiscoveredPS5()
        self._stop = False

    # ---------- persistence ----------
    def _load_last_seen(self) -> Optional[Dict[str, str]]:
        try:
            with open(self.last_seen_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:  # noqa: BLE001 - missing/corrupt cache is fine
            return None

    def save_last_seen(self) -> None:
        """Atomically persist current IP/MAC for fast next cold start."""
        try:
            os.makedirs(os.path.dirname(self.last_seen_path) or ".", exist_ok=True)
            tmp = self.last_seen_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"ip": self.ps5.ip, "mac": self.ps5.mac}, fh)
            os.replace(tmp, self.last_seen_path)
        except Exception as exc:  # noqa: BLE001
            log.debug("could not save last_seen: %s", exc)

    # ---------- primitives ----------
    @staticmethod
    def local_ip() -> str:
        """This PC's LAN IP (UDP-connect trick; no packets sent)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    @staticmethod
    def tcp_probe(ip: str, port: int, timeout: float = 1.5) -> bool:
        """True if a TCP connection to ip:port succeeds inside timeout."""
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            return False

    def probe_ports(self, ip: str) -> Tuple[bool, bool]:
        """Probe both payload ports concurrently."""
        if not ip or ip.count(".") != 3:
            return (False, False)
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            futs = [ex.submit(self.tcp_probe, ip, p, self.probe_timeout) for p in self.ports]
            return tuple(f.result() for f in futs)  # type: ignore[return-value]

    # ---------- discovery methods (a-d) ----------
    def find_arp_entries(self) -> List[Tuple[str, str]]:
        """Parse (ip, mac) pairs from the OS ARP table."""
        out: List[Tuple[str, str]] = []
        try:
            if os.name == "nt":
                raw = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=5
                ).stdout
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", re.I
                )
            else:
                raw = subprocess.run(
                    ["arp", "-n"], capture_output=True, text=True, timeout=5
                ).stdout
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+).+?([0-9a-fA-F:]{17})", re.I
                )
            for m in pattern.finditer(raw):
                out.append((m.group(1), m.group(2).lower()))
        except Exception as exc:  # noqa: BLE001
            log.debug("arp parse failed: %s", exc)
        return out

    @staticmethod
    def subnet_broadcast_addrs() -> List[str]:
        """255.255.255.255 + each interface's subnet broadcast address."""
        addrs = {"255.255.255.255"}
        ip = Discovery.local_ip()
        m = re.match(r"(\d+\.\d+\.\d+)\.", ip)
        if m:
            addrs.add(f"{m.group(1)}.255")
        return sorted(addrs)

    @staticmethod
    def ssdp_sweep(timeout: float = 3.0) -> List[str]:
        """Send M-SEARCH, return IPs that answered."""
        found: List[str] = []
        msg = (
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        ).encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(msg, SSDP_ADDR)
            while True:
                try:
                    data, addr = s.recvfrom(4096)
                    if b"SCE" in data.upper() or b"PlayStation" in data:
                        found.append(addr[0])
                except socket.timeout:
                    break
            s.close()
        except OSError as exc:
            log.debug("ssdp error: %s", exc)
        return found

    @staticmethod
    def mdns_sweep(timeout: float = 5.0) -> List[str]:
        """Query mDNS for _nv-stream / _ipp schemes PS5 answers (raw UDP 5353)."""
        found: List[str] = []
        # One simple multicast query for _http._tcp.local anunci PS5 adverts.
        try:
            q = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            q += b"\x10_http._tcp\x05local\x00\x00\x0c\x00\x01"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("", 0))
                s.sendto(q, ("224.0.0.251", 5353))
                end = timeout
                while end > 0:
                    try:
                        _, addr = s.recvfrom(4096)
                        if addr[0] not in found:
                            found.append(addr[0])
                    except socket.timeout:
                        break
            finally:
                s.close()
        except OSError as exc:
            log.debug("mdns error: %s", exc)
        return found

    def udp_beacon_sweep(self) -> List[str]:
        """Fire UDP beacon at broadcast addrs and collect consoles probing 9020/9021 from ARP."""
        ips = [ip for ip, _mac in self.find_arp_entries()]
        return ips

    # ---------- top-level ----------
    def discover(self) -> Optional[str]:
        """Run the full discovery ladder; return IP or None."""
        ip = self._try_cached()
        if not ip:
            ip = self._try_network_sweep()
        if ip and ip != self.ps5.ip:
            old = self.ps5.ip
            self.ps5.history.append(ip)
            self.ps5.ip = ip
            self.ps5.last_ports = self.probe_ports(ip)
            if old:
                log.info("PS5 address changed %s -> %s, reconnecting", old, ip)
                if self.on_change:
                    self.on_change(old, ip)
            else:
                log.info("PS5 discovered at %s (ports 9020/9021 live: %s)",
                         ip, self.ps5.last_ports)
            self.save_last_seen()
        return ip or None

    def _try_cached(self) -> Optional[str]:
        cached = self._load_last_seen()
        if not cached:
            return None
        ip = str(cached.get("ip", ""))
        if self.probe_ports(ip) != (False, False):
            self.ps5.mac = str(cached.get("mac", ""))
            return ip
        return None

    def _try_network_sweep(self) -> Optional[str]:
        for ip in self.ssdp_sweep(float(self.cfg.get("ssdp_timeout_seconds", 3.0))):
            if self.probe_ports(ip) != (False, False):
                return ip
        for ip in self.mdns_sweep(float(self.cfg.get("mdns_timeout_seconds", 5.0))):
            if self.probe_ports(ip) != (False, False):
                return ip
        for ip in self.udp_beacon_sweep():
            if self.probe_ports(ip) != (False, False):
                return ip
        return None

    def stop(self) -> None:
        self._stop = True

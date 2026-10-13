"""Mock-console integration suite.

An isolated local MockConsole implements ONLY the documented host-side test
interfaces (TCP listeners standing in for :9020, :9021 and the FTP evidence
port, on loopback with ephemeral ports). It uses synthetic test files only -
never real exploit payloads.

CRITICAL DISTINCTION: the mock separates *simulated acknowledgements*
(bytes accepted on the payload port) from *simulated execution evidence*
(the FTP port answering). Reaching COMPLETE against the mock proves the
host's logic works - it does NOT and CANNOT represent a real PS5 jailbreak.
"""
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import chains  # noqa: E402
import discovery  # noqa: E402
import injector as inj_mod  # noqa: E402
import netsvc  # noqa: E402
import payloads as pay_mod  # noqa: E402
from firmware import Profile  # noqa: E402

PROFILE = Profile(
    id="mock_7_13", fw_range="7.00-13.60", userland_stage="relapse_webkit",
    kernel_stage="relapse_kernel", hv_stage="none", payload_chain=["t1.elf", "t2.elf"],
    notes="synthetic", verified_by_user=False, experimental=False,
    kernel_stage_fallbacks=[])


class _Listener:
    """One TCP listener with switchable behavior (accept / reset / refuse)."""

    def __init__(self, ip: str, mode: str = "accept"):
        self.mode = mode
        self.acks = 0
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((ip, 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.ip = ip
        if mode == "absent":
            # Port recorded but immediately freed: connect() must be refused.
            self.srv.close()
            return
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        self.srv.settimeout(0.3)
        while not self._stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.mode == "refuse":
                conn.close()
                continue
            if self.mode == "reset":
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                b"\x01\x00\x00\x00\x00\x00\x00\x00")
                conn.close()  # RST
                continue
            if self.mode == "data_rst":
                # Deterministic: probe connections (client closes immediately)
                # get a graceful close; payload connections (data present) get RST.
                try:
                    conn.settimeout(2)
                    data = conn.recv(65536)
                except OSError:
                    data = b""
                if data:
                    self.acks += len(data)
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                    b"\x01\x00\x00\x00\x00\x00\x00\x00")
                conn.close()
                continue
            try:
                conn.settimeout(2)
                data = conn.recv(65536)
                if data:
                    self.acks += len(data)
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        if self.mode == "absent":
            return
        self._stop.set()
        try:
            self.srv.close()
        except OSError:
            pass


class MockConsole:
    """Simulated console: distinct ack channel vs execution-evidence channel."""

    def __init__(self, ip: str = "127.0.0.1",
                 modes=(("boot", "accept"), ("elfldr", "accept"),
                        ("evidence", "accept"))):
        self.ip = ip
        self.listeners = {}
        for name, mode in modes:
            self.listeners[name] = _Listener(ip, mode)

    @property
    def ports(self):
        return {n: l.port for n, l in self.listeners.items()}

    @property
    def ack_count(self) -> int:
        """Simulated payload acknowledgements (bytes accepted) - NOT proof of execution."""
        return self.listeners["elfldr"].acks

    def stop(self) -> None:
        for l in self.listeners.values():
            l.stop()


def make_settings(console: MockConsole, payload_dir: str, evidence=True) -> dict:
    """Settings wired to the mock's ephemeral ports."""
    p = console.ports
    return {
        "http": {"port": 8080},
        "bootstrap_loader": {"port": p["boot"]},
        "elfldr": {"port": p["elfldr"]},
        "ftp": {"port": p["evidence"]},
        "chain": {
            "userland_max_attempts": 2,
            "userland_stage_timeout_seconds": 0.5,
            "kernel_watchdog_seconds": 1.0,
            "payload_retries": 3,
            "backoff_base_seconds": 0.05,
            "backoff_factor": 2.0,
            "payloads_in_order": ["t1.elf", "t2.elf"],
            "delivery_mode": "raw",
            "notify_success": "succsecfull jailbrea",
            "notify_failure": "failed jailbrea",
            "ftp_port": p["evidence"] if evidence else 1,
            "payload_dir": payload_dir,
        },
    }


def make_payload_dir(tmp_path):
    """Synthetic ELF-ish test files + complete provenance manifest."""
    d = str(tmp_path)
    names = ["t1.elf", "t2.elf"]
    manifest = {}
    for n in names:
        # Structurally valid minimal aarch64 ELF header + synthetic body
        # (test_fixture from tests/test_payloads.py's make_elf).
        e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
        ehdr = e_ident + (2).to_bytes(2, "little") + (183).to_bytes(2, "little") + \
            (1).to_bytes(4, "little") + (0).to_bytes(8, "little") * 3 + \
            (64).to_bytes(8, "little") + (0).to_bytes(2, "little") * 5 + \
            (64).to_bytes(2, "little")
        blob = ehdr + f"synthetic-{n}".encode() * 32
        (tmp_path / n).write_bytes(blob)
        manifest[n] = {"kind": "upstream", "source_url": "synthetic://test",
                       "revision": "test", "sha256": hashlib.sha256(blob).hexdigest()}
    (tmp_path / pay_mod.MANIFEST_NAME).write_text(json.dumps(manifest))
    return d


def make_engine(settings, console, ip=None, allow_placeholder=False, notifications=None):
    inj = inj_mod.Injector(settings, ip or console.ip)
    notes = notifications if notifications is not None else []
    eng = chains.ChainEngine(
        settings, inj, PROFILE, notes.append,
        lambda _x: console.ip, pc_ip=console.ip,
        allow_placeholder_payloads=allow_placeholder)
    return eng, notes


# ---------------------------------------------------------------- discovery --

def test_discovery_reconnect_after_address_change():
    """Console moves 127.0.0.1 -> 127.0.0.2; discovery follows without state loss."""
    settings = {"discovery": {"reprobe_seconds": 0.01}, "bootstrap_loader": {},
                "elfldr": {}}
    c1 = MockConsole("127.0.0.1")
    try:
        settings["bootstrap_loader"]["port"] = c1.ports["boot"]
        settings["elfldr"]["port"] = c1.ports["elfldr"]
        last = os.path.join(tempfile.mkdtemp(), "last_seen.json")
        changes = []
        disc = discovery.Discovery(settings, last_seen_path=last,
                                  on_change=lambda a, b: changes.append((a, b)))
        sweep = ["127.0.0.1"]
        disc._try_network_sweep = lambda: next(
            (ip for ip in sweep if disc.probe_ports(ip) != (False, False)), None)
        assert disc.discover() == "127.0.0.1"
        # IP change: move the console to the second loopback address.
        c1.stop()
        c2 = MockConsole("127.0.0.2")
        settings["bootstrap_loader"]["port"] = c2.ports["boot"]
        settings["elfldr"]["port"] = c2.ports["elfldr"]
        disc = discovery.Discovery(settings, last_seen_path=last,
                                  on_change=lambda a, b: changes.append((a, b)))
        disc.ps5.ip = "127.0.0.1"
        disc._try_network_sweep = lambda: next(
            (ip for ip in ["127.0.0.2"]
             if disc.probe_ports(ip) != (False, False)), None)
        assert disc.discover() == "127.0.0.2"
        assert changes == [("127.0.0.1", "127.0.0.2")]
        assert disc.ps5.ip == "127.0.0.2"
        c2.stop()
    finally:
        c1.stop()


def test_discovery_unavailable_console_returns_none():
    settings = {"discovery": {}, "bootstrap_loader": {"port": 1},
                "elfldr": {"port": 1}}
    disc = discovery.Discovery(settings, last_seen_path=os.path.join(
        tempfile.mkdtemp(), "ls.json"))
    disc._try_network_sweep = lambda: None
    assert disc.discover() is None


# ------------------------------------------------------- chain against mock --

def test_full_chain_complete_with_mock_evidence(tmp_path):
    """Happy path: deliveries accepted AND evidence port answers -> COMPLETE.

    This is a MOCK completion proving host logic, not a PS5 jailbreak.
    """
    payload_dir = make_payload_dir(tmp_path)
    c = MockConsole("127.0.0.1")
    try:
        settings = make_settings(c, payload_dir, evidence=True)
        eng, notes = make_engine(settings, c)
        final = eng.run()
        assert final == "COMPLETE", (final, eng.stage_results)
        assert eng.history == [
            "IDLE", "DISCOVERED", "HOSTING", "WAITING", "USERLAND_VERIFIED",
            "KERNEL_VERIFIED", "PAYLOADS_VERIFIED", "COMPLETE"], eng.history
        assert c.ack_count > 0  # simulated acks happened
        assert not any(n == "failed jailbrea" for n in notes)
        assert eng.stage_results["execution"] == "ftpsrv_port_evidence"
    finally:
        c.stop()


def test_ack_without_evidence_never_complete(tmp_path):
    """Payloads accepted (acks) but evidence port closed -> FAILED, no fake win."""
    payload_dir = make_payload_dir(tmp_path)
    c = MockConsole("127.0.0.1")
    try:
        settings = make_settings(c, payload_dir, evidence=False)
        eng, notes = make_engine(settings, c)
        final = eng.run()
        assert final == "FAILED:unverified_execution", final
        assert c.ack_count > 0
        assert eng.stage_results["execution"] == "no_confirmation"
        assert any(n == "failed jailbrea" for n in notes)
        assert "COMPLETE" not in eng.history
    finally:
        c.stop()


def test_connection_reset_during_injection(tmp_path):
    payload_dir = make_payload_dir(tmp_path)
    c = MockConsole("127.0.0.1",
                    modes=(("boot", "accept"), ("elfldr", "reset"),
                           ("evidence", "accept")))
    try:
        settings = make_settings(c, payload_dir, evidence=True)
        inj = inj_mod.Injector(settings, "127.0.0.1")
        res = inj.inject_raw_path(os.path.join(payload_dir, "t1.elf"))
        assert res.ok is False
        assert "reset" in res.reason or "tcp_error" in res.reason, res.reason
    finally:
        c.stop()


def test_payload_retry_exhaustion_reports_partial(tmp_path):
    payload_dir = make_payload_dir(tmp_path)
    c = MockConsole("127.0.0.1",
                    modes=(("boot", "accept"), ("elfldr", "data_rst"),
                           ("evidence", "accept")))
    try:
        settings = make_settings(c, payload_dir, evidence=True)
        eng, notes = make_engine(settings, c)
        final = eng.run()
        assert final == "FAILED:payload_rejected", final
        assert eng.payload_failures == ["t1.elf"]
        assert "after 3 attempts" in eng.stage_results.get("payload:t1.elf", "")
        assert any(n == "failed jailbrea" for n in notes)
    finally:
        c.stop()


def test_partial_failure_then_recovery(tmp_path):
    """After a partial failure, a fresh run against a healthy console recovers."""
    payload_dir = make_payload_dir(tmp_path)
    c = MockConsole("127.0.0.1",
                    modes=(("boot", "accept"), ("elfldr", "data_rst"),
                           ("evidence", "accept")))
    try:
        settings = make_settings(c, payload_dir, evidence=True)
        eng1, _ = make_engine(settings, c)
        assert eng1.run() == "FAILED:payload_rejected"
        # Recovery: console becomes healthy again (fresh accept-mode listener).
        c.listeners["elfldr"].stop()
        time.sleep(0.3)
        c.listeners["elfldr"] = _Listener(c.ip, "accept")
        settings["elfldr"]["port"] = c.listeners["elfldr"].port  # new ephemeral port
        eng2, notes = make_engine(settings, c)
        assert eng2.run() == "COMPLETE"
        assert not any(n == "failed jailbrea" for n in notes)
    finally:
        c.stop()


def test_cancellation_during_active_run(tmp_path):
    payload_dir = make_payload_dir(tmp_path)
    c = MockConsole("127.0.0.1",
                    modes=(("boot", "accept"), ("elfldr", "absent"),
                           ("evidence", "accept")))
    try:
        settings = make_settings(c, payload_dir, evidence=True)
        settings["chain"]["kernel_watchdog_seconds"] = 30.0  # long wait to cancel
        eng, _ = make_engine(settings, c)
        result = {}

        def worker():
            result["final"] = eng.run()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        time.sleep(1.5)
        eng.cancel()
        t.join(timeout=8)
        assert not t.is_alive(), "run did not stop after cancel"
        assert result["final"] == "FAILED:cancelled", result
    finally:
        c.stop()


def test_duplicate_run_suppressed_while_active(tmp_path):
    payload_dir = make_payload_dir(tmp_path)
    c = MockConsole("127.0.0.1",
                    modes=(("boot", "accept"), ("elfldr", "absent"),
                           ("evidence", "accept")))
    try:
        settings = make_settings(c, payload_dir, evidence=True)
        settings["chain"]["kernel_watchdog_seconds"] = 10.0
        eng, _ = make_engine(settings, c)
        holder = {}

        def worker():
            holder["final"] = eng.run()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        time.sleep(1.0)
        t0 = time.monotonic()
        second = eng.run()  # must return immediately without running
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, f"duplicate run blocked for {elapsed:.2f}s"
        assert second != "COMPLETE"
        eng.cancel()
        t.join(timeout=8)
        # First run owns the transitions; duplicate added nothing.
        assert eng.history.count("HOSTING") == 1, eng.history
    finally:
        c.stop()


# ------------------------------------------------- network service behavior --

def test_loopback_port_conflict_detected():
    """Regression: a 127.0.0.1 occupant must block port_available (Windows allows
    a coexisting wildcard bind that steals loopback traffic)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.listen(1)
    try:
        free, owner = netsvc.port_available(port)
        assert free is False and "loopback" in owner, (free, owner)
    finally:
        s.close()


def test_dns_server_start_stop_releases_port():
    d = netsvc.DnsWildServer("127.0.0.1", port=0)
    d.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    d.sock.bind(("127.0.0.1", 0))
    port = d.sock.getsockname()[1]
    d.start()
    time.sleep(0.3)
    d.stop()
    d.join(timeout=3)
    assert not d.is_alive()
    # Port must be rebindable afterwards (no leaked socket).
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", port))
    probe.close()

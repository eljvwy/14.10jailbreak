"""Unit tests for injector (TCP framing, URI modes, timeouts)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import injector  # noqa: E402

SETTINGS = {"elfldr": {"port": 9021}, "bootstrap_loader": {"port": 9020},
            "http": {"port": 8080}}


class EchoServer:
    """Tiny TCP sink on an ephemeral port recording what was received."""

    def __init__(self):
        self.received = b""
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(1)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        try:
            conn, _ = self.srv.accept()
            conn.settimeout(2)
            self.received = conn.recv(65536)
            conn.close()
        except OSError:
            pass

    def close(self):
        self.srv.close()


def setup_inj(port):
    s = dict(SETTINGS)
    s["elfldr"] = {"port": port}
    return injector.Injector(s, "127.0.0.1")


def test_inject_raw_sends_exact_bytes():
    srv = EchoServer()
    inj = setup_inj(srv.port)
    res = inj.inject_raw(b"\x7fELF-TESTPAYLOAD", port=srv.port)
    assert res.ok and res.bytes_sent == len(b"\x7fELF-TESTPAYLOAD")
    time.sleep(0.1)
    assert srv.received == b"\x7fELF-TESTPAYLOAD"
    srv.close()


def test_inject_uri_line_ending():
    srv = EchoServer()
    inj = setup_inj(srv.port)
    ok = inj.inject_uri("file:/data/kstuff.elf", port=srv.port)
    time.sleep(0.1)
    assert ok.ok
    assert srv.received == b"file:/data/kstuff.elf\n"
    srv.close()


def test_inject_http_composes_url():
    srv = EchoServer()
    inj = setup_inj(srv.port)
    res = inj.inject_http("kstuff.elf", "192.168.1.23")
    assert res.ok  # EchoServer really listens on that port: URI must land
    time.sleep(0.1)
    assert srv.received == b"http://192.168.1.23:8080/payloads/kstuff.elf\n"
    srv.close()


def test_inject_to_dead_port_fails_fast():
    inj = setup_inj(1)  # port 1 on localhost typically refused
    res = inj.inject_uri("file:/data/x.elf")
    assert res.ok is False
    assert res.reason.startswith("tcp_error")


def test_console_responsive_false_when_nothing_listens():
    inj = setup_inj(1)
    assert inj.console_responsive() is False

"""Netsvc tests: HTTP/DNS lifecycle, status endpoint, port conflict, isolation."""
import json
import os
import socket
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import netsvc  # noqa: E402
import payloads  # noqa: E402


def test_port_available_free_then_in_use():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", 0))  # same wildcard scope as the availability probe
    port = srv.getsockname()[1]
    srv.listen(1)
    free, owner = netsvc.port_available(port)
    srv.close()
    assert free is False and owner


def test_port_available_true_on_ephemeral():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free_port = s.getsockname()[1]
    s.close()
    free, owner = netsvc.port_available(free_port)
    assert free and owner is None


def test_http_lifecycle_pending_status_and_shutdown(tmp_path):
    (tmp_path / "index.html").write_text("<html>ok</html>")
    srv = netsvc.make_http_server(str(tmp_path), str(tmp_path), lambda: {"state": "HOSTING"},
                                  port=0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=5).read()
        assert json.loads(body)["state"] == "HOSTING"
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read()
        assert b"<html>ok</html>" in page
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_path_traversal_blocked(tmp_path):
    (tmp_path / "index.html").write_text("<html/></html>")
    srv = netsvc.make_http_server(str(tmp_path), str(tmp_path), lambda: {}, port=0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        evil = f"http://127.0.0.1:{port}/..%2f..%2f.{ '%2f' }etc%2fpasswd"
        try:
            urllib.request.urlopen(evil, timeout=5)
            captured = None
        except Exception as exc:  # 403 or 404 accepted; content leak never
            captured = getattr(exc, "code", None)
        assert captured in (403, 404)
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_payload_missing_404(tmp_path):
    srv = netsvc.make_http_server(str(tmp_path), str(tmp_path), lambda: {}, port=0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/payloads/nope.elf", timeout=5)
            code = 200
        except Exception as exc:
            code = getattr(exc, "code", None)
        assert code == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_dns_wild_server_answers_and_filters(tmp_path):
    # Bind on an ephemeral port (not 53) for CI safety.
    s = netsvc.DnsWildServer("127.0.0.1", port=0)
    # Manually bind to ephemeral port.
    s.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sock.settimeout(1.0)
    s.sock.bind(("127.0.0.1", 0))
    actual_port = s.sock.getsockname()[1]
    s.start()
    time.sleep(0.2)
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cs.settimeout(2)
        cs.sendto(q, ("127.0.0.1", actual_port))
        data, _ = cs.recvfrom(1500)
        assert data[:2] == q[:2]          # echo of transaction id
        assert data[2:4] == b"\x81\x80"   # response flags: QR=1, RA=1
        assert data.endswith(b"\x7f\x00\x00\x01")  # A record -> 127.0.0.1
        cs.close()
    finally:
        s.stop()


def test_refuses_foreign_subnet_when_not_wide_open(tmp_path):
    import ipaddress
    s = netsvc.DnsWildServer("192.168.1.10", port=0)
    assert s._same_subnet("192.168.1.55") is True
    assert s._same_subnet("10.9.9.9") is False


def test_dns_parser_rejects_short_frames():
    assert netsvc._encode_a_response(b"\x00\x00", "1.2.3.4") is None

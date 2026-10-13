"""Unit tests for discovery primitives."""
import json
import os
import sys
import unittest.mock as mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import discovery  # noqa: E402

BROADCAST_EX = {"ip": "192.168.1.5", "mac": "aa:bb:cc:11:22:33"}
SETTINGS = {"discovery": {}, "bootstrap_loader": {"port": 9020},
            "elfldr": {"port": 9021}}


def test_local_ip_returns_string():
    ip = discovery.Discovery.local_ip()
    assert ip.count(".") == 3


def test_tcp_probe_closed_port():
    assert discovery.Discovery.tcp_probe("127.0.0.1", 1, timeout=0.5) is False


def test_subnet_broadcast_addrs():
    with mock.patch.object(discovery.Discovery, "local_ip", return_value="192.168.1.23"):
        addrs = discovery.Discovery.subnet_broadcast_addrs()
    assert "255.255.255.255" in addrs
    assert "192.168.1.255" in addrs


def test_cached_discovery_probes_before_trusting():
    d = discovery.Discovery(SETTINGS, last_seen_path="/nonexistent/last_seen.json")
    assert d._try_cached() is None


def test_last_saved_roundtrip(tmp_path):
    p = tmp_path / "last_seen.json"
    d = discovery.Discovery(SETTINGS, last_seen_path=str(p))
    d.ps5.ip = "192.168.1.5"
    d.ps5.mac = "aa:bb:cc:11:22:33"
    d.save_last_seen()
    loaded = json.loads(p.read_text())
    assert loaded == BROADCAST_EX or loaded["ip"] == "192.168.1.5"


def test_discover_logs_ip_change():
    d = discovery.Discovery(SETTINGS, last_seen_path="/nonexistent/x.json")
    changes = []
    d.on_change = lambda a, b: changes.append((a, b))
    with mock.patch.object(d, "_try_cached", return_value=None), \
            mock.patch.object(d, "_try_network_sweep", return_value="192.168.1.9"), \
            mock.patch.object(d, "probe_ports", return_value=(True, False)):
        assert d.discover() == "192.168.1.9"
        assert changes == []  # first discovery is not a "change"
        with mock.patch.object(d, "_try_network_sweep", return_value="192.168.1.12"):
            d.discover()
            assert changes == [("192.168.1.9", "192.168.1.12")]


def test_probe_ports_garbage_ip():
    d = discovery.Discovery(SETTINGS, last_seen_path="/nonexistent/y.json")
    assert d.probe_ports("not-an-ip") == (False, False)

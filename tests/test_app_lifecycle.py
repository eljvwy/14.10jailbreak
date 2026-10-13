"""App lifecycle regressions: shutdown releases ports, idempotent, no orphans.

Covers the QA defect where headless mode never exited its wait loop after
shutdown (orphaned process holding ports).
"""
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import netsvc  # noqa: E402


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_shutdown_releases_http_port_and_is_idempotent():
    import main as main_mod  # needs src on path (set above)

    app = main_mod.HostApp(dry_run=True)
    # Use an ephemeral TCP port for the test to avoid conflicts.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    http_port = probe.getsockname()[1]
    probe.close()
    app.settings["http"]["port"] = http_port
    app.settings["dns"]["port"] = _free_udp_port()
    app.http_port = http_port

    app.start_services()
    # Services actually answer.
    import urllib.request
    body = urllib.request.urlopen(
        f"http://127.0.0.1:{http_port}/status", timeout=5).read()
    assert b"state" in body

    app.shutdown()
    app.shutdown()  # must be idempotent, not raise

    free, owner = netsvc.port_available(http_port)
    assert free, f"http port leaked after shutdown: {owner}"
    if app.dns:
        assert not app.dns.is_alive() or app.dns.sock is None


def test_headless_loop_stops_when_stop_flag_set():
    """Regression: the wait loop must honor _stop (previously ran forever)."""
    import main as main_mod
    app = main_mod.HostApp(dry_run=True)
    app.settings["http"]["port"] = 0
    app.settings["dns"]["port"] = _free_udp_port()

    # Don't start real services; only prove the loop exits on stop.
    stopped = threading.Event()

    def fake_sleep(_seconds):
        stopped.set()
        app._stop.set()

    original_sleep = main_mod.time.sleep
    main_mod.time.sleep = fake_sleep
    try:
        code = app.run_headless()
    finally:
        main_mod.time.sleep = original_sleep
    assert stopped.is_set()
    assert code == 0

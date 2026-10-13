"""Chain-engine state machine tests: verified states, no false COMPLETE."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import chains  # noqa: E402
import injector as inj_mod  # noqa: E402
import payloads as pay_mod  # noqa: E402
from firmware import Profile  # noqa: E402

SETTINGS = {
    "http": {"port": 8080},
    "chain": {
        "userland_max_attempts": 2,
        "userland_stage_timeout_seconds": 0.2,
        "kernel_watchdog_seconds": 0.2,
        "payload_retries": 2,
        "backoff_base_seconds": 0.05,
        "backoff_factor": 2.0,
        "payloads_in_order": ["a.elf", "b.elf"],
        "delivery_mode": "http",
        "notify_success": "succsecfull jailbrea",
        "notify_failure": "failed jailbrea",
        "ftp_port": 2121,
        "payload_dir": "",
    },
}

PROFILE = Profile(
    id="test", fw_range="7.00-14.10", userland_stage="web", kernel_stage="krnl",
    hv_stage="none", payload_chain=["a.elf", "b.elf"], notes="",
    verified_by_user=False, experimental=False, kernel_stage_fallbacks=[])


class MockInjector:
    """Mock injector exposing controllable port/payload behaviors."""

    boot_port = 9020
    elfldr_port = 9021

    def __init__(self, open_ports=(), ftp_open=False, unreachable=False):
        self._state = set(open_ports)
        self.ftp_open = ftp_open
        self.unreachable = unreachable
        self.delivered = []

    def wait_port(self, port, timeout, poll=1.0, cancel=None):
        return port in self._state

    def elfldr_open(self, port=None, timeout=3.0):
        return port in self._state

    def console_responsive(self, timeout=3.0):
        return {9020, 9021} & self._state

    def inject_http(self, name, pc_ip):
        self.delivered.append(name)
        return inj_mod.InjectResult(True, "injected", 10)

    def inject_raw_path(self, path):
        self.delivered.append(path)
        return inj_mod.InjectResult(True, "injected", 10)

    def inject_uri(self, uri, port=None):
        self.delivered.append(uri)
        return inj_mod.InjectResult(True, "injected", 10)


def make_engine(inj, profile=PROFILE, allow_placeholder=False):
    notifications = []
    eng = chains.ChainEngine(
        SETTINGS, inj, profile, notifications.append,
        lambda _x: None if inj.unreachable else "192.168.1.5",
        pc_ip="192.168.1.23", allow_placeholder_payloads=allow_placeholder)
    return eng, notifications


def mock_payloadassets(monkeypatch=None):
    """Patch validate_ladder to accept anything as a genuine artifact."""
    def fake_ladder(names, payload_dir, allow_placeholder=False):
        return {
            n: pay_mod.PayloadAsset(n, f"/x/{n}", True, "genuine_artifact")
            for n in names
        }
    return fake_ladder


def test_unsupported_firmware_never_runs():
    eng, notes = make_engine(MockInjector(), profile=None)
    assert eng.run() == "FAILED:unsupported_firmware"
    assert all(n == "failed jailbrea" for n in notes)


def test_userland_timeout_reports_timeout():
    inj = MockInjector()
    eng, _ = make_engine(inj)
    eng._validate_assets = lambda: True
    assert eng.run() == "FAILED:timeout"


def test_kernel_probe_only_never_fake_SUCCESS():
    inj = MockInjector(open_ports=(9020, 9021))
    eng, _ = make_engine(inj)
    eng._validate_assets = lambda: True
    final = eng.run()
    assert final.startswith("FAILED:"), final
    assert "COMPLETE" not in final


def test_no_execution_confirmation_blocks_complete(monkeypatch):
    monkeypatch.setattr(pay_mod, "validate_ladder", mock_payloadassets())
    inj = MockInjector(open_ports=(9020, 9021), ftp_open=False)
    eng, _ = make_engine(inj)
    final = eng.run()
    assert final == "FAILED:unverified_execution", final
    assert eng.stage_results.get("execution") == "no_confirmation"


def test_ftpsrv_confirmation_is_the_evidence_gate(monkeypatch):
    monkeypatch.setattr(pay_mod, "validate_ladder", mock_payloadassets())
    inj = MockInjector(open_ports=(9020, 9021, 2121), ftp_open=True)
    eng, notes = make_engine(inj)
    final = eng.run()
    assert final == "COMPLETE", final
    assert eng.stage_results.get("execution") == "ftpsrv_port_evidence"
    assert not any(n == "failed jailbrea" for n in notes)


def test_payload_rejected_by_validator(monkeypatch):
    def reject(*a, **k):
        return {"a.elf": pay_mod.PayloadAsset("a.elf", "", False, "no_provenance_record")}
    monkeypatch.setattr(pay_mod, "validate_ladder", reject)
    inj = MockInjector(open_ports=(9020, 9021, 2121))
    eng, _ = make_engine(inj)
    final = eng.run()
    assert final == "FAILED:payload_rejected", final


def test_missing_assets_reports_missing(monkeypatch):
    def reject(*a, **k):
        return {"a.elf": pay_mod.PayloadAsset("a.elf", "", False, "missing_file")}
    monkeypatch.setattr(pay_mod, "validate_ladder", reject)
    inj = MockInjector(open_ports=(9020, 9021, 2121))
    eng, _ = make_engine(inj)
    assert eng.run() == "FAILED:missing_assets"


def test_retry_then_failure_counts_attempts():
    inj = MockInjector(open_ports=())
    eng, _ = make_engine(inj)
    eng._validate_assets = lambda: True
    eng.run()
    assert "after 2 attempts" in eng.stage_results["userland"]
    assert eng.reason == "timeout"


def test_cancel_stops_ladder(monkeypatch):
    monkeypatch.setattr(pay_mod, "validate_ladder", mock_payloadassets())
    inj = MockInjector(open_ports=(9020, 9021, 2121))
    eng, _ = make_engine(inj)
    eng.cancel()
    assert eng.run().startswith("FAILED:cancelled")


def test_connection_lost_during_payloads(monkeypatch):
    monkeypatch.setattr(pay_mod, "validate_ladder", mock_payloadassets())
    inj = MockInjector(open_ports=(9020, 9021, 2121), unreachable=True)
    eng, _ = make_engine(inj)
    assert eng.run().startswith("FAILED:")
    assert eng.reason in ("connection_interrupted", "kernel_stage_failed",
                          "unverified_execution", "missing_assets", "timeout")


def test_duplicate_run_suppressed():
    inj = MockInjector(open_ports=())
    eng, _ = make_engine(inj)
    eng._validate_assets = lambda: True
    eng._running.set()
    final = eng.run()
    assert final == "IDLE", final  # suppressed, not a state reset

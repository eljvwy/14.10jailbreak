"""Entry point: wires discovery, DNS/HTTP hosts, chain engine and GUI together."""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chains  # noqa: E402
import consoleapp  # noqa: E402
import discovery  # noqa: E402
import firmware  # noqa: E402
import gui as gui_mod  # noqa: E402
import injector as inj_mod  # noqa: E402
import netsvc  # noqa: E402
import payloads as pay_mod  # noqa: E402
import notifier as notif_mod  # noqa: E402
from logger import attach_gui_sink, setup_logging  # noqa: E402

log = logging.getLogger("main")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_settings(path: str) -> Dict:
    """Load settings.json; corrupt file falls back to defaults with a warning."""
    defaults: Dict = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            defaults = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        log.warning("settings.json unusable (%s); using built-in defaults", exc)
    return defaults or {}


class HostApp:
    """Top-level application object owning all background services."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.settings = load_settings(os.path.join(ROOT, "config", "settings.json"))
        self._chain_lock = threading.Lock()  # prevents duplicate chain workers
        self._chain_alive = threading.Event()  # set while a chain thread runs
        os.chdir(ROOT)
        setup_logging(self.settings.get("paths", {}).get("log_file", "logs/ps5jb.log"))
        self.profiles = firmware.load_profiles(
            os.path.join(ROOT, "config", "firmware_profiles.json"))
        self.pc_ip = discovery.Discovery.local_ip()
        self.disc = discovery.Discovery(self.settings)
        self.http_port = int(self.settings.get("http", {}).get("port", 8080))
        self.dns: Optional[netsvc.DnsWildServer] = None
        self.httpd = None
        self.notifier = notif_mod.Notifier(self.settings)
        self.ui: Optional[gui_mod.App] = None
        self.engine: Optional[chains.ChainEngine] = None
        self.installer: Optional[consoleapp.ConsoleAppInstaller] = None
        self.state = "IDLE"
        self.detail = ""
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # ---------- lifecycle ----------
    def start_services(self) -> None:
        """Bind DNS + HTTP; log the exact console steps and URL."""
        dns_port = int(self.settings["dns"]["port"])
        free, owner = netsvc.port_available(self.http_port)
        if not free:
            log.warning("HTTP port %d unavailable (%s); free it or change "
                        "settings.json http.port - a common occupant on Windows "
                        "is Steam's webhelper on 127.0.0.1:8080",
                        self.http_port, owner)
        self.dns = netsvc.DnsWildServer(
            self.pc_ip, dns_port,
            wide_open=bool(self.settings.get("security", {}).get(
                "dns_wide_open", False)))
        self.dns.start()
        exploit_dir = os.path.join(ROOT, self.settings["paths"].get(
            "exploit_dir", "assets/exploit"))
        payload_dir = os.path.join(ROOT, self.settings["paths"].get(
            "payload_dir", "assets/payloads"))
        bind_ip = str(self.settings.get("security", {}).get(
            "bind_interface", "0.0.0.0"))
        self.httpd = netsvc.make_http_server(
            exploit_dir, payload_dir, self._status, port=self.http_port,
            bind_ip=bind_ip)
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True,
                             name="http-host")
        t.start()
        self._threads.append(t)
        log.info("HTTP host: http://%s:%d  (wildcard DNS -> %s)",
                 self.pc_ip, self.http_port, self.pc_ip)
        log.info("Console steps: set PS5 DNS to %s, open browser to "
                 "http://%s:%d, press RUN", self.pc_ip, self.pc_ip, self.http_port)

    def discovery_loop(self) -> None:
        """Background: discover, track IP changes, drive the chain, install tile."""
        pc_port_probe_failures = 0
        while not self._stop.is_set():
            ip = self.disc.discover()
            if ip:
                self.state = max(self.state, "DISCOVERED") if self.state != \
                    "IDLE" else "DISCOVERED"
                self.detail = f"PS5 at {ip}"
                if self.engine is None and self.state in ("DISCOVERED",):
                    prof = self._match_profile()
                    if prof is None:
                        self.detail = "unsupported firmware profile — diagnostic mode only"
                        continue
                    inj = inj_mod.Injector(self.settings, ip)
                    self.engine = chains.ChainEngine(
                        self.settings, inj, prof,
                        self.notifier.console_notify,
                        lambda _x: self.disc.discover() or ip, self.pc_ip,
                        dry_run=self.dry_run,
                        allow_placeholder_payloads=bool(
                            self.settings.get("security", {}).get(
                                "allow_placeholder_payloads", False)))
                    self.installer = consoleapp.ConsoleAppInstaller(self.settings, ip)
                    if self.dry_run:
                        log.info("dry-run: chain machinery wired, NOT injecting")
                    elif not self._chain_alive.is_set():
                        self._chain_alive.set()
                        threading.Thread(target=self._chain_worker, daemon=True,
                                         name="chain").start()
            time.sleep(self.disc.reprobe_seconds)

    def _match_profile(self) -> Optional[firmware.Profile]:
        """Conservative profile choice.

        The console firmware cannot be reliably detected over the public
        network, so automatic selection is limited to NON-experimental
        profiles unless the user explicitly opted in via
        security.allow_experimental_chains. On 14.10 this yields None unless
        opted in — and even then the profile is experimental-only.
        """
        if not self.profiles:
            return None
        if not self.settings.get("security", {}).get(
                "allow_experimental_chains", False):
            non_experimental = [p for p in self.profiles if not p.experimental]
            cands = firmware.match_profile_candidates(non_experimental, 14.10)
            if cands:
                return cands[0]
            return None
        cands = firmware.match_profile_candidates(self.profiles, 14.10)
        return cands[0] if cands else None

    def _chain_worker(self) -> None:
        """Single chain worker: serialized by _chain_alive so overlapping runs
        cannot happen (retry engine rule: never duplicate workers)."""
        try:
            self._run_chain()
        finally:
            self._chain_alive.clear()

    def _run_chain(self) -> None:
        """Run the chain, install the tile only after verified execution."""
        assert self.engine is not None
        try:
            end_state = self.engine.run()
            self.state = end_state
            if end_state == "COMPLETE":
                self.notifier.notify_success()
                assert self.installer is not None
                self.installer.write_status(
                    self.settings["chain"]["notify_success"])
                ok2, reason2 = self.installer.install()
                if ok2:
                    self.state = "HOME_APP_INSTALLED"
                else:
                    log.warning("tile install failed: %s (etaHEN/HL hint: "
                                "ensure ftpsrv running, homebrew enabler active)",
                                reason2)
            else:
                self.notifier.notify_failure(
                    self.settings["chain"]["notify_failure"])
                assert self.installer is not None
                self.installer.write_status(self.settings["chain"]["notify_failure"])
        except Exception as exc:  # noqa: BLE001
            log.exception("chain crashed: %s", exc)
            self.notifier.notify_failure()

    def _status(self) -> Dict:
        return {
            "state": self.engine.state if self.engine else self.state,
            "detail": self.engine.status_text if self.engine else self.detail,
            "ps5_ip": self.disc.ps5.ip,
            "pc_ip": self.pc_ip,
            "http_port": self.http_port,
            "stage_results": (self.engine.stage_results if self.engine else {}),
        }

    # ---------- foreground ----------
    def run_gui(self) -> int:
        """Run with Tkinter GUI; blocks until the window closes or Ctrl+C."""
        self.start_services()
        threading.Thread(target=self.discovery_loop, daemon=True,
                         name="discovery").start()
        self.ui = gui_mod.App(self._status)
        attach_gui_sink(self.ui.log_line)
        self.ui.set_ips(self.disc.ps5.ip, self.pc_ip, self.http_port)
        self._signal_handlers()
        try:
            self.ui.run()
        finally:
            self.shutdown()
        return 0

    def run_headless(self) -> int:
        """--headless: no GUI, log to console; Ctrl+C clean stop."""
        self.start_services()
        self._signal_handlers()
        threading.Thread(target=self.discovery_loop, daemon=True,
                         name="discovery").start()
        print(f"Headless host up. Open on PS5: http://{self.pc_ip}:{self.http_port}")
        try:
            while not self._stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown()
        finally:
            self.shutdown()
        return 0

    def _signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, lambda *_: self.shutdown())
            except (ValueError, OSError):
                pass

    def shutdown(self) -> None:
        """Close all services and sockets; save state; exit cleanly."""
        if self._stop.is_set():
            return
        self._stop.set()
        log.info("shutting down…")
        self.disc.save_last_seen()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.dns:
            self.dns.stop()
        log.info("shutdown complete")


def run_diagnose(app: "HostApp") -> int:
    """--diagnose: check prerequisites and report gaps without touching a console.

    Checks: settings parse, DNS/HTTP port availability, exploit page assets,
    payload validation/provenance, profile table health, and (consultative
    only) firmware 14.10 support status.
    """
    issues: list[str] = []
    ok_count = 0
    def report(label: str, ok: bool, note: str = "") -> None:
        nonlocal ok_count
        print(f"[{ 'OK ' if ok else 'FAIL'}] {label}" + (f" - {note}" if note else ""))
        if ok:
            ok_count += 1
        else:
            issues.append(label)

    report("settings.json parse", bool(app.settings))
    report("firmware profiles loaded", len(app.profiles) >= 8,
           f"{len(app.profiles)} profiles")
    exp = [p for p in app.profiles if p.experimental]
    print("       experimental profiles (14.10 ladder):",
          [p.id for p in exp], "- NOT supported, WARN-level only")
    report("firmware 14.10 public chains", False,
           "NONE VERIFIED - see NOTES.md / AUDIT.md; "
           "host remains useful for diagnostics")

    for name, cfg_key, port in (("DNS :53", "dns", 53),
                                ("HTTP :8080", "http", 8080)):
        port_n = int(app.settings[cfg_key]["port"])
        free, owner = netsvc.port_available(port_n)
        report(f"port {name} ({port_n})",
               free, "" if free else f"occupied: {owner or 'unknown process'}")

    exploit_dir = os.path.join(ROOT, app.settings["paths"]["exploit_dir"])
    report("exploit page assets",
           os.path.isfile(os.path.join(exploit_dir, "index.html")))

    names = app.settings["chain"]["payloads_in_order"]
    ladder = pay_mod.validate_ladder(names, os.path.join(
        ROOT, app.settings["paths"].get("payload_dir", "assets/payloads")))
    for name in names:
        asset = ladder.get(name)
        report(f"payload {name}", bool(asset and asset.ok),
               asset.reason if asset else "not validated")

    print(f"\ndiagnostics: {ok_count} checks OK, "
          f"{len(issues)} blocking: {issues if issues else 'none'}")
    return 0 if not issues else 2


def main() -> int:
    """CLI: --dry-run exercises discovery + hosting without injecting."""
    parser = argparse.ArgumentParser(description="PS5-JB-14.10 host")
    parser.add_argument("--dry-run", action="store_true",
                        help="discovery + hosting only, no payload injection")
    parser.add_argument("--headless", action="store_true",
                        help="no GUI (console mode)")
    parser.add_argument("--diagnose", action="store_true",
                        help="prerequisite diagnostic mode (no console access)")
    args = parser.parse_args()
    try:
        app = HostApp(dry_run=args.dry_run)
        if args.diagnose:
            return run_diagnose(app)
        return app.run_headless() if args.headless else app.run_gui()
    except Exception as exc:  # noqa: BLE001
        log.exception("fatal: %s", exc)
        print(f"ERROR [{type(exc).__name__}]: {exc} — see logs/ps5jb.log")
        return 1


if __name__ == "__main__":
    sys.exit(main())

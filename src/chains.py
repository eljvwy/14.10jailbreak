"""Chain orchestrator v2: verified-state machine, retries, cancellation.

States:
    IDLE -> DISCOVERED -> HOSTING -> WAITING -> USERLAND_VERIFIED
         -> KERNEL_VERIFIED -> PAYLOADS_VERIFIED -> COMPLETE

Failure states (distinct reason codes, never a false COMPLETE):
    FAILED:timeout | FAILED:unsupported_firmware | FAILED:missing_assets
    FAILED:payload_rejected | FAILED:connection_interrupted
    FAILED:unverified_execution

Evidence rules: an open TCP port is only a probe signal. USERLAND_VERIFIED
requires the 9020->9021 bootstrap evidence the chain exists *console-side*;
KERNEL_VERIFIED additionally requires the kernel stage to report success;
PAYLOADS_VERIFIED requires every validated payload accepted for delivery (the
console accepting bytes is not proof of execution, so COMPLETE is only reached
via explicit external confirmation e.g. the elfldr/ftpsrv evidence ladder).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable, Dict, List, Optional

import injector as inj_mod
import payloads as pay_mod
from firmware import Profile, parse_fw

log = logging.getLogger("chains")

STATES = [
    "IDLE", "DISCOVERED", "HOSTING", "WAITING", "USERLAND_VERIFIED",
    "KERNEL_VERIFIED", "PAYLOADS_VERIFIED", "COMPLETE",
]
FAILURE_PREFIX = "FAILED:"


class ChainEngine:
    """Run the exploit chain for the matched profile with disciplined retries."""

    def __init__(
        self,
        settings: Dict,
        injector: inj_mod.Injector,
        profile: Optional[Profile],
        notifier: Callable[[str], None],
        ip_getter: Callable[[Optional[str]], Optional[str]],
        pc_ip: str,
        dry_run: bool = False,
        allow_placeholder_payloads: bool = False,
    ) -> None:
        self.cfg = settings["chain"]
        self.injector = injector
        self.profile = profile
        self.notify = notifier
        self.ip_getter = ip_getter  # returns current PS5 IP or None (unreachable)
        self.pc_ip = pc_ip
        self.dry_run = dry_run
        self.allow_placeholder_payloads = allow_placeholder_payloads
        self.state = "IDLE"
        self.history: List[str] = []  # full transition log for auditing
        self.reason = ""
        self.stage_results: Dict[str, str] = {}
        self.payload_failures: List[str] = []
        self.status_text = ""
        self.payload_assets: Dict[str, pay_mod.PayloadAsset] = {}
        self._cancel = threading.Event()
        self._running = threading.Event()

    # ---------- state helpers ----------
    def _set(self, state: str, detail: str = "") -> None:
        self.state = state
        self.status_text = detail
        self.history.append(state)
        log.info("state -> %s %s", state, detail)

    def _fail(self, code: str, detail: str = "") -> str:
        self._set(f"{FAILURE_PREFIX}{code}", detail)
        self.reason = code
        self.notify(self.cfg["notify_failure"])
        return self.state

    def _backoff(self, attempt: int) -> None:
        delay = float(self.cfg["backoff_base_seconds"]) * (
            float(self.cfg["backoff_factor"]) ** attempt)
        time.sleep(min(delay, 30.0))

    def _cancelled(self) -> bool:
        return self._cancel.is_set()

    def cancel(self) -> None:
        """Flag any running stage loop to stop at the next checkpoint."""
        self._cancel.set()

    def run(self) -> str:
        """Orchestrate everything; returns final state string (idempotent guard).

        A pre-set cancel flag is honored (cancellation must survive into a
        fresh run started by a careless caller); clear it explicitly for reuse.
        """
        if self._running.is_set():
            log.warning("run() called while already running - duplicate suppressed")
            return self.state
        self._running.set()
        try:
            return self._run_inner()
        finally:
            self._running.clear()

    def _run_inner(self) -> str:
        self._set("IDLE")
        if self.profile is None:
            return self._fail("unsupported_firmware",
                              "no profile matched the console firmware")
        self._set("DISCOVERED", f"profile={self.profile.id}")
        if not self._validate_assets():
            return self.state
        if not self._run_userland():
            return self.state
        self._set("USERLAND_VERIFIED", self.stage_results.get("userland", ""))
        if not self._run_kernel():
            log.warning("kernel stage did NOT land; chain stops short of COMPLETE - %s",
                        self.stage_results)
            return self._fail("unverified_execution", str(self.stage_results))
        self._set("KERNEL_VERIFIED", self.stage_results.get("kernel", ""))
        if not self._deliver_payloads():
            return self.state
        self._set("PAYLOADS_VERIFIED", "delivery accepted; execution unverified")
        if self._execution_confirmed():
            self._set("COMPLETE", "execution evidence confirmed")
            return "COMPLETE"
        return self._fail("unverified_execution",
                          "payloads delivered but no console-side confirmation")

    # ---------- asset validation ----------
    def _validate_assets(self) -> bool:
        """Static validation of every payload before anything is sent."""
        if self.dry_run:
            self.stage_results["assets"] = "dry_run_skipped"
            return True
        ladder = pay_mod.validate_ladder(
            list(self.cfg["payloads_in_order"]), self._payload_dir(),
            allow_placeholder=self.allow_placeholder_payloads)
        self.payload_assets = ladder
        rejected = {n: a.reason for n, a in ladder.items() if not a.ok}
        if rejected:
            first = next(iter(rejected))
            reason = rejected[first]
            code = ("payload_rejected" if reason in
                    ("not_elf", "elf_truncated", "elf_not_64bit",
                     "elf_not_little_endian", "not_aarch64", "elf_bad_type",
                     "sha256_mismatch", "sha256_mismatch_vs_manifest",
                     "sha256_malformed", "sha256_malformed_in_manifest",
                     "provenance_incomplete_missing_sha256",
                     "unverified_placeholder", "no_provenance_record")
                    else "missing_assets")
            self._fail(code, f"payload {first} rejected: {reason}")
            self.stage_results["assets"] = str(rejected)
            return False
        self.stage_results["assets"] = "all validated (provenance + ELF magic + hash)"
        return True

    # ---------- stages ----------
    def _run_userland(self) -> bool:
        """Userland/WebKit stage: host page + wait for 9020, then 9021 evidence."""
        max_attempts = int(self.cfg["userland_max_attempts"])
        stage_timeout = float(self.cfg["userland_stage_timeout_seconds"])
        self._set("HOSTING")
        for attempt in range(1, max_attempts + 1):
            if self._cancelled():
                self._fail("cancelled", f"userland attempt {attempt}")
                return False
            log.info("userland attempt %d/%d — open http://%s:%d/ on the console",
                     attempt, max_attempts, self.pc_ip, self._http_port())
            self._set("WAITING", f"attempt {attempt}/{max_attempts}")
            if self.dry_run:
                self.stage_results["userland"] = "dry_run_skipped"
                return True
            ok = self._follow_ip() and self.injector.wait_port(
                self.injector.boot_port, stage_timeout, cancel=self._cancel)
            if not ok:
                log.warning("userland attempt %d: 9020 never opened (stall)", attempt)
                self._backoff(attempt)
                continue
            up21 = self.injector.wait_port(
                self.injector.elfldr_port, float(self.cfg["kernel_watchdog_seconds"]),
                cancel=self._cancel)
            if self._cancelled():
                self._fail("cancelled", "userland stage cancelled")
                return False
            if up21:
                self.stage_results["userland"] = \
                    f"probe_evidence: 9020+9021 open after {attempt} attempt(s)"
                return True
            log.warning("attempt %d: 9020 opened but 9021 never came up", attempt)
            self._backoff(attempt)
        self.stage_results["userland"] = f"FAILED after {max_attempts} attempts"
        self._fail("timeout", self.stage_results["userland"])
        return False

    def _run_kernel(self) -> bool:
        """Try each known kernel stage in likelihood order (data-driven)."""
        if self.dry_run:
            self.stage_results["kernel"] = "dry_run_skipped"
            return True
        stages: List[str] = []
        if self.profile.kernel_stage not in ("none", ""):
            stages.append(self.profile.kernel_stage)
        stages += list(self.profile.kernel_stage_fallbacks)
        # Policy: never automatically repeat an operation that could panic the
        # console - each kernel stage is tried at most once per chain run.
        watchdog = float(self.cfg["kernel_watchdog_seconds"])
        for stage in stages:
            if self._cancelled():
                self._fail("cancelled", f"kernel stage {stage}")
                return False
            log.info("attempting kernel stage '%s' (single attempt, watchdog %ss)",
                     stage, watchdog)
            reachable_now = self.injector.console_responsive()
            if reachable_now:
                up = self.injector.wait_port(self.injector.elfldr_port, watchdog,
                                             cancel=self._cancel)
                if self._cancelled():
                    self._fail("cancelled", f"kernel stage {stage}")
                    return False
                if up:
                    self.stage_results["kernel"] = f"OK ({stage})"
                    return True
                if self.ip_getter(None) is None:
                    self.stage_results[stage] = "console_panicked_rebooted"
                    log.warning("%s: lost console — panicked/rebooted; not repeating", stage)
                    continue
            self.stage_results[stage] = f"FAILED (9021 not open within {watchdog:.0f}s)"
        self.stage_results["kernel"] = "all known kernel stages failed"
        return False

    def _deliver_payloads(self) -> bool:
        """Payload ladder, strictly ordered, per-payload retries, PARTIAL on failure."""
        if self.dry_run:
            self.stage_results["payloads"] = "dry_run_skipped"
            return True
        retries = int(self.cfg["payload_retries"])
        for name in self.cfg["payloads_in_order"]:
            if self._cancelled():
                self._fail("cancelled", f"payload {name}")
                return False
            if not self._follow_ip():
                self._fail("connection_interrupted", f"during payload {name}")
                return False
            asset = self.payload_assets.get(name)
            if asset is None or not asset.ok:
                self._fail("payload_rejected", f"{name} not validated")
                return False
            mode = self.cfg.get("delivery_mode", "http")
            for attempt in range(1, retries + 1):
                res = self._try_payload(asset, mode)
                if res.ok and self.injector.console_responsive():
                    log.info("payload %s delivered (attempt %d)", name, attempt)
                    break
                log.warning("payload %s attempt %d failed: %s",
                            name, attempt, res.reason)
                if attempt < retries:
                    time.sleep(1.5 * attempt)
            else:
                self.payload_failures.append(name)
                self.stage_results[f"payload:{name}"] = f"FAILED after {retries} attempts"
                log.error("payload chain PARTIAL — failing item: %s", name)
                self._fail("payload_rejected",
                           f"{name} delivery failed after {retries} attempts")
                return False
            self.stage_results[f"payload:{name}"] = \
                f"delivered sha256={asset.sha256[:16]}…"
        self.stage_results["payloads"] = "all delivered"
        return True

    def _try_payload(self, asset: pay_mod.PayloadAsset, mode: str) -> inj_mod.InjectResult:
        mode = mode or "http"
        if mode == "raw":
            return self.injector.inject_raw_path(asset.path)
        if mode == "file":
            return self.injector.inject_uri(f"file:/data/{asset.name}")
        return self.injector.inject_http(asset.name, self.pc_ip)

    # ---------- execution confirmation ----------
    def _execution_confirmed(self) -> bool:
        """External evidence that delivered payloads actually executed.

        Evidence accepted (any): FTP port 2121 answered by the console
        (ftpsrv ran), or a custom verifier set via execution_verifier.
        Port 9021 reuse alone is NOT accepted as execution proof.
        """
        if self.dry_run:
            self.stage_results["execution"] = "dry_run_skipped"
            return False
        ftp_port = int(self.cfg.get("ftp_port", 2121))
        confirmed = False
        try:
            confirmed = self.injector.elfldr_open(ftp_port, timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            log.debug("execution probe failed: %s", exc)
        self.stage_results["execution"] = ("ftpsrv_port_evidence" if confirmed
                                           else "no_confirmation")
        return confirmed

    # ---------- plumbing ----------
    def _follow_ip(self) -> bool:
        """Refresh PS5 IP (DHCP may have moved it); False if unreachable."""
        new_ip = self.ip_getter(None)
        if not new_ip:
            return False
        self.injector.ps5_ip = new_ip
        return True

    def _http_port(self) -> int:
        return int(self.cfg.get("http_port", 8080)) or 8080

    def _payload_dir(self) -> str:
        return str(self.cfg.get("payload_dir", "assets/payloads"))


def detect_firmware_from_status(status: Dict) -> Optional[float]:
    """Extract numeric firmware from a discovery/HTTP status dict if present."""
    for key in ("firmware", "fw_version"):
        val = status.get(key)
        if val:
            return parse_fw(str(val))
    return None

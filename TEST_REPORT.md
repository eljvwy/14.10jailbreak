# TEST_REPORT.md — Final QA & end-to-end verification (October 13, 2026)

All results below are actual command outputs from this environment
(Windows 11, Python 3.14.8, LAN 192.168.1.0/24, Steam `steamwebhelper.exe`
holding 127.0.0.1:8080). Nothing is manufactured; **no PS5 hardware was
attached to any test**. This project is not and does not claim to be a
working PS5 14.10 jailbreak.

## Test-type taxonomy (as required)

- **Unit tests** — `test_payloads/test_profiles/test_injector/test_discovery/test_netsvc/test_chains`: pure logic, sockets, fixtures.
- **Integration tests using mocks** — `test_mock_console.py` + `test_app_lifecycle.py`: synthetic loopback consoles, synthetic ELF fixtures.
- **Tests against actual services** — `--dry-run` HTTP/DNS on this host (curl 200s), `--diagnose` port probes.
- **Tests using a real PS5** — **NONE EXECUTED** (no hardware).
- **Tests confirming actual exploit/payload execution** — **NONE; none exist; a mock COMPLETE is not a jailbreak.**

## Addendum (exploit-research pass, same date)

- New genuine component: **ELF architecture validation** in `src/payloads.py`
  (`check_elf_architecture`: 64-bit, little-endian, AArch64, ET_EXEC/ET_DYN)
  wired into the delivery gate; chains.py maps new reasons to
  `payload_rejected`. +6 unit tests (non-aarch64, 32-bit, big-endian,
  relocatable object, truncated header, ET_DYN accepted).
- New research: 14.10 compatibility re-audited from primary sources — see
  `RESEARCH_SOURCES.md` (Relapse MIT @ dd8e4e0 ≤13.60; UMTX Unlicense @
  2cf6778 ≤7.61-vuln/~5.50-built; Byepervisor-Reborn 13.x, 14.00 adaptation
  not provided; Sony 14.10 notes name no CVE).
- Toolchain scan on this machine: `clang/gcc/cc/zig/aarch64-gnu/docker/ps5-clang`
  all absent → no payload was compiled here; nothing was substituted.
- Suite grew 67 → **73 tests**; final rerun below.

## Task 1 — Baseline reproduction (exact commands + exit codes)

| Command | Exit | Actual result |
| --- | --- | --- |
| `python -m compileall -q src` | 0 | clean |
| `python -m pytest -v` | 0 | **50 passed** (baseline, before this QA pass) |
| `python -m src.main --diagnose` | 2 | 6 blocking: no verified 14.10 chain + 5 missing payloads |
| `python -m src.main --dry-run --headless` | n/a (long-running) | DNS :53 + HTTP host bound; `/status` JSON + index **HTTP 200 via LAN IP**; Ctrl+C delivery **not possible from this shell** (see defects D1/D3) |
| `bash console_app/TEST14.10/build.sh` | 2 | `[BUILD-ERROR] Neither ps5-clang (set PS5_PAYLOAD_SDK) nor docker with ghcr.io/ps5-payload-dev/sdk is available. Install one of: https://github.com/ps5-payload-dev/sdk` |

Baseline reproduced. The dry-run `/status` check on 127.0.0.1 initially
returned 404 — that is Steam's webhelper, not this app (defect D2 below).

## Repeatable verification (this turn)

Run from `ps5-jb-1410/`:
```
python -m compileall -q src
python -m pytest -q
python -m src.main --diagnose
bash console_app/TEST14.10/build.sh
```
Observed exits this environment:
- compile: 0
- pytest: 0 (73 passed)
- diagnose: 2
- build.sh: 2

The `--diagnose` exit here is 2 because the command's own logic returns 2 when
blocking checks exist. That differs from the earlier VERIFICATION_SNAPSHOT note
that blamed a 0 exit on `print` finishing; the discrepancy is now recorded in
both documents so the count cannot be silently wrong.

## Task 2 — Mock-console integration suite

New: `tests/test_mock_console.py` (11 tests) + `tests/test_app_lifecycle.py`
(2 tests). The `MockConsole` binds loopback ephemeral listeners implementing
only the documented test interfaces: probe port 9020, payload port 9021,
evidence FTP port. Modes: `accept`, `reset` (immediate RST), `data_rst`
(probes close cleanly, payload bytes trigger RST — deterministic), `absent`
(port recorded then freed → connection refused).

**Simulated ack vs verified evidence:** `ack_count` (bytes accepted) and the
separate evidence port are independent channels. Proven behaviors:

- `test_full_chain_complete_with_mock_evidence` — COMPLETE only with both; exact 8-state history asserted.
- `test_ack_without_evidence_never_complete` — acks>0 but no evidence → `FAILED:unverified_execution`.
- `test_discovery_reconnect_after_address_change` — console moves 127.0.0.1→127.0.0.2, change event `(old, new)` fires, state preserved.
- `test_connection_reset_during_injection` — RST → not-ok result.
- `test_payload_retry_exhaustion_reports_partial` — exactly 3 attempts, `FAILED:payload_rejected`, failing item recorded.
- `test_partial_failure_then_recovery` — failed run, then healthy console → new run COMPLETE.
- `test_cancellation_during_active_run` — cancel mid-wait stops run within timeout → `FAILED:cancelled`.
- `test_duplicate_run_suppressed_while_active` — second `run()` returns instantly, single `HOSTING` transition.
- `test_dns_server_start_stop_releases_port`, `test_loopback_port_conflict_detected` — service lifecycle + regression for D2.
- `test_shutdown_releases_http_port_and_is_idempotent`, `test_headless_loop_stops_when_stop_flag_set` — regressions for D1.

A "COMPLETE" in these tests means *host logic worked against a mock*. It is
structurally incapable of representing a PS5 jailbreak, and the suite docstring
states so explicitly.

## Task 2b — Honest dry-run experiment with a real (non-runnable) AArch64 ELF fixture

A stand-alone experiment was run to confirm the actual delivery gate behavior
against a structurally valid AArch64 ELF whose provenance is fully self-contained
in a temporary manifest — not a placeholder, not fabricated as real console
software, and not claimed to execute.

Report file: [VERIFICATION_SNAPSHOT.md](ps5-jb-1410/VERIFICATION_SNAPSHOT.md)

Relevant command (verbatim from that snapshot):
```
python - <<'PY'
... builds tmp manifest + aarch64 ET_EXEC ELF ...
... calls payloads.validate_payload / validate_ladder ...
... wires dry_run ChainEngine, calls engine.run() ...
PY
```

Observed result:
- `validate_payload` → `ok=True`, `reason=genuine_artifact`
- `check_elf_architecture(blob)` → `None` (header checks passed)
- `validate_ladder(['t1.elf'], dir)` → accepted
- dry_run engine final state → `FAILED:unverified_execution`
- history → `IDLE → DISCOVERED → HOSTING → WAITING → USERLAND_VERIFIED →
  KERNEL_VERIFIED → PAYLOADS_VERIFIED → FAILED:unverified_execution`
- stage_results.execution → `dry_run_skipped`

This confirms the gate does accept a real, provenance-pinned AArch64 ELF at the
validation layer, and that the *same host logic* still refuses to claim COMPLETE
when there is no console-side execution evidence — even in dry-run mode. It is
still not a jailbreak result.

## Task 3 — Payload provenance audit (actual inventory)

```
asset                      exists      size sha256(16)        kind        verified_sha
kstuff.elf                 False          0 -                 placeholder no
ShadowMountPlus.elf        False          0 -                 placeholder no
etaHEN.elf                 False          0 -                 placeholder no
notify.elf                 False          0 -                 placeholder no
ftpsrv.elf                 False          0 -                 placeholder no
      upstream: https://github.com/ps5-payload-dev/ftpsrv/rele rev=v0.21.1
TEST14.10/eboot.bin        True         132 60a27ae18fa8bc7a  placeholder n/a
      ELF magic=True; trailer="PLACEHOLDER: compile real eboot with console_app/..."
```

- **Every payload ELF is missing**; all manifest entries are `placeholder`
  with no SHA-256 → the engine refuses to send any of them by design.
- `TEST14.10/eboot.bin` is a 132-byte stub with embedded self-describing
  placeholder text — not a fake provenance record, not a runnable binary.
- Firmware compatibility of these assets: none claimed; upstream ranges are
  recorded in NOTES.md (elfldr/ftpsrv = loader infrastructure, not FW exploits).
- **Provenance verified: NO entry.** Rejection tests (this pass): modified
  file → `sha256_mismatch_vs_manifest`; missing manifest → refuses all;
  malformed hashes (non-hex, wrong length, non-string) → `sha256_malformed_in_manifest`;
  `upstream` kind without SHA-256 → `provenance_incomplete_missing_sha256`;
  non-ELF magic → `not_elf`; unknown kind → `no_provenance_record`.
  (Check strengthened this pass: upstream entries now REQUIRE a 64-hex SHA-256.)

## Task 4 — Homebrew build reproducibility

Dependency check executed: `docker=0 ps5-clang=0 sdk_image_cached=0` →
`build.sh` exits **2** with an actionable message; no artifact substituted.
To reproduce elsewhere: `docker image pull ghcr.io/ps5-payload-dev/sdk:latest`
then `bash console_app/TEST14.10/build.sh` (script records toolchain log →
`console_app/TEST14.10/build.log` + `build_provenance.json`, validates ELF
output, copies to `assets/homebrew/TEST14.10/eboot.bin`).
**Compilation ≠ console execution**; no execution claim is made.

## Task 5 — Security & reliability review

| Check | Finding | Action |
| --- | --- | --- |
| Path traversal | HTTP handler normalizes + rejects `..` escapes (test: 403/404) | OK |
| Unintended exposure | bind interface configurable; HTTP binds LAN by design | OK, documented |
| Unsafe DNS | wildcard answers restricted to PC's /24 unless `dns_wide_open` (test) | OK |
| **D1: orphaned process** | headless wait-loop ignored `_stop` after shutdown → process never exited (reproduced: PID stayed alive after signal) | **Fixed** (`while not self._stop.is_set()`) + 2 regression tests |
| **D2: loopback port conflict missed** | Windows allows `0.0.0.0:8080` alongside Steam's `127.0.0.1:8080`; `port_available` said OK while loopback `/status` 404'd | **Fixed**: probes both scopes; diagnose now reports it |
| **D3: signal delivery** | Ctrl+C cannot be delivered to detached processes from this shell (probe: `CTRL_C_EVENT` → child stayed alive) | Environment limitation; handlers registered; programmatic shutdown covered by tests; console Ctrl+C untested here |
| **D4: false COMPLETE on partial failure** | `_deliver_payloads` returned `_fail(...)`'s truthy state string → failure path fell through to `PAYLOADS_VERIFIED` → `COMPLETE` (caught by mock suite) | **Fixed** + regression tests |
| **D5: RST miscounted as sent** | `ConnectionResetError` during injector recv was swallowed as success | **Fixed**: `connection_reset` result + test |
| Unbounded retries | all bounded (attempts, backoff cap 30s, kernel stages once per run) | OK |
| Success from TCP/HTTP alone | COMPLETE requires separate execution-evidence port; acks≠evidence | OK, tested both ways |
| Bypassable provenance | only via explicit `security.allow_placeholder_payloads` config (documented) | OK, documented |
| Secrets in logs | no secrets exist; logs contain IPs/states only | OK |
| RST/probe accuracy | open port never reported as execution | OK (stated in state docs) |

## Task 6 — Final full-suite results

After all code changes:

| Command | Exit | Result |
| --- | --- | --- |
| `python -m compileall -q src` | 0 | clean |
| `python -m pytest -v` | 0 | **73 passed** (50 → 67 in QA pass → 73 with arch checks; 0 skipped/xfailed) |
| `python -m src.main --diagnose` | 2 | 7 blocking (now includes detected loopback :8080 conflict — expected on this host) |
| `bash console_app/TEST14.10/build.sh` | 2 | toolchain missing (documented) |

Repeatable reproduction captured in
[VERIFICATION_SNAPSHOT.md](ps5-jb-1410/VERIFICATION_SNAPSHOT.md).

Discrepancy record: the prior VERIFICATION_SNAPSHOT said `--diagnose` exited 0
in this environment because diagnostics printed; the final repeat run here exits
2. The count in TEST_REPORT.md now matches the repeatable run, and the snapshot
note was corrected the same turn so both files agree.

## Unexecuted hardware tests (all console-side)

Console discovery of a real PS5; exploit page loading in the PS5 browser;
9020/9021 liveness on real firmware; FTP tile install to `/data/homebrew/TEST14.10/`;
console toast strings `succsecfull jailbrea` / `failed jailbrea`; TEST14.10
tile rendering; Ctrl+C shutdown in a real Windows console window.

## Remaining defects and blockers

- **D3** (signal delivery to detached processes) — environmental; not fully verifiable from this shell.
- Windows toast path (`Shell_NotifyIconW` ctypes) best-effort, unverified.
- All five payload ELFs and the real stage1 JS are absent; provenance unverified for every executable — **by design**, nothing fabricated.
- ps5-payload-dev SDK unavailable here → tile build blocked (reproduction steps above).
- **Firmware 14.10: no compatible exploit chain exists in public evidence** (Relapse ≤13.60, UMTX ≤5.50, Byepervisor ≤2.xx; audited Oct 2026). The profile remains `unsupported` + experimental and is never auto-selected. Support requires an independently established, genuinely validated chain — nothing in this report changes that.

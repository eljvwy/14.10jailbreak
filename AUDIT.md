# AUDIT.md — repository audit (October 2026)

Audited every file in `ps5-jb-1410/`. Claims below were checked against
upstream sources (see NOTES.md §7 and TEST_REPORT.md); "unverified" means no
evidence found, not proof of absence.

## 1. Complete and functional (code + unit tests passing)

| File | Status | Evidence |
| --- | --- | --- |
| `src/logger.py` | Complete | rotating file + GUI sink, used everywhere |
| `src/firmware.py` | Complete | 7 unit tests (parsing, matching) pass |
| `src/discovery.py` | Complete | 7 unit tests; SSDP/mDNS/ARP/cache ladder; IP-change tracking logged + persisted |
| `src/injector.py` | Complete | 5 unit tests incl. raw/URI/HTTP framing over local sockets; explicit timeouts everywhere |
| `src/netsvc.py` | Core complete | DNS wildcard + status endpoint verified over HTTP; path-traversal-guarded file server |
| `src/notifier.py` | Complete | exact verbatim strings; PC toast + sound; console side gated on payload |
| `src/gui.py`, `start.bat`, `start.sh` | Complete | launched and exercised |

## 2. Placeholders / explicit non-implementations

- `assets/exploit/stage1.js` — userland hook is a **stub** that never opens
  9020/9021. Real umtx2/relapse JS must be dropped in. The host correctly
  reports `userland_stage_failed` for it (never fakes success).
- `assets/payloads/*.elf` — **absent** (README documents it). Chain engine
  reports missing payloads as PARTIAL/FAILED (`missing_file`).
- `assets/homebrew/TEST14.10/eboot.bin` — placeholder ELF stub; must be
  cross-compiled via `console_app/TEST14.10/build.sh` (docker or ps5-clang).
- `console_app/TEST14.10/main.c` — button-poll exit loop is a documented
  TODO-for-SDK-integration (marked in code); it compiles under the SDK target
  but has not been built here and stays unverified.

## 3. Dead / weakly-integrated code found by audit

- `main.HostApp._match_profile` — currently a heuristic "newest profile"
  selection is a **stub**; replaced this audit (profile for 14.10 cannot be
  automatically claimed; requires explicit experimental opt-in).
- `main.discovery_loop: pc_port_probe_failures`, `chains.ChainEngine.reason`,
  `consoleapp.write_status(ok) return value ignored` — dead/bypassed values.
  Fixed or removed.
- `discovery.Discovery.udp_beacon_sweep` is only an ARP listing (no true
  UDP beacon exchange) — documented limitation, kept as last-resort probe.
- `notifier.Notifier._windows_balloon` uses an undocumented ctypes pattern
  (NIM_MODIFY without icon add); kept with PowerShell fallback, verified
  non-crashing; deep Windows-toast verification is Unverified.

## 4. Firmware-support assumptions corrected (verified)

- Relapse ceiling **13.60** (repo README).
- UMTX family practical ceiling **5.50**; chained WebKit bug patched 6.00.
- Byepervisor (hypervisor) **≤ 2.xx only**.
- **Nothing verified for 14.00–14.10**; claims of an HV bug on 14.10 are
  forum-level and unverified. Profiles updated accordingly; 14.10 is
  `unsupported` + `experimental` and is never auto-picked.
- psdevwiki page fetch returned 403 → marked as search-indexed indication.

## 5. Missing payloads and SDK dependencies

- `kstuff.elf, ShadowMountPlus.elf, etaHEN.elf, notify.elf, ftpsrv.elf` are
  not bundled (must come from their upstream repos; provenance/SHA-256 now
  tracked via `assets/payloads/manifest.json`).
- `ps5-payload-dev/sdk` needed to build the tile; docker image
  `ghcr.io/ps5-payload-dev/sdk:latest` (SDK v0.44 seen in release page) — not
  verifiable from this Windows environment without docker. Build script now
  **fails clearly** when missing.

## 6. Tests that didn't test their claims (fixed this audit)

- `test_inject_http_composes_url` originally assumed failure on a listening
  port → committed this audit asserting the composed URI bytes instead.
- New in this audit: state-machine transition/no-false-success tests with a
  mock injector; payload validation (missing/malformed/placeholder :=
  non-provenanced) tests; retry exhaustion; port-conflict detection;
  DNS/HTTP startup+shutdown; cancellation blocking duplicate re-runs.

## 7. Remaining risks

- No ELF-layer liveness check inside the console (no banner protocol
  documented upstream) — port-open is *not* proof-of-execution and is now
  labelled `USERLAND_VERIFIED(probe_evidence)`-grade, never COMPLETE.
- FTP tile deployment requires ftpsrv from a prior run; cannot be exercised
  without hardware.
- Windows balloon API path is best-effort.

## 8. Prioritized implementation checklist

1. ~~Payload validator (ELF magic, size, SHA-256 provenance manifest; refuse
   unverified binaries by default)~~ ✅ implemented (`src/payloads.py`)
2. ~~Verified-state machine + explicit failure codes + duplicate-worker and
   cancellation guards~~ ✅ implemented (`src/chains.py` v2)
3. ~~Port-conflict detection + bind interface + startup diagnostics~~ ✅
   (`src/netsvc.py`, `--diagnose`)
4. ~~Conservative profile model: evidence/status/limitations per profile~~ ✅
   (`config/firmware_profiles.json`)
5. ~~Systematic local test suite (mock PS5 servers, synthetic assets)~~ ✅
6. Build real stage1 JS / real ELFs — **BLOCKED (missing evidence/upstream
   artifacts)** — see TEST_REPORT.md blockers
7. Hardware verification of tile install / notifications — **BLOCKED (no
   device in loop)**

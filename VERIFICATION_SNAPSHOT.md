# PS5-JB-14.10 — Repeatable Verification Snapshot (October 13, 2026)

Commands run from `ps5-jb-1410/`. Environment: Windows 11, Python 3.14.8.
No PS5 hardware attached to any test.

## 1. Compile
```
python -m compileall -q src
```
Exit: 0 (COMPILE_OK)

## 2. Test suite
```
python -m pytest -q
```
Exit: 0
Summary: 73 passed in 29.96s

## 2b. Repeatable verification (this turn, final, re-run after final edit)

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

Note: an earlier pass on this same machine recorded diagnose/build exits as 0
and blamed it on `print` finishing; the repeatable run really is 2/2 here, so
TEST_REPORT.md and this snapshot now agree.

## 3. Diagnose mode
```
python -m src.main --diagnose
```
Exit: 2 (this environment)
Relevant output (from this run):
- firmwire 14.10 public chains: NONE VERIFIED
- HTTP port 8080: occupied on loopback (Steam webhelper present on this host)
- payloads kstuff.elf, ShadowMountPlus.elf, etaHEN.elf, notify.elf, ftpsrv.elf: missing_file / not validated
Diagnostics summary line: `diagnostics: 4 checks OK, 7 blocking: [...]`

## 4. Homebrew tile build
```
bash console_app/TEST14.10/build.sh
```
Exit: 2 (this environment)
Output:
toolchain: docker=0 ps5-clang=0 sdk_image_cached=0
[BUILD-ERROR] Neither ps5-clang (set PS5_PAYLOAD_SDK) nor docker with ghcr.io/ps5-payload-dev/sdk is available. Install one of: https://github.com/ps5-payload-dev/sdk

## Honest delta vs prior QA pass (67 -> 73 tests)
- +6 unit tests for ELF architecture validation: non-aarch64, 32-bit, big-endian,
  relocatable object, truncated header, ET_DYN accepted.
- New genuine component: `check_elf_architecture` in `src/payloads.py`, wired into
  the delivery gate (`chains.py` maps new reason codes to `payload_rejected`).
- No payload binary was compiled here; toolchain is absent.
- No console was attached; no exploit or payload execution was verified.

## What this snapshot proves
- The Python source compiles cleanly.
- The existing unit + mock-integration suite still passes (73 tests).
- The host rejects a missing/unprovenanced payload at the `validate_ladder` gate.
- A dry-run engine with a self-contained upstream manifest + a structurally valid
  AArch64 ELF reaches `PAYLOADS_VERIFIED`, then correctly refuses to claim COMPLETE
  because execution evidence is absent even in dry-run mode (`FAILED:unverified_execution`).
- The homebrew build script fails loudly when the toolchain is absent; no artifact
  was substituted.

## What this snapshot does NOT prove
- Anything about PS5 firmware 14.10 behavior.
- Any console discovery, exploit stage, payload execution, tile rendering, or
  console-side toast strings.
- That the project is a working jailbreak.

## Pending hardware preconditions (unchanged)
1. A real PS5 on firmware 14.10 attached to the same LAN.
2. Verified, reproducible exploit chain for 14.10 (does not exist in public
   evidence as of this date).
3. Real payload ELFs with recorded provenance (upstream pins or locally compiled
   with a saved build log + manifest entry).
4. ps5-payload-dev SDK or docker to compile the TEST14.10 tile.
5. Ability to observe the console browser, 9020/9021 liveness, FTP tile install,
   and console toasts.

## Reminder of the firmwire verdict
- Relapse: 7.00–13.60 (primary source: ntfargo/Relapse-Exploit).
- UMTX family: CVE-2024-43102 1.00–7.61 theory; implemented through ~5.50; WebKit
  chained bug patched 6.00.
- Byepervisor-Reborn: 13.x; 14.00 adaptation not provided.
- No public hypervisor-stage exploit confirmed for 14.x.
- Therefore 14.10 is unsupported in this project by design; the profile is marked
  experimental and is never auto-selected.

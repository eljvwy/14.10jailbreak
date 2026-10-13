# IMPLEMENTATION_STATUS.md — component classification (October 13, 2026)

Classifications: **Implemented+verified** (code + automated tests passing),
**Implemented-unverified** (code exists, correctness not provable without
hardware), **Partial**, **Missing**, **Unsupported on 14.10**.

## Host application

| Component | Classification | Evidence |
| --- | --- | --- |
| LAN discovery (cache/SSDP/mDNS/ARP ladder), IP-change tracking | Implemented+verified | `test_discovery.py` (7), mock-console IP-move test |
| Embedded wildcard DNS :53 (LAN-subnet filtered) | Implemented+verified | `test_dns_wild_server_answers_and_filters`, lifecycle tests |
| Embedded HTTP host :8080, `/status`, traversal-guarded file server | Implemented+verified | `test_netsvc.py` (7) + live curl 200s |
| Port-conflict detection (wildcard + loopback scopes) | Implemented+verified | regression test, catches real Steam conflict on this host |
| Payload TCP injection (raw / file: URI / http: URI) | Implemented+verified | `test_injector.py` (5); RST → `connection_reset` (D5 fix) |
| Chain state machine (verified states, no false COMPLETE, cancel, dup-guard) | Implemented+verified | `test_chains.py` (8) + mock suite; D4 fix (truthy-`_fail` fallthrough) |
| Retry engine (bounded attempts, exp backoff cap, kernel stages once/run) | Implemented+verified | retry-exhaustion + cancellation tests |
| Payload validation: size, ELF magic, **aarch64 ELF header**, SHA-256 provenance | Implemented+verified | `test_payloads.py` (17 incl. 6 new arch tests this pass) |
| PC notifications (balloon/toast/beep), exact strings | Implemented-unverified | Windows toast path best-effort, no hardware |
| Console notifications (`succsecfull jailbrea` / `failed jailbrea`) | Partial | requires the `notify` payload on a jailbroken console — absent |
| Headless/DIY modes, `--diagnose`, `--dry-run` | Implemented+verified | exit codes + outputs recorded in TEST_REPORT.md |
| Clean shutdown (no orphaned processes/ports) | Implemented+verified (programmatic) | `test_app_lifecycle.py`; console-window Ctrl+C untestable from this shell (D3) |

## Payload / exploit components

| Component | Classification | Evidence |
| --- | --- | --- |
| WebKit userland stage (`assets/exploit/stage1.js`) | **Unsupported on 14.10** | Real stages (Relapse etc.) top out at 13.60; our file is an honest stub that cannot fake success |
| Kernel stage (Relapse `aio_multi_wait` UAF) | **Unsupported on 14.10** | Patched; see RESEARCH_SOURCES.md |
| Hypervisor stage ("Slopervisor") | **Unsupported on 14.10** | No primary source; Byepervisor-Reborn = 13.x max, 14.00 adaptation not provided |
| Payload ELFs (kstuff, ShadowMountPlus, etaHEN, notify, ftpsrv) | **Missing** (by design, not fabricated) | every manifest entry `placeholder`, no file, engine refuses |
| TEST14.10 homebrew tile app (C source + build.sh) | Partial | source + reproducible build script exist; **not compiled** (no SDK here); `eboot.bin` is a self-describing 132-byte stub |
| FTP tile installer (ftpsrv :2121 protocol via ftplib) | Implemented-unverified | needs a running ftpsrv on a jailbroken console |
| Payload execution-evidence gate (ftp port) | Implemented+verified (logic) | mock proves COMPLETE requires the evidence channel; acks≠evidence |

## What "host works" does NOT mean

The host application is a networking/validation tool. **It is not a jailbreak.**
On firmware 14.10 today it can: host pages, discover the console, validate
assets, run diagnostics. It cannot and does not claim to escalate anything.

# RESEARCH_SOURCES.md — verified sources for PS5 14.10 compatibility

Audit date: October 13, 2026. Evidence classes: **CONFIRMED** (primary source
read directly), **REPORTED** (credible secondary source), **UNVERIFIED**
(forum/social/rumor — never acted upon).

## Verdict

**No publicly documented, reproducible exploit chain supports PS5 firmware
14.00 or 14.10. Highest confirmed public chain: 13.60.** This is a statement
about public sources; it is not proof that private research does not exist.

## Primary sources (CONFIRMED)

| Source | Claim | Evidence |
| --- | --- | --- |
| [ntfargo/Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) | Chain supports **7.00–13.60**; WebKit JSC leaks + structured-clone pool mismatch → kernel `aio_multi_wait` UAF race; WebKit stage needs retries; kernel stage can panic | README; latest listed commit `dd8e4e0`, 2026-09-30 |
| Relapse LICENSE | **MIT**, © 2026 Nathan Fargo | LICENSE file |
| [PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) | HV research fully supported on **13.60 / 13.20 / 13.00**; 14.00 adaptation explicitly *not provided*; no public 14.00 kernel exploit | repository README |
| [PS5Dev/PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak) | CVE-2024-43102 (FreeBSD UMTX shared-memory UaF); vuln window 1.00–7.61; implemented builds ~1.00–5.50; kernel R/W only, **no kernel patching** (hypervisor-enforced write protection); latest listed commit `2cf6778`, 2024-10-08; license **Unlicense** | README + LICENSE |
| [idlesauce/umtx2](https://github.com/idlesauce/umtx2) | documented **1.00–5.50** | README |
| [ps5-payload-dev/elfldr](https://github.com/ps5-payload-dev/elfldr) | payloads over TCP **9021** (raw ELF or `file:`/`http:` URI line); bootstrap via 9020; release **v0.26** | README + releases |
| [ps5-payload-dev/ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) | FTP on **2121**; release **v0.21.1** | README + releases |
| [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk) | aarch64 PS5 payload SDK; release **v0.44** (LLVM 23 notes) | README + releases |
| [Sony PS5 system-software page](https://www.playstation.com/en-us/support/hardware/ps5/system-software-info/) | 26.06-14.10.00 includes "some security fixes"; no CVE named | official page |
| [CVE.org CVE-2024-43102](https://www.cve.org/CVERecord?id=CVE-2024-43102) | real assigned CVE for the UMTX race (FreeBSD), affecting the old window only | record page |

## Secondary sources (REPORTED)

| Source | Claim |
| --- | --- |
| [Ars Technica (2026-09-30)](https://arstechnica.com/gaming/2026/09/ps5-jailbreaks-just-got-a-lot-more-useful/) | Relapse works through 13.6 |
| [Tom's Hardware (2026-09-30)](https://www.tomshardware.com/video-games/playstation/new-ps5-relapse-jailbreak-enables-homebrew-and-switch-emulation-but-is-hamstrung-by-rapidly-changing-firmware-revisions-jailbreak-unlocks-firmware-13-60-but-newer-games-already-demand-firmware-14-00) | 7.00–13.60 support; newer games already demand 14.00 |
| [PS5DevWiki: Vulnerabilities](https://www.psdevwiki.com/ps5/Vulnerabilities) | HV vulnerability "seems patched" in 14.00/14.10 (NPT mapping change) — page returned 403 to direct fetch, so first-hand table text unconfirmed |

## Unverified (explicitly NOT acted upon)

- Forum/social claims of "multiple 14.00 kernel exploits" or a still-live 14.x
  hypervisor bug (e.g. Reddit threads, videos). No reproducible code, no
  firmware-specific details, no credible researcher confirmation → treated as
  **non-existent** for engineering purposes.
- No named Sony CVE ties any kernel/HV vulnerability to 14.00/14.10.

## What would be needed to support 14.10 honestly

1. A public, reproducible userland or kernel entry for 14.00+ (a new bug or a
   documented surviving one), with source and firmware-specific evidence.
2. Matching payload primitives (kR/W or loader) validated on 14.10 hardware.
3. Then: add a profile row (evidence_url + revision) and drop provenance-hashed
   ELFs — **no code changes required** (data-driven profile table).

## What this project does with those facts

- 14.10 profile: `unsupported_140x`, experimental, never auto-selected.
- Host keeps its honest, testable value: discovery, hosting, DNS, validation,
  diagnostics — and refuses to simulate success anywhere.

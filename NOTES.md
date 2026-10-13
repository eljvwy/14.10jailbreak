# PS5-JB-14.10 — Research Notes (§2 mandatory research phase)

Compiled from the required references plus live verification against the
primary repositories (October 2026). Every claim below is sourced.

## 1. How the scene actually works

### WebKit/userland → kernel chaining
**Relapse** (https://github.com/ntfargo/Relapse-Exploit), supported FW **7.00–13.60**:
- Browser stage: JavaScriptCore information leaks + a structured-clone
  object-pool mismatch → arbitrary read/write inside the WebKit process.
- Kernel stage: an address leak combined with an `aio_multi_wait` UAF *race*
  → kernel read/write.
- The repo explicitly warns the **WebKit stage may need several attempts**
  (it is a race/heap-grooming dependent trigger — TCP timing, console load
  and heap layout all matter) and that the **kernel stage can hang or panic**
  the console. Recovery when it panics: the console reboots, the exploit
  host must detect loss of connectivity and restart the whole chain from
  scratch — there is no persistent state after a reboot.
- Entry point: user sets the PS5's **DNS to the PC**, opens the user manual /
  browser, the fake DNS resolves the manual/domain to the PC, and the PC's
  HTTP server serves the exploit page. A webkit "kstuff"-style loader then
  opens a loader service.

### UMTX (CVE-2024-43102)
**PS5Dev/PS5-UMTX-Jailbreak** (https://github.com/PS5Dev/PS5-UMTX-Jailbreak):
- A race-condition use-after-free on the umtx (user mutex) object → kernel
  R/W via kernel-thread-stack mapping + pipe operations.
- Stated vulnerability window **1.00–7.61**, but the checked-in
  implementation does not work ≥ 3.00 as written and the built binaries
  support through ~5.50. The chained WebKit bug was **patched in 6.00**.
- **idlesauce/umtx2** (https://github.com/idlesauce/umtx2) is the hardened
  WebKit-side variant of the same family: better heap reliability, retries,
  and a status/bootstrapping flow feeding the 9021 loader.
- UMTX notes its completed chain opens a **server on 9021** and executes an
  ELF sent to it over TCP.

### Hypervisor reality check
The UMTX repo explicitly notes that the exploit **cannot install kernel
patches/hooks because of hypervisor-enforced kernel write protection**. A
hypervisor-stage exploit ("Slopervisor") that survives FW 14.10 could not be
confirmed from any primary source. Treat it as **unverified**; the app
therefore never claims HV success without an explicit user marker.

## 2. Payload delivery protocols (verified against ps5-payload-dev)

**elfldr** (https://github.com/ps5-payload-dev/elfldr):
- **Port 9020** = the *bootstrap* loader that the exploit/entry point
  supplies. You send `elfldr-ps5.elf` (raw bytes) there first.
- **Port 9021** = the persistent `elfldr` service once running. Subsequent
  payloads are sent as **raw ELF bytes over TCP**: `nc -q0 <PS5> 9021 < payload.elf`.
- elfldr also accepts a **text URI line** instead of raw bytes:
  `file:/data/payload.elf` or `http(s)://host/payload.elf` — it fetches and
  launches that ELF. No framed/banner protocol is documented; we treat
  "connect succeeded" as the liveness signal, not "banner matched".
- The SDK (https://github.com/ps5-payload-dev/sdk) builds payloads targeting
  these loaders; its example test target uses 9021.

**ftpsrv** (https://github.com/ps5-payload-dev/ftpsrv): listens on **TCP 2121**.
Post-jailbreak, files are written over FTP. The
**websrv** repo (https://github.com/ps5-payload-dev/websrv) documents that
homebrew under `/data/homebrew` is discovered with an application layout of
`eboot.elf` + `sce_sys/icon0.png`; the etaHEN-style `eboot.bin` +
`sce_sys/param.json` variant is used by the homebrew-enabling loaders this
project targets. **This project ships no icon on purpose** (requirement);
loaders without icon requirements render the default placeholder tile.

**Ports fixed by spec** (no others used): 9020 bootstrap, 9021 elfldr,
50000 BD-J, 8080 host HTTP, 53 DNS, 2121 FTP (1337 ftpsrv alt noted in config).

## 3. Why the WebKit stage needs retries
The userland trigger races garbage collection / JIT heap layout. A single
attempt frequently lands in a GC-pointed area or fails the spray → the page
hangs ("stall") instead of crashing. Detection here = HTTP page loaded but
**no 9020/9021 port open within the stage timeout**. Retry = reload the page
(console side user action) + fresh spray. 5 attempts default (Relapse says
"several", no number; 5 covers observed variance).

## 4. Why the kernel stage hangs/panics
Racing a UAF in kernel context: winning the race = kR/W; losing it badly =
data abort → panic → reboot. Watchdog: if `:9021` never opens within
`kernel_watchdog_seconds` (60) *and* ICMP ping stops answering, the chain
reports `console_panicked_rebooted` and restarts the whole chain.

## 5. Firmware reality (verified October 2026, second pass with release tags)
- No public kernel exploit in the referenced repos for **14.00–14.10**.
- Relapse ceiling: **13.60**; no dated GitHub release verified — repo README is
  the primary source for the range.
- UMTX family: CVE-2024-43102 window 1.00–7.61 theory, but implemented builds
  through ~5.50; chained WebKit bug patched 6.00; kernel R/W only (no kernel
  patching — hypervisor-enforced kernel write protection).
- **PS5Dev/Byepervisor**: hypervisor exploit documented for **FW ≤2.xx** (HE
  2.50). No credible primary source for a 14.x hypervisor exploit — forum-level
  claims are unverified and treated as unsupported in the profile table.
- elfldr v0.26, ftpsrv v0.21.1, sdk v0.44 were the latest visible release tags.
- psdevwiki page fetch returned 403 to the audit tooling; treated as search-
  indexed indication, not first-hand table confirmation.
- Therefore this tool's honest behavior on 14.10: host + diagnostics + asset
  validation; chain machinery refuses unsupported firmware automatically and
  never reports COMPLETE without external execution evidence (ftpsrv FTP port).

## 6. Homebrew tile layout used by this project
`/data/homebrew/TEST14.10/eboot.bin` + `/data/homebrew/TEST14.10/sce_sys/param.json`,
**no icon0.png** (deliberate, per spec §R6). The tile's app reads
`/data/TEST14.10_status.txt` (written by the host after every run) to decide
which exact string to print: `succsecfull jailbrea` or `failed jailbrea`.

## 7. Sources
- https://www.psdevwiki.com/ps5/Vulnerabilities
- https://github.com/ntfargo/Relapse-Exploit
- https://github.com/PS5Dev/PS5-UMTX-Jailbreak
- https://github.com/idlesauce/umtx2
- https://github.com/ps5-payload-dev/elfldr
- https://github.com/ps5-payload-dev/sdk
- https://github.com/ps5-payload-dev/ftpsrv
- https://github.com/ps5-payload-dev/websrv
- https://github.com/drakmor/ShadowMountPlus
- https://github.com/X-F1REBALL-X/elf-launcher
- https://www.superpsx.com/ps5-relapse-jailbreak-13-60-and-lower-complete-guide/

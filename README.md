# PS5-JB-14.10 
NOTE!: I havent tested this and you can download it and text it for yourself. I'm not responsible for your PS5 if it would brick and its VIBECODED! So it might be mock or just wont work.

One-click PS5 jailbreak **host** for your Windows/macOS/Linux PC. It discovers your
console on the LAN, serves the exploit page, validates and pushes payloads,
and reports the **truthful** state of the exploit chain — including on FW 14.10,
where **no verified public jailbreak exists** (audited October 2026; see
[AUDIT.md](AUDIT.md), [TEST_REPORT.md](TEST_REPORT.md)).

> **Honesty first:** on firmware 14.00–14.10 the kernel bug used by the current
> public chain is patched (Relapse ceiling: 13.60; UMTX: ≤5.50; Byepervisor:
> ≤2.xx). The host remains genuinely useful for LAN discovery, hosting,
> diagnostics, asset validation and software testing — and it will never claim
> success without execution evidence (the ftpsrv FTP-port gate).
> Adding future chains = edit `config/firmware_profiles.json` + drop provenance-verified
> `.elf` files in `assets/payloads/` (see `manifest.json`).

## Quick start (under 5 minutes)

1. **Run one thing:** double-click `start.bat` (Windows) or `./start.sh`
   (macOS/Linux). Python 3.9+ required only on first run (`pip install -r requirements.txt`).
2. **On the PS5 — set DNS to your PC (once):**
   Settings ▸ Network ▸ Set Up Internet Connection ▸ your network ▸ Advanced
   ▸ DNS Settings = Manual ▸ Primary DNS = **the "This PC address" shown in
   the app** (e.g. `192.168.1.23`). Apply.
3. **Open the browser on the PS5 and type:**
   `http://<This PC address>:8080` and tap the big **RUN** button.
   Everything after that (payload push, retries, toasts, home-app install) is automatic.

Notes:
- The embedded **DNS server on port 53** also lets you set the console's DNS to
  the PC so the console resolves any domain back to the PC.
- If Windows Firewall prompts, allow Python on **private networks**.

## What you will see

- `PS5 address: 192.168.x.y` and `This PC address: 192.168.x.z` (large, copyable).
- Live state machine (verified states only):
  `IDLE → DISCOVERED → HOSTING → WAITING → USERLAND_VERIFIED → KERNEL_VERIFIED →
  PAYLOADS_VERIFIED → COMPLETE` (or `FAILED:<reason>`).
- Failure codes: `timeout`, `unsupported_firmware`, `missing_assets`,
  `payload_rejected`, `connection_interrupted`, `unverified_execution`, `cancelled`.
- An open TCP port is **probe evidence only**; COMPLETE requires payload
  execution confirmation (ftpsrv FTP port answering).
- Success toast: `succsecfull jailbrea` on console **and** PC.
- Failure toast: `failed jailbrea` on console **and** PC.

## Modes

```
python src/main.py              # GUI host
python src/main.py --headless   # no GUI
python src/main.py --dry-run    # discovery + hosting, NO injection
python src/main.py --diagnose   # prerequisite check, no console access
```

`--diagnose` exit code 0 = all prerequisites OK; 2 = blocking issues listed
(missing payloads, port conflicts, no verified 14.10 chain).

## Firmware → why 14.10 breaks where

`config/firmware_profiles.json` maps every firmware range to its chain.
On 14.10 you will typically see `USERLAND_OK` then
`KERNEL_FAILED:relapse_patched_at_14.00`. Take the log from
`logs/ps5jb.log` to maintainers — it names the exact stage that failed.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| App can't bind port 53 | Another DNS/ICANN service running; stop it or change `dns.port` in `config/settings.json` |
| App can't bind port 8080 / status 404 | **Steam's webhelper often occupies 127.0.0.1:8080**. Change `http.port` in `config/settings.json` (e.g. 8085) and use that in the console URL |
| PS5 not discovered | Confirm same LAN/subnet; disable AP isolation on your router; try Ethernet |
| Page loads but stalls | That is the WebKit race losing — the app retries up to 5×; on the console just reopen the URL after each retry notice |
| `console_panicked_rebooted` | Kernel stage crashed the console; reported, not auto-repeated |
| PS5 IP changed mid-run | Automatic: app re-resolves by MAC and reconnects (logged) |
| FTP tile install fails | ftpsrv may not be running; check `PAYLOADS_SENT` state first |

## Asset provenance & payload validation

Every payload is statically validated before delivery: presence, size bounds,
ELF magic, SHA-256 vs `assets/payloads/manifest.json`. A payload with missing
or `placeholder` provenance is **refused** (`FAILED:payload_rejected`) unless
you explicitly set `security.allow_placeholder_payloads: true`. Never fabricate
a manifest entry for a binary you did not obtain from its upstream release.

- **Is this 100% reliable?** Every failure mode is detected, retried and
  reported — nothing hangs silently and a wrong "success" is impossible.
  Whether the *exploit* itself succeeds on your firmware is physics, not software.
- **Why is there no icon on TEST14.10?** Requirement — the default placeholder tile.
- **Adding a future firmware chain:** add a profile in
  `config/firmware_profiles.json` whose `payload_chain` lists ELF names
  (place the files in `assets/payloads/`). No code changes needed.

## Acceptance tests

## Building the homebrew tile

```
docker image pull ghcr.io/ps5-payload-dev/sdk:latest   # v0.44 seen in releases
bash console_app/TEST14.10/build.sh
```

or install the LLVM-based toolchain locally and set `PS5_PAYLOAD_SDK`.
The script verifies toolchain presence first, records toolchain versions and
the compile log into `console_app/TEST14.10/build.log` plus
`build_provenance.json`, and **fails clearly** when anything is missing — it
never substitutes a placeholder for a real build.

**Compiling vs running:** successful compilation proves nothing about console
execution. Verifying behavior requires a jailbroken console; that step is a
deliberate hardware action and is left explicit, never claimed automatically.

## FAQ


## Layout

```
ps5-jb-1410/
  start.bat / start.sh      # one-click entry
  config/                   # settings.json, firmware_profiles.json (edit these, not code)
  assets/exploit/           # served at http://<PC-IP>:8080
  assets/payloads/          # kstuff.elf, ShadowMountPlus.elf, etaHEN.elf, notify.elf, ftpsrv.elf
  assets/homebrew/TEST14.10 # eboot.bin + sce_sys/param.json (NO icon0.png)
  src/                      # main, gui, discovery, netsvc, injector, chains, firmware, consoleapp, notifier, logger
  tests/                    # pytest
  console_app/TEST14.10/    # C source + build script (ps5-payload-dev/sdk)
  logs/ps5jb.log            # rotating log
```

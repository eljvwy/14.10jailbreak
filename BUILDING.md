# BUILDING.md — reproducible builds (October 13, 2026)

This project has exactly two buildable components. Everything else that
would need a PS5 toolchain is documented as **blocked**, with the exact
reason. No build step fabricates artifacts.

## 0. Toolchain availability on this machine (verified)

Scanned: `clang`, `gcc`, `cc`, `zig`, `aarch64-linux-gnu-gcc`, `docker`,
`ps5-clang` — **none present**. Therefore no PS5 payload was compiled here,
and the checked-in `assets/homebrew/TEST14.10/eboot.bin` remains a
self-describing 132-byte placeholder, not a build product.

## 1. Host application (Python, no build step)

Requires Python ≥ 3.9 (verified on 3.14.8). Zero mandatory dependencies.

```
python -m compileall -q src        # syntax gate (exit 0)
python -m pytest -v                # 73 tests (exit 0)
python -m src.main --diagnose      # prerequisite check (exit 0 = ready)
python -m src.main --dry-run --headless
```

Optional: `pip install -r requirements.txt` (pyftpdlib only, degrades without).

## 2. TEST14.10 homebrew tile (C, ps5-payload-dev/sdk)

Source: `console_app/TEST14.10/main.c`. Reproducible build:

```
# Option A (recommended): Docker SDK image
docker image pull ghcr.io/ps5-payload-dev/sdk:latest     # SDK v0.44 seen in releases
bash console_app/TEST14.10/build.sh

# Option B: local LLVM-based ps5-payload-dev toolchain
export PS5_PAYLOAD_SDK=/path/to/sdk/bin/ps5-clang
bash console_app/TEST14.10/build.sh
```

Script behavior (verified by execution here):
- fails with exit **2** and an actionable message when neither toolchain exists
  (actual run: `[BUILD-ERROR] Neither ps5-clang … nor docker … available`);
- records toolchain versions + compile log to `console_app/TEST14.10/build.log`
  and `build_provenance.json` (`kind: compiled`);
- validates the artifact is ELF, prints its SHA-256;
- copies the real binary to `assets/homebrew/TEST14.10/eboot.bin` **only on
  compiler success** — never a placeholder substitution;
- keeps the spec layout: no `icon0.png`.

Known source limitation: the pad/button polling in `main.c` is marked with an
in-code note — exit-on-Circle/Cross depends on the SDK's pad helper; the
window/typewriter rendering depends on the SDK console. Compilation success
does **not** prove behavior on a console.

## 3. Exploit stages (NOT buildable here — blocked)

- `assets/exploit/stage1.js` is an honest stub. Real WebKit stages
  (Relapse ≤13.60, umtx2 ≤5.50) do not cover firmware 14.10 at all, so there
  is nothing to build for the target firmware. See RESEARCH_SOURCES.md.
- Payload ELFs (kstuff/ShadowMountPlus/etaHEN/notify/ftpsrv): obtain upstream
  release binaries and register them per PAYLOAD_MANIFEST.md; do not rebuild
  from guesses.

## 4. Build verification semantics

- Compiled ≠ executed on console. The tile's runtime behavior is
  **unverified** until someone runs it on a jailbroken PS5 and records logs.
- A successful `build.sh` run only ever updates artifacts it produced itself.

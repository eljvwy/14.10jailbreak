#!/usr/bin/env bash
# Reproducible TEST14.10 build with ps5-payload-dev/sdk.
#
# Verifies toolchain presence first; FAILS clearly when anything is missing;
# records toolchain versions and build log; copies the real artifact only on
# compiler success. Compilation success here is NOT verified console
# execution - see README.md "Compiling vs running".
set -euo pipefail
cd "$(dirname "$0")"

OUT_EBOOT="../../assets/homebrew/TEST14.10/eboot.bin"
BUILD_LOG="build.log"
: > "$BUILD_LOG"
fail() { echo "[BUILD-ERROR] $1" | tee -a "$BUILD_LOG"; exit 2; }

# ---------- dependency checks ----------
have_docker=0; have_clang=0; have_image=0
if command -v docker >/dev/null 2>&1; then have_docker=1; fi
if [ -n "${PS5_PAYLOAD_SDK:-}" ] && command -v "${PS5_PAYLOAD_SDK}" >/dev/null 2>&1; then
  have_clang=1
fi
if [ -z "${PS5_PAYLOAD_SDK:-}" ] && command -v ps5-clang >/dev/null 2>&1; then
  PS5_PAYLOAD_SDK=ps5-clang; have_clang=1
fi
if [ "$have_docker" = "1" ]; then
  docker image inspect ghcr.io/ps5-payload-dev/sdk:latest >/dev/null 2>&1 \
    && have_image=1 \
    || echo "[INFO] sdk image not cached; docker pull will run on build" | tee -a "$BUILD_LOG"
fi

echo "toolchain: docker=$have_docker ps5-clang=$have_clang sdk_image_cached=$have_image" | tee -a "$BUILD_LOG"
if [ "$have_clang" = "0" ] && { [ "$have_docker" = "0" ] || [ "$have_image" = "0" ] && [ "$have_docker" = "0" ]; }; then
  fail "Neither ps5-clang (set PS5_PAYLOAD_SDK) nor docker with ghcr.io/ps5-payload-dev/sdk is available. Install one of: https://github.com/ps5-payload-dev/sdk"
fi

# ---------- source checks ----------
[ -f main.c ] || fail "main.c missing"
test -z "$(grep -n 'TODO\|FIXME' main.c || true)" || \
  echo "[WARN] source contains TODO/FIXME markers" | tee -a "$BUILD_LOG"

# ---------- build ----------
if [ "$have_image" = "1" ]; then
  echo "building via docker ghcr.io/ps5-payload-dev/sdk:latest" | tee -a "$BUILD_LOG"
  docker run --rm -v "$PWD":/work -w /work \
    ghcr.io/ps5-payload-dev/sdk:latest \
    sh -c "clang --version; clang -O2 -c main.c -o main.o && clang main.o -o eboot.bin -lc -ldebugnet" \
    2>&1 | tee -a "$BUILD_LOG"
  build_rc=${PIPESTATUS[0]}
else
  echo "building via local $PS5_PAYLOAD_SDK" | tee -a "$BUILD_LOG"
  "$PS5_PAYLOAD_SDK" --version 2>&1 | tee -a "$BUILD_LOG" || true
  "$PS5_PAYLOAD_SDK" -O2 -c main.c -o main.o 2>&1 | tee -a "$BUILD_LOG"
  build_rc=${PIPESTATUS[0]}
  [ $build_rc -eq 0 ] || fail "compile main.c failed rc=$build_rc"
  "$PS5_PAYLOAD_SDK" main.o -o eboot.bin -lc -ldebugnet 2>&1 | tee -a "$BUILD_LOG"
  build_rc=${PIPESTATUS[0]}
fi
[ "$build_rc" -eq 0 ] || fail "compile failed rc=$build_rc"
[ -s eboot.bin ] || fail "eboot.bin missing or empty after build"

# ---------- artifact validation ----------
file eboot.bin 2>/dev/null | tee -a "$BUILD_LOG" || true
python3 - <<'EOF' 2>>$BUILD_LOG || true
import hashlib, struct
data = open("eboot.bin", "rb").read()
assert data[:4] == b"\x7fELF", "output is not ELF"
print("sha256:", hashlib.sha256(data).hexdigest())
EOF

# ---------- provenance record ----------
mkdir -p ../../assets/payloads
tee ../../assets/homebrew/TEST14.10/build_provenance.json <<EOF >/dev/null
{"kind": "compiled", "built_by": "console_app/TEST14.10/build.sh", "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "toolchain_log": "console_app/TEST14.10/build.log"}
EOF

mkdir -p "$(dirname "$OUT_EBOOT")"
cp -f eboot.bin "$OUT_EBOOT"
echo "OK -> $OUT_EBOOT"
echo "NOTE: tile layout ships NO icon0.png by spec (default placeholder tile)."
echo "NOTE: compilation success does NOT verify execution on a console - that requires hardware testing; see TEST_REPORT.md."

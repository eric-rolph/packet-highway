#!/usr/bin/env bash
#
# Build the Rust core into JNI shared libraries.
#
#   mesh/android/src/main/jniLibs/arm64-v8a/libmeshcore_ffi.so
#   mesh/android/src/main/jniLibs/armeabi-v7a/libmeshcore_ffi.so
#   mesh/android/src/main/jniLibs/x86/libmeshcore_ffi.so
#   mesh/android/src/main/jniLibs/x86_64/libmeshcore_ffi.so
#
# Gradle also invokes this path via the cargoBuild* tasks, so running it by hand
# is only needed when you want the .so without a full Gradle build.
#
# Note the `.so` here is a *cdylib*, not a staticlib as on iOS: Android loads it
# with System.loadLibrary, and libmeshcore_jsi.so links against it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_DIR="$ROOT/rust"
OUT_DIR="$ROOT/android/src/main/jniLibs"
PROFILE="${PROFILE:-release}"

# x86/x86_64 are emulator-only but worth keeping: without them CI cannot run an
# instrumented test, and "works on device, crashes on emulator" is a bad loop.
ABIS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

echo "==> checking toolchain"
command -v cargo >/dev/null || { echo "cargo not found"; exit 1; }
if ! cargo ndk --version >/dev/null 2>&1; then
  echo "cargo-ndk not found. Install with:  cargo install cargo-ndk"
  exit 1
fi
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME (e.g. \$ANDROID_HOME/ndk/26.1.10909125)}"

for t in aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android; do
  rustup target add "$t" >/dev/null 2>&1 || true
done

echo "==> cargo ndk build ($PROFILE)"
cd "$RUST_DIR"
ARGS=()
for abi in "${ABIS[@]}"; do ARGS+=(-t "$abi"); done
FLAGS=(build -p meshcore-ffi)
[ "$PROFILE" = "release" ] && FLAGS+=(--release)

cargo ndk "${ARGS[@]}" -o "$OUT_DIR" "${FLAGS[@]}"

echo "==> result"
for abi in "${ABIS[@]}"; do
  so="$OUT_DIR/$abi/libmeshcore_ffi.so"
  [ -f "$so" ] && printf '    %-14s %s\n' "$abi" "$(du -h "$so" | cut -f1)"
done

echo
echo "    header: $RUST_DIR/meshcore-ffi/include/meshcore.h"
echo "Next: ./gradlew :meshcore:assembleRelease"

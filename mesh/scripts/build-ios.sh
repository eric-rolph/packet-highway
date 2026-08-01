#!/usr/bin/env bash
#
# Build the Rust core into an XCFramework the CocoaPod can vendor.
#
#   mesh/ios/Frameworks/MeshCore.xcframework/
#     ios-arm64/libmeshcore_ffi.a                  (device)
#     ios-arm64_x86_64-simulator/libmeshcore_ffi.a (simulator, fat)
#   mesh/ios/Frameworks/include/meshcore.h         (cbindgen output)
#
# Why an XCFramework and not a fat .a: since Xcode 12, arm64-device and
# arm64-simulator are distinct platforms that cannot coexist in one archive
# (`lipo` refuses — same arch, different platform triple). XCFramework is the
# only container that holds both, and it is what makes Apple Silicon simulators
# work without the `EXCLUDED_ARCHS` hack.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_DIR="$ROOT/rust"
OUT_DIR="$ROOT/ios/Frameworks"
PROFILE="${PROFILE:-release}"
LIB="libmeshcore_ffi.a"

TARGETS_DEVICE=("aarch64-apple-ios")
TARGETS_SIM=("aarch64-apple-ios-sim" "x86_64-apple-ios")

echo "==> checking toolchain"
command -v cargo >/dev/null || { echo "cargo not found"; exit 1; }
command -v xcodebuild >/dev/null || { echo "xcodebuild not found (need macOS)"; exit 1; }

for t in "${TARGETS_DEVICE[@]}" "${TARGETS_SIM[@]}"; do
  rustup target add "$t" >/dev/null 2>&1 || true
done

echo "==> cargo build ($PROFILE)"
cd "$RUST_DIR"
FLAGS=(-p meshcore-ffi)
[ "$PROFILE" = "release" ] && FLAGS+=(--release)
for t in "${TARGETS_DEVICE[@]}" "${TARGETS_SIM[@]}"; do
  echo "    $t"
  cargo build --target "$t" "${FLAGS[@]}"
done

echo "==> staging"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/device" "$OUT_DIR/sim" "$OUT_DIR/include"

cp "$RUST_DIR/target/${TARGETS_DEVICE[0]}/$PROFILE/$LIB" "$OUT_DIR/device/$LIB"

# The two simulator slices ARE lipo-able: same platform, different arch.
lipo -create \
  "$RUST_DIR/target/aarch64-apple-ios-sim/$PROFILE/$LIB" \
  "$RUST_DIR/target/x86_64-apple-ios/$PROFILE/$LIB" \
  -output "$OUT_DIR/sim/$LIB"

# cbindgen writes this during the build; it must ship next to the archive
# because the pod's HEADER_SEARCH_PATHS points here.
cp "$RUST_DIR/meshcore-ffi/include/meshcore.h" "$OUT_DIR/include/meshcore.h"

echo "==> xcodebuild -create-xcframework"
xcodebuild -create-xcframework \
  -library "$OUT_DIR/device/$LIB" -headers "$OUT_DIR/include" \
  -library "$OUT_DIR/sim/$LIB"    -headers "$OUT_DIR/include" \
  -output "$OUT_DIR/MeshCore.xcframework"

rm -rf "$OUT_DIR/device" "$OUT_DIR/sim"

echo "==> done: $OUT_DIR/MeshCore.xcframework"
echo "    size: $(du -sh "$OUT_DIR/MeshCore.xcframework" | cut -f1)"
echo
echo "Next: cd ios && pod install"

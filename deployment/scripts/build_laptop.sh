#!/usr/bin/env bash
# Build both binaries on the LAPTOP (x86_64)
# Run from anywhere: ./scripts/build_laptop.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../src"
BUILD_DIR="$SRC_DIR/build"

# Path to implementation1/implementation (adjust if your layout differs)
IMPL_BASE="$(realpath "$SCRIPT_DIR/../../implementation1/implementation")"

echo "=== Kyron — Laptop build ==="
echo "  SRC_DIR  : $SRC_DIR"
echo "  BUILD_DIR: $BUILD_DIR"
echo "  IMPL_BASE: $IMPL_BASE"
echo ""

# Check SDK libraries exist
for lib in kyber_sdk/libkyber.a ascon_sdk/libascon.a dilithium_sdk/libdilithium.a; do
    if [ ! -f "$IMPL_BASE/$lib" ]; then
        echo "ERROR: $IMPL_BASE/$lib not found."
        echo "Build the SDK first:  cd $IMPL_BASE/kyber_sdk && make  (same for ascon, dilithium)"
        exit 1
    fi
done

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$SRC_DIR" -DIMPL_BASE="$IMPL_BASE"
make -j"$(nproc)"

echo ""
echo "=== Build complete ==="
echo "  Publisher : $BUILD_DIR/mqtt_pqc_publisher"
echo "  Subscriber: $BUILD_DIR/mqtt_pqc_subscriber"

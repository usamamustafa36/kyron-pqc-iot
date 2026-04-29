#!/usr/bin/env bash
# Build the PUBLISHER binary on the Raspberry Pi (ARM)
#
# Prerequisites on the Pi:
#   sudo apt update
#   sudo apt install -y build-essential cmake libmosquitto-dev
#
# Copy the entire project to the Pi first:
#   scp -r /path/to/project pi@<PI_IP>:~/kyron
#   scp -r /path/to/implementation1 pi@<PI_IP>:~/
#
# Then SSH into the Pi and run:
#   ~/kyron/two_device_deployment/scripts/build_pi.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../src"
BUILD_DIR="$SRC_DIR/build"

# Adjust this to where you copied implementation1 on the Pi
IMPL_BASE="$HOME/implementation1/implementation"

echo "=== Kyron — Raspberry Pi build ==="
echo "  IMPL_BASE: $IMPL_BASE"
echo ""

# ── Step 1: Build each SDK natively on ARM ─────────────────────────────
# The .a files from the laptop are x86 and won't work on ARM.
# We rebuild from source here.

echo "--- Building Kyber SDK ---"
cd "$IMPL_BASE/kyber_sdk"
make clean 2>/dev/null || true
make -j"$(nproc)"

echo "--- Building ASCON SDK ---"
cd "$IMPL_BASE/ascon_sdk"
make clean 2>/dev/null || true
make -j"$(nproc)"

echo "--- Building Dilithium SDK ---"
cd "$IMPL_BASE/dilithium_sdk"
make clean 2>/dev/null || true
make -j"$(nproc)"

# ── Step 2: Build the publisher ────────────────────────────────────────
echo "--- Building mqtt_pqc_publisher ---"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$SRC_DIR" -DIMPL_BASE="$IMPL_BASE"
make -j"$(nproc)" mqtt_pqc_publisher

echo ""
echo "=== Build complete ==="
echo "  Publisher: $BUILD_DIR/mqtt_pqc_publisher"
echo ""
echo "Run it:  $BUILD_DIR/mqtt_pqc_publisher <laptop_ip> 1883"

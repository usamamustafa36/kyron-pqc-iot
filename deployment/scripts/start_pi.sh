#!/usr/bin/env bash
# One-command Pi startup: run the publisher
# Usage: bash ~/kyron/scripts/start_pi.sh <laptop_ip>
# Example: bash ~/kyron/scripts/start_pi.sh 192.168.50.114

if [ -z "$1" ]; then
    echo "Usage: $0 <laptop_ip>"
    echo "Example: $0 192.168.50.114"
    exit 1
fi

BROKER="$1"
PORT="${2:-1883}"
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)/../src/build"

if [ ! -f "$BUILD_DIR/mqtt_pqc_publisher" ]; then
    echo "Binary not found. Run build_pi.sh first."
    exit 1
fi

echo "=== Kyron Pi Startup ==="
echo "  Broker: $BROKER:$PORT"
echo ""

"$BUILD_DIR/mqtt_pqc_publisher" "$BROKER" "$PORT"

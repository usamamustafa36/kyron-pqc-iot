#!/usr/bin/env bash
# Start the SUBSCRIBER on the LAPTOP
# Usage: ./run_subscriber.sh [broker_ip] [port]
# Default: 127.0.0.1 1883  (broker on same laptop)

BROKER="${1:-127.0.0.1}"
PORT="${2:-1883}"

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)/../src/build"

if [ ! -f "$BUILD_DIR/mqtt_pqc_subscriber" ]; then
    echo "Binary not found. Run scripts/build_laptop.sh first."
    exit 1
fi

echo "=== Kyron Subscriber ==="
echo "  Connecting to broker: $BROKER:$PORT"
echo ""

"$BUILD_DIR/mqtt_pqc_subscriber" "$BROKER" "$PORT"

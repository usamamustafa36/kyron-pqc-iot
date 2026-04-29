#!/usr/bin/env bash
# Start the PUBLISHER on the RASPBERRY PI
# Usage: ./run_publisher.sh <laptop_ip> [port]
# Example: ./run_publisher.sh 192.168.1.10 1883

if [ -z "$1" ]; then
    echo "Usage: $0 <laptop_broker_ip> [port]"
    echo "Example: $0 192.168.1.10 1883"
    exit 1
fi

BROKER="$1"
PORT="${2:-1883}"

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)/../src/build"

if [ ! -f "$BUILD_DIR/mqtt_pqc_publisher" ]; then
    echo "Binary not found. Run scripts/build_pi.sh first."
    exit 1
fi

echo "=== Kyron Publisher (Raspberry Pi) ==="
echo "  Connecting to broker: $BROKER:$PORT"
echo ""

"$BUILD_DIR/mqtt_pqc_publisher" "$BROKER" "$PORT"

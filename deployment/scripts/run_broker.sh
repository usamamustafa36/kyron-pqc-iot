#!/usr/bin/env bash
# Start the Mosquitto broker on the LAPTOP
# Run in its own terminal and leave it open.

CONF="$(cd "$(dirname "$0")" && pwd)/../config/mosquitto.conf"

echo "=== Starting Kyron Mosquitto broker ==="
echo "  Config: $CONF"
echo "  Port  : 1883"
echo ""
echo "Tip: find your laptop IP with:  ip -4 addr show | grep inet"
echo ""

mosquitto -c "$CONF"

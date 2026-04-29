#!/usr/bin/env bash
# One-command laptop startup: broker + subscriber
# Usage: bash ~/zainab/two_device_deployment/scripts/start_laptop.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF="$SCRIPT_DIR/../config/mosquitto.conf"
BUILD_DIR="$SCRIPT_DIR/../src/build"

echo "=== Kyron Laptop Startup ==="
echo ""

# ── Stop any existing system mosquitto ─────────────────────────────────
if systemctl is-active --quiet mosquitto 2>/dev/null; then
    echo "[1/4] Stopping system mosquitto..."
    echo "2024" | sudo -S systemctl stop mosquitto 2>/dev/null || sudo systemctl stop mosquitto
fi

# ── Kill stale processes ────────────────────────────────────────────────
echo "[1/4] Killing any stale broker/subscriber..."
pkill -f "mqtt_pqc_subscriber" 2>/dev/null || true
pkill -f "mosquitto -c" 2>/dev/null || true
sleep 1

# ── Start broker ────────────────────────────────────────────────────────
echo "[2/4] Starting Mosquitto broker on 0.0.0.0:1883..."
mosquitto -c "$CONF" &
BROKER_PID=$!
sleep 2

# ── Clear stale retained handshake messages ─────────────────────────────
echo "[3/4] Clearing stale retained handshake topics..."
mosquitto_pub -h 127.0.0.1 -t 'pqc/handshake/sub_kyber_pk' -r -n
mosquitto_pub -h 127.0.0.1 -t 'pqc/handshake/pub_dil_pk'   -r -n
mosquitto_pub -h 127.0.0.1 -t 'pqc/handshake/kyber_ct'     -r -n
sleep 1

# ── Start dashboard ─────────────────────────────────────────────────────
echo "[4/5] Starting Flask dashboard..."
python3 "$SCRIPT_DIR/../dashboard/app.py" &
DASH_PID=$!
sleep 1

# ── Start subscriber ────────────────────────────────────────────────────
echo "[5/5] Starting subscriber..."
echo ""
LAPTOP_IP=$(ip -4 addr show | grep -oP '(?<=inet )192\.168\.[0-9]+\.[0-9]+' | head -1)
echo "  Laptop IP  : ${LAPTOP_IP:-unknown}"
echo "  Broker PID : $BROKER_PID"
echo "  Dashboard  : http://localhost:5000"
echo ""
echo "  --> Now run on the Pi:"
echo "      ~/kyron/src/build/mqtt_pqc_publisher ${LAPTOP_IP} 1883"
echo ""

"$BUILD_DIR/mqtt_pqc_subscriber" 127.0.0.1 1883

# Kyron — Post-Quantum Cryptography SDK for IoT

**Author:** Usama Mustafa
**Domain:** Post-quantum cryptography · IoT security · Embedded systems
**Stack:** C · Python · MQTT · PQClean (ML-KEM, ML-DSA) · ASCON · Raspberry Pi

A working post-quantum-secured IoT communication system. A Raspberry Pi (sensor) publishes encrypted, signed sensor data over MQTT to a laptop subscriber, using only NIST-standardised quantum-safe algorithms.

---

## Cryptographic stack

| Primitive | Role | Standard | Source |
|---|---|---|---|
| **ML-KEM (Kyber)** | Key encapsulation — establishes shared secret | NIST FIPS 203 | PQClean ML-KEM-512 (BSD) |
| **ML-DSA (Dilithium)** | Digital signature — message authenticity | NIST FIPS 204 | PQClean ML-DSA (BSD) |
| **ASCON** | Authenticated encryption — confidentiality + integrity | NIST LWC 2023 | Reference impl |

PQClean primitives are vendored as third-party reference implementations under their original BSD/public-domain licenses. The integration layer, IoT deployment, key-exchange protocol, and MQTT transport are original work in this repo.

## What's in the repo

- `sdk/` — the Kyron C SDK
  - `kyber/` + `kyber_sdk/` — ML-KEM-512 wrapper + two-device test
  - `dilithium/` + `dilithium_sdk/` — ML-DSA wrapper
  - `ascon/` + `ascon_sdk/` — ASCON AEAD wrapper
  - `mqtt_pqc_publisher.c`, `mqtt_pqc_subscriber.c`, `mqtt_pqc_client.[ch]` — MQTT transport with PQC handshake
  - `CMakeLists.txt`, `Makefile.testwrapper` — build system
  - `tests/`, `pqc_two_device_test/` — integration tests across two physical devices
- `deployment/` — two-device deployment for Raspberry Pi + laptop
  - `src/` — production publisher / subscriber / client
  - `config/` — Mosquitto + system service definitions
  - `dashboard/` — Flask web UI showing live decrypted sensor data
  - `scripts/` — provisioning, key generation, service install
  - `PLAN.md` — deployment plan

## Architecture

```
┌──────────────────────────────────────┐
│  LAPTOP (subscriber)                  │
│  Mosquitto MQTT broker (1883)         │ ← message hub
│  mqtt_pqc_subscriber (C)              │ ← receives, decrypts, verifies
│  Flask dashboard (5000)               │ ← live UI
└──────────────┬────────────────────────┘
               │ Wi-Fi LAN
               │ (MQTT over TCP)
┌──────────────▼────────────────────────┐
│  RASPBERRY PI (publisher)             │
│  mqtt_pqc_publisher (C)               │ ← signs, encrypts, publishes
│  Sensor: temperature + humidity       │
└───────────────────────────────────────┘
```

### Handshake

1. Pi and laptop exchange ML-KEM public keys (over MQTT topic, signed with ML-DSA)
2. Laptop encapsulates a shared secret with Pi's ML-KEM public key
3. Both derive an ASCON session key from the shared secret
4. Sensor data thereafter: ASCON-encrypted + ML-DSA-signed → MQTT publish → subscriber decrypts + verifies → dashboard

## Why this exists

The PQC literature is dominated by benchmarks on x86 servers. Resource-constrained IoT is the deployment frontier: tight memory, slow MCUs, MQTT-shaped messages. Kyron shows a working PQC stack on a Raspberry Pi 4 with realistic bandwidth and latency, and gives the integration glue (key exchange protocol, MQTT framing, dashboard) that PQClean alone does not.

## Build

```bash
cd sdk
cmake -B build
cmake --build build

cd ../deployment
./scripts/provision.sh    # generate keys, install services
```

Two-device test:
```bash
cd sdk
make -f Makefile.testwrapper
./pqc_two_device_test
```

## License

MIT for the integration / deployment code in this repo.
PQClean primitives retain their original BSD / public-domain licenses (see `sdk/*/LICENSE` where applicable).

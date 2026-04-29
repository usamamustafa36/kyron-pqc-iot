# Kyron — Two-Device Deployment Plan (1 Laptop + 1 Raspberry Pi)

## 1. Goal
Run the Kyron PQC SDK across two physical machines so they communicate securely
over a real network using:
- **Kyber** → quantum-safe key exchange
- **Dilithium** → digital signatures
- **ASCON** → authenticated encryption of MQTT payloads

---

## 2. Hardware Roles

```
┌────────────────────────────────┐
│          LAPTOP                │
│  • Mosquitto broker  (1883)    │
│  • mqtt_pqc_subscriber (C)     │  ← receives + decrypts + verifies
│  • Flask dashboard   (5000)    │
│  IP: <LAPTOP_IP>               │
└──────────────┬─────────────────┘
               │ Wi-Fi LAN
               │
┌──────────────▼─────────────────┐
│         RASPBERRY PI           │
│  • mqtt_pqc_publisher (C)      │  ← signs + encrypts + publishes
│  IP: <PI_IP>                   │
└────────────────────────────────┘
```

| Machine | Role | Binary |
|---|---|---|
| Laptop | Broker + Subscriber + Dashboard | `mqtt_pqc_subscriber` |
| Raspberry Pi | Publisher ("IoT sensor") | `mqtt_pqc_publisher` |

---

## 3. Problem With Current Code

Current code exchanges the 4 key files through `/tmp/`:

```
/tmp/pub_kyber_pk.bin   ← publisher writes, subscriber reads
/tmp/pub_dil_pk.bin     ← publisher writes, subscriber reads
/tmp/sub_kyber_pk.bin   ← subscriber writes, publisher reads
/tmp/kyber_ct.bin       ← publisher writes, subscriber reads
```

This only works when both programs run on the **same** machine — they share one `/tmp/`.
On laptop + Pi, each machine has its own `/tmp/`, so the files never reach the other side.

---

## 4. Chosen Solution — MQTT Handshake Topics

Use the MQTT broker itself to exchange keys, instead of files.
Reserve four handshake topics on the broker:

| Topic | Payload | Who publishes | Who subscribes |
|---|---|---|---|
| `pqc/handshake/sub_kyber_pk` | Subscriber's Kyber public key (1184 B) | Subscriber | Publisher |
| `pqc/handshake/pub_dil_pk` | Publisher's Dilithium public key (1952 B) | Publisher | Subscriber |
| `pqc/handshake/kyber_ct` | Kyber ciphertext (1088 B) | Publisher | Subscriber |
| `sensors/temperature` | nonce(16) ‖ ASCON ciphertext (msg + sig) | Publisher | Subscriber |

All handshake topics use **QoS 1 + retain=true** so order of startup doesn't matter.

### Handshake sequence

```
Subscriber (Laptop)                    Publisher (Pi)
───────────────────                    ──────────────
1. Connect to broker
2. Kyber keygen
3. Publish sub_kyber_pk  (retained) ─►
4. Subscribe pub_dil_pk, kyber_ct
                                       1. Connect to broker
                                       2. Kyber + Dilithium keygen
                                       3. Subscribe sub_kyber_pk
                                    ◄─ 4. Receive sub_kyber_pk
                                       5. Kyber encapsulate → session key
                                       6. Publish pub_dil_pk  (retained) ─►
                                       7. Publish kyber_ct    (retained) ─►
5. Receive pub_dil_pk  ◄──────────────
6. Receive kyber_ct    ◄──────────────
7. Kyber decapsulate → same session key
8. Signal: session ready
                                       8. Start publishing sensors/temperature
9. Decrypt + Dilithium-verify each msg ◄─
```

After step 7, both sides hold the **same 32-byte ASCON key** without ever putting it on the wire.

---

## 5. Folder Layout

```
two_device_deployment/
├── PLAN.md                        ← this file
├── README.md                      ← quick-start guide (written after code)
├── src/
│   ├── mqtt_pqc_client.c          ← modified: adds handshake over MQTT
│   ├── mqtt_pqc_client.h          ← modified: new handshake API
│   ├── mqtt_pqc_publisher.c       ← rewritten: no /tmp/ files, uses MQTT handshake
│   ├── mqtt_pqc_subscriber.c      ← rewritten: no /tmp/ files, uses MQTT handshake
│   └── CMakeLists.txt             ← copy of original, adjusted paths if needed
├── config/
│   └── mosquitto.conf             ← broker config for the laptop
└── scripts/
    ├── build_laptop.sh            ← builds subscriber on laptop
    ├── build_pi.sh                ← copy-to-Pi + build there
    ├── run_broker.sh              ← starts mosquitto on laptop
    ├── run_subscriber.sh          ← starts subscriber on laptop
    └── run_publisher.sh           ← starts publisher on Pi
```

The three SDK libraries (`libkyber.a`, `libascon.a`, `libdilithium.a`) are **reused as-is**
from `implementation1/implementation/`. Nothing inside the SDKs changes.
On the Pi, they must be **rebuilt natively** (ARM) from the SDK source folders.

---

## 6. Step-by-Step Plan

### Phase 1 — Code changes (done on laptop, no hardware yet)
1. Copy `mqtt_pqc_client.c/.h`, publisher, subscriber, `CMakeLists.txt` into `two_device_deployment/src/`
2. In `mqtt_pqc_client.h` add new API:
   - `mqtt_pqc_handshake_publisher(ctx)` — does steps 2–7 on publisher side
   - `mqtt_pqc_handshake_subscriber(ctx)` — does steps 3–7 on subscriber side
3. In `mqtt_pqc_client.c` implement those:
   - Use `mosquitto_publish(..., qos=1, retain=true)` for handshake topics
   - Use `mosquitto_subscribe` + a synchronous wait loop (`mosquitto_loop` with timeout) until all expected handshake messages arrive
   - Copy received bytes directly into `ctx->session.*` fields (no disk I/O)
4. Rewrite `mqtt_pqc_publisher.c`: remove all `/tmp/*.bin` `fopen` code, replace with `mqtt_pqc_handshake_publisher()`
5. Rewrite `mqtt_pqc_subscriber.c`: same — remove `/tmp/*.bin`, call `mqtt_pqc_handshake_subscriber()`
6. Make broker host + port configurable via `argv[1]` / `argv[2]` or env vars
   (so we don't recompile to change IPs)
7. Build locally on laptop, test with both binaries on the **laptop** first
   (broker on laptop, subscriber on laptop, publisher on laptop pointed at `127.0.0.1`)

### Phase 2 — Laptop setup (broker + dashboard host)
1. `sudo apt install mosquitto mosquitto-clients libmosquitto-dev`
2. Drop `config/mosquitto.conf` into `/etc/mosquitto/conf.d/kyron.conf`
   - listener 1883 on `0.0.0.0`
   - `allow_anonymous true` (LAN-only demo; TLS/auth left as future work)
3. `sudo systemctl restart mosquitto`
4. Verify: `mosquitto_sub -h <LAPTOP_IP> -t test` from another terminal, then `mosquitto_pub` to it
5. Find laptop IP: `ip -4 addr show | grep inet` → note as `<LAPTOP_IP>`
6. Allow port 1883 through the firewall if one is active (`sudo ufw allow 1883`)

### Phase 3 — Raspberry Pi setup (publisher)
1. Flash Raspberry Pi OS (64-bit Lite), enable SSH + Wi-Fi in imager
2. `sudo apt update && sudo apt install git build-essential cmake libmosquitto-dev`
3. Confirm Pi is on the **same LAN** as the laptop: `ping <LAPTOP_IP>`
4. `scp -r two_device_deployment pi@<PI_IP>:~/` to copy code
5. Also scp `implementation1/implementation/kyber_sdk`, `ascon_sdk`, `dilithium_sdk`
6. On the Pi, build each SDK natively (`make` in each SDK folder) → produces ARM `.a` files
7. On the Pi, `cmake` + `make` in `two_device_deployment/src/build/` → builds `mqtt_pqc_publisher`

### Phase 4 — End-to-end run
1. **Terminal 1 (laptop):** `./run_broker.sh` — starts mosquitto
2. **Terminal 2 (laptop):** `./run_subscriber.sh 127.0.0.1 1883`
3. **Terminal 3 (Pi over SSH):** `./run_publisher.sh <LAPTOP_IP> 1883`
4. Expected output:
   - Pi: "Kyber + Dilithium keys generated", "Session ready", "Published N encrypted bytes"
   - Laptop: "Session accepted", "Signature OK", "Decrypted payload: {..temp..}"
5. Kill publisher (Ctrl+C), restart — verify fresh handshake works every run

### Phase 5 — Dashboard wire-up (optional, later)
- Flask app on laptop subscribes to `sensors/temperature` + handshake topics
- Displays live plaintext (after decrypt), verification status, handshake events
- Logs per-message timing for the benchmarking chapter of the report

---

## 7. Acceptance Criteria

- [ ] Publisher binary runs on Pi (ARM), subscriber binary runs on laptop (x86_64)
- [ ] No file in `/tmp/` is read or written by either binary
- [ ] Kyber shared secret is established in under 2 seconds from start
- [ ] At least 10 consecutive signed + encrypted messages delivered with "Signature OK"
- [ ] Dropping the Pi's Wi-Fi and reconnecting restarts handshake cleanly
- [ ] Broker host/port are set via CLI args, no recompilation to change IPs

---

## 8. Risks / Things to Watch

1. **SDK is x86-compiled.** The `.a` files in `implementation1/implementation/*_sdk/`
   are built for laptop CPU. They **will not** link on ARM. We must rebuild from source on the Pi.
2. **Retained handshake messages persist on the broker.** If a test leaves stale
   retained keys, a future run might accept them. Clear with
   `mosquitto_pub -h <broker> -t 'pqc/handshake/+' -r -n` between runs.
3. **Static buffers sized for Kyber-768 / Dilithium3.** Don't switch security levels
   without updating `KYBER_*_BYTES` and `DILITHIUM_*_BYTES` in `mqtt_pqc_client.h`.
4. **Firewall on laptop.** Pi can't reach broker if `ufw`/Windows Defender blocks 1883.
5. **No TLS in this phase.** Traffic *payload* is PQC-encrypted, but MQTT metadata
   (topic names, QoS, timing) is in the clear. Fine for demo, note it in the report.

---

## 9. What We Keep Untouched

- The three SDK folders (`kyber_sdk/`, `dilithium_sdk/`, `ascon_sdk/`) — pure reuse
- `pqc_test_wrapper.c/.h` — the unified SDK API, unchanged
- Original `CMakeLists.txt` structure (we only tweak paths)

Everything new lives inside `two_device_deployment/`.

---

## 10. Next Action

Review this plan. If approved, I'll start with **Phase 1, step 1–6** (code changes) —
all on the laptop, no hardware needed yet. Hardware comes in Phase 2.

# Self-Healing IoT Network: Automated Quarantine, Broker-Mediated Rerouting, and Tamper-Evident Logging

**UFCE8A-30-3 Cyber Applied Project**
**University of the West of England, Bristol**

---

## Overview

This repository contains the full implementation of a lightweight, broker-mediated self-healing IoT security architecture. The system monitors ESP32 node behaviour in real time, automatically isolates compromised nodes via MQTT-layer quarantine, reroutes traffic through unaffected nodes, and records all security-relevant events in a tamper-evident hash-chained log.

The architecture is evaluated against simulated application-layer availability attacks in a controlled five-node testbed, achieving a mean detection-to-containment latency of 10.8 seconds with quarantine enforced within ≤2 seconds in every run.

---

## Repository Structure

```
behaviour_engine.py       Central detection, quarantine, and logging engine
verify_chain.py           Standalone hash-chain integrity verifier
main.cpp                  ESP32 node firmware
Examples/
  example_log.jsonl      Example log demonstrating a full quarantine event
.gitignore
README.md
```

---

## System Requirements

### Raspberry Pi 5 (Control Node)

- Raspberry Pi OS (64-bit)
- Python 3.10 or later
- Mosquitto MQTT Broker 2.0 or later

Install Python dependencies:

```bash
pip install paho-mqtt flask
```

### ESP32 Nodes

- PlatformIO or Arduino IDE
- Required libraries: `PubSubClient`, `Adafruit BME280`, `Adafruit BMP280`, `BH1750`, `Adafruit VL53L0X`

---

## Setup

### 1. Network Configuration

The system is designed around a dedicated IoT access point hosted by the Raspberry Pi, with a static IP address of `10.42.0.1`. This can be configured using NetworkManager:

```bash
nmcli device wifi hotspot ifname wlan0 ssid IoT password yourpassword
```

All ESP32 nodes must connect to this network. Before flashing the firmware, update the following constants in `main.cpp` to match your access point:

```cpp
static const char* WIFI_SSID = "IoT";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
```

### 2. Mosquitto Broker Setup

Install Mosquitto on the Raspberry Pi:

```bash
sudo apt install mosquitto mosquitto-clients
```

Edit `/etc/mosquitto/mosquitto.conf` to enable authentication:

```
listener 1883
allow_anonymous false
password_file /etc/mosquitto/passwd
```

Create credentials for each node and for the behaviour engine:

```bash
sudo mosquitto_passwd -c /etc/mosquitto/passwd node1
sudo mosquitto_passwd    /etc/mosquitto/passwd node2
sudo mosquitto_passwd    /etc/mosquitto/passwd node3
sudo mosquitto_passwd    /etc/mosquitto/passwd node4
sudo mosquitto_passwd    /etc/mosquitto/passwd node5
sudo mosquitto_passwd    /etc/mosquitto/passwd engine
```

Restart the broker to apply changes:

```bash
sudo systemctl restart mosquitto
sudo systemctl enable mosquitto
```

### 3. ESP32 Node Provisioning

Each node uses the same firmware binary. Identity and credentials are stored in NVS (non-volatile storage) and provisioned individually over serial on first boot.

1. Flash `main.cpp` to each ESP32 using PlatformIO or Arduino IDE
2. Open a serial monitor at **115200 baud**
3. On first boot the node will print:
   ```
   Not provisioned. Type P within 10 seconds.
   ```
4. Type `P` and press Enter
5. Enter the node ID (`node1` through `node5`), MQTT username, and MQTT password when prompted
6. The node saves credentials to flash and reboots automatically

Credentials persist across reboots and power cycles. Re-provisioning is only required if credentials change.

### 4. Running the Behaviour Engine

Start the engine on the Raspberry Pi:

```bash
python behaviour_engine.py
```

You will be prompted for MQTT credentials. Use the `engine` account created in step 2.

To pass credentials via environment variables and skip the prompt:

```bash
export MQTT_USER=engine
export MQTT_PASS=yourpassword
python behaviour_engine.py --no-prompt
```

To start with the live monitoring dashboard:

```bash
python behaviour_engine.py --dashboard
```

Open `http://127.0.0.1:8000` in a browser to view node states, risk scores, and a live event stream. Once running, the engine discovers nodes automatically as they connect and begins scoring their behaviour against the weighted indicator model.

---

## Verifying Log Integrity

The behaviour engine writes all security events to a hash-chained log file. To verify the integrity of the chain:

```bash
python verify_chain.py behaviour_engine_chain.jsonl
```

To test against the included example log:

```bash
python verify_chain.py examples/sample_chain.jsonl
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Chain intact — no violations detected |
| `1` | Tampering detected — violations reported |
| `2` | Usage error |

---

## Configuration

All detection thresholds and timing parameters can be overridden at runtime using environment variables, allowing the system to be reconfigured without modifying source code.

| Variable | Default | Description |
|---|---|---|
| `MQTT_HOST` | `10.42.0.1` | Broker IP address |
| `THRESH_SUSPECT` | `5` | Risk score required to enter SUSPECT state |
| `THRESH_QUARANTINE` | `8` | Risk score required to trigger quarantine |
| `QUARANTINE_TIME` | `30` | Duration of quarantine in seconds |
| `RECOVERY_TIME` | `10` | Minimum time in RECOVERING state before reintegration |
| `ROLLING_WINDOW` | `10` | Observation window for rate-based indicators (seconds) |
| `OFFLINE_AFTER_S` | `15` | Silence duration before a node is marked offline |
| `EXPECTED_NODES` | ` ` | Comma-separated list of node IDs to pre-register |
| `PRINT_EVERY_TICK` | `0` | Set to `1` to print node state on every engine tick |

---

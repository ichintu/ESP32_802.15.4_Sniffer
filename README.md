# ESP32_802.15.4_Sniffer

---

# ESP32-C5/6 802.15.4 + BLE High-Speed Sniffer

A high-performance **IEEE 802.15.4 packet sniffer** using **ESP32-C6** with **Wireshark PCAP output** support.

This project uses:

* **ESP32-C6** (Arduino / ESP-IDF radio driver)
* **High-speed serial streaming (2 Mbps)**
* **Python helper (`sniffer.py`)**
* **Wireshark-compatible PCAP output**
* **Channel hopping support**
* **RSSI + LQI metadata**
* **Robust host disconnect recovery**

---

# Features

* High-speed packet capture
* 2.4 GHz IEEE 802.15.4 support
* BLE advertisement/beacon dump mode
* Channel hopping mode
* Wireshark live capture support
* RSSI + LQI metadata (via TAP header)
* Robust host disconnect handling (no reset required)
* Low packet loss ring-buffer architecture
* Cross-platform (Linux / macOS / Windows)

---

# Hardware Requirements

* ESP32-C6 board
  Tested with:

  * ESP32-C6 DevKit
  * ESP32-C6 Mini boards

---

# Software Requirements

### Python

* Python 3.8+
* pyserial

Install:

```bash
pip install pyserial
```

### Wireshark (optional but recommended)

Download:

[https://www.wireshark.org/](https://www.wireshark.org/)

---

# Files

```
esp32c6_sniffer.ino     # ESP32 firmware
sniffer.py              # Python capture helper
README.md               # This file
```

---

# Architecture

```
ESP32-C6 Radio
     │
     │ 802.15.4 packets
     ▼
ESP32 Firmware
     │
     │ High-speed serial (2 Mbps)
     ▼
sniffer.py
     │
     │ PCAP stream
     ▼
Wireshark / File
```

---

# Flashing the ESP32-C6

Open:

```
esp32c6_sniffer.ino
```

In Arduino IDE:

* Board: **ESP32-C6**
* Upload Speed: **921600 (recommended)**
* Flash

---

# Usage

## Basic Capture

```bash
python sniffer.py -p /dev/ttyACM0
```

Windows:

```bash
python sniffer.py -p COM5
```

---

## Capture Specific Channel

```bash
python sniffer.py -p /dev/ttyACM0 -c 15
```

---

## Channel Hopping

```bash
python sniffer.py -p /dev/ttyACM0 --hop
```

---

## Write to PCAP file

```bash
python sniffer.py -p /dev/ttyACM0 -w capture.pcap
```

---

## BLE Advertisement / Beacon Dump

```bash
python sniffer.py -p /dev/ttyACM0 --ble
```

Default mode remains Zigbee / IEEE 802.15.4 (`--zbee`).

---

## Live Wireshark Capture

Linux/macOS:

```bash
python sniffer.py -p /dev/ttyACM0 | wireshark -k -i -
```

Windows:

```bash
python sniffer.py -p COM5 | Wireshark.exe -k -i -
```

---

# Command Line Options

| Option   | Description                           |
| -------- | ------------------------------------- |
| `-p`     | Serial port                           |
| `-c`     | Fixed channel                         |
| `--hop`  | Channel hopping                       |
| `-w`     | Write PCAP file                       |
| `--zbee` | Zigbee / IEEE 802.15.4 mode (default) |
| `--ble`  | BLE advertisement / beacon dump mode  |

---

# Serial Protocol

### Host → ESP32

```
PING
START:C=<channel>,H=<0|1>,M=<ZBEE|BLE>
STOP
```

### ESP32 → Host

```
PONG:ESP32C6_SNIFFER
ACK:START
```

---

# Packet Format

Binary packet format:

```
Magic      0xAA55AA55
Length     1 byte
Channel    1 byte
RSSI       int8
LQI        uint8
Payload    N bytes
```

Converted to:

```
PCAP + IEEE 802.15.4 TAP header
```

---

# Performance

Typical performance:

| Metric          | Value    |
| --------------- | -------- |
| Serial Speed    | 2 Mbps   |
| Max Packets/sec | ~4000    |
| Packet Loss     | Very Low |
| Latency         | ~1-3 ms  |

---

# Improvements in This Version

* Fixed host disconnect requiring reset
* Auto-stop when host disconnects
* Improved ring buffer performance
* Static TX buffer (faster)
* Better Python cleanup
* Reduced flush overhead
* Robust handshake

---

# Troubleshooting

### No packets

Check:

* Correct channel
* Antenna connected
* 802.15.4 traffic exists

---

### Permission error (Linux)

```bash
sudo usermod -a -G dialout $USER
```

Log out/in.

---

### Serial busy

Kill previous process:

```bash
lsof /dev/ttyACM0
```

---

# Tested With

* Zigbee devices
* Thread networks
* Matter devices
* 802.15.4 dev kits

---

# Roadmap

Future improvements:

* Timestamp from ESP32 hardware
* Wireshark extcap plugin
* BLE coexistence support
* Web UI
* PCAP-NG support

---

# License

MIT License

---

# Credits

Inspired by:

* Nordic nRF Sniffer
* KillerBee
* Wireshark IEEE 802.15.4 tools

---

# Contributing

Pull requests welcome.

Please include:

* Description
* Hardware used
* Test results

---

# Author

ESP32-C6 802.15.4 Sniffer
High-Speed Packet Capture Project

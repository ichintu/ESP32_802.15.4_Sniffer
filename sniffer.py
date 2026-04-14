import serial
import struct
import time
import sys
import argparse

PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAJOR = 2
PCAP_MINOR = 4
PCAP_SNAPLEN = 65535
DLT_IEEE802_15_4_TAP = 283
DLT_BLUETOOTH_LE_LL = 251

BLE_ADV_PDU_TYPES = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXT_IND",
}

def log_info(message):
    sys.stderr.write(message + "\n")
    sys.stderr.flush()

def log_status(message):
    sys.stderr.write("\r\033[K" + message)
    sys.stderr.flush()

def build_pcap_global_header(linktype):
    return struct.pack('<IHHIIII', PCAP_MAGIC, PCAP_MAJOR, PCAP_MINOR, 0, 0, PCAP_SNAPLEN, linktype)

def build_tap_header(channel, rssi, lqi):
    # TLV 0 — FCS present (1 byte)
    tlv_fcs = struct.pack('<HHBxxx', 0, 1, 1)

    # TLV 3 — Channel assignment (channel number + page)
    # page 0 for 2.4 GHz 802.15.4
    tlv_chan = struct.pack('<HHBBxx', 3, 2, channel, 0)

    # TLV 1 — RSSI (float dBm)
    tlv_rssi = struct.pack('<HHf', 1, 4, float(rssi))

    # TLV 10 — LQI (uint8)
    tlv_lqi = struct.pack('<HHBxxx', 10, 1, lqi)

    tlvs = tlv_fcs + tlv_chan + tlv_rssi + tlv_lqi

    return struct.pack('<BBH', 0, 0, 4 + len(tlvs)) + tlvs

def build_pcap_packet(tap_header, payload):
    ts_sec = int(time.time())
    ts_usec = int((time.time() - ts_sec) * 1000000)
    incl_len = len(tap_header) + len(payload)
    return struct.pack('<IIII', ts_sec, ts_usec, incl_len, incl_len) + tap_header + payload

def build_pcap_packet_raw(payload):
    ts_sec = int(time.time())
    ts_usec = int((time.time() - ts_sec) * 1000000)
    incl_len = len(payload)
    return struct.pack('<IIII', ts_sec, ts_usec, incl_len, incl_len) + payload

def parse_ble_advertisement(payload):
    if len(payload) < 2:
        return None

    pdu_header = payload[0] | (payload[1] << 8)
    pdu_type = pdu_header & 0x0F
    pdu_len = (pdu_header >> 8) & 0x3F
    if pdu_len == 0:
        return None

    body_end = 2 + pdu_len
    if body_end > len(payload):
        return None

    pdu_name = BLE_ADV_PDU_TYPES.get(pdu_type, f"UNKNOWN(0x{pdu_type:02x})")
    body = payload[2:body_end]

    advertiser = None
    ad_structures = b""

    if pdu_type in (0x00, 0x02, 0x04, 0x06) and len(body) >= 6:
        advertiser = ":".join(f"{b:02X}" for b in body[5::-1])
        ad_structures = body[6:]
    elif pdu_type == 0x01 and len(body) >= 12:
        advertiser = ":".join(f"{b:02X}" for b in body[5::-1])
        ad_structures = body[12:]
    elif pdu_type in (0x03, 0x05) and len(body) >= 12:
        advertiser = ":".join(f"{b:02X}" for b in body[11:5:-1])
        ad_structures = body[12:]

    beacon_tag = None
    idx = 0
    while idx < len(ad_structures):
        ad_len = ad_structures[idx]
        if ad_len == 0:
            break
        next_idx = idx + 1 + ad_len
        if next_idx > len(ad_structures):
            break
        ad_type = ad_structures[idx + 1]
        ad_data = ad_structures[idx + 2:next_idx]

        if ad_type == 0xFF and len(ad_data) >= 4:
            if ad_data[0:4] == b"\x4c\x00\x02\x15":
                beacon_tag = "iBeacon"
                break
        elif ad_type == 0x16 and len(ad_data) >= 2:
            if ad_data[0:2] in (b"\xAA\xFE", b"\xFE\xAA"):
                beacon_tag = "Eddystone"
                break

        idx = next_idx

    return {
        "pdu_name": pdu_name,
        "advertiser": advertiser,
        "beacon_tag": beacon_tag,
        "pdu_len": pdu_len,
    }

def perform_handshake(ser, channel, is_hopping, mode):
    log_info("[*] Initiating handshake with ESP32-C6...")
    
    # CRITICAL FIX: Aggressively silence the board from previous runs
    # If the board is already sending binary, we must break its loop first
    for _ in range(3):
        ser.write(b"\nSTOP\n")
        time.sleep(0.1)
    
    ser.reset_input_buffer()
    
    # Now ask for PING
    ser.write(b"PING\n")
    start_time = time.time()
    ping_ok = False
    
    while time.time() - start_time < 2.0:
        try:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if "PONG:ESP32C6_SNIFFER" in line:
                ping_ok = True
                break
        except:
            pass
            
    if not ping_ok:
        log_info("[!] ERROR: Handshake failed. Did not receive PONG.")
        sys.exit(1)
        
    hop_val = 1 if is_hopping else 0
    ch_val = channel if channel else 11
    ser.write(f"START:C={ch_val},H={hop_val},M={mode}\n".encode('utf-8'))
    
    config_ok = False
    start_time = time.time()
    while time.time() - start_time < 2.0:
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line.startswith("ACK:START"):
            log_info(f"[*] Handshake Successful! Board Confirmed: {line}")
            config_ok = True
            break
            
    if not config_ok:
        log_info("[!] ERROR: Board did not acknowledge configuration.")
        sys.exit(1)
        
    ser.reset_input_buffer()

def safe_stop(ser):
    try:
        if ser and ser.is_open:
            ser.write(b"\nSTOP\n")
            ser.flush()
            time.sleep(0.2)
            ser.reset_input_buffer()
            ser.reset_output_buffer()
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="ESP32-C6 Sniffer (802.15.4 / BLE)")
    parser.add_argument('-p', '--port', required=True)
    parser.add_argument('-c', '--channel', type=int)
    parser.add_argument('--hop', action='store_true')
    parser.add_argument('-w', '--write')
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--zbee', action='store_true', help='Capture IEEE 802.15.4 packets (default)')
    mode_group.add_argument('--ble', action='store_true', help='Capture BLE advertisements/beacons')
    args = parser.parse_args()
    is_ble_mode = args.ble
    capture_mode = "BLE" if is_ble_mode else "ZBEE"

    ser = None
    out_file = None

    try:
        ser = serial.Serial()
        ser.port = args.port
        ser.baudrate = 2000000
        ser.timeout = 0.1
        ser.write_timeout = 0.5
        ser.dtr = False
        ser.rts = False
        ser.open()

        # Avoid forcing odd modem-line states unless you truly need them.
        # On many boards this is harmless, on some it contributes to reset weirdness.
        time.sleep(0.3)

        perform_handshake(ser, args.channel, args.hop, capture_mode)

        if args.write:
            out_file = open(args.write, 'wb')
        else:
            if sys.platform == "win32":
                import os, msvcrt
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            out_file = sys.stdout.buffer

        linktype = DLT_BLUETOOTH_LE_LL if is_ble_mode else DLT_IEEE802_15_4_TAP
        out_file.write(build_pcap_global_header(linktype))
        out_file.flush()

        packet_count = 0
        last_packet_time = time.time()
        if is_ble_mode:
            log_info("\n[*] Listening for BLE advertisements/beacons...")
        else:
            log_info("\n[*] Listening for 802.15.4 packets...")

        buffer = bytearray()

        while True:
            chunk = ser.read(max(1, ser.in_waiting))
            if chunk:
                buffer.extend(chunk)
            elif time.time() - last_packet_time > 2.0:
                log_status("[!] No packets received in 2 seconds. (Quiet airwaves or wrong channel?)")

            while len(buffer) >= 8:
                if buffer[0:4] != b'\xAA\x55\xAA\x55':
                    del buffer[0:1]
                    continue

                length, channel, rssi, lqi = struct.unpack('<BBbB', buffer[4:8])

                if length > 127:
                    del buffer[0:1]
                    continue

                total_len = 8 + length
                if len(buffer) < total_len:
                    break

                payload = buffer[8:total_len]
                if is_ble_mode:
                    pcap_pkt = build_pcap_packet_raw(payload)
                else:
                    tap_hdr = build_tap_header(channel, rssi, lqi)
                    pcap_pkt = build_pcap_packet(tap_hdr, payload)

                out_file.write(pcap_pkt)
                out_file.flush()

                del buffer[:total_len]
                packet_count += 1
                last_packet_time = time.time()
                if is_ble_mode:
                    ble_info = parse_ble_advertisement(payload)
                    if ble_info:
                        beacon_suffix = f" | {ble_info['beacon_tag']}" if ble_info["beacon_tag"] else ""
                        adv_addr = ble_info["advertiser"] if ble_info["advertiser"] else "N/A"
                        log_status(
                            f"[*] Captured: {packet_count} | Last BLE: Ch {channel} | "
                            f"RSSI: {rssi:3d} dBm | PDU: {ble_info['pdu_name']} | "
                            f"AdvA: {adv_addr}{beacon_suffix} | Len: {ble_info['pdu_len']:3d}"
                        )
                    else:
                        log_status(
                            f"[*] Captured: {packet_count} | Last BLE: Ch {channel} | "
                            f"RSSI: {rssi:3d} dBm | Len: {length:3d}"
                        )
                else:
                    log_status(
                        f"[*] Captured: {packet_count} | Last Pkt: Ch {channel} | "
                        f"RSSI: {rssi:3d} dBm | LQI: {lqi:3d} | Len: {length:3d}"
                    )

    except (KeyboardInterrupt, BrokenPipeError):
        log_info("\n\n[*] Capture stopped by user.")
    except serial.SerialException as e:
        log_info(f"\n[!] Serial error: {e}")
    finally:
        log_info("[*] Stopping sniffer and closing port...")
        safe_stop(ser)

        try:
            if out_file and args.write:
                out_file.close()
        except Exception:
            pass

        try:
            if ser and ser.is_open:
                ser.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()

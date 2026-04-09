#include <Arduino.h>
#include "esp_system.h"
#include "esp_ieee802154.h"

#define MAX_FRAME_LEN 127
#define MAX_PSDU_NOFCS (MAX_FRAME_LEN - 2)
#define RING_BUF_SIZE 128

typedef struct {
    uint8_t length;   // on-air frame length including the 2-byte FCS
    uint8_t channel;  // actual RX channel reported by the driver
    int8_t rssi;
    uint8_t lqi;
    uint8_t data[MAX_FRAME_LEN]; // PSDU + reconstructed FCS
} sniffer_packet_t;

volatile sniffer_packet_t rx_ring[RING_BUF_SIZE];
volatile uint16_t rx_head = 0;
volatile uint16_t rx_tail = 0;

volatile uint8_t current_channel = 11;
volatile bool is_hopping = false;
volatile bool sniffer_active = false;
volatile bool radio_started = false;
volatile bool hop_requested = false;
volatile uint8_t requested_channel = 11;
volatile uint32_t dropped_packets = 0;

unsigned long last_hop_time = 0;
const unsigned long HOP_INTERVAL_MS = 100;

char cmd_buf[64];
int cmd_idx = 0;

static inline void flush_ring() {
    noInterrupts();
    rx_head = 0;
    rx_tail = 0;
    interrupts();
}

static inline void stop_rx() {
    esp_ieee802154_sleep();
    radio_started = false;
}

static inline void start_rx_on_channel(uint8_t ch) {
    stop_rx();
    delayMicroseconds(200);
    esp_ieee802154_set_channel(ch);
    current_channel = ch;
    esp_ieee802154_receive();
    radio_started = true;
}

static uint16_t ieee802154_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0x0000;
    while (len--) {
        crc ^= *data++;
        for (int i = 0; i < 8; ++i) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

extern "C" void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
    if (sniffer_active && frame != nullptr && frame_info != nullptr) {
        uint8_t wire_len = frame[0];
        if (wire_len < 2) {
            wire_len = 2;
        }
        if (wire_len > MAX_FRAME_LEN) {
            wire_len = MAX_FRAME_LEN;
        }

        // On ESP32-C6 RX, the original on-air FCS bytes are not delivered.
        // Reconstruct them so the host can keep advertising "FCS present".
        const uint8_t psdu_len = wire_len - 2;

        uint16_t head = rx_head;
        uint16_t next_head = (head + 1) % RING_BUF_SIZE;

        if (next_head != rx_tail) {
            rx_ring[head].length = wire_len;
            rx_ring[head].channel = frame_info->channel;
            rx_ring[head].rssi = frame_info->rssi;
            rx_ring[head].lqi = frame_info->lqi;

            if (psdu_len > 0) {
                memcpy((void *)rx_ring[head].data, &frame[1], psdu_len);
            }

            const uint16_t fcs = ieee802154_crc16(&frame[1], psdu_len);
            rx_ring[head].data[psdu_len + 0] = (uint8_t)(fcs & 0xFF);
            rx_ring[head].data[psdu_len + 1] = (uint8_t)((fcs >> 8) & 0xFF);

            rx_head = next_head;
        } else {
            dropped_packets++;
        }
    }

    if (frame != nullptr) {
        esp_ieee802154_receive_handle_done(frame);
    }

    // Important: do NOT manually call esp_ieee802154_receive() here for normal sniffing.
    // Keep RX on continuously via rx_when_idle=true. This avoids the "one packet then stall"
    // behavior seen on some ESP32-C6 802.15.4 driver builds when re-arming in the callback.
}

extern "C" void IRAM_ATTR esp_ieee802154_receive_failed(uint16_t error) {
    (void)error;
    // Leave the radio in RX-on-when-idle mode. No manual re-arm here.
}

void process_serial_commands() {
    while (Serial.available() > 0) {
        int v = Serial.read();
        if (v < 0) break;
        char c = (char)v;

        if (c == '\n') {
            cmd_buf[cmd_idx] = '\0';
            cmd_idx = 0;

            if (strcmp(cmd_buf, "STOP") == 0) {
                sniffer_active = false;
                is_hopping = false;
                hop_requested = false;
                stop_rx();
                flush_ring();
                Serial.println("ACK:STOP");
                Serial.flush();
            } else if (strcmp(cmd_buf, "PING") == 0) {
                Serial.println("PONG:ESP32C6_SNIFFER_V6");
            } else {
                int ch = 11;
                int h = 0;
                if (sscanf(cmd_buf, "START:C=%d,H=%d", &ch, &h) == 2) {
                    if (ch < 11 || ch > 26) ch = 11;

                    sniffer_active = false;
                    is_hopping = false;
                    hop_requested = false;
                    stop_rx();
                    flush_ring();

                    requested_channel = (uint8_t)ch;
                    current_channel = requested_channel;
                    is_hopping = (h == 1);
                    sniffer_active = true;
                    start_rx_on_channel(requested_channel);
                    last_hop_time = millis();

                    Serial.printf("ACK:START,C=%d,H=%d\n", requested_channel, is_hopping ? 1 : 0);
                }
            }
        } else if (c != '\r') {
            if (cmd_idx < (int)sizeof(cmd_buf) - 1) {
                cmd_buf[cmd_idx++] = c;
            } else {
                cmd_idx = 0;
            }
        }
    }
}

void handle_channel_hopping() {
    if (!sniffer_active || !is_hopping) return;

    unsigned long now = millis();
    if ((now - last_hop_time) >= HOP_INTERVAL_MS) {
        uint8_t next = current_channel + 1;
        if (next > 26) next = 11;

        hop_requested = true;
        start_rx_on_channel(next);
        hop_requested = false;
        last_hop_time = now;
    }
}

void drain_packets_to_serial() {
    while (sniffer_active && rx_head != rx_tail) {
        uint16_t tail = rx_tail;
        uint8_t len = rx_ring[tail].length;
        uint16_t total_len = 8 + len;

        if (!Serial || Serial.availableForWrite() < total_len) {
            return;
        }

        uint8_t out_buf[8 + MAX_FRAME_LEN];
        out_buf[0] = 0xAA;
        out_buf[1] = 0x55;
        out_buf[2] = 0xAA;
        out_buf[3] = 0x55;
        out_buf[4] = len;
        out_buf[5] = rx_ring[tail].channel;
        out_buf[6] = (uint8_t)rx_ring[tail].rssi;
        out_buf[7] = rx_ring[tail].lqi;
        if (len > 0) {
            memcpy(&out_buf[8], (const void *)rx_ring[tail].data, len);
        }

        size_t written = Serial.write(out_buf, total_len);
        if (written != total_len) {
            return;
        }

        rx_tail = (tail + 1) % RING_BUF_SIZE;
    }
}

void setup() {
    Serial.begin(2000000);
    Serial.setTxTimeoutMs(0);

    esp_ieee802154_enable();
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_rx_when_idle(true);
    esp_ieee802154_set_coordinator(false);
    esp_ieee802154_set_pending_mode(ESP_IEEE802154_AUTO_PENDING_DISABLE);

    stop_rx();
    flush_ring();
}

void loop() {
    process_serial_commands();
    handle_channel_hopping();
    drain_packets_to_serial();
}

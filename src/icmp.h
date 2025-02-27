#pragma once

#include <stddef.h>
#include <unistd.h>

void init_packet_data(uint8_t *packet, size_t payload_size, const uint8_t *pattern, uint8_t pattern_len);
uint16_t icmp_checksum(const uint8_t *packet, size_t packet_size);
bool has_our_payload(const uint8_t *payload, size_t payload_len, const uint8_t *pattern, uint8_t pattern_len);

static inline uint16_t packet_id(void) {
    return (uint16_t)(getpid() & 0xFFFF);
}

void debug_packet(const uint8_t *packet, size_t packet_size);
void debug_error_packet(const uint8_t *packet, size_t packet_size);
const char *icmp_type_str(int type);
const char *icmp_code_str(int type, int code);

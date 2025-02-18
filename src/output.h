#pragma once

#include <arpa/inet.h>

#include "context.h"
#include "statistics.h"

struct LogOptions {
    bool no_reverse_dns_resolution;
    bool print_timestamps;
};

struct ErrorDetails {
    struct sockaddr *hop_addr;
    ssize_t received_bytes;
    uint64_t sequence;
};

struct LogDetails {
    ssize_t received_bytes;
    const char *peer_hostname;
    const char *peer_ip_str;
    uint64_t sequence;
    uint8_t ttl;
    double rtt;
    ssize_t size_mismatch;
};

#define ICMP_CODE_STR_BUFFER_SIZE 100

/**
 * Get an ASCII representation of the IP address of a peer.
 *
 * @param[in] address Pointer to the peer's socket address
 *
 * @return ASCII representation of the peer's IP address
 */
static inline const char *address_to_ip_str(struct sockaddr *address) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)address)->sin_addr, ip_str, sizeof(ip_str));
    return (const char *)strdup(ip_str);
}

void print_ping_header(const struct Context *ctx);
void print_statistics(const char *peer_hostname, const struct Statistics *stats);

void log_received_msg(const struct LogOptions *log_opts, const struct LogDetails *log_details);

void log_packet_too_short(uint32_t from_ip, ssize_t received_bytes);

void log_checksum_mismatch(const struct LogOptions *log_opts, const struct ErrorDetails *error_details);
void log_time_exceeded(const struct LogOptions *log_opts, const struct ErrorDetails *error_details);
void log_destination_unreachable(const struct LogOptions *log_opts, const struct ErrorDetails *error_details, uint8_t code);
void log_redirect(const struct LogOptions *log_opts, const struct ErrorDetails *error_details, uint8_t code);
void log_parameter_problem(const struct LogOptions *log_opts, const struct ErrorDetails *error_details, uint8_t code);
void log_bad_icmp_type(const struct LogOptions *log_opts, const struct ErrorDetails *error_details, uint8_t type);

void dump_headers(const uint8_t *buf);

#include <netinet/ip.h>
#include <linux/icmp.h>
#include <string.h>
#include <sys/time.h>

#include "output.h"
#include "dns.h"
#include "icmp_packet.h"

/**
 * Print ping's starting paragraph.
 *
 * @param[in] ctx Context
 */
void print_ping_header(const struct Context *ctx) {
    printf("PING %s (%s) %d(%lu) data bytes", ctx->destination->ai_canonname, ctx->peer_ip_str,
        ctx->opts.payload_size, sizeof(struct iphdr) + sizeof(struct icmphdr) + ctx->opts.payload_size
    );

    if (ctx->opts.verbose) {
        printf(", id 0x%04x = %d\n", packet_id(), packet_id());
    } else {
        printf(".\n");
    }
}

/**
 * Print ping's statistics.
 *
 * @param[in] peer_hostname Hostname of the peer
 * @param[in] stats Statistics to print
 */
void print_statistics(const char *peer_hostname, const struct Statistics *stats) {
    printf("\n--- %s ping statistics ---\n", peer_hostname);
    printf("%llu packets transmitted, %llu received",
        stats->packets_transmitted, stats->packets_received
    );

    if (stats->corrupted > 0) {
        printf(", +%llu corrupted", stats->corrupted);
    }

    if (stats->errors > 0) {
        printf(", +%llu errors", stats->errors);
    }

    if (stats->packets_received > stats->packets_transmitted) {
        printf(", -- somebody is printing forged packets!");
    } else {
        printf(", %d%% packet loss", packet_loss(stats->packets_transmitted, stats->packets_received));
    }

    printf(", time %lldms\n", stats->end_timestamp - stats->start_timestamp);

    // Don't print RTT statistics if:
    // 1. There were any errors (we simply don't print rtt stats if there were errors)
    // 2. No packets were received (no rtt stats to print)
    // 3. Received packets didn't have valid timestamps, therefore we haven't collected rtt stats
    if (stats->errors > 0 || stats->packets_received == 0 || stats->sum_of_rtt == 0) {
        return;
    }

    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
        stats->min_rtt,
        avg_rtt(stats->packets_received, stats->sum_of_rtt),
        stats->max_rtt,
        mean_deviation(stats->packets_received, stats->sum_of_squared_rtts, stats->sum_of_rtt)
    );
}

/**
 * Log received message.
 * e.g. 100 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=50.123ms
 *
 * @param[in] log_opts Log options
 * @param[in] log_details Log details
 */
void log_received_msg(
    const struct LogOptions *log_opts,
    const struct LogDetails *log_details
) {
    if (log_opts->print_timestamps) {
        struct timeval tv = {0};
        gettimeofday(&tv, NULL);
        printf("[%ld.%06ld] ", tv.tv_sec, tv.tv_usec);
    }

    printf("%lu bytes from %s", log_details->received_bytes, log_details->peer_ip_str);

    if (!log_opts->no_reverse_dns_resolution && log_details->peer_hostname != NULL) {
        printf(" (%s)", log_details->peer_hostname);
    }

    printf(": icmp_seq=%lu ttl=%d", log_details->sequence, log_details->ttl);

    if (log_details->rtt != 0) {
        printf(" time=%.3f ms", log_details->rtt);
    }

    if (log_details->size_mismatch != 0) {
        printf(" (%+ld bytes)", log_details->size_mismatch);
    }

    printf("\n");
}

/**
 * Log a packet too short message.
 *
 * @param from_ip IP address of the sender
 * @param received_bytes Bytes received
 */
inline void log_packet_too_short(
    uint32_t from_ip,
    ssize_t received_bytes
) {
    struct sockaddr_in from_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = from_ip
    };

    const char *from_ip_str = address_to_ip_str((struct sockaddr *)&from_addr);
    fprintf(stderr, "packet too short (%ld bytes) from %s\n", received_bytes, from_ip_str);
    free((void *)from_ip_str);
}

/**
 * Generic error message logger, called by specific error message log functions.
 * e.g. 100 bytes from 192.168.1.1: icmp_seq=1 Time to live exceeded
 *
 * @param[in] log_opts Log options
 * @param[in] error_details Error details
 * @param[in] msg Message to print
 */
static void log_error_message(
    const struct LogOptions *log_opts,
    const struct ErrorDetails *error_details,
    const char *msg
) {
    const char *hop_hostname = reverse_dns_lookup(error_details->hop_addr, sizeof(*error_details->hop_addr));
    const char *hop_ip_str = address_to_ip_str(error_details->hop_addr);

    if (log_opts->print_timestamps) {
        struct timeval tv = {0};
        gettimeofday(&tv, NULL);
        printf("[%ld.%06ld] ", tv.tv_sec, tv.tv_usec);
    }

    printf("%lu bytes from %s", error_details->received_bytes, hop_ip_str);

    if (!log_opts->no_reverse_dns_resolution && hop_hostname != NULL) {
        printf(" (%s)", hop_hostname);
    }

    printf(": icmp_seq=%lu %s\n", error_details->sequence, msg);

    if (hop_hostname != NULL) {
        free((void *)hop_hostname);
        hop_hostname = NULL;
    }

    if (hop_ip_str != NULL) {
        free((void *)hop_ip_str);
        hop_ip_str = NULL;
    }
}

/**
 * Log a checksum mismatch message.
 *
 * @param[in] log_opts Log options
 * @param[in] error_details Error details
 */
inline void log_checksum_mismatch(
    const struct LogOptions *log_opts,
    const struct ErrorDetails *error_details
) {
    log_error_message(log_opts, error_details, "(BAD CHECKSUM!)");
}

/**
 * Log a time exceeded message.
 *
 * @param[in] log_opts Log options
 * @param[in] error_details Error details
 */
inline void log_time_exceeded(
    const struct LogOptions *log_opts,
    const struct ErrorDetails *error_details
) {
    log_error_message(log_opts, error_details, "Time to live exceeded");
}

/**
 * Log a destination unreachable message.
 *
 * @param[in] log_opts Log options
 * @param[in] error_details Error details
 * @param code ICMP code
 */
inline void log_destination_unreachable(
    const struct LogOptions *log_opts,
    const struct ErrorDetails *error_details,
    uint8_t code
) {
    char msg[ICMP_CODE_STR_BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "Destination Unreachable: %s", icmp_code_str(ICMP_DEST_UNREACH, code));
    log_error_message(log_opts, error_details, msg);
}

/**
 * Log a redirect message.
 *
 * @param[in] log_opts Log options
 * @param[in] error_details Error details
 * @param code ICMP code
 */
inline void log_redirect(
    const struct LogOptions *log_opts,
    const struct ErrorDetails *error_details,
    uint8_t code
) {
    char msg[ICMP_CODE_STR_BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "Redirect: %s", icmp_code_str(ICMP_REDIRECT, code));
    log_error_message(log_opts, error_details, msg);
}

/**
 * Log a parameter problem message.
 *
 * @param[in] log_opts Log options
 * @param[in] error_details Error details
 * @param code ICMP code
 */
inline void log_parameter_problem(
    const struct LogOptions *log_opts,
    const struct ErrorDetails *error_details,
    uint8_t code
) {
    char msg[ICMP_CODE_STR_BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "Parameter Problem: %s", icmp_code_str(ICMP_PARAMETERPROB, code));
    log_error_message(log_opts, error_details, msg);
}

/**
 * Log bad ICMP type message.
 *
 * @param[in] log_opts Log options
 * @param[in] error_details Error details
 * @param type ICMP type
 */
inline void log_bad_icmp_type(
    const struct LogOptions *log_opts,
    const struct ErrorDetails *error_details,
    uint8_t type
) {
    char msg[ICMP_CODE_STR_BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "Bad ICMP type: %d", type);
    log_error_message(log_opts, error_details, msg);
}

/**
 * Dump IP and ICMP headers of a packet.
 *
 * @param[in] buf Buffer containing an ICMP packet
 */
void dump_headers(const uint8_t *buf) {
    struct iphdr *ip_hdr = (struct iphdr *)buf;
    struct icmphdr *icmp_hdr = (struct icmphdr *)&buf[sizeof(struct iphdr)];

    size_t hdr_len = ip_hdr->ihl << 2;

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip_str, sizeof(dst_ip_str));

    // Extract IP flags and offset
    uint16_t flags = ntohs(ip_hdr->frag_off);
    uint16_t flag_bits = (flags & 0xe000) >> 13;
    uint16_t offset = flags & IP_OFFMASK;

    printf("IP Hdr Dump:\n");
    for (size_t i = 0; i + 1 < sizeof(struct iphdr); i += 2) {
        printf(" %02x%02x", buf[i], buf[i + 1]);
    }
    printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data\n");
    printf(" %1x  %1x  %02x %04x %04x   %1x %04x  %02x  %02x %04x %s  %s\n",
        ip_hdr->version, ip_hdr->ihl, ip_hdr->tos,
        (ip_hdr->tot_len > 0x2000 ? ntohs(ip_hdr->tot_len) : ip_hdr->tot_len) , ntohs(ip_hdr->id), flag_bits,
        offset, ip_hdr->ttl, ip_hdr->protocol,
        ntohs(ip_hdr->check), src_ip_str, dst_ip_str
    );

    printf("ICMP: type %d, code %d, size %ld, id 0x%04x, seq 0x%04x\n",
        icmp_hdr->type, icmp_hdr->code, ntohs(ip_hdr->tot_len) - hdr_len,
        ntohs(icmp_hdr->un.echo.id), ntohs(icmp_hdr->un.echo.sequence)
    );
}

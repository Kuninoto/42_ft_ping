#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "network.h"
#include "icmp_packet.h"
#include "dns.h"
#include "output.h"
#include "utils.h"

/**
 * Parse the destination host and set the destination in the context.
 *
 * @param[out] ctx Context to set destination information in
 * @param[in] destination Destination host to parse (e.g. "x.com")
 *
 * @return `0` on success, `-1` on error
 */
int parse_destination(struct Context *ctx, const char *destination) {
    #ifdef DEBUG
        printf("================= Destination parsing ==================\n");
    #endif

    if (destination == NULL || strlen(destination) == 0) {
        fprintf(stderr, "ft_ping: fatal: destination required\n");
        return -1;
    }

    struct addrinfo *peer = dns_lookup(destination);
    if (peer == NULL) {
        return -1;
    }

    ctx->destination = peer;
    ctx->peer_hostname = reverse_dns_lookup(peer->ai_addr, peer->ai_addrlen);
    ctx->peer_ip_str = address_to_ip_str(peer->ai_addr);

    #ifdef DEBUG
        printf("Destination (domain name): %s\n", destination);
        printf("Hostname: %s\n", ctx->peer_hostname);
        printf("IP: %s\n", ctx->peer_ip_str);
        printf("========================================================\n");
    #endif

    return 0;
}

/**
 * Setup a Berkeley Packet Filter (BPF) to filter packets at kernel level.
 *
 * Because we're using a RAW socket, the kernel will handle a copy of each (ICMP) packet sent to the host.
 * BPF allows us to filter out packets at that level. The filter installed by this function will:
 *  - Discard ICMP_ECHO packets (ICMP type 8), to prevent receiving our own sent ping requests when pinging localhost;
 *  - Discard packets with id != our id because they are not meant to be received by us (to prevent receiving packets meant for another process)
 *
 * @see https://www.kernel.org/doc/html/latest/networking/filter.html
 * @see https://man.netbsd.org/bpf.4
 *
 * @param socketfd File descriptor of the socket to apply the filter to
 *
 * @return `0` on success, `-1` on failure
 */
static int setup_bpf_filter(int socketfd) {
    struct sock_filter filter[] = {
        // Load ICMP type
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, sizeof(struct iphdr)), // ICMP type is the first byte after IP header

        // Check if ICMP type is ICMP_ECHO. If true, jump to reject
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ICMP_ECHO, 6, 0),

        // Check if it's an ICMP_ECHOREPLY:
        // If it is, jump to handle ICMP_ECHOREPLY
        // If it's not, jump to handle error packets
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ICMP_ECHOREPLY, 0, 2),

        // Handle ICMP_ECHOREPLY:
        // Load and verify ID from reply packet
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, sizeof(struct iphdr) + offsetof(struct icmphdr, un.echo.id)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, packet_id(), 2, 3),

        // Handle error packets:
        // Load and verify ID from original packet inside error message
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + offsetof(struct icmphdr, un.echo.id)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, packet_id(), 0, 1),

        // Accept packet
        BPF_STMT(BPF_RET + BPF_K, (u_int32_t)-1),

        // Reject packet
        BPF_STMT(BPF_RET + BPF_K, 0),
    };

    struct sock_fprog prog = {
        .len = ARRAY_SIZE(filter),
        .filter = filter,
    };

    #ifdef DEBUG
        printf("BPF filter setup:\n");
        printf("- ICMP ID offset: %zu\n", sizeof(struct iphdr) + offsetof(struct icmphdr, un.echo.id));
        printf("- Our packet ID: %d (network order: %d)\n", packet_id(), htons(packet_id()));
        printf("Attaching BPF filter with %u instructions...\n", prog.len);
    #endif

    if (setsockopt(socketfd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == -1) {
        perror("ft_ping: error: failed to attach BPF filter, setsockopt() failed");
        return -1;
    }

    #ifdef DEBUG
        printf("BPF filter attached successfully\n");
    #endif

    return 0;
}

/**
 * Create a RAW socket for the ICMP protocol with various options setup.
 *
 * @param[in] opts Pointer to the options struct
 *
 * @return socketfd on success, -1 on failure
 */
int setup_socket(const struct Options *opts) {
    #ifdef DEBUG
        printf("===================== Socket setup =====================\n");
    #endif

    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketfd == -1) {
        perror("ft_ping: error: failed to setup socket, socket() failed");
        return -1;
    }

    if (setsockopt(socketfd, IPPROTO_IP, IP_TTL, &opts->ttl, sizeof(opts->ttl)) == -1) {
        perror("ft_ping: error: failed to setup socket, setsocketopt() failed when setting IP_TTL option");
        return -1;
    }

    if (setup_bpf_filter(socketfd) == -1) {
        return -1;
    }

    if (opts->timeout > 0) {
        struct timeval timeout = {
            .tv_sec = opts->timeout,
            .tv_usec = 0
        };

        if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
            perror("ft_ping: error: failed to setup socket, setsocketopt() failed when setting SO_RCVTIMEO option");
            return -1;
        }
    }

    if (opts->dont_route) {
        int on = 1;
        if (setsockopt(socketfd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on)) == -1) {
            perror("ft_ping: error: failed to setup socket, setsocketopt() failed when setting SO_DONTROUTE option");
            return -1;
        }
    }

    if (opts->debug) {
        int on = 1;
        if (setsockopt(socketfd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) == -1) {
            perror("ft_ping: error: failed to setup socket, setsocketopt() failed when setting SO_DEBUG option");
            return -1;
        }
    }

    #ifdef DEBUG
        printf("Socket fd = %d\n", socketfd);
        printf("========================================================\n");
    #endif

    return socketfd;
}

/**
 * Send a packet to `ctx->destination`.
 *
 * @param[in] ctx The context struct
 * @param[in] packet The packet to send
 * @param packet_size Size of `packet`
 *
 * @return `0` on success, `-1` on failure
 */
static int send_packet(const struct Context *ctx, const uint8_t *packet, size_t packet_size) {
    #ifdef DEBUG
        printf("==================== Sending packet ====================\n");
        debug_packet(packet, packet_size);
    #endif

    ssize_t ret = sendto(ctx->socketfd, packet, packet_size, 0,
        ctx->destination->ai_addr, ctx->destination->ai_addrlen);
    if (ret == -1) {
        perror("ft_ping: error: failed to send packet to destination, sendto() failed");
        return -1;
    }

    if ((size_t)ret < packet_size) {
        fprintf(stderr, "ft_ping: notice: failed to send entire packet to destination");
        return -1;
    }

    #ifdef DEBUG
        printf("sendto() sent %ld bytes of data\n", ret);
        printf("========================================================\n");
    #endif

    return 0;
}

/**
 * Ping `ctx->destination`.
 * Updates `packet`'s sequence number, checksum and timestamp.
 *
 * @param[in,out] ctx A pointer to the context struct
 * @param[in,out] packet A pointer to the packet to send
 * @param packet_size Size of `packet`
 *
 * @return `0` on success, `-1` on failure
 */
int ping(struct Context *ctx, uint8_t *packet, size_t packet_size) {
    struct icmphdr *hdr = (struct icmphdr *)packet;
    hdr->un.echo.sequence = htons(ctx->stats.packets_transmitted + 1);

    const bool has_space_for_timestamp = (packet_size - sizeof(struct icmphdr)) >= sizeof(struct timeval);
    if (has_space_for_timestamp) {
        // Fill (or overwrite) the first bytes of payload with the current timestamp
        struct timeval *timestamp = (struct timeval *)&packet[sizeof(struct icmphdr)];
        if (gettimeofday(timestamp, NULL) == -1) {
            perror("ft_ping: error: failed to fill timestamp in request's payload, gettimeofday() failed");
            return -1;
        }
    }

    // Recalculate checksum for the updated packet
    hdr->checksum = 0;
    hdr->checksum = icmp_checksum((uint8_t *)packet, packet_size);

    if (send_packet(ctx, packet, packet_size) == -1) {
        return -1;
    }

    ctx->stats.packets_transmitted += 1;
    if (ctx->opts.flood && !ctx->opts.quiet) {
        putchar('.');
    }

    return 0;
}

/**
 * Log ICMP errors.
 *
 * @param[in] opts Program options
 * @param[in] buf Buffer containing the error packet
 * @param icmp_msg_len Length of reply's ICMP message (ICMP header + original packet's IP header + original packet's ICMP header + payload)
 */
static void handle_icmp_error_logging(
    const struct Options *opts,
    const uint8_t *buf,
    ssize_t icmp_msg_len
) {
    struct iphdr *ip_hdr = (struct iphdr *)&buf[0];
    struct icmphdr *icmp_hdr = (struct icmphdr *)&buf[sizeof(struct iphdr)];
    struct icmphdr *orig_icmp_hdr = (struct icmphdr *)&buf[sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr)];

    struct LogOptions log_opts = {
        .no_reverse_dns_resolution = opts->no_reverse_dns_resolution,
        .print_timestamps = opts->print_timestamps
    };

    struct sockaddr_in hop_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = ip_hdr->saddr
    };
    struct ErrorDetails error_details = {
        .hop_addr = (struct sockaddr *)&hop_addr,
        .received_bytes = icmp_msg_len,
        .sequence = ntohs(orig_icmp_hdr->un.echo.sequence)
    };

    switch (icmp_hdr->type) {
        case ICMP_TIME_EXCEEDED:
            log_time_exceeded(&log_opts, &error_details);
            break;
        case ICMP_DEST_UNREACH:
            log_destination_unreachable(&log_opts, &error_details, icmp_hdr->code);
            break;
        case ICMP_REDIRECT:
            log_redirect(&log_opts, &error_details, icmp_hdr->code);
            break;
        case ICMP_PARAMETERPROB:
            log_parameter_problem(&log_opts, &error_details, icmp_hdr->code);
            break;
        default:
            log_bad_icmp_type(&log_opts, &error_details, icmp_hdr->type);
            break;
    }

    if (opts->verbose) {
        // Dump original packet headers
        dump_headers(&buf[sizeof(struct iphdr) + sizeof(struct icmphdr)]);
    }
}

/**
 * Validate an ICMP checksum.
 *
 * @param[in] icmp_hdr ICMP header
 * @param[in] buf Buffer containing the ICMP message
 * @param icmp_msg_len Length of `icmp_msg`
 *
 * @return `true` if the checksum matches, `false` otherwise
 */
static bool icmp_checksum_matches(
    struct icmphdr *icmp_hdr,
    const uint8_t *buf,
    size_t icmp_msg_len
) {
    uint16_t received_checksum = icmp_hdr->checksum;
    icmp_hdr->checksum = 0; // Reset checksum field to calculate packet's checksum
    uint16_t calculated_checksum = icmp_checksum(buf, icmp_msg_len);
    icmp_hdr->checksum = received_checksum; // Restore original checksum

    #ifdef DEBUG
        printf("=============== Validating ICMP checksum ===============\n");
        printf("- Message length: %zu\n", icmp_msg_len);
        printf("- Received checksum: 0x%x\n", received_checksum);
        printf("- Calculated checksum: 0x%x\n", calculated_checksum);
        printf("Checksum %s\n", (received_checksum == calculated_checksum) ? "matches!" : "doesn't match!");
        printf("========================================================\n");
    #endif

    return received_checksum == calculated_checksum;
}

/**
 * Wait for a response from ctx->destination.
 *
 * @param[in,out] ctx A pointer to the context struct
 * @param packet_size Size of the ICMP packet that we've sent
 *
 * @return `0` if a response, timeout or CTRL+C is received, `-1` on failure
 */
int receive_response(struct Context *ctx, const size_t packet_size) {
    #ifdef DEBUG
        printf("================== Receiving response ==================\n");
    #endif

    /* In a normal reply, we'll receive the reply's IP header + ICMP header + payload.
    In case of error, we'll receive the reply's IP header + ICMP header + sent packet's IP header + ICMP header + payload.
    Since the error message is bigger, we'll allocate a buffer that can hold the worst case scenario.
    See https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol */
    const size_t buf_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + packet_size;
    uint8_t *buf = calloc(buf_size, sizeof(uint8_t));
    if (buf == NULL) {
        perror("ft_ping: error: failed to allocate buffer for response, calloc() failed");
        return -1;
    }

    struct iovec iov[1] = { { .iov_base = buf, .iov_len = buf_size } };
    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    const ssize_t received_bytes = recvmsg(ctx->socketfd, &msg, ctx->opts.flood ? MSG_DONTWAIT : 0);
    if (received_bytes == -1) {
        const bool timeout = errno == EAGAIN || errno == EWOULDBLOCK;
        if (timeout || errno == EINTR) {
            // Timeout or CTRL+C received
            #ifdef DEBUG
                if (timeout) {
                    printf("Timeout received!\n");
                } else {
                    printf("CTRL+C received!\n");
                }
                printf("========================================================\n");
            #endif
            free(buf);
            return 0;
        }

        perror("ft_ping: fatal: failed to receive data from peer, recvmsg() failed");
        free(buf);
        return -1;
    }

    struct iphdr *ip_hdr = (struct iphdr *)&buf[0];

    size_t icmp_msg_len = received_bytes - sizeof(struct iphdr);
    if (icmp_msg_len == 0) {
        log_packet_too_short(ip_hdr->saddr, received_bytes);
        free(buf);
        return 0;
    }

    struct icmphdr *icmp_hdr = (struct icmphdr *)&buf[sizeof(struct iphdr)];

    #ifdef DEBUG
        if (icmp_hdr->type == ICMP_ECHOREPLY) {
            debug_packet(&buf[sizeof(struct iphdr)], icmp_msg_len);
        } else {
            debug_error_packet(&buf[sizeof(struct iphdr)], icmp_msg_len);
        }
    #endif

    if (!icmp_checksum_matches(icmp_hdr, &buf[sizeof(struct iphdr)], icmp_msg_len)) {
        ctx->stats.corrupted += 1;
        struct LogOptions log_opts = {
            .no_reverse_dns_resolution = ctx->opts.no_reverse_dns_resolution,
            .print_timestamps = ctx->opts.print_timestamps
        };

        struct sockaddr_in hop_addr = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = ip_hdr->saddr
        };

        if (icmp_hdr->type != ICMP_ECHOREPLY) {
            icmp_hdr = (struct icmphdr *)&buf[sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr)];
        }
        struct ErrorDetails error_details = {
            .hop_addr = (struct sockaddr *)&hop_addr,
            .received_bytes = icmp_msg_len,
            .sequence = ntohs(icmp_hdr->un.echo.sequence)
        };

        if (!ctx->opts.quiet) {
            if (ctx->opts.flood) {
                write(STDOUT_FILENO, "\bE", 2);
            } else {
                log_checksum_mismatch(&log_opts, &error_details);
            }
        }

        #ifdef DEBUG
            printf("========================================================\n");
        #endif

        free(buf);
        return 0;
    }

    icmp_hdr->un.echo.id = ntohs(icmp_hdr->un.echo.id);
    icmp_hdr->un.echo.sequence = ntohs(icmp_hdr->un.echo.sequence);

    if (icmp_hdr->type != ICMP_ECHOREPLY) {
        ctx->stats.errors += 1;
        if (!ctx->opts.quiet) {
            if (ctx->opts.flood) {
                write(STDOUT_FILENO, "\bE", 2);
            } else {
                handle_icmp_error_logging(&ctx->opts, buf, icmp_msg_len);
            }
        }
        free(buf);
        return 0;
    }

    // Validate sequence number
    if (icmp_hdr->un.echo.sequence > ctx->stats.packets_transmitted) {
        if (ctx->opts.verbose) {
            fprintf(stderr, "ft_ping: notice: received packet with sequence number %d, expected <= %lld\n",
                icmp_hdr->un.echo.sequence, ctx->stats.packets_transmitted
            );
        }
        free(buf);
        return 0;
    }

    // Validate payload
    uint8_t *payload;
    size_t payload_size;
    const bool has_space_for_timestamp =
        (received_bytes - sizeof(struct iphdr) - sizeof(struct icmphdr)) >= sizeof(struct timeval);
    if (has_space_for_timestamp) {
        payload = &buf[sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct timeval)];
        payload_size = received_bytes - sizeof(struct iphdr) - sizeof(struct icmphdr) - sizeof(struct timeval);
    } else {
        payload = &buf[sizeof(struct iphdr) + sizeof(struct icmphdr)];
        payload_size = received_bytes - sizeof(struct iphdr) - sizeof(struct icmphdr);
    }

    if (!has_our_payload(payload, payload_size, ctx->opts.pattern.bytes, ctx->opts.pattern.len)) {
        if (ctx->opts.verbose) {
            fprintf(stderr, "ft_ping: notice: received packet with non-matching payload pattern\n");
        }
        free(buf);
        return 0;
    }

    // Process successful reply
    ctx->stats.packets_received += 1;

    struct LogOptions log_opts = {
        .no_reverse_dns_resolution = ctx->opts.no_reverse_dns_resolution,
        .print_timestamps = ctx->opts.print_timestamps
    };

    struct LogDetails log_details = {
        .received_bytes = icmp_msg_len,
        .peer_hostname = ctx->peer_hostname,
        .peer_ip_str = ctx->peer_ip_str,
        .sequence = icmp_hdr->un.echo.sequence,
        .ttl = ip_hdr->ttl,
        .rtt = 0,
        .size_mismatch = icmp_msg_len - packet_size
    };

    // Calculate RTT if timestamp is present in payload
    if (has_space_for_timestamp) {
        struct timeval timestamp = {0};
        memcpy(&timestamp, &buf[sizeof(struct iphdr) + sizeof(struct icmphdr)], sizeof(struct timeval));

        if (timestamp.tv_sec != 0 && timestamp.tv_usec != 0) {
            long long timestamp_on_packet = timeval_to_us(&timestamp);
            long long current_time = now_us();

            // Calculate RTT in microseconds first for precision, then convert to milliseconds with 3 decimal places
            double rtt = (current_time - timestamp_on_packet) / 1000.0;
            gather_rtt_statistics(&ctx->stats, rtt);

            log_details.rtt = rtt;
        }
    }

    if (!ctx->opts.quiet) {
        if (ctx->opts.flood) {
            putchar('\b');
        } else {
            log_received_msg(&log_opts, &log_details);
        }
    }

    free(buf);
    return 0;
}

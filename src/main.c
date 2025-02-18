#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <linux/icmp.h>
#include <getopt.h>

#include "context.h"
#include "icmp_packet.h"
#include "output.h"
#include "options.h"
#include "dns.h"
#include "network.h"
#include "utils.h"

#define HELP_MESSAGE\
    "\
Usage\n\
  ft_ping [options] <destination>\n\
\n\
Options:\n\
  -a                use audible ping\n\
  -c <count>        stop after <count> replies\n\
  -D                print timestamps\n\
  -d                use SO_DEBUG socket option\n\
  -f                flood ping\n\
  -h, -?            print help and exit\n\
  -i <interval>     wait <interval> seconds between sending each packet\n\
  -l <preload>      send <preload> packets as fast as possible before falling into normal mode of execution\n\
  -n                no reverse DNS name resolution\n\
  -p <pattern>      content of padding bytes\n\
  -q                quiet output\n\
  -r                ignore routing\n\
  -t <ttl>          IP time to live\n\
  -v                verbose output\n\
  -V                print version and exit\n\
  -s <size>         packet's payload size\n\
  -w <deadline>     stop after <deadline> seconds\n\
  -W <timeout>      wait <timeout> seconds for response\n\
\n\
Argument:\n\
  <destination>     domain name or IP address"

#define VERSION "1.0.0"

#define FLOOD_PING_INTERVAL 0.01 // seconds

volatile sig_atomic_t g_run = 1; // Global variable to control the main loop

/**
* Handles signals by setting `g_run` to `0`.
*
* @param signum Signal number
*/
static void sig_handler(int signum) {
    (void)signum;
    g_run = 0;
}

/**
 * Setup handlers for the `SIGINT` and `SIGALRM` signals.
 *
 * @return `0` on success, `-1` on failure
 */
static inline int setup_signal_handlers(void) {
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        perror("ft_ping: fatal: failed to set SIGINT signal handler");
        return -1;
    }

    if (signal(SIGALRM, sig_handler) == SIG_ERR) {
        perror("ft_ping: fatal: failed to set SIGALRM signal handler");
        return -1;
    }

    return 0;
}

/**
 * Preloads `nr_packets` packets.
 *
 * @param[in,out] ctx Pointer to the context
 * @param[in,out] packet Pointer to the packet to send
 * @param packet_size Size of `packet`
 * @param nr_packets Number of packets to send
 *
 * @return `0` on success, `1` on failure
 */
static int preload(
    struct Context *ctx,
    uint8_t *packet,
    size_t packet_size,
    long long nr_packets
) {
    // Send <nr_packets> as fast as possible
    for (long long i = 0; i < nr_packets && g_run; i += 1) {
        if (ping(ctx, packet, packet_size) == -1) {
            return 1;
        }
    }

    // Wait for responses and, in case count option was provided,
    // verify if we've already received <count> packets
    for (long long i = 0; i < nr_packets && g_run; i += 1) {
        if (receive_response(ctx, packet_size) == -1) {
            return 1;
        }

        long long all_received_packets =
            ctx->stats.packets_received + ctx->stats.corrupted + ctx->stats.errors;
        if (ctx->opts.count != DEFAULT_COUNT && all_received_packets == ctx->opts.count) {
            // We've (sent and) received <count> packets on preload phase, stop execution
            g_run = 0;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "ft_ping: fatal: destination required\n");
        return EXIT_FAILURE;
    }

    struct Options opts = new_options();
    if (parse_options(&opts, argc, argv) == -1) {
        return EXIT_FAILURE;
    }

    if (opts.help == true) {
        puts(HELP_MESSAGE);
        return EXIT_SUCCESS;
    }

    if (opts.version == true) {
        printf("ft_ping %s by Kuninoto\n", VERSION);
        return EXIT_SUCCESS;
    }

    if (geteuid() != ROOT_UID) {
        fprintf(stderr, "ft_ping: fatal: operation not permitted. Root privileges needed\n");
        return EXIT_FAILURE;
    }

    if (setup_signal_handlers() == -1) {
        return EXIT_FAILURE;
    }

    struct Statistics stats = {0};
    struct Context ctx = new_context(stats, opts);

    if (parse_destination(&ctx, argv[optind]) == -1) {
        destroy_context(&ctx);
        return EXIT_FAILURE;
    }

    int socketfd = setup_socket(&opts);
    if (socketfd == -1) {
        destroy_context(&ctx);
        return EXIT_FAILURE;
    }
    ctx.socketfd = socketfd;

    const size_t packet_size = sizeof(struct icmphdr) + opts.payload_size;
    uint8_t packet[packet_size];
    init_packet_data(packet, opts.payload_size, opts.pattern.bytes, opts.pattern.len);

    struct icmphdr *hdr = (struct icmphdr *)packet;
    hdr->type = ICMP_ECHO;
    hdr->un.echo.id = htons(packet_id());

    print_ping_header(&ctx);
    ctx.stats.start_timestamp = now_ms();

    if (ctx.opts.deadline != DEFAULT_DEADLINE) {
        // Set alarm to stop execution after <deadline> seconds
        alarm(ctx.opts.deadline);
    }

    if (ctx.opts.preload_packets != DEFAULT_PRELOAD_PACKAGES) {
        long long n = ctx.opts.preload_packets;
        if (ctx.opts.count != DEFAULT_COUNT) {
            // If <count> was provided, we should preload the minimum between <count> and <preload_packets>
            n = MIN(ctx.opts.count, ctx.opts.preload_packets);
        }

        if (preload(&ctx, packet, packet_size, n) == -1) {
            destroy_context(&ctx);
            return EXIT_FAILURE;
        }
    }

    while (g_run) {
        if (ping(&ctx, packet, packet_size) == -1) {
            // Sending failed, nothing to receive
            continue;
        }

        receive_response(&ctx, packet_size);

        if (ctx.opts.audible_ping) {
            putchar('\a');
        }

        if (ctx.opts.count != DEFAULT_COUNT && (ctx.stats.packets_received + ctx.stats.errors + ctx.stats.corrupted) == ctx.opts.count) {
            // We've (sent and) received <count> packets, stop execution
            break;
        }

        if (ctx.opts.flood) {
            usleep(FLOOD_PING_INTERVAL * 1000000);
        } else {
            usleep(ctx.opts.interval * 1000000);
        }
    }

    ctx.stats.end_timestamp = now_ms();
    print_statistics(ctx.destination->ai_canonname, &ctx.stats);
    destroy_context(&ctx);
    return EXIT_SUCCESS;
}

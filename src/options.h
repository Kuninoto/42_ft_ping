#pragma once

#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define DEFAULT_AUDIBLE_PING              false
#define DEFAULT_COUNT                     0
#define DEFAULT_PRINT_TIMESTAMPS          false
#define DEFAULT_DEBUG                     false
#define DEFAULT_FLOOD                     false
#define DEFAULT_HELP                      false
#define DEFAULT_INTERVAL                  1.0 // seconds
#define DEFAULT_PRELOAD_PACKAGES          0
#define DEFAULT_NO_REVERSE_DNS_RESOLUTION false
#define DEFAULT_QUIET                     false
#define DEFAULT_DONT_ROUTE                false
#define DEFAULT_TTL                       IPDEFTTL
#define DEFAULT_VERBOSE                   false
#define DEFAULT_VERSION                   false
#define DEFAULT_PAYLOAD_SIZE              56
#define DEFAULT_DEADLINE                  0
#define DEFAULT_TIMEOUT                   10 // seconds

#define OPT_STRING "ac:Ddfh?i:l:np:qrt:vVs:w:W:"

#define MAX_PAYLOAD_SIZE 65507 // Max IP packet size (65535) - IP header (20) - ICMP header (8)

#define MAX_PATTERN_LEN 16

struct Pattern {
    uint8_t bytes[MAX_PATTERN_LEN]; // Pattern bytes
    uint8_t len;                    // Length of the pattern
};

struct Options {
    bool audible_ping;                 // `-a` Audible ping
    long long count;                   // `-c` Stop after sending <count> ECHO_REQUEST packets
    bool print_timestamps;             // `-D` Prints timestamps on pings' logs
    bool debug;                        // `-d` Set the SO_DEBUG option on the socket being used.
    bool flood;                        // `-f` Flood ping
    bool help;                         // `-h` Print help and exit
    double interval;                   // `-i` Wait <interval> seconds between sending each packet
    int preload_packets;              // `-l` Send <preload> packets as fast as possible before falling into normal mode of execution
    bool no_reverse_dns_resolution;    // `-n` No reverse DNS name resolution
    struct Pattern pattern;            // `-p` Contents of padding bytes
    bool quiet;                        // `-q` Quiet output
    bool dont_route;                   // `-r` Ignore routing
    uint8_t ttl;                       // `-t` Time to live
    bool verbose;                      // `-v` Verbose output
    bool version;                      // `-V` Print version and exit
    uint16_t payload_size;             // `-s` Packet's payload size
    int deadline;                      // `-w` Stop execution after <deadline> seconds
    int timeout;                       // `-W` Wait <timeout> seconds for response
};

/**
* Creates a new Options struct with the default values for each option.
*
* @return New Options
*/
static inline struct Options new_options(void) {
    return (struct Options) {
        .audible_ping = DEFAULT_AUDIBLE_PING,
        .count = DEFAULT_COUNT,
        .print_timestamps = DEFAULT_PRINT_TIMESTAMPS,
        .debug = DEFAULT_DEBUG,
        .flood = DEFAULT_FLOOD,
        .help = DEFAULT_HELP,
        .interval = DEFAULT_INTERVAL,
        .preload_packets = DEFAULT_PRELOAD_PACKAGES,
        .no_reverse_dns_resolution = DEFAULT_NO_REVERSE_DNS_RESOLUTION,
        .pattern = {
            .bytes = {0x0},
            .len = 0,
        },
        .quiet = DEFAULT_QUIET,
        .dont_route = DEFAULT_DONT_ROUTE,
        .ttl = DEFAULT_TTL,
        .verbose = DEFAULT_VERBOSE,
        .version = DEFAULT_VERSION,
        .payload_size = DEFAULT_PAYLOAD_SIZE,
        .deadline = DEFAULT_DEADLINE,
        .timeout = DEFAULT_TIMEOUT,
    };
}

/**
 * Print debug info about options.
 *
 * @param[in] opts Pointer to the options struct
 */
static inline void debug_options(const struct Options *opts) {
    printf("Options:\n");
    printf("\topts.audible_ping = %s\n", opts->audible_ping ? "true" : "false");
    printf("\topts.count = %lld\n", opts->count);
    printf("\topts.print_timestamps = %s\n", opts->print_timestamps ? "true" : "false");
    printf("\topts.debug = %s\n", opts->debug ? "true" : "false");
    printf("\topts.flood = %s\n", opts->flood ? "true" : "false");
    printf("\topts.help = %s\n", opts->help ? "true" : "false");
    printf("\topts.interval = %f\n", opts->interval);
    printf("\topts.preload_packets = %d\n", opts->preload_packets);
    printf("\topts.no_reverse_dns_resolution = %s\n",
           opts->no_reverse_dns_resolution ? "true" : "false");
    printf("\topts.pattern = ");
    for (int i = 0; i < opts->pattern.len; i += 1) {
        printf("%x", opts->pattern.bytes[i]);
    }
    printf("\n");
    printf("\topts.quiet = %s\n", opts->quiet ? "true" : "false");
    printf("\topts.dont_route = %s\n", opts->dont_route ? "true" : "false");
    printf("\topts.ttl = %d\n", opts->ttl);
    printf("\topts.verbose = %s\n", opts->verbose ? "true" : "false");
    printf("\topts.version = %s\n", opts->version ? "true" : "false");
    printf("\topts.payload_size = %d\n", opts->payload_size);
    printf("\topts.deadline = %d\n", opts->deadline);
    printf("\topts.timeout = %d\n", opts->timeout);
}

int parse_options(struct Options *opts, const int argc, char **argv);

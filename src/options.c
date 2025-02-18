#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "options.h"
#include "utils.h"

/**
 * Checks if `value` is within the long long data type valid range
 * and if it's within the specified range. Checks for errno == ERANGE,
 * therefore, should be called after strto*() (e.g. strtoll()) functions.
 *
 * @param value The value to check
 * @param min The minimum value
 * @param max The maximum value
 *
 * @return Whether the value is within the valid range
 */
static inline bool is_within_valid_range_ll(const long long value, const long long min, const long long max) {
    const bool is_out_of_data_range = (value == LONG_MIN || value == LONG_MAX) && errno == ERANGE;
    return !is_out_of_data_range && (value >= min && value <= max);
}

/**
 * Parses the command-line options and populates `opts`.
 *
 * @param[out] opts Options struct to be populated
 * @param argc Number of command-line arguments
 * @param[in] argv Array of command-line arguments
 *
 * @return `0` on success, `-1` on error
 */
int parse_options(struct Options *opts, int argc, char **argv) {
    #ifdef DEBUG
        printf("======================== Options =======================\n");
        printf("Parsing options...\n");
    #endif

    char *endptr = NULL;
    bool interval_was_set = false; // Used to check if -i was set (since 1 is a valid value, we can't check for != DEFAULT_INTERVAL)

    char opt;
    while ((opt = getopt(argc, argv, OPT_STRING)) != EOF) {
        switch (opt) {
        case 'a': {
            opts->audible_ping = true;
            break;
        }
        case 'c': {
            long long parsed_count = strtoll(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "ft_ping: error: invalid count (c) argument: not a number `%c`\n", *endptr);
                return -1;
            }

            if (!is_within_valid_range_ll(parsed_count, 1, LONG_MAX)) {
                fprintf(stderr, "ft_ping: error: invalid count (c) argument: out of range (1-9223372036854775807)\n");
                return -1;
            }

            opts->count = parsed_count;
            break;
        }
        case 'D': {
            opts->print_timestamps = true;
            break;
        }
        case 'd': {
            opts->debug = true;
            break;
        }
        case 'f': {
            opts->flood = true;
            break;
        }
        case 'h': {
            opts->help = true;
            return 0; // Since we exit the program when -h is passed, no need to parse further
        }
        case '?': {
            opts->help = true;
            return 0; // Since we exit the program when -? is passed, no need to parse further
        }
        case 'i': {
            double parsed_interval = strtod(optarg, &endptr);
            if (*endptr != '\0') {
                fprintf(stderr, "ft_ping: error: invalid interval (i) argument: not a number `%c`\n", *endptr);
                return -1;
            }

            if (parsed_interval < 0 || parsed_interval > DBL_MAX) {
                fprintf(stderr, "ft_ping: error: invalid interval (i) argument: out of range (0-1.7976931348623157e+308)\n");
                return -1;
            }

            opts->interval = parsed_interval;
            interval_was_set = true;
            break;
        }
        case 'l': {
            uint64_t parsed_preload_packages = strtoul(optarg, &endptr, 0);
            if (*endptr != '\0') {
                fprintf(stderr, "ft_ping: error: invalid preload (l) argument: not a number `%c`\n", *endptr);
                return -1;
            }

            if (!is_within_valid_range_ll(parsed_preload_packages, 1, INT_MAX)) {
                fprintf(stderr, "ft_ping: error: invalid preload (l) argument: out of range (1-2147483647)\n");
                return -1;
            }

            opts->preload_packets = (int)parsed_preload_packages;
            break;
        }
        case 'n': {
            opts->no_reverse_dns_resolution = true;
            break;
        }
        case 'p': {
            int c = 0;
            int off = 0;
            int i = 0;

            // Process each hex byte pair from the pattern string
            while (*optarg && i < MAX_PATTERN_LEN) {
                if (sscanf(optarg, "%2x%n", &c, &off) != 1) {
                    fprintf(stderr, "ft_ping: error: invalid pattern (p) argument: not an hexadecimal pattern\n");
                    return -1;
                }

                opts->pattern.bytes[i] = c;
                optarg += off;
                i += 1;
            }

            opts->pattern.len = i;
            break;
        }
        case 'q': {
            opts->quiet = true;
            break;
        }
        case 'r': {
            opts->dont_route = true;
            break;
        }
        case 't': {
            long long parsed_ttl = strtoll(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "ft_ping: error: invalid time to live (t) argument: not a number `%c`\n", *endptr);
                return -1;
            }

            if (!is_within_valid_range_ll(parsed_ttl, 1, UINT8_MAX)) {
                fprintf(stderr, "ft_ping: error: invalid time to live (t) argument: out of range (1-255)\n");
                return -1;
            }

            opts->ttl = (uint8_t)parsed_ttl;
            break;
        }
        case 'v': {
            opts->verbose = true;
            break;
        }
        case 'V': {
            opts->version = true;
            return 0; // Since we exit the program when -V is passed, no need to parse further
        }
        case 's': {
            long long parsed_payload_size = strtoll(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "ft_ping: error: invalid size (s) argument: not a number `%c`\n", *endptr);
                return -1;
            }

            if (!is_within_valid_range_ll(parsed_payload_size, 0, MAX_PAYLOAD_SIZE)) {
                fprintf(stderr, "ft_ping: error: invalid size (s) argument: out of range (0-65507)\n");
                return -1;
            }

            opts->payload_size = (uint16_t)parsed_payload_size;
            break;
        }
        case 'w': {
            long long parsed_deadline = strtoll(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "ft_ping: error: invalid deadline (w) argument: not a number `%c`\n", *endptr);
                return -1;
            }

            if (!is_within_valid_range_ll(parsed_deadline, 1, INT_MAX)) {
                fprintf(stderr, "ft_ping: error: invalid deadline (w) argument: out of range (1-2147483647)\n");
                return -1;
            }

            opts->deadline = (int)parsed_deadline;
            break;
        }
        case 'W': {
            long long parsed_timeout = strtoll(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "ft_ping: error: invalid timeout (W) argument: not a number `%c`\n", *endptr);
                return -1;
            }

            if (!is_within_valid_range_ll(parsed_timeout, 1, INT_MAX)) {
                fprintf(stderr, "ft_ping: error: invalid timeout (W) argument: out of range (1-2147483647)\n");
                return -1;
            }

            opts->timeout = (int)parsed_timeout;
            break;
        }
        default: {
            // Unknown option, getopt() already prints an error message
            return -1;
        }
        }
    }

    if (opts->flood != DEFAULT_FLOOD && interval_was_set) {
        fprintf(stderr, "ft_ping: error: -f and -i are incompatible options\n");
        return -1;
    }

    #ifdef DEBUG
        printf("Options parsed successfully\n");
        printf("========================================================\n");
    #endif

    return 0;
}

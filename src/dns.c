#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "dns.h"
#include "output.h"

/**
 * Reverse DNS lookup `address` and return its hostname as a string.
 *
 * @param[in] address Address to get the hostname of
 * @param address_len Length of `address`
 *
 * @return hostname or `NULL` in case of error
 */
const char *reverse_dns_lookup(struct sockaddr *address, socklen_t address_len) {
    char host_buffer[NI_MAXHOST] = {0};
    int ret = getnameinfo(address, address_len, host_buffer, sizeof(host_buffer), NULL, 0, 0);
    if (ret != 0) {
        #ifdef DEBUG
            fprintf(stderr, "getnameinfo failed: %s\n", gai_strerror(ret));
        #endif
        return NULL;
    }

    return (const char *)strdup(host_buffer);
}

/**
 * Lookup `host` on DNS and return a `addrinfo` linkedlist describing it.
 *
 * @param[in] host The domain name to lookup
 *
 * @return `addrinfo` linkedlist describing `host` or `NULL` on error
 */
struct addrinfo *dns_lookup(const char *host) {
    #ifdef DEBUG
        printf("Looking up \"%s\" IP address on DNS...\n", host);
    #endif

    struct addrinfo hints;
    struct addrinfo *peer;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4 only
    hints.ai_flags = AI_CANONNAME;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int ret = getaddrinfo(host, NULL, &hints, &peer);
    if (ret != 0) {
        fprintf(stderr, "ft_ping: fatal: failed to get \"%s\" address info: %s\n",
                host, gai_strerror(ret));
        return NULL;
    }

    #ifdef DEBUG
        printf("Destination addrinfo linked list:\n");
        debug_addrinfo(peer);
    #endif

    return peer;
}

/**
 * Print debug information (type, family, ip address) about `host`'s addrinfo(s).
 *
 * @param[in] host `addrinfo` struct to print debug information about
 */
void debug_addrinfo(struct addrinfo *host) {
    for (struct addrinfo *tmp = host; tmp != NULL; tmp = tmp->ai_next) {
        printf("Entry:\n");
        printf("\tType: %d\n", tmp->ai_socktype);
        printf("\tFamily: %d\n", tmp->ai_family);

        const char *ip_str = address_to_ip_str(tmp->ai_addr);
        printf("\tIP Address = %s\n", ip_str);

        if (ip_str != NULL) {
            free((void *)ip_str);
            ip_str = NULL;
        }
    }
}

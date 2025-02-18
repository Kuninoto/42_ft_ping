#pragma once

#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "options.h"
#include "statistics.h"

struct Context {
    int socketfd;
    struct addrinfo *destination;
    const char *peer_hostname;
    const char *peer_ip_str;
    struct Statistics stats;
    const struct Options opts;
};

/**
 * Creates a new Context struct.
 *
 * @param stats Statistics struct
 * @param opts Options struct
 *
 * @return New Context
 */
static inline struct Context new_context(struct Statistics stats, const struct Options opts) {
    return (struct Context) {
        .socketfd = -1,
        .destination = NULL,
        .peer_hostname = NULL,
        .peer_ip_str = NULL,
        .stats = stats,
        .opts = opts
    };
}

/**
 * Destroys a Context struct.
 *
 * @param[in,out] ctx Pointer to the Context struct
 */
static inline void destroy_context(struct Context *ctx) {
    if (ctx->socketfd > 0) {
        close(ctx->socketfd);
        ctx->socketfd = -1;
    }

    if (ctx->destination != NULL) {
        freeaddrinfo(ctx->destination);
        ctx->destination = NULL;
    }

    if (ctx->peer_hostname != NULL) {
        free((void *)ctx->peer_hostname);
        ctx->peer_hostname = NULL;
    }

    if (ctx->peer_ip_str != NULL) {
        free((void *)ctx->peer_ip_str);
        ctx->peer_ip_str = NULL;
    }
}

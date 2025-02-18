#pragma once

#include <netdb.h>

const char *reverse_dns_lookup(struct sockaddr *address, socklen_t address_len);
struct addrinfo *dns_lookup(const char *host);

void debug_addrinfo(struct addrinfo *host);

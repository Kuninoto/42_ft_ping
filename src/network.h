#pragma once

#include "context.h"
#include "options.h"

int parse_destination(struct Context *ctx, const char *destination);
int setup_socket(const struct Options *opts);
int ping(struct Context *ctx, uint8_t *packet, size_t packet_size);
int receive_response(struct Context *ctx, const size_t packet_size);

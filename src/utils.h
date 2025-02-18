#pragma once

#include <sys/time.h>

#define ROOT_UID 0

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

/**
 * Get the current time in milliseconds.
 *
 * @return Current time in milliseconds
 */
static inline long long now_ms(void) {
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);

    return (((long long)tv.tv_sec) * 1000) + (tv.tv_usec / 1000);
}

/**
 * Get the current time in microseconds.
 *
 * @return Current time in microseconds
 */
static inline long long now_us(void) {
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);

    return (((long long)tv.tv_sec) * 1000000) + tv.tv_usec;
}

/**
 * Convert a timeval struct to microseconds.
 *
 * @param tv Timeval to convert
 *
 * @return Timeval in microseconds
 */
static inline long long timeval_to_us(const struct timeval *tv) {
    return (((long long)tv->tv_sec) * 1000000) + tv->tv_usec;
}

#pragma once

#include <math.h>

struct Statistics {
    long long packets_transmitted;
    long long packets_received;
    long long start_timestamp;
    long long end_timestamp;
    double min_rtt;
    double sum_of_rtt;
    double sum_of_squared_rtts;
    double max_rtt;
    long long errors;
    long long corrupted;
};

/**
 * Calculate the average RTT.
 *
 * @param packets_received Number of packets received
 * @param sum_of_rtt Sum of RTT values
 *
 * @return Average RTT
 */
static inline double avg_rtt(long long packets_received, double sum_of_rtt) {
    if (packets_received == 0) {
        return 0.0;
    }

    return sum_of_rtt / packets_received;
}

/**
 * Calculate packet loss percentage.
 *
 * @param packets_transmitted Number of packets transmitted
 * @param packets_received Number of packets received
 *
 * @return Packet loss as a whole number percentage (0-100), no decimal precision
 */
static inline int packet_loss(long long packets_transmitted, long long packets_received) {
    if (packets_transmitted == 0) {
        return 0;
    }

    return (packets_transmitted - packets_received) * 100 / packets_transmitted;
}

/**
 * Calculate mean deviation (mdev).
 *
 * @param packets_received Number of packets received
 * @param sum_of_squared_rtts Sum of squared round-trip time values
 * @param sum_of_rtt Sum of round-trip time values
 *
 * @return Mean deviation
 */
static inline double mean_deviation(long long packets_received, double sum_of_squared_rtts, double sum_of_rtt) {
    if (packets_received == 0) {
        return 0.0;
    }

    double avg = sum_of_rtt / packets_received;
    return sqrt((sum_of_squared_rtts / packets_received) - pow(avg, 2));
}

/**
 * Gather round-trip time (RTT) statistics.
 *
 * @param[in,out] stats Statistics to update
 * @param rtt Round-trip time value
 */
static inline void gather_rtt_statistics(struct Statistics *stats, double rtt) {
    if (stats->packets_received == 1) {
        // First packet received, set min and max RTT
        stats->min_rtt = rtt;
        stats->max_rtt = rtt;
    } else if (rtt < stats->min_rtt) {
        stats->min_rtt = rtt;
    } else if (rtt > stats->max_rtt) {
        stats->max_rtt = rtt;
    }

    stats->sum_of_rtt += rtt;
    stats->sum_of_squared_rtts += pow(rtt, 2);
}

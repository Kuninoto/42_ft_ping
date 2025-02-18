#include <arpa/inet.h>
#include <linux/icmp.h>
#include <netinet/ip.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include "icmp_packet.h"

/**
 * Initializes `packet`'s data. Does nothing if `packet` is `NULL` or `pattern_len` is bigger than 0 and `pattern` is `NULL`.
 *
 * @param[out] packet Pointer to the packet to initialize
 * @param packet_size Size of `packet`
 * @param[in] pattern Pointer to the pattern to use
 * @param pattern_len Length of `pattern`
 */
void init_packet_data(
    uint8_t *packet,
    size_t payload_size,
    const uint8_t *pattern,
    uint8_t pattern_len
) {
    if (packet == NULL || (pattern_len > 0 && pattern == NULL)) {
        return;
    }

    // Initialize ICMP header to 0s
    memset(packet, 0, sizeof(struct icmphdr));

    size_t payload_offset = sizeof(struct icmphdr);
    if (payload_size >= sizeof(struct timeval)) {
        // If payload has space for a timestamp,
        // we should start filling after the bytes
        // that will later have it
        payload_offset += sizeof(struct timeval);
    }

    // Initialize payload
    uint8_t value;
    for (size_t i = 0; i < payload_size; i += 1) {
        if (pattern_len > 0) {
            // With pattern value, cycling through pattern
            value = pattern[i % pattern_len];
        } else {
            // With incremental values
            value = i;
        }
        packet[payload_offset + i] = value;
    }
}

/**
 * Calculate the checksum of an ICMP packet.
 *
 * @param[in] packet The packet to calculate the checksum of
 * @param packet_size Size of `packet`
 *
 * @return The checksum of the packet
 */
uint16_t icmp_checksum(const uint8_t *packet, size_t packet_size) {
	uint32_t sum = 0;
    uint16_t *buff = (uint16_t *)packet;
    size_t count = packet_size;

    /* Using a 32 bit accumulator (sum), we add sequential 16 bit
    words to it, and at the end, fold back all the carry bits
    from the top 16 bits into the lower 16 bits */
    while (count > 1) {
        sum += *buff;
        buff += 1;
        count -= 2;
    }

    // Handle remaining byte if packet_size is odd
	if (count == 1) {
        sum += *(uint8_t *)buff;
    }

    // Add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF); // Add high 16 to low 16
    sum += (sum >> 16);                 // Add carry

	return (uint16_t)~sum; // Return sum truncate to 16 bits
}

/**
 * Check if the packet contains the pattern in its payload.
 *
 * @param payload Packet's payload
 * @param payload_len Length of `payload`
 * @param pattern Pattern to look for
 * @param pattern_len Length of `pattern`
 *
 * @return `true` if the pattern is found, `false` otherwise
 */
bool has_our_payload(
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *pattern,
    uint8_t pattern_len
) {
    // Verify payload against
    uint8_t value;
    for (size_t i = 0; i < payload_len; i += 1) {
        if (pattern_len > 0) {
            // Pattern, cycling through pattern
            value = pattern[i % pattern_len];
        } else {
            // Incremental values
            value = i;
        }

        if (payload[i] != value) {
            return false;
        }
    }

    return true;
}

/**
 * Print debug information about a packet.
 *
 * @param[in] packet Packet to print debug information about
 * @param packet_size Size of `packet`
 */
void debug_packet(const uint8_t *packet, size_t packet_size) {
    struct icmphdr *hdr = (struct icmphdr *)packet;
    const uint8_t *payload = &packet[sizeof(struct icmphdr)];
    int payload_size = packet_size - sizeof(struct icmphdr);

    printf("Packet:\n");
    printf("\tsize: %ld\n", packet_size);
    printf("\tICMP header:\n");

    printf("\t\ttype = %s (%d)\n", icmp_type_str(hdr->type), hdr->type);
    printf("\t\tcode = %s (%d)\n", icmp_code_str(hdr->type, hdr->code), hdr->code);
    printf("\t\tchecksum = %u\n", hdr->checksum);
    printf("\t\tid = %u\n", ntohs(hdr->un.echo.id));
    printf("\t\tsequence = %u\n", ntohs(hdr->un.echo.sequence));

    if ((size_t)payload_size < sizeof(struct timeval)) {
        printf("\t\ttimestamp = <not set>\n");
    } else {
        struct timeval timestamp = {0};
        memcpy(&timestamp, payload, sizeof(struct timeval));

        if (timestamp.tv_sec == 0 && timestamp.tv_usec == 0) {
            printf("\t\ttimestamp = <not set>\n");
        } else {
            struct tm *time_info = localtime(&timestamp.tv_sec);

            if (time_info == NULL) {
                printf("\t\ttimestamp = <invalid time>\n");
            } else {
                char time_str[64] = {0};
                strftime(time_str, sizeof(time_str), "%B %d, %Y %H:%M:%S", time_info);
                printf("\t\ttimestamp = %s.%06ld %s\n", time_str, timestamp.tv_usec, time_info->tm_zone);
            }
        }
    }

    printf("\tPayload:\n");
    printf("\t\tsize: %d\n", payload_size);
    printf("\t\tdata: ");
    for (int i = 0; i < payload_size; i += 1) {
        printf("0x%X ", payload[i]);
    }

    printf("\n");
}

/**
 * Print debug information about an error packet.
 *
 * @param[in] packet Packet to print debug information about
 * @param packet_size Size of `packet`
 */
void debug_error_packet(const uint8_t *packet, size_t packet_size) {
    struct icmphdr *icmp_hdr = (struct icmphdr *)packet;
    struct icmphdr *og_icmp_hdr = (struct icmphdr *)&packet[sizeof(struct icmphdr) + sizeof(struct iphdr)];
    const uint8_t *payload = &packet[sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)];
    int payload_size = packet_size - sizeof(struct icmphdr) - sizeof(struct iphdr) - sizeof(struct icmphdr);

    printf("Packet:\n");
    printf("\tsize: %ld\n", packet_size);
    printf("\tICMP header:\n");

    printf("\t\ttype = %s (%d)\n", icmp_type_str(icmp_hdr->type), icmp_hdr->type);
    printf("\t\tcode = %s (%d)\n", icmp_code_str(icmp_hdr->type, icmp_hdr->code), icmp_hdr->code);
    printf("\t\tchecksum = %u\n", icmp_hdr->checksum);
    printf("\t\tid = %u | our id = %d\n", ntohs(icmp_hdr->un.echo.id), packet_id());
    printf("\t\tsequence = %u\n", ntohs(icmp_hdr->un.echo.sequence));

    printf("\tOriginal packet ICMP header:\n");

    printf("\t\ttype = %s (%d)\n", icmp_type_str(og_icmp_hdr->type), og_icmp_hdr->type);
    printf("\t\tcode = %s (%d)\n", icmp_code_str(og_icmp_hdr->type, og_icmp_hdr->code), og_icmp_hdr->code);
    printf("\t\tchecksum = %u\n", og_icmp_hdr->checksum);
    printf("\t\tid = %u | our id = %d\n", ntohs(og_icmp_hdr->un.echo.id), packet_id());
    printf("\t\tsequence = %u\n", ntohs(og_icmp_hdr->un.echo.sequence));

    if ((size_t)payload_size < sizeof(struct timeval)) {
        printf("\t\ttimestamp = <not set>\n");
    } else {
        struct timeval timestamp;
        memcpy(&timestamp, payload, sizeof(struct timeval));

        if (timestamp.tv_sec == 0 && timestamp.tv_usec == 0) {
            printf("\t\ttimestamp = <not set>\n");
        } else {
            struct tm *time_info = localtime(&timestamp.tv_sec);

            if (time_info == NULL) {
                printf("\t\ttimestamp = <invalid time>\n");
            } else {
                char time_str[64] = {0};
                strftime(time_str, sizeof(time_str), "%B %d, %Y %H:%M:%S", time_info);
                printf("\t\ttimestamp = %s.%06ld %s\n", time_str, timestamp.tv_usec, time_info->tm_zone);
            }
        }
    }

    printf("\tOriginal packet payload:\n");
    printf("\t\tsize: %d\n", payload_size);
    printf("\t\tdata: ");
    for (int i = 0; i < payload_size; i += 1) {
        printf("0x%X ", payload[i]);
    }

    printf("\n");
}

/**
 * Get a string describing an ICMP type as per the ICMP Parameters on RFC2780, excluding the deprecated types.
 *
 * @see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
 *
 * @param type The ICMP type
 *
 * @return A string describing the ICMP type
*/
const char *icmp_type_str(int type) {
    switch (type) {
        case ICMP_ECHOREPLY: return "Echo Reply";
        case ICMP_DEST_UNREACH: return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH: return "Source Quench";
        case ICMP_REDIRECT: return "Redirect";
        case ICMP_ECHO: return "Echo";
        case 9: return "Router Advertisement";
        case 10: return "Router Solicitation";
        case ICMP_TIME_EXCEEDED: return "Time Exceeded";
		case ICMP_PARAMETERPROB: return "Parameter Problem";
		case ICMP_TIMESTAMP: return "Timestamp";
		case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
        case 19: return "Reserved";
        case 20: return "Reserved";
        case 21: return "Reserved";
        case 22: return "Reserved";
        case 23: return "Reserved";
        case 24: return "Reserved";
        case 25: return "Reserved";
        case 26: return "Reserved";
        case 27: return "Reserved";
        case 28: return "Reserved";
        case 29: return "Reserved";
        case 40: return "Photuris";
        case 41: return "ICMP messages utilized by experimental mobility protocols";
        case 42: return "Extended Echo Request";
        case 43: return "Extended Echo Reply";
        case 253: return "RFC3692-style Experiment 1";
        case 254: return "RFC3692-style Experiment 2";
        case 255: return "Reserved";

        default: return "Unknown";
    }
}

/**
 * Get a string describing a ICMP code as per the ICMP Parameters on RFC2780, excluding the deprecated types.
 *
 * @see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
 *
 * @param type The ICMP type
 * @param code The ICMP code
 *
 * @return A string describing the ICMP code
*/
const char *icmp_code_str(int type, int code) {
    switch (type) {
    case ICMP_ECHOREPLY: return "No code";
    case ICMP_DEST_UNREACH:
        switch (code) {
        case ICMP_NET_UNREACH: return "Net unreachable";
        case ICMP_HOST_UNREACH: return "Host unreachable";
        case ICMP_PROT_UNREACH: return "Protocol unreachable";
        case ICMP_PORT_UNREACH: return "Port unreachable";
        case ICMP_FRAG_NEEDED: return "Fragmentation Needed and Don't Fragment was Set";
        case ICMP_SR_FAILED: return "Source route failed";
        case ICMP_NET_UNKNOWN: return "Destination network unknown";
        case ICMP_HOST_UNKNOWN: return "Destination host unknown";
        case ICMP_HOST_ISOLATED: return "Source host isolated";
        case ICMP_NET_ANO: return "Destination net prohibited";
        case ICMP_HOST_ANO: return "Communication with destination host is administratively prohibited";
        case ICMP_NET_UNR_TOS: return "Destination network unreachable for type of service";
        case ICMP_HOST_UNR_TOS: return "Destination host unreachable for type of service";
        case ICMP_PKT_FILTERED: return "Communication administratively prohibited";
        case ICMP_PREC_VIOLATION: return "Host precedence violation";
        case ICMP_PREC_CUTOFF: return "Precedence cutoff in effect";
        default: return "Destination unreachable: Unknown code";
        }
    case ICMP_SOURCE_QUENCH: return "No code";
	case ICMP_REDIRECT:
		switch (code) {
		case ICMP_REDIR_NET: return "Redirect datagram for the network (or subnet)";
		case ICMP_REDIR_HOST: return "Redirect datagram for the host";
		case ICMP_REDIR_NETTOS: return "Redirect datagram for the type of service and network";
		case ICMP_REDIR_HOSTTOS: return "Redirect datagram for the type of service and host";
		default: return "Redirect: Unknown code";
		}
	case ICMP_ECHO: return "No code";
    case 9:
        switch (code) {
        case 0: return "Normal router advertisement";
        case 16: return "Does not route common traffic";
        default: return "Router Advertisement: Unknown code";
        }
    case 10: return "No code";
    case ICMP_TIME_EXCEEDED:
        switch (code) {
        case 0: return "Time to live exceeded in transit";
        case 1: return "Fragment reassembly time exceeded";
        default: return "Time Exceeded: Unknown code";
        }
    case ICMP_PARAMETERPROB:
        switch (code) {
        case 0: return "Pointer indicates the error";
        case 1: return "Missing a required option";
        case 2: return "Bad length";
        default: return "Parameter Problem: Unknown code";
        }
    case ICMP_TIMESTAMP: return "No code";
    case ICMP_TIMESTAMPREPLY: return "No code";
    case 40:
        switch (code) {
        case 0: return "Bad SPI";
        case 1: return "Authentication failed";
        case 2: return "Decompression failed";
        case 3: return "Decryption failed";
        case 4: return "Need authentication";
        case 5: return "Need authorization";
        default: return "Photuris: Unknown code";
        }
    case 42:
        switch (code) {
        case 0: return "No error";
        default: return "Unassigned";
        }
    case 43:
        switch (code) {
        case 0: return "No error";
        case 1: return "Malformed query";
        case 2: return "No such interface";
        case 3: return "No such table entry";
        case 4: return "Multiple interfaces satisfy query";
        default: return "Unassigned";
        }
    }

    return "No registrations";
}

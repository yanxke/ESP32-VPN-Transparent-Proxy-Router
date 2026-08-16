#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* sing-mux v0.3.5 request and smux framing, carried by a VLESS TCP request
 * to sp.mux.sing-box.arpa:444. */
#define SINGMUX_REQUEST_VERSION_0 0
#define SINGMUX_PROTOCOL_SMUX 0
#define SMUX_VERSION_1 1
#define SMUX_CMD_SYN 0
#define SMUX_CMD_FIN 1
#define SMUX_CMD_PSH 2
#define SMUX_CMD_NOP 3
#define SMUX_HEADER_SIZE 8

/** Writes the sing-mux v0 request selector for the smux protocol. */
bool singmux_encode_session_request(uint8_t output[2]);

/** Writes one little-endian smux frame header; payload bytes follow separately. */
bool singmux_encode_smux_header(uint8_t output[SMUX_HEADER_SIZE], uint8_t command,
                                uint32_t stream_id, uint16_t payload_length);
/** Parses one complete smux header without consuming payload bytes. */
bool singmux_decode_smux_header(const uint8_t input[SMUX_HEADER_SIZE], uint8_t *command,
                                uint32_t *stream_id, uint16_t *payload_length);
/** Encodes an IPv4 UDP stream request and its first datagram. */
bool singmux_encode_udp_request(uint8_t *output, size_t output_size, size_t *output_length,
                                uint32_t destination_ip, uint16_t destination_port,
                                const uint8_t *payload, size_t payload_length, bool first_packet);
/* First payload written to an smux TCP stream: big-endian flags=0, then a
 * SOCKS-style destination (IPv4 address type, address, and port). */
bool singmux_encode_tcp_ipv4_request(uint8_t output[9], uint32_t destination_ip,
                                     uint16_t destination_port);
/** Encodes a TCP request using a DNS name destination. */
bool singmux_encode_tcp_domain_request(uint8_t *output, size_t output_size, size_t *output_length,
                                       const char *destination, uint16_t destination_port);

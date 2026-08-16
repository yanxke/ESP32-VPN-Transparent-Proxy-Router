#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Serializes the first direct VLESS XUDP datagram for an IPv4 destination.
 * Returns false when output is too small or an argument is invalid.
 */
bool xudp_encode_ipv4(uint8_t *output, size_t output_size, size_t *output_length,
                      uint32_t destination_ip, uint16_t destination_port, const uint8_t *payload,
                      size_t payload_length);
/** Serializes a subsequent XUDP Keep datagram for an existing association. */
bool xudp_encode_ipv4_keep(uint8_t *output, size_t output_size, size_t *output_length,
                           uint32_t destination_ip, uint16_t destination_port,
                           const uint8_t *payload, size_t payload_length);
/** Parses and validates the XUDP metadata preceding a received datagram. */
bool xudp_decode_header(const uint8_t *metadata, size_t metadata_length, uint8_t *option,
                        uint32_t *source_ip, uint16_t *source_port);

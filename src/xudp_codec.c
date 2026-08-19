#include "xudp_codec.h"

#include <string.h>

bool xudp_encode_ipv4(uint8_t *output, size_t output_size, size_t *output_length,
                      uint32_t destination_ip, uint16_t destination_port, const uint8_t *payload,
                      size_t payload_length)
{
    /* 2-byte metadata length, then 12-byte frame metadata, 2-byte payload length. */
    const size_t required = 16 + payload_length;
    if (!output || !payload || !output_length || payload_length == 0 ||
        payload_length > UINT16_MAX || output_size < required)
    {
        return false;
    }
    size_t p    = 0;
    output[p++] = 0;
    output[p++] = 12;
    output[p++] = 0;
    output[p++] = 0; /* session id */
    output[p++] = 1;
    output[p++] = 1;
    output[p++] = 2; /* New, data, UDP */
    output[p++] = destination_port >> 8;
    output[p++] = destination_port;
    output[p++] = 1; /* V2Ray IPv4 address type */
    memcpy(output + p, &destination_ip, 4);
    p += 4;
    output[p++] = payload_length >> 8;
    output[p++] = payload_length;
    memcpy(output + p, payload, payload_length);
    p += payload_length;
    *output_length = p;
    return true;
}

bool xudp_encode_ipv4_keep(uint8_t *output, size_t output_size, size_t *output_length,
                           uint32_t destination_ip, uint16_t destination_port,
                           const uint8_t *payload, size_t payload_length)
{
    const size_t required = 16 + payload_length;
    if (!output || !payload || !output_length || payload_length == 0 ||
        payload_length > UINT16_MAX || output_size < required)
    {
        return false;
    }
    size_t p    = 0;
    output[p++] = 0;
    output[p++] = 12;
    output[p++] = 0;
    output[p++] = 0; /* one direct-XUDP association per VLESS stream */
    output[p++] = 2;
    output[p++] = 1;
    output[p++] = 2; /* Keep, data, UDP */
    output[p++] = destination_port >> 8;
    output[p++] = destination_port;
    output[p++] = 1;
    memcpy(output + p, &destination_ip, 4);
    p += 4;
    output[p++] = payload_length >> 8;
    output[p++] = payload_length;
    memcpy(output + p, payload, payload_length);
    p += payload_length;
    *output_length = p;
    return true;
}

bool xudp_decode_header(const uint8_t *metadata, size_t metadata_length, uint8_t *option,
                        uint32_t *source_ip, uint16_t *source_port)
{
    if (!metadata || metadata_length < 4 || metadata[2] != 2 || !option)
    {
        return false;
    }
    *option = metadata[3];
    if (metadata_length == 4)
    {
        return true;
    }
    /* Keep frame with an explicit V2Ray IPv4 source address. */
    if (metadata_length != 12 || metadata[4] != 2 || metadata[7] != 1)
    {
        return false;
    }
    if (source_port)
    {
        *source_port = ((uint16_t)metadata[5] << 8) | metadata[6];
    }
    if (source_ip)
    {
        memcpy(source_ip, metadata + 8, 4);
    }
    return true;
}

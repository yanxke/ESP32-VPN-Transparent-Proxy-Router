#include "singmux_codec.h"
#include <string.h>

static void put_le16(uint8_t *o, uint16_t v)
{
    o[0] = v;
    o[1] = v >> 8;
}
static void put_le32(uint8_t *o, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
    {
        o[i] = v >> (8 * i);
    }
}
static uint16_t get_le16(const uint8_t *i)
{
    return (uint16_t)i[0] | ((uint16_t)i[1] << 8);
}
static uint32_t get_le32(const uint8_t *i)
{
    uint32_t v = 0;
    for (int n = 0; n < 4; ++n)
    {
        v |= (uint32_t)i[n] << (8 * n);
    }
    return v;
}

bool singmux_encode_session_request(uint8_t output[2])
{
    if (!output)
    {
        return false;
    }

    output[0] = SINGMUX_REQUEST_VERSION_0;
    output[1] = SINGMUX_PROTOCOL_SMUX;
    return true;
}

bool singmux_encode_smux_header(uint8_t o[SMUX_HEADER_SIZE], uint8_t cmd, uint32_t id, uint16_t len)
{
    if (!o || cmd > SMUX_CMD_NOP)
    {
        return false;
    }
    o[0] = SMUX_VERSION_1;
    o[1] = cmd;
    put_le16(o + 2, len);
    put_le32(o + 4, id);
    return true;
}
bool singmux_decode_smux_header(const uint8_t i[SMUX_HEADER_SIZE], uint8_t *cmd, uint32_t *id,
                                uint16_t *len)
{
    if (!i || !cmd || !id || !len || i[0] != SMUX_VERSION_1 || i[1] > SMUX_CMD_NOP)
    {
        return false;
    }
    *cmd = i[1];
    *len = get_le16(i + 2);
    *id  = get_le32(i + 4);
    return true;
}

bool singmux_encode_udp_request(uint8_t *o, size_t size, size_t *length, uint32_t ip, uint16_t port,
                                const uint8_t *payload, size_t payload_length, bool first)
{
    size_t required = (first ? 9 : 0) + 2 + payload_length;
    if (!o || !length || !payload || !payload_length || payload_length > UINT16_MAX ||
        size < required)
    {
        return false;
    }
    size_t p = 0;
    if (first)
    {
        o[p++] = 0;
        o[p++] = 1;
        o[p++] = 1;
        memcpy(o + p, &ip, 4);
        p += 4;
        o[p++] = port >> 8;
        o[p++] = port;
    }
    o[p++] = payload_length >> 8;
    o[p++] = payload_length;
    memcpy(o + p, payload, payload_length);
    p += payload_length;
    *length = p;
    return true;
}

bool singmux_encode_tcp_ipv4_request(uint8_t o[9], uint32_t ip, uint16_t port)
{
    if (!o)
    {
        return false;
    }
    o[0] = 0;
    o[1] = 0; /* flags: TCP */
    o[2] = 1; /* SOCKS IPv4 */
    memcpy(o + 3, &ip, 4);
    o[7] = port >> 8;
    o[8] = port;
    return true;
}

bool singmux_encode_tcp_domain_request(uint8_t *o, size_t size, size_t *length,
                                       const char *destination, uint16_t port)
{
    size_t name_length = destination ? strlen(destination) : 0;
    if (!o || !length || !name_length || name_length > 253 || size < name_length + 6)
    {
        return false;
    }
    o[0] = 0;
    o[1] = 0; /* flags: TCP */
    o[2] = 3;
    o[3] = name_length;
    memcpy(o + 4, destination, name_length);
    o[4 + name_length] = port >> 8;
    o[5 + name_length] = port;
    *length            = name_length + 6;
    return true;
}

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>

#include "esp_log.h"

#include "transport_tcp.h"

/* Keep wire-level VLESS/direct transport logs scoped to the transport module. */
#ifndef VLESS_TRAFFIC_LOGS
#define VLESS_TRAFFIC_LOGS 0
#endif
#if VLESS_TRAFFIC_LOGS
#define TRAFFIC_LOG(...) ESP_LOGI(__VA_ARGS__)
#else
#define TRAFFIC_LOG(...)                                                                           \
    do                                                                                             \
    {                                                                                              \
    } while (0)
#endif

static const char *TAG = "transport_tcp";

/* 1 KiB relay reads cause excessive task/socket scheduling on an AP+STA
   router.  This stays comfortably below lwIP's MSS aggregation limits while
   reducing copy and select overhead on sustained transfers. */
#define TRANSPORT_RELAY_BUFFER_SIZE 4096

bool transport_tcp_uuid_to_bytes(const char *uuid, uint8_t bytes[16])
{
    int output = 0;
    for (int input = 0; uuid[input] && output < 16;)
    {
        if (uuid[input] == '-')
        {
            input++;
            continue;
        }
        char high_char = uuid[input++];
        char low_char  = uuid[input++];
        int  high = (high_char >= '0' && high_char <= '9')
                        ? high_char - '0'
                        : ((high_char >= 'a' && high_char <= 'f')
                               ? high_char - 'a' + 10
                               : ((high_char >= 'A' && high_char <= 'F')
                                      ? high_char - 'A' + 10
                                      : -1));
        int low = (low_char >= '0' && low_char <= '9')
                      ? low_char - '0'
                      : ((low_char >= 'a' && low_char <= 'f')
                             ? low_char - 'a' + 10
                             : ((low_char >= 'A' && low_char <= 'F')
                                    ? low_char - 'A' + 10
                                    : -1));
        if (high < 0 || low < 0)
        {
            return false;
        }
        bytes[output++] = (uint8_t)((high << 4) | low);
    }
    return output == 16 && uuid[0] && uuid[strlen(uuid) - 1] != '-';
}

static bool socket_send_all(int socket_fd, const uint8_t *data, size_t length)
{
    while (length)
    {
        int sent = send(socket_fd, data, length, 0);
        if (sent <= 0)
        {
            return false;
        }
        data += sent;
        length -= sent;
    }
    return true;
}

static int open_direct_tcp_stream(bool has_upstream, const char *destination,
                                  uint16_t destination_port)
{
    if (!has_upstream || !destination || !destination[0] || strlen(destination) > 253)
    {
        return -1;
    }
    char server_port[6];
    snprintf(server_port, sizeof(server_port), "%u", destination_port);
    struct addrinfo  hints     = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(destination, server_port, &hints, &addresses) != 0)
    {
        return -1;
    }
    int socket_fd = socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
    if (socket_fd < 0 || connect(socket_fd, addresses->ai_addr, addresses->ai_addrlen) != 0)
    {
        if (socket_fd >= 0)
        {
            close(socket_fd);
        }
        freeaddrinfo(addresses);
        return -1;
    }
    freeaddrinfo(addresses);
    return socket_fd;
}

static int open_direct_ipv4_stream(bool has_upstream, uint32_t destination_ip,
                                   uint16_t destination_port)
{
    if (!has_upstream)
    {
        return -1;
    }
    int                socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in address   = {
        .sin_family = AF_INET, .sin_port = htons(destination_port), .sin_addr.s_addr = destination_ip};
    if (socket_fd < 0 || connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        if (socket_fd >= 0)
        {
            close(socket_fd);
        }
        return -1;
    }
    return socket_fd;
}

int transport_tcp_open_vless_stream(const router_config_t *config, bool has_upstream,
                                    const char *destination, uint16_t destination_port)
{
    uint8_t uuid[16];
    if (!has_upstream || !config || !transport_tcp_uuid_to_bytes(config->vless_uuid, uuid) ||
        !destination || strlen(destination) > 253)
    {
        ESP_LOGW(TAG, "VLESS stream unavailable: upstream=%d configuration=%d", has_upstream,
                 config && config->vless_host[0] != '\0');
        return -1;
    }
    char server_port[6];
    snprintf(server_port, sizeof(server_port), "%u", config->vless_port);
    struct addrinfo  hints     = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(config->vless_host, server_port, &hints, &addresses) != 0)
    {
        ESP_LOGW(TAG, "Could not resolve VLESS server");
        return -1;
    }
    int socket_fd = socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
    if (socket_fd < 0 || connect(socket_fd, addresses->ai_addr, addresses->ai_addrlen) != 0)
    {
        if (socket_fd >= 0)
        {
            close(socket_fd);
        }
        freeaddrinfo(addresses);
        return -1;
    }
    TRAFFIC_LOG(TAG, "opening VLESS stream to %s:%u", destination, destination_port);
    freeaddrinfo(addresses);
    uint8_t header[300] = {0};
    size_t  length      = 0;
    header[length++]    = 0;
    memcpy(header + length, uuid, sizeof(uuid));
    length += sizeof(uuid);
    header[length++] = 0;
    header[length++] = 1;
    header[length++] = destination_port >> 8;
    header[length++] = destination_port;
    header[length++] = 2;
    header[length++] = strlen(destination);
    memcpy(header + length, destination, strlen(destination));
    length += strlen(destination);
    if (!socket_send_all(socket_fd, header, length))
    {
        ESP_LOGW(TAG, "VLESS handshake failed");
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

int transport_tcp_open_vless_ipv4_stream(const router_config_t *config, bool has_upstream,
                                         uint32_t destination_ip, uint16_t destination_port)
{
    uint8_t uuid[16];
    if (!has_upstream || !config || !transport_tcp_uuid_to_bytes(config->vless_uuid, uuid))
    {
        return -1;
    }
    char server_port[6];
    snprintf(server_port, sizeof(server_port), "%u", config->vless_port);
    struct addrinfo  hints     = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(config->vless_host, server_port, &hints, &addresses) != 0)
    {
        return -1;
    }
    int socket_fd = socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
    if (socket_fd < 0 || connect(socket_fd, addresses->ai_addr, addresses->ai_addrlen) != 0)
    {
        if (socket_fd >= 0)
        {
            close(socket_fd);
        }
        freeaddrinfo(addresses);
        return -1;
    }
    freeaddrinfo(addresses);
    uint8_t header[26] = {0};
    size_t  length     = 0;
    header[length++]   = 0;
    memcpy(header + length, uuid, sizeof(uuid));
    length += sizeof(uuid);
    header[length++] = 0;
    header[length++] = 1;
    header[length++] = destination_port >> 8;
    header[length++] = destination_port;
    header[length++] = 1;
    memcpy(header + length, &destination_ip, 4);
    length += 4;
    if (!socket_send_all(socket_fd, header, length))
    {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

int transport_tcp_open_domain(transparent_mode_t mode, const router_config_t *config,
                              bool has_upstream, const char *destination,
                              uint16_t destination_port)
{
    return mode == TRANSPARENT_MODE_VLESS
               ? transport_tcp_open_vless_stream(config, has_upstream, destination,
                                                 destination_port)
               : open_direct_tcp_stream(has_upstream, destination, destination_port);
}

int transport_tcp_open_ipv4(transparent_mode_t mode, const router_config_t *config,
                            bool has_upstream, uint32_t destination_ip,
                            uint16_t destination_port)
{
    return mode == TRANSPARENT_MODE_VLESS
               ? transport_tcp_open_vless_ipv4_stream(config, has_upstream, destination_ip,
                                                      destination_port)
               : open_direct_ipv4_stream(has_upstream, destination_ip, destination_port);
}

void transport_tcp_relay_vless(int client, int tunnel, const char *label,
                               transport_tcp_bandwidth_fn upload,
                               transport_tcp_bandwidth_fn download)
{
    bool vless_header_pending = true;
    uint8_t vless_header[257];
    size_t  vless_header_length   = 0;
    size_t  vless_header_expected = 0;
    bool    prefer_tunnel         = false;
    for (;;)
    {
        fd_set reads;
        FD_ZERO(&reads);
        FD_SET(client, &reads);
        FD_SET(tunnel, &reads);
        int max_fd = client > tunnel ? client : tunnel;
        if (select(max_fd + 1, &reads, NULL, NULL, NULL) <= 0)
        {
            break;
        }
        bool client_ready = FD_ISSET(client, &reads);
        bool tunnel_ready = FD_ISSET(tunnel, &reads);
        int  source       = tunnel_ready && (!client_ready || prefer_tunnel) ? tunnel : client;
        prefer_tunnel     = !prefer_tunnel;
        int     target    = source == client ? tunnel : client;
        uint8_t buffer[TRANSPORT_RELAY_BUFFER_SIZE];
        int     count = recv(source, buffer, sizeof(buffer), 0);
        if (count <= 0)
        {
            break;
        }
        TRAFFIC_LOG(TAG, "%s relaying %d bytes from %s", label, count,
                    source == client ? "client" : "VLESS");
        if (source == tunnel && vless_header_pending)
        {
            size_t consumed = 0;
            while (consumed < (size_t)count && vless_header_pending)
            {
                if (vless_header_length >= sizeof(vless_header))
                {
                    ESP_LOGW(TAG, "%s VLESS response header is too large", label);
                    return;
                }
                vless_header[vless_header_length++] = buffer[consumed++];
                if (vless_header_length == 1 && vless_header[0] != 0)
                {
                    ESP_LOGW(TAG, "%s received an invalid VLESS response header", label);
                    return;
                }
                if (vless_header_length == 2)
                {
                    vless_header_expected = 2U + vless_header[1];
                    if (vless_header_expected > sizeof(vless_header))
                    {
                        ESP_LOGW(TAG, "%s VLESS response header length is invalid", label);
                        return;
                    }
                }
                if (vless_header_expected && vless_header_length == vless_header_expected)
                {
                    vless_header_pending = false;
                    TRAFFIC_LOG(TAG, "%s VLESS stream established", label);
                }
            }
            if (vless_header_pending || consumed == (size_t)count)
            {
                continue;
            }
            memmove(buffer, buffer + consumed, (size_t)count - consumed);
            count -= (int)consumed;
        }
        if (count && !socket_send_all(target, buffer, count))
        {
            break;
        }
        if (source == client)
        {
            upload((size_t)count);
        }
        else
        {
            download((size_t)count);
        }
    }
}

void transport_tcp_relay_plain(int client, int upstream, const char *label,
                               transport_tcp_bandwidth_fn upload,
                               transport_tcp_bandwidth_fn download)
{
    bool prefer_upstream = false;
    for (;;)
    {
        fd_set reads;
        FD_ZERO(&reads);
        FD_SET(client, &reads);
        FD_SET(upstream, &reads);
        int max_fd = client > upstream ? client : upstream;
        if (select(max_fd + 1, &reads, NULL, NULL, NULL) <= 0)
        {
            break;
        }
        bool client_ready   = FD_ISSET(client, &reads);
        bool upstream_ready = FD_ISSET(upstream, &reads);
        int  source = upstream_ready && (!client_ready || prefer_upstream) ? upstream : client;
        prefer_upstream = !prefer_upstream;
        int     target = source == client ? upstream : client;
        uint8_t buffer[TRANSPORT_RELAY_BUFFER_SIZE];
        int     count = recv(source, buffer, sizeof(buffer), 0);
        if (count <= 0)
        {
            break;
        }
        TRAFFIC_LOG(TAG, "%s relaying %d bytes from %s", label, count,
                    source == client ? "client" : "upstream");
        if (!socket_send_all(target, buffer, count))
        {
            break;
        }
        if (source == client)
        {
            upload((size_t)count);
        }
        else
        {
            download((size_t)count);
        }
    }
}

void transport_tcp_relay(transparent_mode_t mode, int client, int tunnel, const char *label,
                         transport_tcp_bandwidth_fn upload,
                         transport_tcp_bandwidth_fn download)
{
    if (mode == TRANSPARENT_MODE_VLESS)
    {
        transport_tcp_relay_vless(client, tunnel, label, upload, download);
    }
    else
    {
        transport_tcp_relay_plain(client, tunnel, label, upload, download);
    }
}

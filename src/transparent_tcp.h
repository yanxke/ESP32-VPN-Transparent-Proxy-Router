#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRANSPARENT_TCP_MAX_FLOWS 60
#define TRANSPARENT_TCP_LISTEN_BACKLOG 64
#define TRANSPARENT_UDP_MAX_FLOWS 128
#define TRANSPARENT_UDP_RELAY_PORT 15002

typedef struct
{
    bool     in_use;
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t original_ip;
    uint16_t original_port;
    uint16_t relay_port;
    uint32_t last_activity_ms;
} transparent_tcp_flow_t;

typedef struct
{
    bool     in_use;
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t original_ip;
    uint16_t original_port;
    uint32_t last_activity_ms;
} transparent_udp_flow_t;

/** Initializes packet-hook state and all bounded flow/DNS tables. */
void transparent_tcp_init(void);
/** Supplies the SoftAP netif used for packet interception and reply rewriting. */
void transparent_tcp_set_ap_netif(void *netif_impl);
/** Installs the AP link-output hook after the AP network interface exists. */
void transparent_tcp_install_ap_output(void);
/** Enables or disables transparent interception; disabled mode preserves portal access. */
void transparent_tcp_set_enabled(bool enabled);
bool transparent_tcp_is_enabled(void);
/** Adds or refreshes an IPv4 DNS cache entry used to recover VLESS domains. */
void transparent_tcp_dns_record(const char *name, uint32_t address);
/** Resolves a cached IPv4 address to a DNS name; returns false on a cache miss. */
bool transparent_tcp_dns_name_for_ip(uint32_t address, char *name, size_t name_size);
/** Looks up an intercepted TCP flow by original client tuple. */
bool transparent_tcp_get(uint32_t client_ip, uint16_t client_port, transparent_tcp_flow_t *flow);
/** Creates or refreshes an intercepted TCP flow and returns its current state. */
bool transparent_tcp_create_or_get(uint32_t client_ip, uint16_t client_port, uint32_t original_ip,
                                   uint16_t original_port, transparent_tcp_flow_t *flow);
/** Updates last activity for a TCP flow. */
void transparent_tcp_touch(uint32_t client_ip, uint16_t client_port);
/** Records the local relay port used to restore reply tuples. */
void transparent_tcp_set_relay_port(uint32_t client_ip, uint16_t client_port, uint16_t relay_port);
/** Removes one TCP flow after its relay task completes. */
void transparent_tcp_remove(uint32_t client_ip, uint16_t client_port);
/** Removes expired TCP flows; call periodically from the maintenance task. */
void transparent_tcp_expire(uint32_t now_ms);
/** Looks up an intercepted UDP flow by client tuple. */
bool transparent_udp_get(uint32_t client_ip, uint16_t client_port, transparent_udp_flow_t *flow);
/** Creates or refreshes an intercepted UDP flow and returns its current state. */
bool transparent_udp_create_or_get(uint32_t client_ip, uint16_t client_port, uint32_t original_ip,
                                   uint16_t original_port, transparent_udp_flow_t *flow);
/** Updates last activity for a UDP flow. */
void transparent_udp_touch(uint32_t client_ip, uint16_t client_port);
/** Removes expired UDP flows; call periodically from the maintenance task. */
void transparent_udp_expire(uint32_t now_ms);

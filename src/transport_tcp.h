#ifndef TRANSPORT_TCP_H
#define TRANSPORT_TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "router_config.h"

typedef void (*transport_tcp_bandwidth_fn)(size_t bytes);

bool transport_tcp_uuid_to_bytes(const char *uuid, uint8_t bytes[16]);
int  transport_tcp_open_vless_stream(const router_config_t *config, bool has_upstream,
                                     const char *destination, uint16_t destination_port);
int  transport_tcp_open_vless_ipv4_stream(const router_config_t *config, bool has_upstream,
                                          uint32_t destination_ip, uint16_t destination_port);
int  transport_tcp_open_domain(transparent_mode_t mode, const router_config_t *config,
                               bool has_upstream, const char *destination,
                               uint16_t destination_port);
int  transport_tcp_open_ipv4(transparent_mode_t mode, const router_config_t *config,
                             bool has_upstream, uint32_t destination_ip,
                             uint16_t destination_port);
void transport_tcp_relay_vless(int client, int tunnel, const char *label,
                               transport_tcp_bandwidth_fn upload,
                               transport_tcp_bandwidth_fn download);
void transport_tcp_relay_plain(int client, int upstream, const char *label,
                               transport_tcp_bandwidth_fn upload,
                               transport_tcp_bandwidth_fn download);
void transport_tcp_relay(transparent_mode_t mode, int client, int tunnel, const char *label,
                         transport_tcp_bandwidth_fn upload,
                         transport_tcp_bandwidth_fn download);

#endif
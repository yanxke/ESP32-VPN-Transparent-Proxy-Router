#pragma once

#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

int transparent_tcp_ip4_input(struct pbuf *packet, struct netif *input_netif);

#define LWIP_HOOK_IP4_INPUT(packet, input_netif) transparent_tcp_ip4_input(packet, input_netif)

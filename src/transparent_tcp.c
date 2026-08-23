#include <string.h>

#include "esp_timer.h"
#include "esp_log.h"
#include "transparent_tcp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip4.h"
#include "freertos/FreeRTOS.h"

#define TRANSPARENT_RELAY_PORT 15001

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

static transparent_tcp_flow_t s_flows[TRANSPARENT_TCP_MAX_FLOWS];
static transparent_udp_flow_t s_udp_flows[TRANSPARENT_UDP_MAX_FLOWS];
static portMUX_TYPE           s_flow_lock = portMUX_INITIALIZER_UNLOCKED;
static struct netif          *s_ap_netif;
static netif_output_fn        s_ap_original_output;
static netif_linkoutput_fn    s_ap_original_linkoutput;
static bool                   s_reinjecting;
static bool                   s_enabled = true;
static uint32_t               s_last_udp_discovery_log_ms;
typedef struct
{
    bool     in_use;
    uint32_t address;
    char     name[254];
} dns_entry_t;
/* Modern pages resolve many CDN hostnames before opening their TLS sockets.
   Keep enough A-record context that transparent VLESS can retain a domain
   destination throughout a normal browser page load. */
static dns_entry_t  s_dns_entries[64];
static portMUX_TYPE s_dns_lock = portMUX_INITIALIZER_UNLOCKED;
static const char  *TAG        = "transparent_tcp";

static uint32_t access_point_ipv4(void)
{
    return netif_ip4_addr(s_ap_netif)->addr;
}

/* Link-local service discovery is not routable through a remote VPN endpoint.
   Dropping it here keeps mDNS, LLMNR and WS-Discovery bursts from consuming
   the bounded XUDP relay resources used by real Internet traffic. */
static bool is_link_local_multicast_or_broadcast(uint32_t destination_ip)
{
    const uint8_t *address = (const uint8_t *)&destination_ip;
    return address[0] >= 224;
}

/* RFC 1624 incremental Internet checksum update.  Redirecting a packet changes
 * only four 16-bit
 * words (IPv4 source/destination and the two ports), so
 * rescanning every payload byte is
 * needless work in the AP+STA hot path. */
static uint16_t checksum_replace(uint16_t checksum, uint16_t old_word, uint16_t new_word)
{
    uint32_t sum = (uint16_t)~checksum + (uint16_t)~old_word + new_word;
    sum          = (sum & 0xffff) + (sum >> 16);
    sum          = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t read_u16(const uint8_t *data)
{
    return ((uint16_t)data[0] << 8) | data[1];
}

static uint16_t checksum_replace_u32(uint16_t checksum, uint32_t old_value, uint32_t new_value)
{
    const uint8_t *old_bytes = (const uint8_t *)&old_value;
    const uint8_t *new_bytes = (const uint8_t *)&new_value;
    checksum                 = checksum_replace(checksum, read_u16(old_bytes), read_u16(new_bytes));
    return checksum_replace(checksum, read_u16(old_bytes + 2), read_u16(new_bytes + 2));
}

static bool rewrite_packet(struct pbuf *packet, const uint8_t ip_header[60], uint8_t ihl,
                           uint32_t source_ip, uint16_t source_port, uint32_t destination_ip,
                           uint16_t destination_port)
{
    uint16_t total_length    = read_u16(ip_header + 2);
    uint8_t  protocol        = ip_header[9];
    uint16_t minimum_length  = protocol == 6 ? 20 : (protocol == 17 ? 8 : 0);
    uint16_t checksum_offset = protocol == 6 ? 16 : 6;
    if (!minimum_length || total_length < ihl + minimum_length || total_length > packet->tot_len)
    {
        return false;
    }
    uint8_t header[64];
    memcpy(header, ip_header, ihl);
    uint32_t old_source_ip;
    uint32_t old_destination_ip;
    memcpy(&old_source_ip, ip_header + 12, sizeof(old_source_ip));
    memcpy(&old_destination_ip, ip_header + 16, sizeof(old_destination_ip));
    uint16_t old_ip_checksum = read_u16(header + 10);
    uint8_t  old_ports[4];
    if (pbuf_copy_partial(packet, old_ports, sizeof(old_ports), ihl) != sizeof(old_ports))
    {
        return false;
    }
    uint16_t old_source_port      = read_u16(old_ports);
    uint16_t old_destination_port = read_u16(old_ports + 2);
    uint8_t  transport_checksum_bytes[2];
    if (pbuf_copy_partial(packet, transport_checksum_bytes, sizeof(transport_checksum_bytes),
                          ihl + checksum_offset) != sizeof(transport_checksum_bytes))
    {
        return false;
    }
    uint16_t transport_checksum = read_u16(transport_checksum_bytes);
    memcpy(header + 12, &source_ip, sizeof(source_ip));
    memcpy(header + 16, &destination_ip, sizeof(destination_ip));
    uint16_t ip_checksum = checksum_replace_u32(old_ip_checksum, old_source_ip, source_ip);
    ip_checksum          = checksum_replace_u32(ip_checksum, old_destination_ip, destination_ip);
    header[10]           = ip_checksum >> 8;
    header[11]           = ip_checksum;
    if (pbuf_take_at(packet, header, ihl, 0) != ERR_OK)
    {
        return false;
    }

    uint8_t ports[4] = {source_port >> 8, source_port, destination_port >> 8, destination_port};
    if (pbuf_take_at(packet, ports, sizeof(ports), ihl) != ERR_OK)
    {
        return false;
    }
    /* UDP over IPv4 may deliberately omit its checksum; preserve that case. */
    if (transport_checksum == 0 && protocol == 17)
    {
        return true;
    }
    transport_checksum = checksum_replace_u32(transport_checksum, old_source_ip, source_ip);
    transport_checksum =
        checksum_replace_u32(transport_checksum, old_destination_ip, destination_ip);
    transport_checksum = checksum_replace(transport_checksum, old_source_port, source_port);
    transport_checksum =
        checksum_replace(transport_checksum, old_destination_port, destination_port);
    if (protocol == 17 && transport_checksum == 0)
    {
        transport_checksum = 0xffff; /* RFC 768 wire representation. */
    }
    transport_checksum_bytes[0] = transport_checksum >> 8;
    transport_checksum_bytes[1] = transport_checksum;
    return pbuf_take_at(packet, transport_checksum_bytes, sizeof(transport_checksum_bytes),
                        ihl + checksum_offset) == ERR_OK;
}

int transparent_tcp_ip4_input(struct pbuf *packet, struct netif *input_netif)
{
    if (!s_enabled)
    {
        return 0;
    }
    if (s_reinjecting)
    {
        return 0;
    }
    if (input_netif != s_ap_netif || packet->tot_len < 40)
    {
        return 0;
    }
    uint8_t header[60];
    if (pbuf_copy_partial(packet, header, 40, 0) != 40)
    {
        return 0;
    }
    uint8_t ihl = (header[0] & 0x0f) * 4;
    if ((header[0] >> 4) != 4 || ihl < 20 || packet->tot_len < ihl)
    {
        return 0;
    }
    if (ihl > 40 && pbuf_copy_partial(packet, header, ihl, 0) != ihl)
    {
        return 0;
    }
    uint32_t client_ip, destination_ip;
    memcpy(&client_ip, header + 12, sizeof(client_ip));
    memcpy(&destination_ip, header + 16, sizeof(destination_ip));
    uint32_t ap_ip = access_point_ipv4();
    if (destination_ip == ap_ip)
    {
        return 0; /* Keep the portal, DNS, SOCKS listener, and router services local. */
    }
    if (header[9] == 17)
    {
        /* DHCP uses broadcast during lease acquisition/renewal, so keep it. */
        if (packet->tot_len < ihl + 8)
        {
            return 0;
        }
        uint16_t source_port      = ((uint16_t)header[ihl] << 8) | header[ihl + 1];
        uint16_t destination_port = ((uint16_t)header[ihl + 2] << 8) | header[ihl + 3];
        if (source_port == 68 && destination_port == 67)
        {
            return 0;
        }
        if (is_link_local_multicast_or_broadcast(destination_ip))
        {
            uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
            if (now - s_last_udp_discovery_log_ms >= 5000)
            {
                s_last_udp_discovery_log_ms = now;
                TRAFFIC_LOG(TAG, "dropping local multicast/broadcast UDP before XUDP relay");
            }
            pbuf_free(packet);
            return 1;
        }
        transparent_udp_flow_t flow;
        if (!transparent_udp_create_or_get(client_ip, source_port, destination_ip, destination_port,
                                           &flow))
        {
            ESP_LOGW(TAG, "UDP flow table full; dropping client datagram");
            pbuf_free(packet);
            return 1;
        }
        transparent_udp_touch(client_ip, source_port);
        struct pbuf *rewritten_packet = pbuf_alloc(PBUF_RAW, packet->tot_len, PBUF_RAM);
        if (!rewritten_packet || pbuf_copy(rewritten_packet, packet) != ERR_OK)
        {
            if (rewritten_packet)
            {
                pbuf_free(rewritten_packet);
            }
            return 0;
        }
        if (!rewrite_packet(rewritten_packet, header, ihl, client_ip, source_port, ap_ip,
                            TRANSPARENT_UDP_RELAY_PORT))
        {
            pbuf_free(rewritten_packet);
            return 0;
        }
        s_reinjecting = true;
        ip4_input(rewritten_packet, input_netif);
        s_reinjecting = false;
        pbuf_free(packet);
        return 1;
    }
    if (header[9] != 6 || packet->tot_len < ihl + 20)
    {
        return 0;
    }
    uint16_t               client_port      = ((uint16_t)header[ihl] << 8) | header[ihl + 1];
    uint16_t               destination_port = ((uint16_t)header[ihl + 2] << 8) | header[ihl + 3];
    uint8_t                flags            = header[ihl + 13];
    transparent_tcp_flow_t flow;
    bool                   have_flow = transparent_tcp_get(client_ip, client_port, &flow);
    if (!have_flow && (flags & 0x02) && !(flags & 0x10))
    {
        have_flow = transparent_tcp_create_or_get(client_ip, client_port, destination_ip,
                                                  destination_port, &flow);
        if (have_flow)
        {
            TRAFFIC_LOG(TAG, "redirecting client TCP %u -> remote port %u", client_port,
                        destination_port);
        }
    }
    if (!have_flow)
    {
        return 0;
    }
    transparent_tcp_touch(client_ip, client_port);
    struct pbuf *rewritten_packet = pbuf_alloc(PBUF_RAW, packet->tot_len, PBUF_RAM);
    if (!rewritten_packet || pbuf_copy(rewritten_packet, packet) != ERR_OK)
    {
        if (rewritten_packet)
        {
            pbuf_free(rewritten_packet);
        }
        ESP_LOGW(TAG, "could not allocate packet for transparent rewrite");
        return 0;
    }
    if (!rewrite_packet(rewritten_packet, header, ihl, client_ip, client_port, ap_ip,
                        TRANSPARENT_RELAY_PORT))
    {
        pbuf_free(rewritten_packet);
        ESP_LOGW(TAG, "could not rewrite intercepted packet");
        return 0;
    }
    /* The outer ip4_input already captured an IP-header pointer before this hook.
       Reinject so the normal path reparses the rewritten tuple, then mark this
       original invocation as consumed. */
    s_reinjecting = true;
    ip4_input(rewritten_packet, input_netif);
    s_reinjecting = false;
    pbuf_free(packet);
    return 1;
}

static err_t transparent_tcp_ap_output(struct netif *netif, struct pbuf *packet,
                                       const ip4_addr_t *ipaddr)
{
    if (!s_ap_original_output)
    {
        return ERR_IF;
    }
    if (!s_enabled)
    {
        return s_ap_original_output(netif, packet, ipaddr);
    }
    if (packet->tot_len < 40)
    {
        return s_ap_original_output(netif, packet, ipaddr);
    }
    uint8_t header[60];
    if (pbuf_copy_partial(packet, header, 40, 0) != 40)
    {
        return s_ap_original_output(netif, packet, ipaddr);
    }
    uint8_t ihl = (header[0] & 0x0f) * 4;
    if ((header[0] >> 4) != 4 || ihl < 20 || ihl > sizeof(header) ||
        (header[9] != 6 && header[9] != 17) || packet->tot_len < ihl + 8)
    {
        return s_ap_original_output(netif, packet, ipaddr);
    }
    if (ihl > 40 && pbuf_copy_partial(packet, header, ihl, 0) != ihl)
    {
        return s_ap_original_output(netif, packet, ipaddr);
    }
    uint32_t source_ip, destination_ip;
    memcpy(&source_ip, header + 12, 4);
    memcpy(&destination_ip, header + 16, 4);
    uint16_t source_port      = ((uint16_t)header[ihl] << 8) | header[ihl + 1];
    uint16_t destination_port = ((uint16_t)header[ihl + 2] << 8) | header[ihl + 3];
    if (source_ip == access_point_ipv4() && source_port == TRANSPARENT_RELAY_PORT)
    {
        transparent_tcp_flow_t flow;
        if (transparent_tcp_get(destination_ip, destination_port, &flow))
        {
            TRAFFIC_LOG(TAG, "rewriting transparent relay reply to client port %u",
                        flow.client_port);
            rewrite_packet(packet, header, ihl, flow.original_ip, flow.original_port,
                           flow.client_ip, flow.client_port);
        }
    }
    else if (header[9] == 17 && source_ip == access_point_ipv4() &&
             source_port == TRANSPARENT_UDP_RELAY_PORT)
    {
        transparent_udp_flow_t flow;
        if (transparent_udp_get(destination_ip, destination_port, &flow))
        {
            rewrite_packet(packet, header, ihl, flow.original_ip, flow.original_port,
                           flow.client_ip, flow.client_port);
        }
    }
    return s_ap_original_output(netif, packet, ipaddr);
}

static err_t transparent_tcp_ap_linkoutput(struct netif *netif, struct pbuf *packet)
{
    if (!s_ap_original_linkoutput)
    {
        return ERR_IF;
    }
    if (!s_enabled)
    {
        return s_ap_original_linkoutput(netif, packet);
    }
    if (packet->tot_len < 40)
    {
        return s_ap_original_linkoutput(netif, packet);
    }
    uint8_t first[14];
    if (pbuf_copy_partial(packet, first, sizeof(first), 0) != sizeof(first))
    {
        return s_ap_original_linkoutput(netif, packet);
    }
    size_t ip_offset = 0;
    if ((first[0] >> 4) != 4)
    {
        if (first[12] != 0x08 || first[13] != 0x00 || packet->tot_len < 54)
        {
            return s_ap_original_linkoutput(netif, packet);
        }
        ip_offset = 14;
        if (pbuf_header(packet, -(s16_t)ip_offset) != 0)
        {
            return s_ap_original_linkoutput(netif, packet);
        }
    }

    uint8_t header[60];
    bool    rewritten = false;
    if (pbuf_copy_partial(packet, header, 40, 0) == 40)
    {
        uint8_t ihl = (header[0] & 0x0f) * 4;
        if ((header[0] >> 4) == 4 && ihl >= 20 && ihl <= sizeof(header) - 4 &&
            (header[9] == 6 || header[9] == 17) && packet->tot_len >= ihl + 8 &&
            (ihl + 4 <= 40 || pbuf_copy_partial(packet, header, ihl + 4, 0) == ihl + 4))
        {
            uint32_t source_ip, destination_ip;
            memcpy(&source_ip, header + 12, 4);
            memcpy(&destination_ip, header + 16, 4);
            uint16_t source_port      = ((uint16_t)header[ihl] << 8) | header[ihl + 1];
            uint16_t destination_port = ((uint16_t)header[ihl + 2] << 8) | header[ihl + 3];
            if (source_ip == access_point_ipv4() && source_port == TRANSPARENT_RELAY_PORT)
            {
                transparent_tcp_flow_t flow;
                if (transparent_tcp_get(destination_ip, destination_port, &flow))
                {
                    TRAFFIC_LOG(TAG, "rewriting link-layer relay reply to client port %u",
                                flow.client_port);
                    rewritten =
                        rewrite_packet(packet, header, ihl, flow.original_ip, flow.original_port,
                                       flow.client_ip, flow.client_port);
                }
            }
            else if (header[9] == 17 && source_ip == access_point_ipv4() &&
                     source_port == TRANSPARENT_UDP_RELAY_PORT)
            {
                transparent_udp_flow_t flow;
                if (transparent_udp_get(destination_ip, destination_port, &flow))
                {
                    rewritten =
                        rewrite_packet(packet, header, ihl, flow.original_ip, flow.original_port,
                                       flow.client_ip, flow.client_port);
                }
            }
        }
    }
    (void)rewritten;
    if (ip_offset)
    {
        pbuf_header(packet, (s16_t)ip_offset);
    }
    return s_ap_original_linkoutput(netif, packet);
}

void transparent_tcp_set_ap_netif(void *netif_impl)
{
    s_ap_netif = netif_impl;
}

void transparent_tcp_install_ap_output(void)
{
    if (s_ap_netif && !s_ap_original_output)
    {
        s_ap_original_output = s_ap_netif->output;
        s_ap_netif->output   = transparent_tcp_ap_output;
        ESP_LOGI(TAG, "AP output tuple rewriter installed");
    }
    if (s_ap_netif && !s_ap_original_linkoutput)
    {
        s_ap_original_linkoutput = s_ap_netif->linkoutput;
        s_ap_netif->linkoutput   = transparent_tcp_ap_linkoutput;
        ESP_LOGI(TAG, "AP link-output tuple rewriter installed");
    }
}

void transparent_tcp_init(void)
{
    memset(s_flows, 0, sizeof(s_flows));
    memset(s_udp_flows, 0, sizeof(s_udp_flows));
    memset(s_dns_entries, 0, sizeof(s_dns_entries));
}

void transparent_tcp_set_enabled(bool enabled)
{
    s_enabled = enabled;
    ESP_LOGW(TAG, "transparent TCP interception %s",
             enabled ? "enabled" : "disabled for this boot");
}

bool transparent_tcp_is_enabled(void)
{
    return s_enabled;
}

void transparent_tcp_dns_record(const char *name, uint32_t address)
{
    if (!name || !name[0] || !address)
    {
        return;
    }
    portENTER_CRITICAL(&s_dns_lock);
    dns_entry_t *entry = NULL;
    for (int i = 0; i < 64; ++i)
    {
        if (s_dns_entries[i].in_use && s_dns_entries[i].address == address)
        {
            entry = &s_dns_entries[i];
            break;
        }
    }
    if (!entry)
    {
        for (int i = 0; i < 64; ++i)
        {
            if (!s_dns_entries[i].in_use)
            {
                entry = &s_dns_entries[i];
                break;
            }
        }
    }
    if (!entry)
    {
        entry = &s_dns_entries[0];
    }
    entry->in_use  = true;
    entry->address = address;
    strlcpy(entry->name, name, sizeof(entry->name));
    portEXIT_CRITICAL(&s_dns_lock);
}

bool transparent_tcp_dns_name_for_ip(uint32_t address, char *name, size_t name_size)
{
    bool found = false;
    portENTER_CRITICAL(&s_dns_lock);
    for (int i = 0; i < 64; ++i)
    {
        if (s_dns_entries[i].in_use && s_dns_entries[i].address == address)
        {
            strlcpy(name, s_dns_entries[i].name, name_size);
            found = true;
            break;
        }
    }
    portEXIT_CRITICAL(&s_dns_lock);
    return found;
}

static transparent_tcp_flow_t *flow_find_locked(uint32_t client_ip, uint16_t client_port)
{
    for (int i = 0; i < TRANSPARENT_TCP_MAX_FLOWS; ++i)
    {
        if (s_flows[i].in_use && s_flows[i].client_ip == client_ip &&
            s_flows[i].client_port == client_port)
        {
            return &s_flows[i];
        }
    }
    return NULL;
}

bool transparent_tcp_get(uint32_t client_ip, uint16_t client_port, transparent_tcp_flow_t *flow)
{
    bool found = false;
    portENTER_CRITICAL(&s_flow_lock);
    transparent_tcp_flow_t *entry = flow_find_locked(client_ip, client_port);
    if (entry && flow)
    {
        *flow = *entry;
        found = true;
    }
    portEXIT_CRITICAL(&s_flow_lock);
    return found;
}

bool transparent_tcp_create_or_get(uint32_t client_ip, uint16_t client_port, uint32_t original_ip,
                                   uint16_t original_port, transparent_tcp_flow_t *flow)
{
    bool found = false;
    portENTER_CRITICAL(&s_flow_lock);
    transparent_tcp_flow_t *entry = flow_find_locked(client_ip, client_port);
    if (!entry)
    {
        for (int i = 0; i < TRANSPARENT_TCP_MAX_FLOWS; ++i)
        {
            if (!s_flows[i].in_use)
            {
                entry = &s_flows[i];
                break;
            }
        }
    }
    if (entry)
    {
        if (!entry->in_use)
        {
            *entry = (transparent_tcp_flow_t){.in_use        = true,
                                              .client_ip     = client_ip,
                                              .client_port   = client_port,
                                              .original_ip   = original_ip,
                                              .original_port = original_port,
                                              .last_activity_ms =
                                                  (uint32_t)(esp_timer_get_time() / 1000)};
        }
        if (flow)
        {
            *flow = *entry;
        }
        found = true;
    }
    portEXIT_CRITICAL(&s_flow_lock);
    return found;
}

void transparent_tcp_touch(uint32_t client_ip, uint16_t client_port)
{
    portENTER_CRITICAL(&s_flow_lock);
    transparent_tcp_flow_t *entry = flow_find_locked(client_ip, client_port);
    if (entry)
    {
        entry->last_activity_ms = (uint32_t)(esp_timer_get_time() / 1000);
    }
    portEXIT_CRITICAL(&s_flow_lock);
}

void transparent_tcp_set_relay_port(uint32_t client_ip, uint16_t client_port, uint16_t relay_port)
{
    portENTER_CRITICAL(&s_flow_lock);
    transparent_tcp_flow_t *entry = flow_find_locked(client_ip, client_port);
    if (entry)
    {
        entry->relay_port = relay_port;
    }
    portEXIT_CRITICAL(&s_flow_lock);
}

void transparent_tcp_remove(uint32_t client_ip, uint16_t client_port)
{
    portENTER_CRITICAL(&s_flow_lock);
    transparent_tcp_flow_t *entry = flow_find_locked(client_ip, client_port);
    if (entry)
    {
        memset(entry, 0, sizeof(*entry));
    }
    portEXIT_CRITICAL(&s_flow_lock);
}

void transparent_tcp_expire(uint32_t now_ms)
{
    portENTER_CRITICAL(&s_flow_lock);
    for (int i = 0; i < TRANSPARENT_TCP_MAX_FLOWS; ++i)
    {
        if (s_flows[i].in_use && now_ms - s_flows[i].last_activity_ms > 120000)
        {
            s_flows[i].in_use = false;
        }
    }
    portEXIT_CRITICAL(&s_flow_lock);
}

static transparent_udp_flow_t *udp_flow_find_locked(uint32_t client_ip, uint16_t client_port)
{
    for (int i = 0; i < TRANSPARENT_UDP_MAX_FLOWS; ++i)
    {
        if (s_udp_flows[i].in_use && s_udp_flows[i].client_ip == client_ip &&
            s_udp_flows[i].client_port == client_port)
        {
            return &s_udp_flows[i];
        }
    }
    return NULL;
}

bool transparent_udp_get(uint32_t client_ip, uint16_t client_port, transparent_udp_flow_t *flow)
{
    bool found = false;
    portENTER_CRITICAL(&s_flow_lock);
    transparent_udp_flow_t *entry = udp_flow_find_locked(client_ip, client_port);
    if (entry && flow)
    {
        *flow = *entry;
        found = true;
    }
    portEXIT_CRITICAL(&s_flow_lock);
    return found;
}

bool transparent_udp_create_or_get(uint32_t client_ip, uint16_t client_port, uint32_t original_ip,
                                   uint16_t original_port, transparent_udp_flow_t *flow)
{
    bool found = false;
    portENTER_CRITICAL(&s_flow_lock);
    transparent_udp_flow_t *entry = udp_flow_find_locked(client_ip, client_port);
    if (!entry)
    {
        for (int i = 0; i < TRANSPARENT_UDP_MAX_FLOWS; ++i)
        {
            if (!s_udp_flows[i].in_use)
            {
                entry = &s_udp_flows[i];
                break;
            }
        }
    }
    if (entry)
    {
        if (!entry->in_use)
        {
            *entry = (transparent_udp_flow_t){.in_use        = true,
                                              .client_ip     = client_ip,
                                              .client_port   = client_port,
                                              .original_ip   = original_ip,
                                              .original_port = original_port,
                                              .last_activity_ms =
                                                  (uint32_t)(esp_timer_get_time() / 1000)};
        }
        if (flow)
        {
            *flow = *entry;
        }
        found = true;
    }
    portEXIT_CRITICAL(&s_flow_lock);
    return found;
}

void transparent_udp_touch(uint32_t client_ip, uint16_t client_port)
{
    portENTER_CRITICAL(&s_flow_lock);
    transparent_udp_flow_t *entry = udp_flow_find_locked(client_ip, client_port);
    if (entry)
    {
        entry->last_activity_ms = (uint32_t)(esp_timer_get_time() / 1000);
    }
    portEXIT_CRITICAL(&s_flow_lock);
}

void transparent_udp_expire(uint32_t now_ms)
{
    portENTER_CRITICAL(&s_flow_lock);
    for (int i = 0; i < TRANSPARENT_UDP_MAX_FLOWS; ++i)
    {
        if (s_udp_flows[i].in_use && now_ms - s_udp_flows[i].last_activity_ms > 120000)
        {
            s_udp_flows[i].in_use = false;
        }
    }
    portEXIT_CRITICAL(&s_flow_lock);
}

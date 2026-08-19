#ifndef ROUTER_CONFIG_H
#define ROUTER_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "lwip/ip4_addr.h"

#define AP_SSID "ESP32-VLESS-Setup"
#define AP_PASSWORD "configureme"
#define DEFAULT_AP_IPV4 "192.168.4.1"
#define CONFIG_NAMESPACE "vless_router"
#define CONFIG_KEY "config"
#define ADMIN_PASSWORD_KEY "admin_password_hash"
#define ADMIN_USERNAME "admin"
#define DEFAULT_ADMIN_PASSWORD "changeme"
#define DEFAULT_DNS_RESOLVER "one.one.one.one"
#define UPSTREAM_NETWORK_MAX 10

typedef enum
{
    TRANSPARENT_MODE_VLESS,
    TRANSPARENT_MODE_UPSTREAM,
} transparent_mode_t;

typedef struct
{
    char ssid[33];
    char password[65];
} upstream_network_t;

typedef struct
{
    char     ap_ssid[33];
    char     ap_password[65];
    char     ap_ip[16];
    char     upstream_ssid[33];
    char     upstream_password[65];
    uint8_t  upstream_network_count;
    upstream_network_t upstream_networks[UPSTREAM_NETWORK_MAX];
    char     vless_host[128];
    char     vless_uuid[48];
    uint16_t vless_port;
    char     dns_resolver[254];
    bool     singmux_enabled;
} router_config_t;

const char *configured_or_default(const char *configured, const char *fallback);
const char *configured_ap_ipv4(const router_config_t *config);
bool        parse_access_point_ipv4(const char *text, ip4_addr_t *address);

void      load_router_config(router_config_t *config, const char *tag);
esp_err_t save_router_config(const router_config_t *config);
void      router_config_sync_active_upstream(router_config_t *config);
void      router_config_store_upstream(router_config_t *config, const char *ssid,
                                       const char *password, bool keep_existing_password);
bool      router_config_delete_upstream(router_config_t *config, const char *ssid);

void      hash_admin_password(const char *password, uint8_t hash[32]);
bool      password_hash_matches(const uint8_t left[32], const uint8_t right[32]);
void      load_admin_password_hash(uint8_t hash[32], const char *tag);
esp_err_t save_admin_password_hash(const char *password, uint8_t hash[32]);

#endif
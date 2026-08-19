#include <string.h>

#include "nvs.h"
#include "esp32s3/rom/sha.h"
#include "esp_log.h"

#include "router_config.h"

/* Layout used before AP credentials were added; retained for NVS migration. */
typedef struct
{
    char     upstream_ssid[33];
    char     upstream_password[65];
    char     vless_host[128];
    char     vless_uuid[48];
    uint16_t vless_port;
} legacy_router_config_t;

typedef struct
{
    char     ap_ssid[33];
    char     ap_password[65];
    char     upstream_ssid[33];
    char     upstream_password[65];
    char     vless_host[128];
    char     vless_uuid[48];
    uint16_t vless_port;
} router_config_before_dns_t;

/* Configuration used immediately before the sing-box smux setting was added. */
typedef struct
{
    char     ap_ssid[33];
    char     ap_password[65];
    char     upstream_ssid[33];
    char     upstream_password[65];
    char     vless_host[128];
    char     vless_uuid[48];
    uint16_t vless_port;
    char     dns_resolver[254];
} router_config_before_singmux_t;

typedef struct
{
    char     ap_ssid[33];
    char     ap_password[65];
    char     upstream_ssid[33];
    char     upstream_password[65];
    uint8_t  upstream_network_count;
    upstream_network_t upstream_networks[UPSTREAM_NETWORK_MAX];
    char     vless_host[128];
    char     vless_uuid[48];
    uint16_t vless_port;
    char     dns_resolver[254];
    bool     singmux_enabled;
} router_config_before_ap_ip_t;

static int upstream_network_index(const router_config_t *config, const char *ssid)
{
    for (int i = 0; i < config->upstream_network_count && i < UPSTREAM_NETWORK_MAX; ++i)
    {
        if (strcmp(config->upstream_networks[i].ssid, ssid) == 0)
        {
            return i;
        }
    }
    return -1;
}

const char *configured_or_default(const char *configured, const char *fallback)
{
    return configured[0] ? configured : fallback;
}

const char *configured_ap_ipv4(const router_config_t *config)
{
    return configured_or_default(config->ap_ip, DEFAULT_AP_IPV4);
}

bool parse_access_point_ipv4(const char *text, ip4_addr_t *address)
{
    ip4_addr_t parsed;
    if (!text || !text[0] || !ip4addr_aton(text, &parsed))
    {
        return false;
    }
    if ((ntohl(parsed.addr) & 0xffU) != 1U)
    {
        return false;
    }
    if (address)
    {
        address->addr = parsed.addr;
    }
    return true;
}

void router_config_sync_active_upstream(router_config_t *config)
{
    if (config->upstream_network_count > UPSTREAM_NETWORK_MAX)
    {
        config->upstream_network_count = UPSTREAM_NETWORK_MAX;
    }
    if (!config->upstream_network_count)
    {
        config->upstream_ssid[0]     = '\0';
        config->upstream_password[0] = '\0';
        return;
    }
    strlcpy(config->upstream_ssid, config->upstream_networks[0].ssid,
            sizeof(config->upstream_ssid));
    strlcpy(config->upstream_password, config->upstream_networks[0].password,
            sizeof(config->upstream_password));
}

void router_config_store_upstream(router_config_t *config, const char *ssid, const char *password,
                                  bool keep_existing_password)
{
    upstream_network_t next = {0};
    strlcpy(next.ssid, ssid, sizeof(next.ssid));
    int existing = upstream_network_index(config, ssid);
    if (password && password[0])
    {
        strlcpy(next.password, password, sizeof(next.password));
    }
    else if (keep_existing_password && existing >= 0)
    {
        strlcpy(next.password, config->upstream_networks[existing].password, sizeof(next.password));
    }

    upstream_network_t reordered[UPSTREAM_NETWORK_MAX] = {0};
    reordered[0]                                       = next;
    uint8_t count                                      = 1;
    for (int i = 0; i < config->upstream_network_count && count < UPSTREAM_NETWORK_MAX; ++i)
    {
        if (strcmp(config->upstream_networks[i].ssid, ssid) == 0)
        {
            continue;
        }
        reordered[count++] = config->upstream_networks[i];
    }
    memcpy(config->upstream_networks, reordered, sizeof(reordered));
    config->upstream_network_count = count;
    router_config_sync_active_upstream(config);
}

bool router_config_delete_upstream(router_config_t *config, const char *ssid)
{
    int index = upstream_network_index(config, ssid);
    if (index < 0)
    {
        return false;
    }
    for (int i = index; i + 1 < config->upstream_network_count && i + 1 < UPSTREAM_NETWORK_MAX;
         ++i)
    {
        config->upstream_networks[i] = config->upstream_networks[i + 1];
    }
    if (config->upstream_network_count)
    {
        --config->upstream_network_count;
    }
    if (config->upstream_network_count < UPSTREAM_NETWORK_MAX)
    {
        memset(&config->upstream_networks[config->upstream_network_count], 0,
               sizeof(config->upstream_networks[config->upstream_network_count]));
    }
    router_config_sync_active_upstream(config);
    return true;
}

void load_router_config(router_config_t *config, const char *tag)
{
    bool         loaded_current_config = false;
    nvs_handle_t nvs;
    memset(config, 0, sizeof(*config));
    if (nvs_open(CONFIG_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK)
    {
        size_t length = 0;
        if (nvs_get_blob(nvs, CONFIG_KEY, NULL, &length) != ESP_OK)
        {
            ESP_LOGW(tag, "No saved configuration; using defaults");
        }
        else if (length == sizeof(*config))
        {
            nvs_get_blob(nvs, CONFIG_KEY, config, &length);
            loaded_current_config = true;
        }
        else if (length == sizeof(legacy_router_config_t))
        {
            legacy_router_config_t legacy = {0};
            nvs_get_blob(nvs, CONFIG_KEY, &legacy, &length);
            strlcpy(config->upstream_ssid, legacy.upstream_ssid, sizeof(config->upstream_ssid));
            strlcpy(config->upstream_password, legacy.upstream_password,
                    sizeof(config->upstream_password));
            strlcpy(config->vless_host, legacy.vless_host, sizeof(config->vless_host));
            strlcpy(config->vless_uuid, legacy.vless_uuid, sizeof(config->vless_uuid));
            config->vless_port = legacy.vless_port;
            ESP_LOGI(tag, "Migrated saved Wi-Fi and VLESS configuration");
        }
        else if (length == sizeof(router_config_before_dns_t))
        {
            router_config_before_dns_t old = {0};
            nvs_get_blob(nvs, CONFIG_KEY, &old, &length);
            memcpy(config, &old, sizeof(old));
            ESP_LOGI(tag, "Migrated saved configuration; DNS resolver is unset");
        }
        else if (length == sizeof(router_config_before_singmux_t))
        {
            router_config_before_singmux_t old = {0};
            nvs_get_blob(nvs, CONFIG_KEY, &old, &length);
            memcpy(config, &old, sizeof(old));
            ESP_LOGI(tag, "Migrated saved configuration; sing-box multiplex is disabled");
        }
        else if (length == sizeof(router_config_before_ap_ip_t))
        {
            router_config_before_ap_ip_t old = {0};
            nvs_get_blob(nvs, CONFIG_KEY, &old, &length);
            memcpy(config, &old, sizeof(old));
            ESP_LOGI(tag, "Migrated saved configuration; AP IPv4 is unset");
        }
        else
        {
            ESP_LOGW(tag, "Ignoring incompatible saved configuration");
        }
        nvs_close(nvs);
    }
    if (!loaded_current_config && !config->dns_resolver[0])
    {
        strlcpy(config->dns_resolver, DEFAULT_DNS_RESOLVER, sizeof(config->dns_resolver));
    }
    if (!config->ap_ip[0])
    {
        strlcpy(config->ap_ip, DEFAULT_AP_IPV4, sizeof(config->ap_ip));
    }
    if (!config->upstream_network_count && config->upstream_ssid[0])
    {
        router_config_store_upstream(config, config->upstream_ssid, config->upstream_password,
                                     false);
    }
    else
    {
        router_config_sync_active_upstream(config);
    }
}

esp_err_t save_router_config(const router_config_t *config)
{
    nvs_handle_t nvs;
    esp_err_t    err = nvs_open(CONFIG_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK)
    {
        return err;
    }
    err = nvs_set_blob(nvs, CONFIG_KEY, config, sizeof(*config));
    if (err == ESP_OK)
    {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return err;
}

void hash_admin_password(const char *password, uint8_t hash[32])
{
    SHA_CTX context;
    ets_sha_enable();
    ets_sha_init(&context, SHA2_256);
    ets_sha_update(&context, (const unsigned char *)password, strlen(password), false);
    ets_sha_finish(&context, hash);
}

bool password_hash_matches(const uint8_t left[32], const uint8_t right[32])
{
    uint8_t difference = 0;
    for (size_t i = 0; i < 32; ++i)
    {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

void load_admin_password_hash(uint8_t hash[32], const char *tag)
{
    nvs_handle_t nvs;
    size_t       length = 32;
    if (nvs_open(CONFIG_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK)
    {
        esp_err_t result = nvs_get_blob(nvs, ADMIN_PASSWORD_KEY, hash, &length);
        nvs_close(nvs);
        if (result == ESP_OK && length == 32)
        {
            return;
        }
    }

    hash_admin_password(DEFAULT_ADMIN_PASSWORD, hash);
    if (nvs_open(CONFIG_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK)
    {
        nvs_set_blob(nvs, ADMIN_PASSWORD_KEY, hash, 32);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
    ESP_LOGW(tag, "Portal admin password initialized to the factory default");
}

esp_err_t save_admin_password_hash(const char *password, uint8_t hash[32])
{
    nvs_handle_t nvs;
    esp_err_t    result = nvs_open(CONFIG_NAMESPACE, NVS_READWRITE, &nvs);
    if (result != ESP_OK)
    {
        return result;
    }
    uint8_t next_hash[32];
    hash_admin_password(password, next_hash);
    result = nvs_set_blob(nvs, ADMIN_PASSWORD_KEY, next_hash, sizeof(next_hash));
    if (result == ESP_OK)
    {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result == ESP_OK)
    {
        memcpy(hash, next_hash, sizeof(next_hash));
    }
    return result;
}
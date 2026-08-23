#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <errno.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_private/esp_clk.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "driver/gpio.h"
#include "driver/temperature_sensor.h"
#include "lwip/ip4_addr.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "portal_page.h"
#include "router_config.h"
#include "status_led.h"
#include "transport_tcp.h"
#include "transparent_tcp.h"
#include "xudp_codec.h"
#include "singmux_codec.h"

#ifndef BUILD_GIT_VERSION
#define BUILD_GIT_VERSION "unknown"
#endif

#define BOOT_BUTTON_GPIO GPIO_NUM_0
#define UDP_ASSOCIATION_MAX 56
#define UDP_MANAGER_QUEUE_DEPTH 160
/* 2 KiB covers common 1200/1350-byte QUIC packets and leaves headroom for
   encapsulation.  IP fragmentation is deliberately not intercepted: broken
   fragments are worse than a predictable MTU limit for a tunnel router. */
#define UDP_DATAGRAM_MAX 2048
#define UDP_RX_BUFFER_MAX (UDP_DATAGRAM_MAX * 4 + 512)
/* Shared smux reassembly buffer; allocated from PSRAM. */
#define SINGMUX_RX_BUFFER_MAX (128 * 1024)
#define SINGMUX_SOCKET_READ_SIZE 4096
#define UDP_QUEUE_SEND_WAIT_MS 2
/* smux keeps transport sockets scarce.  TCP payloads themselves are allocated
   in PSRAM and only pointers travel through this small control queue. */
#define SINGMUX_TCP_STREAM_MAX 100
/* Absorb a browser's burst of SYN/data/FIN control messages without making
   the manager's queue
 * the limiting factor before all 100 stream slots can be
   used. */
#define SINGMUX_CONTROL_QUEUE_DEPTH 120
#define SINGMUX_CONTROL_BATCH_MAX 8
#define SINGMUX_TCP_RX_QUEUE_DEPTH 24
#define SINGMUX_TCP_DATA_MAX 2048
#define UDP_MANAGER_BATCH_MAX 8
#define OTA_UPLOAD_BUFFER_SIZE 1024
#define BANDWIDTH_HISTORY_SECONDS 30

/* Set -DVLESS_TRAFFIC_LOGS=1 in platformio.ini when packet-by-packet relay
   diagnostics are needed. It is off by default to keep the console usable. */
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

typedef enum
{
    CONFIG_SECTION_UPSTREAM,
    CONFIG_SECTION_VLESS,
    CONFIG_SECTION_ACCESS_POINT,
} config_section_t;

static const char *TAG = "vless_router";

typedef struct
{
    uint64_t upload_bytes;
    uint64_t download_bytes;
    uint32_t upload_bps;
    uint32_t download_bps;
    uint32_t upload_bps_10s;
    uint32_t download_bps_10s;
    uint32_t upload_bps_30s;
    uint32_t download_bps_30s;
} bandwidth_stats_t;

/* These are deliberately aggregate and lock-free: their purpose is to show
 * persistent pressure/failures without perturbing the forwarding hot path. */
typedef struct
{
    uint32_t sessions_opened;
    uint32_t sessions_closed;
    uint32_t close_eof;
    uint32_t close_socket_error;
    uint32_t close_protocol_error;
    uint32_t tx_frames;
    uint32_t rx_frames;
    uint64_t tx_wire_bytes;
    uint64_t rx_wire_bytes;
    uint32_t tcp_rx_queue_full;
    uint32_t tcp_rx_alloc_failures;
    uint32_t tcp_control_queue_timeouts;
    uint32_t tcp_stream_open_failures;
    uint16_t tcp_rx_queue_high_water;
    uint32_t rx_reads;
    uint32_t scheduler_yields;
    uint32_t rx_reassembly_high_water;
    uint32_t last_session_open_ms;
    uint32_t last_session_close_ms;
    int      last_socket_errno;
} singmux_stats_t;

typedef struct
{
    uint16_t length;
    uint8_t  data[];
} singmux_tcp_data_t;

typedef struct
{
    bool          in_use;
    bool          response_pending;
    bool          peer_closed;
    uint32_t      stream_id;
    QueueHandle_t receive_queue;
} singmux_tcp_stream_t;

typedef enum
{
    SINGMUX_CONTROL_OPEN,
    SINGMUX_CONTROL_DATA,
    SINGMUX_CONTROL_CLOSE
} singmux_control_type_t;

typedef struct
{
    singmux_control_type_t type;
    int                    slot;
    uint32_t               stream_id;
    TaskHandle_t           reply_task;
    uint32_t               destination_ip;
    uint16_t               destination_port;
    char                   destination_name[254];
    singmux_tcp_data_t    *data;
} singmux_control_t;

static router_config_t    s_config;
static uint8_t            s_admin_password_hash[32];
static bool               s_has_upstream;
static transparent_mode_t s_transparent_mode = TRANSPARENT_MODE_VLESS;
static esp_netif_t       *s_ap_netif;
static esp_netif_t       *s_sta_netif;
static int                s_udp_relay_socket = -1;
static QueueHandle_t      s_udp_manager_queue;
static QueueHandle_t      s_singmux_control_queue;
static uint32_t           s_udp_queue_drops;
static uint32_t           s_udp_rx_drops;
static uint32_t           s_udp_tunnel_failures;
static volatile uint32_t  s_udp_active_associations;
static portMUX_TYPE       s_bandwidth_lock = portMUX_INITIALIZER_UNLOCKED;
static uint64_t           s_upload_bytes;
static uint64_t           s_download_bytes;
static uint64_t           s_sample_upload_bytes;
static uint64_t           s_sample_download_bytes;
static uint32_t           s_sample_time_ms;
/* A sampler, rather than HTTP/serial polling, owns these time windows.  This
 * lets us compare a
 * transfer's opening seconds with its sustained rate. */
static uint32_t                    s_upload_history[BANDWIDTH_HISTORY_SECONDS];
static uint32_t                    s_download_history[BANDWIDTH_HISTORY_SECONDS];
static uint8_t                     s_bandwidth_history_next;
static uint8_t                     s_bandwidth_history_count;
static uint32_t                    s_upload_bps_10s;
static uint32_t                    s_download_bps_10s;
static uint32_t                    s_upload_bps_30s;
static uint32_t                    s_download_bps_30s;
static temperature_sensor_handle_t s_temperature_sensor;
static bool                        s_temperature_sensor_ready;
static float                       s_chip_temperature_c;
static uint8_t                     s_cpu_load_core0;
static uint8_t                     s_cpu_load_core1;
static uint16_t                    s_cpu_frequency_mhz;
static uint32_t                    s_previous_idle_runtime[2];
static uint64_t                    s_cpu_sample_time_us;
static int                         s_singmux_tunnel         = -1;
static uint32_t                    s_singmux_next_stream_id = 3;
static uint8_t                    *s_singmux_rx_buffer;
/* Only the smux manager calls recv(), so this does not need per-task storage.
 * Keeping it static avoids consuming most of that task's 6 KiB stack. */
static uint8_t              s_singmux_socket_read_buffer[SINGMUX_SOCKET_READ_SIZE];
static size_t               s_singmux_rx_length;
static bool                 s_singmux_vless_response_pending;
static singmux_tcp_stream_t s_singmux_tcp_streams[SINGMUX_TCP_STREAM_MAX];
static singmux_stats_t      s_singmux_stats;
static uint32_t             s_upload_bps;
static uint32_t             s_download_bps;
static volatile bool        s_transport_reset_requested;
static bool                 s_configuration_mode;
static wifi_ap_record_t     s_scan_records[20];
static uint16_t             s_scan_record_count;
static bool                 s_scan_results_available;
/* The first configured upstream gets its normal connection attempt.  If that
   fails during boot, scan once for a saved alternative instead of retrying the
   same unavailable AP forever. */
static bool s_boot_upstream_scan_scheduled;
static bool s_boot_upstream_connected;
static char s_boot_failed_upstream_ssid[33];

static bool     socket_send_all(int socket_fd, const uint8_t *data, size_t length);
static bool     socket_recv_all(int socket_fd, uint8_t *data, size_t length);
static uint32_t now_ms(void);
static bool     dns_name(const uint8_t *packet, int bytes, int *offset, char name[254]);
static void     json_string(httpd_req_t *req, const char *text);
static void     apply_access_point_task(void *argument);
static void     reset_transparent_transport_state(void);
static void     set_transparent_mode(transparent_mode_t mode);
static void     schedule_boot_upstream_scan(void);

static void initialize_device_health_monitoring(void)
{
    s_cpu_frequency_mhz                = (uint16_t)(esp_clk_cpu_freq() / 1000000U);
    temperature_sensor_config_t config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
    esp_err_t                   result = temperature_sensor_install(&config, &s_temperature_sensor);
    if (result == ESP_OK)
    {
        result = temperature_sensor_enable(s_temperature_sensor);
    }
    if (result == ESP_OK)
    {
        s_temperature_sensor_ready = true;
        ESP_LOGI(TAG, "on-die temperature monitoring enabled");
    }
    else
    {
        ESP_LOGW(TAG, "on-die temperature monitoring unavailable: %s", esp_err_to_name(result));
        if (s_temperature_sensor)
        {
            temperature_sensor_uninstall(s_temperature_sensor);
            s_temperature_sensor = NULL;
        }
    }
}

static void sample_device_health(void)
{
    float temperature_c = s_chip_temperature_c;
    if (s_temperature_sensor_ready)
    {
        (void)temperature_sensor_get_celsius(s_temperature_sensor, &temperature_c);
    }

    uint64_t now_us          = esp_timer_get_time();
    uint32_t idle_runtime[2] = {
        (uint32_t)ulTaskGetIdleRunTimeCounterForCore(0),
        (uint32_t)ulTaskGetIdleRunTimeCounterForCore(1),
    };
    uint8_t cpu_load[2] = {s_cpu_load_core0, s_cpu_load_core1};
    if (s_cpu_sample_time_us)
    {
        uint64_t elapsed_us = now_us - s_cpu_sample_time_us;
        if (elapsed_us)
        {
            for (size_t core = 0; core < 2; ++core)
            {
                uint64_t idle_us = (uint32_t)(idle_runtime[core] - s_previous_idle_runtime[core]);
                uint64_t busy_us = idle_us >= elapsed_us ? 0 : elapsed_us - idle_us;
                uint64_t load    = (busy_us * 100U) / elapsed_us;
                cpu_load[core]   = (uint8_t)(load > 100 ? 100 : load);
            }
        }
    }
    s_previous_idle_runtime[0] = idle_runtime[0];
    s_previous_idle_runtime[1] = idle_runtime[1];
    s_cpu_sample_time_us       = now_us;

    portENTER_CRITICAL(&s_bandwidth_lock);
    s_chip_temperature_c = temperature_c;
    s_cpu_load_core0     = cpu_load[0];
    s_cpu_load_core1     = cpu_load[1];
    portEXIT_CRITICAL(&s_bandwidth_lock);
}

static uint32_t bandwidth_window_bps(const uint32_t *history, uint8_t count, uint8_t next,
                                     uint8_t seconds)
{
    uint8_t window = count < seconds ? count : seconds;
    if (!window)
    {
        return 0;
    }
    uint64_t total = 0;
    for (uint8_t offset = 0; offset < window; ++offset)
    {
        uint8_t index =
            (uint8_t)((next + BANDWIDTH_HISTORY_SECONDS - 1 - offset) % BANDWIDTH_HISTORY_SECONDS);
        total += history[index];
    }
    return (uint32_t)(total / window);
}

static void bandwidth_sampler_task(void *argument)
{
    (void)argument;
    uint64_t   previous_upload   = 0;
    uint64_t   previous_download = 0;
    bool       initialized       = false;
    TickType_t wake_time         = xTaskGetTickCount();
    for (;;)
    {
        vTaskDelayUntil(&wake_time, pdMS_TO_TICKS(1000));
        sample_device_health();
        portENTER_CRITICAL(&s_bandwidth_lock);
        if (!initialized)
        {
            previous_upload   = s_upload_bytes;
            previous_download = s_download_bytes;
            initialized       = true;
        }
        else
        {
            s_upload_history[s_bandwidth_history_next] =
                (uint32_t)(s_upload_bytes - previous_upload);
            s_download_history[s_bandwidth_history_next] =
                (uint32_t)(s_download_bytes - previous_download);
            previous_upload   = s_upload_bytes;
            previous_download = s_download_bytes;
            s_bandwidth_history_next =
                (uint8_t)((s_bandwidth_history_next + 1) % BANDWIDTH_HISTORY_SECONDS);
            if (s_bandwidth_history_count < BANDWIDTH_HISTORY_SECONDS)
            {
                ++s_bandwidth_history_count;
            }
            s_upload_bps_10s   = bandwidth_window_bps(s_upload_history, s_bandwidth_history_count,
                                                      s_bandwidth_history_next, 10);
            s_download_bps_10s = bandwidth_window_bps(s_download_history, s_bandwidth_history_count,
                                                      s_bandwidth_history_next, 10);
            s_upload_bps_30s   = bandwidth_window_bps(s_upload_history, s_bandwidth_history_count,
                                                      s_bandwidth_history_next, 30);
            s_download_bps_30s = bandwidth_window_bps(s_download_history, s_bandwidth_history_count,
                                                      s_bandwidth_history_next, 30);
        }
        portEXIT_CRITICAL(&s_bandwidth_lock);
    }
}

static bool text_changed(const char *left, const char *right)
{
    return strcmp(left, right) != 0;
}

static void bandwidth_record_upload(size_t bytes)
{
    portENTER_CRITICAL(&s_bandwidth_lock);
    s_upload_bytes += bytes;
    portEXIT_CRITICAL(&s_bandwidth_lock);
}

static void bandwidth_record_download(size_t bytes)
{
    portENTER_CRITICAL(&s_bandwidth_lock);
    s_download_bytes += bytes;
    portEXIT_CRITICAL(&s_bandwidth_lock);
}

static bool transparent_mode_uses_vless(void)
{
    return s_transparent_mode == TRANSPARENT_MODE_VLESS;
}

static const char *transparent_mode_name(void)
{
    return transparent_mode_uses_vless() ? "transparent-vless" : "transparent-upstream";
}

static void refresh_transparent_interception_state(void)
{
    bool enabled = s_has_upstream;
    if (transparent_tcp_is_enabled() != enabled)
    {
        transparent_tcp_set_enabled(enabled);
    }
}

static bandwidth_stats_t bandwidth_snapshot(void)
{
    const uint32_t    now = (uint32_t)(esp_timer_get_time() / 1000);
    bandwidth_stats_t stats;
    portENTER_CRITICAL(&s_bandwidth_lock);
    if (!s_sample_time_ms)
    {
        s_sample_time_ms        = now;
        s_sample_upload_bytes   = s_upload_bytes;
        s_sample_download_bytes = s_download_bytes;
    }
    uint32_t elapsed = now - s_sample_time_ms;
    if (elapsed >= 250)
    {
        s_upload_bps = (uint32_t)(((s_upload_bytes - s_sample_upload_bytes) * 1000ULL) / elapsed);
        s_download_bps =
            (uint32_t)(((s_download_bytes - s_sample_download_bytes) * 1000ULL) / elapsed);
        s_sample_time_ms        = now;
        s_sample_upload_bytes   = s_upload_bytes;
        s_sample_download_bytes = s_download_bytes;
    }
    stats = (bandwidth_stats_t){s_upload_bytes,   s_download_bytes,  s_upload_bps,
                                s_download_bps,   s_upload_bps_10s,  s_download_bps_10s,
                                s_upload_bps_30s, s_download_bps_30s};
    portEXIT_CRITICAL(&s_bandwidth_lock);
    return stats;
}

/* Safe to call while a speed test is running.  It reports aggregate payload
   flow without enabling the high-volume packet logging switch. */
static void serial_diagnostics(void)
{
    bandwidth_stats_t  bandwidth          = bandwidth_snapshot();
    wifi_ap_record_t   upstream           = {0};
    uint8_t            primary            = 0;
    wifi_second_chan_t secondary          = WIFI_SECOND_CHAN_NONE;
    wifi_sta_list_t    clients            = {0};
    esp_err_t          upstream_result    = esp_wifi_sta_get_ap_info(&upstream);
    esp_err_t          client_result      = esp_wifi_ap_get_sta_list(&clients);
    uint32_t           singmux_tcp_active = 0;
    (void)esp_wifi_get_channel(&primary, &secondary);
    for (size_t index = 0; index < SINGMUX_TCP_STREAM_MAX; ++index)
    {
        if (s_singmux_tcp_streams[index].in_use)
        {
            ++singmux_tcp_active;
        }
    }

    ESP_LOGW(TAG,
             "DIAG route=%s upstream=%s Wi-Fi channel=%u secondary=%d AP-clients=%u; "
             "TCP wnd=32768 snd=32768 recvmbox=32; payload up=%u B/s down=%u B/s "
             "(%.2f/%.2f Mbps); rolling 10s up/down=%u/%u B/s, 30s=%u/%u B/s",
             transparent_mode_name(), s_has_upstream ? "up" : "down", primary, (int)secondary,
             client_result == ESP_OK ? clients.num : 0, bandwidth.upload_bps,
             bandwidth.download_bps, bandwidth.upload_bps * 8.0 / 1000000.0,
             bandwidth.download_bps * 8.0 / 1000000.0, bandwidth.upload_bps_10s,
             bandwidth.download_bps_10s, bandwidth.upload_bps_30s, bandwidth.download_bps_30s);
    if (upstream_result == ESP_OK)
    {
        ESP_LOGW(TAG, "DIAG uplink RSSI=%d dBm channel=%u auth=%d", upstream.rssi, upstream.primary,
                 upstream.authmode);
    }
    else
    {
        ESP_LOGW(TAG, "DIAG uplink association unavailable: %s", esp_err_to_name(upstream_result));
    }
    ESP_LOGW(TAG,
             "DIAG queues: UDP=%u/%u drops=%u rx_drops=%u tunnel_failures=%u; smux=%s "
             "TCP-streams=%u/%u control=%u/%u; heap internal=%u PSRAM=%u",
             s_udp_manager_queue ? (unsigned)uxQueueMessagesWaiting(s_udp_manager_queue) : 0,
             UDP_MANAGER_QUEUE_DEPTH, (unsigned)s_udp_queue_drops, (unsigned)s_udp_rx_drops,
             (unsigned)s_udp_tunnel_failures, s_singmux_tunnel >= 0 ? "connected" : "off",
             (unsigned)singmux_tcp_active, SINGMUX_TCP_STREAM_MAX,
             s_singmux_control_queue ? (unsigned)uxQueueMessagesWaiting(s_singmux_control_queue)
                                     : 0,
             SINGMUX_CONTROL_QUEUE_DEPTH, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    ESP_LOGW(TAG,
             "DIAG smux: sessions open/closed=%u/%u EOF=%u socket=%u protocol=%u last_errno=%d "
             "wire tx/rx=%llu/%llu frames=%u/%u; TCP rx queue high=%u/%u full=%u alloc_fail=%u "
             "control_timeout=%u open_fail=%u; reads=%u yields=%u reassembly_high=%u",
             (unsigned)s_singmux_stats.sessions_opened, (unsigned)s_singmux_stats.sessions_closed,
             (unsigned)s_singmux_stats.close_eof, (unsigned)s_singmux_stats.close_socket_error,
             (unsigned)s_singmux_stats.close_protocol_error, s_singmux_stats.last_socket_errno,
             (unsigned long long)s_singmux_stats.tx_wire_bytes,
             (unsigned long long)s_singmux_stats.rx_wire_bytes, (unsigned)s_singmux_stats.tx_frames,
             (unsigned)s_singmux_stats.rx_frames, (unsigned)s_singmux_stats.tcp_rx_queue_high_water,
             SINGMUX_TCP_RX_QUEUE_DEPTH, (unsigned)s_singmux_stats.tcp_rx_queue_full,
             (unsigned)s_singmux_stats.tcp_rx_alloc_failures,
             (unsigned)s_singmux_stats.tcp_control_queue_timeouts,
             (unsigned)s_singmux_stats.tcp_stream_open_failures, (unsigned)s_singmux_stats.rx_reads,
             (unsigned)s_singmux_stats.scheduler_yields,
             (unsigned)s_singmux_stats.rx_reassembly_high_water);
    ESP_LOGW(TAG, "DIAG health: CPU=%u MHz chip=%.1f C core0=%u%% core1=%u%%",
             (unsigned)s_cpu_frequency_mhz, s_chip_temperature_c, (unsigned)s_cpu_load_core0,
             (unsigned)s_cpu_load_core1);
}

static bool access_point_ip_info(esp_netif_ip_info_t *info)
{
    ip4_addr_t ap_ip = {0};
    if (!parse_access_point_ipv4(configured_ap_ipv4(&s_config), &ap_ip))
    {
        return false;
    }
    memset(info, 0, sizeof(*info));
    info->ip.addr = ap_ip.addr;
    info->gw.addr = ap_ip.addr;
    IP4_ADDR(&info->netmask, 255, 255, 255, 0);
    return true;
}

static uint32_t access_point_ipv4_addr(void)
{
    esp_netif_ip_info_t info = {0};
    if (s_ap_netif && esp_netif_get_ip_info(s_ap_netif, &info) == ESP_OK)
    {
        return info.ip.addr;
    }
    ip4_addr_t ap_ip = {0};
    if (parse_access_point_ipv4(configured_ap_ipv4(&s_config), &ap_ip))
    {
        return ap_ip.addr;
    }
    parse_access_point_ipv4(DEFAULT_AP_IPV4, &ap_ip);
    return ap_ip.addr;
}

static void apply_access_point_ip_config(void)
{
    if (!s_ap_netif)
    {
        return;
    }
    esp_netif_ip_info_t info = {0};
    if (!access_point_ip_info(&info))
    {
        ESP_LOGW(TAG, "Ignoring invalid AP IPv4 '%s'", configured_ap_ipv4(&s_config));
        return;
    }
    esp_err_t err = esp_netif_dhcps_stop(s_ap_netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED)
    {
        ESP_LOGW(TAG, "Could not stop AP DHCP server: %s", esp_err_to_name(err));
    }
    ESP_ERROR_CHECK(esp_netif_set_ip_info(s_ap_netif, &info));
    esp_netif_dns_info_t dns = {.ip.type = ESP_IPADDR_TYPE_V4};
    dns.ip.u_addr.ip4        = info.ip;
    ESP_ERROR_CHECK(esp_netif_set_dns_info(s_ap_netif, ESP_NETIF_DNS_MAIN, &dns));
    err = esp_netif_dhcps_start(s_ap_netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED)
    {
        ESP_ERROR_CHECK(err);
    }
}

static void apply_access_point_config(void)
{
    wifi_config_t ap = {.ap = {.channel = 1, .max_connection = 8, .authmode = WIFI_AUTH_WPA2_PSK}};
    const char   *ssid     = configured_or_default(s_config.ap_ssid, AP_SSID);
    const char   *password = configured_or_default(s_config.ap_password, AP_PASSWORD);
    apply_access_point_ip_config();
    strlcpy((char *)ap.ap.ssid, ssid, sizeof(ap.ap.ssid));
    ap.ap.ssid_len = strlen(ssid);
    strlcpy((char *)ap.ap.password, password, sizeof(ap.ap.password));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
}

static void connect_upstream(void)
{
    if (s_configuration_mode)
    {
        ESP_LOGI(TAG, "Configuration mode active; upstream Wi-Fi remains disconnected");
        return;
    }
    if (!s_config.upstream_ssid[0])
    {
        return;
    }
    wifi_config_t station = {0};
    strlcpy((char *)station.sta.ssid, s_config.upstream_ssid, sizeof(station.sta.ssid));
    strlcpy((char *)station.sta.password, s_config.upstream_password, sizeof(station.sta.password));
    station.sta.threshold.authmode =
        s_config.upstream_password[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    station.sta.pmf_cfg.capable = true;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &station));
    ESP_ERROR_CHECK(esp_wifi_connect());
    ESP_LOGI(TAG, "Connecting to upstream '%s' with password '%s'%s", s_config.upstream_ssid,
             s_config.upstream_password, s_config.upstream_password[0] ? "" : " (open network)");
}

/* Runs outside the Wi-Fi event loop because esp_wifi_scan_start(..., true)
   blocks until the scan is complete.  Scan all reported APs: limiting the
   result to the web UI's 20 entries could otherwise miss a weaker, but saved,
   upstream. */
static void boot_upstream_scan_task(void *argument)
{
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(250));

    wifi_scan_config_t scan = {
        .show_hidden      = false,
        .scan_type        = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active = {.min = 100, .max = 300},
    };
    ESP_LOGI(TAG, "Boot upstream recovery: scanning for saved Wi-Fi networks");
    esp_err_t err = esp_wifi_scan_start(&scan, true);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "Boot upstream recovery scan failed: %s", esp_err_to_name(err));
        vTaskDelete(NULL);
        return;
    }

    uint16_t count = 0;
    err            = esp_wifi_scan_get_ap_num(&count);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "Could not read boot scan results: %s", esp_err_to_name(err));
        vTaskDelete(NULL);
        return;
    }
    wifi_ap_record_t *records = count ? calloc(count, sizeof(*records)) : NULL;
    if (count && !records)
    {
        ESP_LOGW(TAG, "Not enough memory to process %u boot scan results", (unsigned)count);
        vTaskDelete(NULL);
        return;
    }
    if (count)
    {
        err = esp_wifi_scan_get_ap_records(&count, records);
        if (err != ESP_OK)
        {
            ESP_LOGW(TAG, "Could not retrieve boot scan results: %s", esp_err_to_name(err));
            free(records);
            vTaskDelete(NULL);
            return;
        }
    }

    int best_profile             = -1;
    int best_rssi                = -127;
    int best_alternative_profile = -1;
    int best_alternative_rssi    = -127;
    for (uint16_t record = 0; record < count; ++record)
    {
        for (uint8_t profile = 0;
             profile < s_config.upstream_network_count && profile < UPSTREAM_NETWORK_MAX; ++profile)
        {
            if (strcmp((const char *)records[record].ssid,
                       s_config.upstream_networks[profile].ssid) != 0)
            {
                continue;
            }
            if (best_profile < 0 || records[record].rssi > best_rssi)
            {
                best_profile = profile;
                best_rssi    = records[record].rssi;
            }
            if (strcmp(s_config.upstream_networks[profile].ssid, s_boot_failed_upstream_ssid) !=
                    0 &&
                (best_alternative_profile < 0 || records[record].rssi > best_alternative_rssi))
            {
                best_alternative_profile = profile;
                best_alternative_rssi    = records[record].rssi;
            }
        }
    }
    free(records);

    /* Do not immediately retry a profile which already failed at boot when a
       different saved AP is available. */
    if (best_alternative_profile >= 0)
    {
        best_profile = best_alternative_profile;
        best_rssi    = best_alternative_rssi;
    }
    if (best_profile < 0)
    {
        ESP_LOGW(TAG, "Boot upstream recovery: no saved upstream was found in %u AP(s)",
                 (unsigned)count);
        vTaskDelete(NULL);
        return;
    }

    const upstream_network_t *selected = &s_config.upstream_networks[best_profile];
    strlcpy(s_config.upstream_ssid, selected->ssid, sizeof(s_config.upstream_ssid));
    strlcpy(s_config.upstream_password, selected->password, sizeof(s_config.upstream_password));
    ESP_LOGI(TAG, "Boot upstream recovery: selected saved AP '%s' (%d dBm)", s_config.upstream_ssid,
             best_rssi);
    connect_upstream();
    vTaskDelete(NULL);
}

static void schedule_boot_upstream_scan(void)
{
    if (s_boot_upstream_scan_scheduled || s_configuration_mode)
    {
        return;
    }
    s_boot_upstream_scan_scheduled = true;
    if (xTaskCreate(boot_upstream_scan_task, "boot_wifi_scan", 4096, NULL, 4, NULL) != pdPASS)
    {
        ESP_LOGW(TAG, "Could not start boot upstream recovery scan task");
    }
}

static const char *wifi_disconnect_reason_text(uint8_t reason)
{
    switch (reason)
    {
    case WIFI_REASON_NO_AP_FOUND:
        return "access point not found";
    case WIFI_REASON_AUTH_FAIL:
        return "authentication failed (check the password)";
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
        return "security handshake timed out (check the password or signal)";
    case WIFI_REASON_ASSOC_FAIL:
        return "association failed";
    case WIFI_REASON_CONNECTION_FAIL:
        return "connection failed";
    case WIFI_REASON_BEACON_TIMEOUT:
        return "access point stopped responding";
    default:
        return "unspecified disconnect";
    }
}

static void network_event(void *arg, esp_event_base_t base, int32_t event, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && event == WIFI_EVENT_AP_START)
    {
        transparent_tcp_install_ap_output();
    }
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_START)
    {
        if (s_config.upstream_ssid[0])
        {
            connect_upstream();
        }
        else
        {
            /* This still scans on a first boot with no profiles, making the
               available networks discoverable in the boot log. */
            schedule_boot_upstream_scan();
        }
    }
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_DISCONNECTED && s_config.upstream_ssid[0])
    {
        const wifi_event_sta_disconnected_t *disconnected = data;
        ESP_LOGW(TAG, "Upstream '%s' disconnected: %s (reason=%u)", s_config.upstream_ssid,
                 wifi_disconnect_reason_text(disconnected->reason), (unsigned)disconnected->reason);
        s_has_upstream = false;
        reset_transparent_transport_state();
        refresh_transparent_interception_state();
        if (s_configuration_mode)
        {
            ESP_LOGI(TAG, "Configuration mode active; not reconnecting upstream Wi-Fi");
            return;
        }
        status_led_show_mode(s_transparent_mode, s_has_upstream);
        if (s_boot_upstream_connected)
        {
            ESP_LOGI(TAG, "Retrying established upstream connection");
            esp_wifi_connect();
            return;
        }
        strlcpy(s_boot_failed_upstream_ssid, s_config.upstream_ssid,
                sizeof(s_boot_failed_upstream_ssid));
        schedule_boot_upstream_scan();
    }
    if (base == IP_EVENT && event == IP_EVENT_STA_GOT_IP)
    {
        const ip_event_got_ip_t *got_ip = data;
        char                     ip[16];
        esp_ip4addr_ntoa(&got_ip->ip_info.ip, ip, sizeof(ip));
        if (s_configuration_mode)
        {
            ESP_LOGI(TAG, "Ignoring upstream IP %s while configuration mode is active", ip);
            esp_wifi_disconnect();
            return;
        }
        s_has_upstream            = true;
        s_boot_upstream_connected = true;
        refresh_transparent_interception_state();
        status_led_show_mode(s_transparent_mode, s_has_upstream);
        ESP_LOGI(TAG, "Upstream '%s' connected with IP %s; %s", s_config.upstream_ssid, ip,
                 s_config.upstream_password[0] ? "password accepted" : "open network");
    }
}

static int from_hex(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

static void url_decode(char *text)
{
    char *read = text, *write = text;
    while (*read)
    {
        if (*read == '+')
        {
            *write++ = ' ';
            read++;
        }
        else if (*read == '%' && from_hex(read[1]) >= 0 && from_hex(read[2]) >= 0)
        {
            *write++ = (char)((from_hex(read[1]) << 4) | from_hex(read[2]));
            read += 3;
        }
        else
        {
            *write++ = *read++;
        }
    }
    *write = '\0';
}

static int base64_value(char value)
{
    if (value >= 'A' && value <= 'Z')
    {
        return value - 'A';
    }
    if (value >= 'a' && value <= 'z')
    {
        return value - 'a' + 26;
    }
    if (value >= '0' && value <= '9')
    {
        return value - '0' + 52;
    }
    if (value == '+')
    {
        return 62;
    }
    if (value == '/')
    {
        return 63;
    }
    return -1;
}

static size_t base64_decode(const char *encoded, uint8_t *decoded, size_t decoded_size)
{
    uint32_t accumulator = 0;
    int      bits        = 0;
    size_t   length      = 0;
    for (; *encoded && *encoded != '='; ++encoded)
    {
        int value = base64_value(*encoded);
        if (value < 0)
        {
            return 0;
        }
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        while (bits >= 8)
        {
            bits -= 8;
            if (length >= decoded_size)
            {
                return 0;
            }
            decoded[length++] = (uint8_t)(accumulator >> bits);
        }
    }
    return length;
}

static bool admin_request_is_authorized(httpd_req_t *req)
{
    size_t header_length = httpd_req_get_hdr_value_len(req, "Authorization");
    if (header_length < 7 || header_length >= 192)
    {
        return false;
    }
    char authorization[192];
    if (httpd_req_get_hdr_value_str(req, "Authorization", authorization, sizeof(authorization)) !=
            ESP_OK ||
        strncmp(authorization, "Basic ", 6) != 0)
    {
        return false;
    }
    uint8_t credentials[128] = {0};
    size_t  credential_length =
        base64_decode(authorization + 6, credentials, sizeof(credentials) - 1);
    if (credential_length <= strlen(ADMIN_USERNAME) + 1)
    {
        return false;
    }
    credentials[credential_length] = '\0';
    size_t username_length         = strlen(ADMIN_USERNAME);
    if (memcmp(credentials, ADMIN_USERNAME, username_length) != 0 ||
        credentials[username_length] != ':')
    {
        return false;
    }
    uint8_t candidate_hash[32];
    hash_admin_password((const char *)credentials + username_length + 1, candidate_hash);
    return password_hash_matches(candidate_hash, s_admin_password_hash);
}

static esp_err_t require_admin_auth(httpd_req_t *req)
{
    if (admin_request_is_authorized(req))
    {
        return ESP_OK;
    }
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ESP32 VLESS Router\"");
    return httpd_resp_sendstr(req, "Administrator credentials required");
}

static void parse_config_form(char *body, router_config_t *config, char *port, size_t port_size,
                              char *vless_uri, size_t uri_size)
{
    for (char *field = body; field && *field;)
    {
        char *next = strchr(field, '&');
        if (next)
        {
            *next = '\0';
        }
        char *equals = strchr(field, '=');
        if (equals)
        {
            *equals = '\0';
            url_decode(field);
            url_decode(equals + 1);
            if (strcmp(field, "ap_ssid") == 0 && equals[1])
            {
                strlcpy(config->ap_ssid, equals + 1, sizeof(config->ap_ssid));
            }
            else if (strcmp(field, "ap_password") == 0 && equals[1])
            {
                strlcpy(config->ap_password, equals + 1, sizeof(config->ap_password));
            }
            else if (strcmp(field, "ap_ip") == 0 && equals[1])
            {
                strlcpy(config->ap_ip, equals + 1, sizeof(config->ap_ip));
            }
            else if (strcmp(field, "ssid") == 0 && equals[1])
            {
                strlcpy(config->upstream_ssid, equals + 1, sizeof(config->upstream_ssid));
            }
            else if (strcmp(field, "password") == 0 && equals[1])
            {
                strlcpy(config->upstream_password, equals + 1, sizeof(config->upstream_password));
            }
            else if (strcmp(field, "host") == 0 && equals[1])
            {
                strlcpy(config->vless_host, equals + 1, sizeof(config->vless_host));
            }
            else if (strcmp(field, "uuid") == 0 && equals[1])
            {
                strlcpy(config->vless_uuid, equals + 1, sizeof(config->vless_uuid));
            }
            else if (strcmp(field, "port") == 0 && equals[1])
            {
                strlcpy(port, equals + 1, port_size);
            }
            else if (strcmp(field, "vless_uri") == 0 && equals[1])
            {
                strlcpy(vless_uri, equals + 1, uri_size);
            }
            else if (strcmp(field, "dns_resolver") == 0)
            {
                strlcpy(config->dns_resolver, equals + 1, sizeof(config->dns_resolver));
            }
            else if (strcmp(field, "singmux_enabled") == 0)
            {
                config->singmux_enabled = strcmp(equals + 1, "1") == 0 ||
                                          strcmp(equals + 1, "true") == 0 ||
                                          strcmp(equals + 1, "on") == 0;
            }
        }
        if (!next)
        {
            break;
        }
        field = next + 1;
    }
}

static bool form_value(const char *body, const char *name, char *value, size_t value_size)
{
    size_t name_length = strlen(name);
    for (const char *field = body; field && *field;)
    {
        const char *next         = strchr(field, '&');
        size_t      field_length = next ? (size_t)(next - field) : strlen(field);
        if (field_length > name_length && memcmp(field, name, name_length) == 0 &&
            field[name_length] == '=')
        {
            size_t length = field_length - name_length - 1;
            if (length >= value_size)
            {
                return false;
            }
            memcpy(value, field + name_length + 1, length);
            value[length] = '\0';
            url_decode(value);
            return true;
        }
        field = next ? next + 1 : NULL;
    }
    return false;
}

static bool query_has_value(const char *query, const char *name, const char *value)
{
    size_t name_length  = strlen(name);
    size_t value_length = strlen(value);

    while (query && *query && *query != '#')
    {
        const char *end    = strpbrk(query, "&#");
        size_t      length = end ? (size_t)(end - query) : strlen(query);

        if (length == name_length + value_length + 1 && strncmp(query, name, name_length) == 0 &&
            query[name_length] == '=' && strncmp(query + name_length + 1, value, value_length) == 0)
        {
            return true;
        }

        query = (end && *end == '&') ? end + 1 : NULL;
    }
    return false;
}

/* Supports plain VLESS TCP URIs: vless://UUID@HOST:PORT?encryption=none&type=tcp */
static bool parse_vless_tcp_uri(const char *uri, router_config_t *config)
{
    static const char scheme[] = "vless://";
    const char       *user;
    const char       *at;
    const char       *authority_end;
    const char       *host;
    const char       *port_start;
    char              port_text[6] = {0};

    if (strncmp(uri, scheme, sizeof(scheme) - 1) != 0)
    {
        return false;
    }

    user = uri + sizeof(scheme) - 1;
    at   = strchr(user, '@');
    if (!at || at == user || (size_t)(at - user) >= sizeof(config->vless_uuid))
    {
        return false;
    }

    authority_end = strpbrk(at + 1, "?#/");
    if (!authority_end)
    {
        authority_end = uri + strlen(uri);
    }
    if (authority_end == at + 1)
    {
        return false;
    }

    host = at + 1;
    if (*host == '[')
    {
        const char *close = strchr(host, ']');
        if (!close || close + 1 >= authority_end || close[1] != ':' ||
            (size_t)(close - host - 1) >= sizeof(config->vless_host))
        {
            return false;
        }
        memcpy(config->vless_host, host + 1, close - host - 1);
        config->vless_host[close - host - 1] = '\0';
        port_start                           = close + 2;
    }
    else
    {
        const char *colon = authority_end;
        while (colon > host && colon[-1] != ':')
        {
            --colon;
        }
        if (colon == host || (size_t)(colon - host - 1) >= sizeof(config->vless_host))
        {
            return false;
        }
        memcpy(config->vless_host, host, colon - host - 1);
        config->vless_host[colon - host - 1] = '\0';
        port_start                           = colon;
    }

    if (port_start >= authority_end || (size_t)(authority_end - port_start) >= sizeof(port_text))
    {
        return false;
    }
    memcpy(port_text, port_start, authority_end - port_start);
    char *port_end;
    long  port = strtol(port_text, &port_end, 10);
    if (*port_end || port < 1 || port > 65535)
    {
        return false;
    }

    if (*authority_end != '?' || !query_has_value(authority_end + 1, "encryption", "none") ||
        !query_has_value(authority_end + 1, "type", "tcp"))
    {
        return false;
    }

    memcpy(config->vless_uuid, user, at - user);
    config->vless_uuid[at - user] = '\0';
    config->vless_port            = (uint16_t)port;
    return true;
}

static esp_err_t send_json(httpd_req_t *req, const char *json)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, json);
}

static esp_err_t root_get(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, portal_page_html(), HTTPD_RESP_USE_STRLEN);
}

static esp_err_t config_get(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    esp_netif_ip_info_t  info           = {0};
    esp_netif_dns_info_t dns            = {0};
    char                 ap_ip[16]      = "";
    char                 ip[16]         = "";
    char                 gateway[16]    = "";
    char                 netmask[16]    = "";
    char                 dns_server[16] = "";
    strlcpy(ap_ip, configured_ap_ipv4(&s_config), sizeof(ap_ip));
    if (s_has_upstream && s_sta_netif && esp_netif_get_ip_info(s_sta_netif, &info) == ESP_OK)
    {
        esp_ip4addr_ntoa(&info.ip, ip, sizeof(ip));
        esp_ip4addr_ntoa(&info.gw, gateway, sizeof(gateway));
        esp_ip4addr_ntoa(&info.netmask, netmask, sizeof(netmask));
        if (esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK)
        {
            esp_ip4addr_ntoa(&dns.ip.u_addr.ip4, dns_server, sizeof(dns_server));
        }
    }
    bandwidth_stats_t bandwidth          = bandwidth_snapshot();
    uint32_t          singmux_tcp_active = 0;
    uint32_t          free_internal      = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    uint32_t largest_internal_block      = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    uint32_t free_psram                  = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    uint32_t free_total                  = esp_get_free_heap_size();
    for (size_t index = 0; index < SINGMUX_TCP_STREAM_MAX; ++index)
    {
        if (s_singmux_tcp_streams[index].in_use)
        {
            ++singmux_tcp_active;
        }
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    char chunk[2048];
    snprintf(chunk, sizeof(chunk),
             "{\"firmware_version\":\"%s\",\"ap_ssid\":\"%s\",\"ap_ip\":\"%s\",\"ssid\":\"%s\","
             "\"open_network\":%s,",
             BUILD_GIT_VERSION, configured_or_default(s_config.ap_ssid, AP_SSID), ap_ip,
             s_config.upstream_ssid, s_config.upstream_password[0] ? "false" : "true");
    httpd_resp_sendstr_chunk(req, chunk);
    httpd_resp_sendstr_chunk(req, "\"upstream_networks\":[");
    for (int index = 0; index < s_config.upstream_network_count && index < UPSTREAM_NETWORK_MAX;
         ++index)
    {
        if (index)
        {
            httpd_resp_sendstr_chunk(req, ",");
        }
        httpd_resp_sendstr_chunk(req, "{\"ssid\":");
        json_string(req, s_config.upstream_networks[index].ssid);
        snprintf(chunk, sizeof(chunk), ",\"open\":%s}",
                 s_config.upstream_networks[index].password[0] ? "false" : "true");
        httpd_resp_sendstr_chunk(req, chunk);
    }
    httpd_resp_sendstr_chunk(req, "],\"scan_results\":");
    if (s_scan_results_available)
    {
        httpd_resp_sendstr_chunk(req, "[");
        for (int index = 0; index < s_scan_record_count; ++index)
        {
            if (index)
            {
                httpd_resp_sendstr_chunk(req, ",");
            }
            httpd_resp_sendstr_chunk(req, "{\"ssid\":");
            json_string(req, (const char *)s_scan_records[index].ssid);
            snprintf(chunk, sizeof(chunk), ",\"rssi\":%d}", s_scan_records[index].rssi);
            httpd_resp_sendstr_chunk(req, chunk);
        }
        httpd_resp_sendstr_chunk(req, "]");
    }
    else
    {
        httpd_resp_sendstr_chunk(req, "null");
    }
    snprintf(
        chunk, sizeof(chunk),
        ",\"host\":\"%s\",\"port\":%u,\"dns_resolver\":\"%s\",\"singmux_enabled\":%s,"
        "\"mode\":\"%s\",\"connected\":%s,\"ip\":\"%s\",\"gateway\":\"%s\",\"netmask\":\"%s\","
        "\"dns\":\"%s\",\"xudp_active\":%u,\"xudp_queued\":%u,\"xudp_dropped\":%u,"
        "\"xudp_rx_dropped\":%u,\"xudp_tunnel_failures\":%u,\"transparent_tcp_max\":%u,"
        "\"singmux_connected\":%s,\"singmux_tcp_active\":%u,\"singmux_control_queued\":%u,"
        "\"singmux_sessions_opened\":%u,\"singmux_sessions_closed\":%u,"
        "\"singmux_close_eof\":%u,\"singmux_close_socket_error\":%u,\"singmux_close_protocol_"
        "error\":%u,"
        "\"singmux_last_errno\":%d,\"singmux_tx_wire_bytes\":%llu,\"singmux_rx_wire_bytes\":%llu,"
        "\"singmux_tx_frames\":%u,\"singmux_rx_frames\":%u,\"singmux_tcp_rx_queue_high_water\":%u,"
        "\"singmux_tcp_rx_queue_full\":%u,\"singmux_tcp_rx_alloc_failures\":%u,"
        "\"singmux_control_timeouts\":%u,\"singmux_tcp_open_failures\":%u,"
        "\"singmux_rx_reads\":%u,\"singmux_scheduler_yields\":%u,"
        "\"singmux_rx_reassembly_high_water\":%u,"
        "\"up_bps\":%u,\"down_bps\":%u,\"up_bps_10s\":%u,\"down_bps_10s\":%u,"
        "\"up_bps_30s\":%u,\"down_bps_30s\":%u,\"chip_temperature_c\":%.1f,"
        "\"cpu_frequency_mhz\":%u,\"cpu_load_core0\":%u,\"cpu_load_core1\":%u,"
        "\"up_bytes\":%llu,\"down_bytes\":%llu,"
        "\"free_internal\":%u,\"largest_internal_block\":%u,\"free_psram\":%u,"
        "\"free_total\":%u}",
        s_config.vless_host, s_config.vless_port, s_config.dns_resolver,
        s_config.singmux_enabled ? "true" : "false", transparent_mode_name(),
        s_has_upstream ? "true" : "false", ip, gateway, netmask, dns_server,
        (unsigned)s_udp_active_associations,
        s_udp_manager_queue ? (unsigned)uxQueueMessagesWaiting(s_udp_manager_queue) : 0,
        (unsigned)s_udp_queue_drops, (unsigned)s_udp_rx_drops, (unsigned)s_udp_tunnel_failures,
        (unsigned)TRANSPARENT_TCP_MAX_FLOWS, s_singmux_tunnel >= 0 ? "true" : "false",
        (unsigned)singmux_tcp_active,
        s_singmux_control_queue ? (unsigned)uxQueueMessagesWaiting(s_singmux_control_queue) : 0,
        (unsigned)s_singmux_stats.sessions_opened, (unsigned)s_singmux_stats.sessions_closed,
        (unsigned)s_singmux_stats.close_eof, (unsigned)s_singmux_stats.close_socket_error,
        (unsigned)s_singmux_stats.close_protocol_error, s_singmux_stats.last_socket_errno,
        (unsigned long long)s_singmux_stats.tx_wire_bytes,
        (unsigned long long)s_singmux_stats.rx_wire_bytes, (unsigned)s_singmux_stats.tx_frames,
        (unsigned)s_singmux_stats.rx_frames, (unsigned)s_singmux_stats.tcp_rx_queue_high_water,
        (unsigned)s_singmux_stats.tcp_rx_queue_full,
        (unsigned)s_singmux_stats.tcp_rx_alloc_failures,
        (unsigned)s_singmux_stats.tcp_control_queue_timeouts,
        (unsigned)s_singmux_stats.tcp_stream_open_failures, (unsigned)s_singmux_stats.rx_reads,
        (unsigned)s_singmux_stats.scheduler_yields,
        (unsigned)s_singmux_stats.rx_reassembly_high_water, (unsigned)bandwidth.upload_bps,
        (unsigned)bandwidth.download_bps, (unsigned)bandwidth.upload_bps_10s,
        (unsigned)bandwidth.download_bps_10s, (unsigned)bandwidth.upload_bps_30s,
        (unsigned)bandwidth.download_bps_30s, s_chip_temperature_c, (unsigned)s_cpu_frequency_mhz,
        (unsigned)s_cpu_load_core0, (unsigned)s_cpu_load_core1,
        (unsigned long long)bandwidth.upload_bytes, (unsigned long long)bandwidth.download_bytes,
        (unsigned)free_internal, (unsigned)largest_internal_block, (unsigned)free_psram,
        (unsigned)free_total);
    httpd_resp_sendstr_chunk(req, chunk);
    return httpd_resp_sendstr_chunk(req, NULL);
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

static bool socket_recv_all(int socket_fd, uint8_t *data, size_t length)
{
    while (length)
    {
        int received = recv(socket_fd, data, length, 0);
        if (received <= 0)
        {
            return false;
        }
        data += received;
        length -= received;
    }
    return true;
}

static int open_direct_udp_stream(uint32_t destination_ip, uint16_t destination_port)
{
    if (!s_has_upstream)
    {
        return -1;
    }
    int                socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in address   = {.sin_family      = AF_INET,
                                    .sin_port        = htons(destination_port),
                                    .sin_addr.s_addr = destination_ip};
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

static bool udp_socket_send_datagram(int socket_fd, const uint8_t *data, size_t length)
{
    int sent = send(socket_fd, data, length, 0);
    return sent == (int)length;
}

/* sing-box multiplex is a normal VLESS TCP stream addressed to its reserved
   mux endpoint.
 * sing-mux v0 starts with a two-byte request selector
   (version 0, smux protocol), followed by
 * smux version-1 frames. */
static int open_singmux_session(void)
{
    int socket_fd =
        transport_tcp_open_vless_stream(&s_config, s_has_upstream, "sp.mux.sing-box.arpa", 444);
    if (socket_fd < 0)
    {
        return -1;
    }

    uint8_t request[2];
    if (!singmux_encode_session_request(request) ||
        !socket_send_all(socket_fd, request, sizeof(request)))
    {
        close(socket_fd);
        return -1;
    }

    /* sing-box returns this VLESS response together with (or before) the first
       smux frame.
     * The manager strips it before parsing smux frames. */
    s_singmux_vless_response_pending = true;
    s_singmux_stats.sessions_opened++;
    s_singmux_stats.last_session_open_ms = now_ms();
    return socket_fd;
}

static bool singmux_send_frame(int socket_fd, uint8_t command, uint32_t stream_id,
                               const uint8_t *payload, size_t payload_length)
{
    uint8_t header[SMUX_HEADER_SIZE];
    if (payload_length > UINT16_MAX ||
        !singmux_encode_smux_header(header, command, stream_id, (uint16_t)payload_length))
    {
        return false;
    }
    bool ok = socket_send_all(socket_fd, header, sizeof(header)) &&
              (!payload_length || socket_send_all(socket_fd, payload, payload_length));
    if (ok)
    {
        s_singmux_stats.tx_frames++;
        s_singmux_stats.tx_wire_bytes += sizeof(header) + payload_length;
    }
    else
    {
        s_singmux_stats.last_socket_errno = errno;
    }
    return ok;
}

/* Opens a plain VLESS TCP request addressed by an already-resolved IPv4 address. */
/* Open the VLESS Mux transport used by Xray's XUDP packet encoding.  Unlike a
   TCP/UDP VLESS request, Mux has no destination address in its VLESS header. */
static int open_vless_mux_stream(void)
{
    uint8_t uuid[16];
    if (!s_has_upstream || !transport_tcp_uuid_to_bytes(s_config.vless_uuid, uuid))
    {
        return -1;
    }
    char server_port[6];
    snprintf(server_port, sizeof(server_port), "%u", s_config.vless_port);
    struct addrinfo  hints     = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(s_config.vless_host, server_port, &hints, &addresses) != 0)
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
    uint8_t header[19] = {0};
    header[0]          = 0;
    memcpy(header + 1, uuid, sizeof(uuid));
    header[17] = 0; /* VLESS addon length */
    header[18] = 3; /* VLESS Mux command */
    if (!socket_send_all(socket_fd, header, sizeof(header)))
    {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

static esp_err_t xudp_test_get(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    static const uint8_t dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 'g',
        'o',  'o',  'g',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
    };
    int tunnel = open_vless_mux_stream();
    if (tunnel < 0)
    {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "VLESS Mux connection failed");
    }
    struct timeval timeout = {.tv_sec = 12, .tv_usec = 0};
    setsockopt(tunnel, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    uint8_t frame[2 + 12 + 2 + sizeof(dns_query)] = {0};
    size_t  frame_length                          = 0;
    /* Direct sing-box XUDP: Mux header followed by a New/Data/UDP frame,
       whose destination uses V2Ray's port-then-address serialization. */
    bool ok = xudp_encode_ipv4(frame, sizeof(frame), &frame_length, 0x01010101, 53, dns_query,
                               sizeof(dns_query));
    if (ok)
    {
        ok = socket_send_all(tunnel, frame, frame_length);
    }
    uint8_t vless[2];
    if (ok)
    {
        ok = socket_recv_all(tunnel, vless, sizeof(vless)) && vless[0] == 0;
    }
    static uint8_t addon[255];
    if (ok && vless[1])
    {
        ok = socket_recv_all(tunnel, addon, vless[1]);
    }
    uint8_t metadata_length_bytes[2] = {0};
    if (ok)
    {
        ok = socket_recv_all(tunnel, metadata_length_bytes, sizeof(metadata_length_bytes));
    }
    size_t  metadata_length = ((size_t)metadata_length_bytes[0] << 8) | metadata_length_bytes[1];
    uint8_t metadata[64]    = {0};
    if (ok && (metadata_length < 4 || metadata_length > sizeof(metadata)))
    {
        ok = false;
    }
    if (ok)
    {
        ok = socket_recv_all(tunnel, metadata, metadata_length);
    }
    uint8_t payload_length_bytes[2] = {0};
    uint8_t xudp_option             = 0;
    if (ok)
    {
        ok = xudp_decode_header(metadata, metadata_length, &xudp_option, NULL, NULL) &&
             xudp_option == 1 &&
             socket_recv_all(tunnel, payload_length_bytes, sizeof(payload_length_bytes));
    }
    size_t  payload_length = ((size_t)payload_length_bytes[0] << 8) | payload_length_bytes[1];
    uint8_t response[512]  = {0};
    if (ok && (payload_length < 12 || payload_length > sizeof(response)))
    {
        ok = false;
    }
    if (ok)
    {
        ok = socket_recv_all(tunnel, response, payload_length);
    }
    close(tunnel);
    ESP_LOGI(TAG,
             "XUDP probe trace: ok=%d meta=%u status=%u opt=%u payload=%u dns=%02x%02x flags=%02x",
             ok, (unsigned)metadata_length, metadata[2], metadata[3], (unsigned)payload_length,
             response[0], response[1], response[2]);
    if (!ok || response[0] != 0x12 || response[1] != 0x34 || !(response[2] & 0x80))
    {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "VLESS server did not return a valid XUDP DNS response");
    }
    ESP_LOGI(TAG, "XUDP VLESS probe passed (%u-byte DNS response)", (unsigned)payload_length);
    return send_json(req, "{\"message\":\"XUDP VLESS probe passed.\"}");
}

static void dns_cache_response_records(const uint8_t *packet, int bytes)
{
    int         offset = 12;
    static char question[254];
    memset(question, 0, sizeof(question));
    if (!dns_name(packet, bytes, &offset, question) || offset + 4 > bytes)
    {
        return;
    }
    offset += 4;
    int answers = ((int)packet[6] << 8) | packet[7];
    for (int i = 0; i < answers && offset + 12 <= bytes; ++i)
    {
        if ((packet[offset] & 0xc0) == 0xc0)
        {
            offset += 2;
        }
        else
        {
            static char ignored[254];
            if (!dns_name(packet, bytes, &offset, ignored))
            {
                break;
            }
        }
        if (offset + 10 > bytes)
        {
            break;
        }
        uint16_t type     = ((uint16_t)packet[offset] << 8) | packet[offset + 1];
        uint16_t rdlength = ((uint16_t)packet[offset + 8] << 8) | packet[offset + 9];
        offset += 10;
        if (offset + rdlength > bytes)
        {
            break;
        }
        if (type == 1 && rdlength == 4)
        {
            uint32_t address;
            memcpy(&address, packet + offset, 4);
            transparent_tcp_dns_record(question, address);
        }
        offset += rdlength;
    }
}

static bool dns_direct_query(uint8_t *packet, int *bytes)
{
    if (!s_has_upstream)
    {
        return false;
    }
    const char *resolver        = s_config.dns_resolver[0] ? s_config.dns_resolver : NULL;
    char        resolver_ip[16] = "";
    if (!resolver && s_sta_netif)
    {
        esp_netif_dns_info_t dns = {0};
        if (esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK)
        {
            esp_ip4addr_ntoa(&dns.ip.u_addr.ip4, resolver_ip, sizeof(resolver_ip));
            resolver = resolver_ip;
        }
    }
    if (!resolver || !resolver[0])
    {
        return false;
    }
    struct addrinfo  hints     = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM};
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(resolver, "53", &hints, &addresses) != 0)
    {
        return false;
    }
    int socket_fd = socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
    if (socket_fd < 0)
    {
        freeaddrinfo(addresses);
        return false;
    }
    struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    bool ok =
        sendto(socket_fd, packet, *bytes, 0, addresses->ai_addr, addresses->ai_addrlen) == *bytes;
    if (ok)
    {
        int response_length = recv(socket_fd, packet, 512, 0);
        ok                  = response_length >= 12;
        if (ok)
        {
            *bytes = response_length;
            dns_cache_response_records(packet, *bytes);
        }
    }
    close(socket_fd);
    freeaddrinfo(addresses);
    return ok;
}

/* Extracts the first DNS name from a complete TLS ClientHello carried in one TCP read. */
static bool tls_client_hello_sni(const uint8_t *data, size_t length, char host[254])
{
    if (length < 44 || data[0] != 0x16 || data[5] != 0x01)
    {
        return false;
    }
    size_t offset = 9 + 2 + 32; /* handshake header, legacy version, random */
    if (offset >= length)
    {
        return false;
    }
    size_t session_length = data[offset++];
    if (offset + session_length + 2 > length)
    {
        return false;
    }
    offset += session_length;
    size_t cipher_length = ((size_t)data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (offset + cipher_length + 1 > length)
    {
        return false;
    }
    offset += cipher_length;
    size_t compression_length = data[offset++];
    if (offset + compression_length + 2 > length)
    {
        return false;
    }
    offset += compression_length;
    size_t extensions_length = ((size_t)data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (offset + extensions_length > length)
    {
        return false;
    }
    size_t extensions_end = offset + extensions_length;
    while (offset + 4 <= extensions_end)
    {
        uint16_t type             = ((uint16_t)data[offset] << 8) | data[offset + 1];
        size_t   extension_length = ((size_t)data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        if (offset + extension_length > extensions_end)
        {
            return false;
        }
        if (type == 0 && extension_length >= 5)
        {
            size_t names_end   = offset + 2 + (((size_t)data[offset] << 8) | data[offset + 1]);
            size_t name_offset = offset + 2;
            if (names_end > offset + extension_length)
            {
                return false;
            }
            while (name_offset + 3 <= names_end)
            {
                uint8_t name_type   = data[name_offset++];
                size_t  name_length = ((size_t)data[name_offset] << 8) | data[name_offset + 1];
                name_offset += 2;
                if (name_offset + name_length > names_end)
                {
                    return false;
                }
                if (name_type == 0 && name_length && name_length < 254)
                {
                    memcpy(host, data + name_offset, name_length);
                    host[name_length] = '\0';
                    return true;
                }
                name_offset += name_length;
            }
        }
        offset += extension_length;
    }
    return false;
}

static BaseType_t create_stream_task(TaskFunction_t task, const char *name, void *argument)
{
    /* Wi-Fi and lwIP need internal RAM.  Relay task stacks can safely live in
       PSRAM, so connection capacity is not constrained by that scarce heap. */
    return xTaskCreateWithCaps(task, name, 8192, argument, 5, NULL,
                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

static void socks_client_task(void *arg)
{
    int client = (int)(intptr_t)arg;
    ESP_LOGI(TAG, "SOCKS client connected");
    uint8_t greeting[2];
    if (!socket_recv_all(client, greeting, 2) || greeting[0] != 5 || greeting[1] == 0)
    {
        goto done;
    }
    uint8_t methods[16];
    if (greeting[1] > sizeof(methods) || !socket_recv_all(client, methods, greeting[1]))
    {
        goto done;
    }
    uint8_t ok[] = {5, 0};
    if (!socket_send_all(client, ok, sizeof(ok)))
    {
        goto done;
    }
    uint8_t request[4];
    if (!socket_recv_all(client, request, 4) || request[0] != 5 || request[1] != 1 ||
        request[3] != 3)
    {
        goto done;
    }
    uint8_t len;
    if (!socket_recv_all(client, &len, 1) || len == 0 || len > 253)
    {
        goto done;
    }
    char host[254] = {0};
    if (!socket_recv_all(client, (uint8_t *)host, len))
    {
        goto done;
    }
    uint8_t port_bytes[2];
    if (!socket_recv_all(client, port_bytes, 2))
    {
        goto done;
    }
    uint16_t destination_port = ((uint16_t)port_bytes[0] << 8) | port_bytes[1];
    ESP_LOGI(TAG, "SOCKS CONNECT %s:%u", host, destination_port);
    int tunnel = transport_tcp_open_vless_stream(&s_config, s_has_upstream, host, destination_port);
    uint8_t reply[] = {5, tunnel >= 0 ? 0 : 1, 0, 1, 0, 0, 0, 0, 0, 0};
    if (!socket_send_all(client, reply, sizeof(reply)) || tunnel < 0)
    {
        goto done;
    }
    transport_tcp_relay_vless(client, tunnel, "SOCKS", bandwidth_record_upload,
                              bandwidth_record_download);
    close(tunnel);
done:
    ESP_LOGI(TAG, "SOCKS client closed");
    close(client);
    vTaskDeleteWithCaps(NULL);
}

static void socks_server_task(void *arg)
{
    (void)arg;
    int                listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in address  = {
         .sin_family = AF_INET, .sin_port = htons(1080), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, TRANSPARENT_TCP_LISTEN_BACKLOG) < 0)
    {
        ESP_LOGE(TAG, "SOCKS listener failed");
        vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "Internal VLESS SOCKS5 relay listening on port 1080");
    for (;;)
    {
        int client = accept(listener, NULL, NULL);
        if (client >= 0 && create_stream_task(socks_client_task, "socks_client",
                                              (void *)(intptr_t)client) != pdPASS)
        {
            ESP_LOGW(TAG, "SOCKS stream task allocation failed");
            close(client);
        }
    }
}

static int singmux_tcp_open(uint32_t destination_ip, const char *destination_name,
                            uint16_t destination_port, const uint8_t *initial,
                            size_t initial_length)
{
    if (!s_config.singmux_enabled || !s_singmux_control_queue ||
        initial_length > SINGMUX_TCP_DATA_MAX)
    {
        return -1;
    }
    singmux_tcp_data_t *first = NULL;
    if (initial_length)
    {
        first =
            heap_caps_malloc(sizeof(*first) + initial_length, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!first)
        {
            return -1;
        }
        first->length = initial_length;
        memcpy(first->data, initial, initial_length);
    }
    singmux_control_t control = {.type             = SINGMUX_CONTROL_OPEN,
                                 .slot             = -1,
                                 .reply_task       = xTaskGetCurrentTaskHandle(),
                                 .destination_ip   = destination_ip,
                                 .destination_port = destination_port,
                                 .data             = first};
    if (destination_name)
    {
        strlcpy(control.destination_name, destination_name, sizeof(control.destination_name));
    }
    if (xQueueSend(s_singmux_control_queue, &control, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        s_singmux_stats.tcp_control_queue_timeouts++;
        free(first);
        return -1;
    }
    uint32_t answer = 0;
    if (xTaskNotifyWait(0, UINT32_MAX, &answer, pdMS_TO_TICKS(15000)) != pdTRUE || !answer)
    {
        s_singmux_stats.tcp_stream_open_failures++;
        return -1;
    }
    return (int)answer - 1;
}

static bool singmux_tcp_queue_data(int slot, uint32_t stream_id, const uint8_t *data, size_t length)
{
    if (slot < 0 || length > SINGMUX_TCP_DATA_MAX || !s_singmux_control_queue)
    {
        return false;
    }
    singmux_tcp_data_t *copy =
        heap_caps_malloc(sizeof(*copy) + length, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!copy)
    {
        return false;
    }
    copy->length = length;
    memcpy(copy->data, data, length);
    singmux_control_t control = {
        .type = SINGMUX_CONTROL_DATA, .slot = slot, .stream_id = stream_id, .data = copy};
    if (xQueueSend(s_singmux_control_queue, &control, pdMS_TO_TICKS(250)) != pdTRUE)
    {
        s_singmux_stats.tcp_control_queue_timeouts++;
        free(copy);
        return false;
    }
    return true;
}

/* A close is acknowledged only after the manager has detached the stream.
 * This lets the relay, which owns the queue allocation, delete it safely. */
static bool singmux_tcp_close(int slot, uint32_t stream_id)
{
    if (!s_singmux_control_queue || slot < 0)
    {
        return false;
    }
    singmux_control_t control = {.type       = SINGMUX_CONTROL_CLOSE,
                                 .slot       = slot,
                                 .stream_id  = stream_id,
                                 .reply_task = xTaskGetCurrentTaskHandle()};
    if (xQueueSend(s_singmux_control_queue, &control, pdMS_TO_TICKS(250)) != pdTRUE)
    {
        s_singmux_stats.tcp_control_queue_timeouts++;
        return false;
    }
    uint32_t answer = 0;
    return xTaskNotifyWait(0, UINT32_MAX, &answer, pdMS_TO_TICKS(1000)) == pdTRUE && answer;
}

static void relay_singmux_tcp_stream(int client, int slot)
{
    if (slot < 0 || slot >= SINGMUX_TCP_STREAM_MAX)
    {
        return;
    }
    /* The manager does not delete this queue after a successful open.  Take a
     * private handle before relaying so a detached slot can be reused safely. */
    QueueHandle_t receive_queue = s_singmux_tcp_streams[slot].receive_queue;
    uint32_t      stream_id     = s_singmux_tcp_streams[slot].stream_id;
    if (!receive_queue || !stream_id)
    {
        return;
    }
    bool detached = false;
    for (;;)
    {
        fd_set reads;
        FD_ZERO(&reads);
        FD_SET(client, &reads);
        /* When downstream data is already queued, drain it immediately rather
         * than
         * waiting a full 20 ms for client input.  The latter let a fast
         * smux download
         * fill a 12-frame queue and terminate that stream. */
        bool           have_downstream = uxQueueMessagesWaiting(receive_queue) != 0;
        struct timeval timeout         = {.tv_sec = 0, .tv_usec = have_downstream ? 0 : 20000};
        int            ready           = select(client + 1, &reads, NULL, NULL, &timeout);
        if (ready > 0 && FD_ISSET(client, &reads))
        {
            uint8_t buffer[1024];
            int     count = recv(client, buffer, sizeof(buffer), 0);
            if (count <= 0 || !singmux_tcp_queue_data(slot, stream_id, buffer, count))
            {
                break;
            }
        }
        singmux_tcp_data_t *item = NULL;
        while (xQueueReceive(receive_queue, &item, 0) == pdTRUE)
        {
            if (!item)
            {
                detached = singmux_tcp_close(slot, stream_id);
                goto done;
            }
            bool ok = socket_send_all(client, item->data, item->length);
            free(item);
            if (!ok)
            {
                goto close_stream;
            }
        }
        /* A full queue can happen when this AP client cannot accept data
         * quickly enough.  It must close only this stream, never the shared
         * session carrying unrelated browser connections. */
        if (s_singmux_tcp_streams[slot].peer_closed && uxQueueMessagesWaiting(receive_queue) == 0)
        {
            detached = singmux_tcp_close(slot, stream_id);
            goto done;
        }
    }
close_stream:
    detached = singmux_tcp_close(slot, stream_id);
done:
    if (detached)
    {
        singmux_tcp_data_t *item = NULL;
        while (xQueueReceive(receive_queue, &item, 0) == pdTRUE)
        {
            free(item);
        }
        vQueueDelete(receive_queue);
    }
}

static void transparent_client_task(void *arg)
{
    int                client      = (int)(intptr_t)arg;
    struct sockaddr_in peer        = {0};
    socklen_t          peer_length = sizeof(peer);
    uint16_t           peer_port   = 0;
    if (getpeername(client, (struct sockaddr *)&peer, &peer_length) != 0)
    {
        goto done;
    }
    peer_port = ntohs(peer.sin_port);
    TRAFFIC_LOG(TAG, "transparent accepted peer=%08lx:%u", (unsigned long)peer.sin_addr.s_addr,
                peer_port);
    transparent_tcp_flow_t flow;
    bool                   have_flow = transparent_tcp_get(peer.sin_addr.s_addr, peer_port, &flow);
    if (!have_flow)
    {
        ESP_LOGW(TAG, "transparent client has no flow state");
        goto done;
    }
    transparent_tcp_set_relay_port(peer.sin_addr.s_addr, peer_port, 15001);
    uint8_t initial[1024];
    int     initial_length = recv(client, initial, sizeof(initial) - 1, 0);
    if (initial_length <= 0)
    {
        goto done;
    }
    initial[initial_length]       = '\0';
    int  tunnel                   = -1;
    char singmux_destination[254] = {0};
    bool use_vless                = transparent_mode_uses_vless();
    if (flow.original_port == 80)
    {
        char *host_start = strstr((char *)initial, "\nHost:");
        if (host_start)
        {
            host_start += 6;
            while (*host_start == ' ')
            {
                host_start++;
            }
            char *host_end = strpbrk(host_start, "\r\n:");
            if (host_end && host_end > host_start && host_end - host_start < 254)
            {
                char host[254] = {0};
                memcpy(host, host_start, host_end - host_start);
                TRAFFIC_LOG(TAG, "transparent HTTP Host '%s' used for %s", host,
                            use_vless ? "VLESS" : "upstream");
                if (use_vless && s_config.singmux_enabled)
                {
                    strlcpy(singmux_destination, host, sizeof(singmux_destination));
                }
                else
                {
                    tunnel = transport_tcp_open_domain(s_transparent_mode, &s_config,
                                                       s_has_upstream, host, flow.original_port);
                }
            }
        }
    }
    if (tunnel < 0 && !singmux_destination[0])
    {
        char host[254] = {0};
        if (transparent_tcp_dns_name_for_ip(flow.original_ip, host, sizeof(host)))
        {
            TRAFFIC_LOG(TAG, "transparent DNS cache '%s' used for %s", host,
                        use_vless ? "VLESS" : "upstream");
            if (use_vless && s_config.singmux_enabled)
            {
                strlcpy(singmux_destination, host, sizeof(singmux_destination));
            }
            else
            {
                tunnel = transport_tcp_open_domain(s_transparent_mode, &s_config, s_has_upstream,
                                                   host, flow.original_port);
            }
        }
    }
    if (tunnel < 0 && !singmux_destination[0])
    {
        char host[254] = {0};
        if (tls_client_hello_sni(initial, initial_length, host))
        {
            ESP_LOGI(TAG, "transparent TLS SNI '%s' used for %s", host,
                     use_vless ? "VLESS" : "upstream");
            if (use_vless && s_config.singmux_enabled)
            {
                strlcpy(singmux_destination, host, sizeof(singmux_destination));
            }
            else
            {
                tunnel = transport_tcp_open_domain(s_transparent_mode, &s_config, s_has_upstream,
                                                   host, flow.original_port);
            }
        }
    }
    if (use_vless && s_config.singmux_enabled)
    {
        int slot =
            singmux_tcp_open(flow.original_ip, singmux_destination[0] ? singmux_destination : NULL,
                             flow.original_port, initial, initial_length);
        if (slot < 0)
        {
            ESP_LOGW(TAG, "transparent sing-box smux connection failed");
            goto done;
        }
        relay_singmux_tcp_stream(client, slot);
        goto done;
    }
    if (tunnel < 0)
    {
        ESP_LOGI(TAG, "transparent flow opening %s IPv4 destination port %u",
                 use_vless ? "VLESS" : "upstream", flow.original_port);
        tunnel = transport_tcp_open_ipv4(s_transparent_mode, &s_config, s_has_upstream,
                                         flow.original_ip, flow.original_port);
    }
    if (tunnel < 0)
    {
        ESP_LOGW(TAG, "transparent %s connection failed", use_vless ? "VLESS" : "upstream");
        goto done;
    }
    if (!socket_send_all(tunnel, initial, initial_length))
    {
        close(tunnel);
        goto done;
    }
    transport_tcp_relay(s_transparent_mode, client, tunnel, "transparent", bandwidth_record_upload,
                        bandwidth_record_download);
    close(tunnel);
done:
    if (peer.sin_addr.s_addr && peer_port)
    {
        transparent_tcp_remove(peer.sin_addr.s_addr, peer_port);
    }
    close(client);
    vTaskDeleteWithCaps(NULL);
}

static void transparent_maintenance_task(void *arg)
{
    (void)arg;
    for (;;)
    {
        transparent_tcp_expire((uint32_t)(esp_timer_get_time() / 1000));
        transparent_udp_expire((uint32_t)(esp_timer_get_time() / 1000));
        vTaskDelay(pdMS_TO_TICKS(30000));
    }
}

typedef struct
{
    size_t  length;
    uint8_t payload[UDP_DATAGRAM_MAX];
} udp_datagram_t;
typedef struct
{
    bool                   in_use;
    struct sockaddr_in     client;
    transparent_udp_flow_t flow;
    int                    tunnel;
    uint32_t               singmux_stream_id;
    bool                   request_written;
    bool                   vless_response_pending;
    bool                   singmux_response_pending;
    uint8_t               *rx_buffer;
    size_t                 rx_length;
    uint32_t               last_activity_ms;
} udp_association_t;
static udp_association_t s_udp_associations[UDP_ASSOCIATION_MAX];
typedef struct
{
    struct sockaddr_in     client;
    transparent_udp_flow_t flow;
    udp_datagram_t        *datagram;
} udp_ingress_t;
static uint32_t s_udp_last_backpressure_log_ms;
static int      udp_association_find_singmux_stream(uint32_t stream_id);
static int      singmux_tcp_stream_find(uint32_t stream_id);
static bool     singmux_receive_available(void);
static bool     singmux_socket_readable(void);

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static int singmux_tcp_stream_find(uint32_t stream_id)
{
    for (int i = 0; i < SINGMUX_TCP_STREAM_MAX; ++i)
    {
        if (s_singmux_tcp_streams[i].in_use && s_singmux_tcp_streams[i].stream_id == stream_id)
        {
            return i;
        }
    }
    return -1;
}

/* The relay task owns a queue after OPEN succeeds.  The manager only detaches
 * the slot; the acknowledged relay then drains and deletes its own queue. */
static void singmux_tcp_stream_detach(int slot)
{
    if (slot < 0 || slot >= SINGMUX_TCP_STREAM_MAX || !s_singmux_tcp_streams[slot].in_use)
    {
        return;
    }
    memset(&s_singmux_tcp_streams[slot], 0, sizeof(s_singmux_tcp_streams[slot]));
}

/* OPEN can fail before its caller receives a slot.  In that case no relay owns
 * the queue, so the manager must reclaim it itself. */
static void singmux_tcp_stream_discard(int slot)
{
    if (slot < 0 || slot >= SINGMUX_TCP_STREAM_MAX || !s_singmux_tcp_streams[slot].in_use)
    {
        return;
    }
    singmux_tcp_data_t *item = NULL;
    while (s_singmux_tcp_streams[slot].receive_queue &&
           xQueueReceive(s_singmux_tcp_streams[slot].receive_queue, &item, 0) == pdTRUE)
    {
        free(item);
    }
    if (s_singmux_tcp_streams[slot].receive_queue)
    {
        vQueueDelete(s_singmux_tcp_streams[slot].receive_queue);
    }
    memset(&s_singmux_tcp_streams[slot], 0, sizeof(s_singmux_tcp_streams[slot]));
}

static bool singmux_tcp_deliver(int slot, const uint8_t *payload, size_t length)
{
    singmux_tcp_stream_t *stream = &s_singmux_tcp_streams[slot];
    if (stream->response_pending)
    {
        if (!length)
        {
            return true;
        }
        if (payload[0] != 0)
        {
            return false;
        }
        ++payload;
        --length;
        stream->response_pending = false;
    }
    if (!length)
    {
        return true;
    }
    singmux_tcp_data_t *item =
        heap_caps_malloc(sizeof(*item) + length, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!item)
    {
        s_singmux_stats.tcp_rx_alloc_failures++;
        stream->peer_closed = true;
        return true;
    }
    item->length = length;
    memcpy(item->data, payload, length);
    if (xQueueSend(stream->receive_queue, &item, 0) != pdTRUE)
    {
        free(item);
        s_singmux_stats.tcp_rx_queue_full++;
        stream->peer_closed = true;
        return true;
    }
    UBaseType_t depth = uxQueueMessagesWaiting(stream->receive_queue);
    if (depth > s_singmux_stats.tcp_rx_queue_high_water)
    {
        s_singmux_stats.tcp_rx_queue_high_water = (uint16_t)depth;
    }
    bandwidth_record_download(length);
    return true;
}

static bool singmux_tcp_notify_closed(int slot)
{
    singmux_tcp_data_t   *end    = NULL;
    singmux_tcp_stream_t *stream = &s_singmux_tcp_streams[slot];
    stream->peer_closed          = true;
    return stream->receive_queue && xQueueSend(stream->receive_queue, &end, 0) == pdTRUE;
}

static void singmux_tcp_notify_all_closed(void)
{
    for (int i = 0; i < SINGMUX_TCP_STREAM_MAX; ++i)
    {
        if (s_singmux_tcp_streams[i].in_use)
        {
            singmux_tcp_notify_closed(i);
        }
    }
}

static int udp_association_find(uint32_t client_ip, uint16_t client_port)
{
    for (int i = 0; i < UDP_ASSOCIATION_MAX; ++i)
    {
        if (s_udp_associations[i].in_use && s_udp_associations[i].flow.client_ip == client_ip &&
            s_udp_associations[i].flow.client_port == client_port)
        {
            return i;
        }
    }
    return -1;
}

static void udp_association_release(int slot)
{
    if (slot >= 0 && slot < UDP_ASSOCIATION_MAX && s_udp_associations[slot].in_use)
    {
        if (s_udp_associations[slot].tunnel >= 0)
        {
            close(s_udp_associations[slot].tunnel);
        }
        free(s_udp_associations[slot].rx_buffer);
        if (s_udp_active_associations)
        {
            s_udp_active_associations--;
        }
        memset(&s_udp_associations[slot], 0, sizeof(s_udp_associations[slot]));
        s_udp_associations[slot].tunnel = -1;
    }
}

/* VLESS/XUDP runs over TCP, so receive boundaries are arbitrary.  Keep a
   bounded per-stream buffer and consume as many complete frames as available;
   this is the demultiplexer for the manager's independent XUDP streams. */
static bool xudp_receive_available(udp_association_t *association)
{
    uint8_t received[1024];
    for (;;)
    {
        int bytes = recv(association->tunnel, received, sizeof(received), MSG_DONTWAIT);
        if (bytes > 0)
        {
            if ((size_t)bytes > UDP_RX_BUFFER_MAX - association->rx_length)
            {
                s_udp_rx_drops++;
                return false; /* peer is not framing bounded UDP data */
            }
            memcpy(association->rx_buffer + association->rx_length, received, bytes);
            association->rx_length += (size_t)bytes;
            continue;
        }
        if (bytes == 0)
        {
            return false;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            break;
        }
        return false;
    }

    size_t consumed = 0;
    while (consumed < association->rx_length)
    {
        size_t   available = association->rx_length - consumed;
        uint8_t *frame     = association->rx_buffer + consumed;
        if (association->vless_response_pending)
        {
            if (available < 2)
            {
                break;
            }
            size_t addon_length = frame[1];
            if (frame[0] != 0)
            {
                return false;
            }
            if (available < 2 + addon_length)
            {
                break;
            }
            consumed += 2 + addon_length;
            association->vless_response_pending = false;
            continue;
        }
        if (available < 2)
        {
            break;
        }
        size_t metadata_length = ((size_t)frame[0] << 8) | frame[1];
        if (metadata_length < 4 || metadata_length > 64)
        {
            return false;
        }
        if (available < 2 + metadata_length + 2)
        {
            break;
        }
        uint8_t  option      = 0;
        uint32_t source_ip   = 0;
        uint16_t source_port = 0;
        if (!xudp_decode_header(frame + 2, metadata_length, &option, &source_ip, &source_port))
        {
            return false;
        }
        size_t payload_length =
            ((size_t)frame[2 + metadata_length] << 8) | frame[3 + metadata_length];
        if (payload_length > UDP_DATAGRAM_MAX)
        {
            return false;
        }
        if (available < 4 + metadata_length + payload_length)
        {
            break;
        }
        if (option & 1)
        {
            /* An association has one expected remote tuple.  Rejecting a
               mismatched explicit tuple prevents cross-flow delivery. */
            if ((source_ip && source_ip != association->flow.original_ip) ||
                (source_port && source_port != association->flow.original_port))
            {
                return false;
            }
            if (payload_length)
            {
                sendto(s_udp_relay_socket, frame + 4 + metadata_length, payload_length, 0,
                       (struct sockaddr *)&association->client, sizeof(association->client));
                bandwidth_record_download(payload_length);
                transparent_udp_touch(association->flow.client_ip, association->flow.client_port);
                association->last_activity_ms = now_ms();
            }
        }
        consumed += 4 + metadata_length + payload_length;
    }
    if (consumed)
    {
        memmove(association->rx_buffer, association->rx_buffer + consumed,
                association->rx_length - consumed);
        association->rx_length -= consumed;
    }
    return true;
}

static bool direct_udp_receive_available(udp_association_t *association)
{
    uint8_t packet[UDP_DATAGRAM_MAX];
    for (;;)
    {
        int bytes = recv(association->tunnel, packet, sizeof(packet), MSG_DONTWAIT);
        if (bytes > 0)
        {
            sendto(s_udp_relay_socket, packet, bytes, 0, (struct sockaddr *)&association->client,
                   sizeof(association->client));
            bandwidth_record_download((size_t)bytes);
            transparent_udp_touch(association->flow.client_ip, association->flow.client_port);
            association->last_activity_ms = now_ms();
            continue;
        }
        if (bytes == 0)
        {
            return false;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return true;
        }
        return false;
    }
}

/* The UDP manager owns the one smux socket.  TCP relay tasks send control
   messages instead of ever calling recv()/send() on it themselves. */
static void singmux_process_control(void)
{
    singmux_control_t control;
    for (size_t processed = 0; processed < SINGMUX_CONTROL_BATCH_MAX && s_singmux_control_queue &&
                               xQueueReceive(s_singmux_control_queue, &control, 0) == pdTRUE;
         ++processed)
    {
        if (control.type == SINGMUX_CONTROL_OPEN)
        {
            int slot = -1;
            for (int i = 0; i < SINGMUX_TCP_STREAM_MAX; ++i)
            {
                if (!s_singmux_tcp_streams[i].in_use)
                {
                    slot = i;
                    break;
                }
            }
            bool ok = false;
            if (slot >= 0)
            {
                if (s_singmux_tunnel < 0)
                {
                    s_singmux_tunnel         = open_singmux_session();
                    s_singmux_next_stream_id = 3;
                    s_singmux_rx_length      = 0;
                    if (!s_singmux_rx_buffer)
                    {
                        s_singmux_rx_buffer = heap_caps_malloc(SINGMUX_RX_BUFFER_MAX,
                                                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                    }
                }
                uint8_t request[270];
                size_t  request_length = 0;
                if (control.destination_name[0])
                {
                    ok = singmux_encode_tcp_domain_request(
                        request, sizeof(request), &request_length, control.destination_name,
                        control.destination_port);
                }
                else
                {
                    ok = singmux_encode_tcp_ipv4_request(request, control.destination_ip,
                                                         control.destination_port),
                    request_length = 9;
                }
                if (ok && s_singmux_tunnel >= 0 && s_singmux_rx_buffer)
                {
                    s_singmux_tcp_streams[slot].receive_queue =
                        xQueueCreate(SINGMUX_TCP_RX_QUEUE_DEPTH, sizeof(singmux_tcp_data_t *));
                    if (!s_singmux_tcp_streams[slot].receive_queue)
                    {
                        ok = false;
                    }
                    else
                    {
                        s_singmux_tcp_streams[slot].in_use           = true;
                        s_singmux_tcp_streams[slot].response_pending = true;
                        s_singmux_tcp_streams[slot].stream_id        = s_singmux_next_stream_id;
                        s_singmux_next_stream_id += 2;
                        ok = singmux_send_frame(s_singmux_tunnel, SMUX_CMD_SYN,
                                                s_singmux_tcp_streams[slot].stream_id, NULL, 0) &&
                             singmux_send_frame(s_singmux_tunnel, SMUX_CMD_PSH,
                                                s_singmux_tcp_streams[slot].stream_id, request,
                                                request_length);
                        if (ok && control.data && control.data->length)
                        {
                            ok = singmux_send_frame(s_singmux_tunnel, SMUX_CMD_PSH,
                                                    s_singmux_tcp_streams[slot].stream_id,
                                                    control.data->data, control.data->length);
                        }
                    }
                }
            }
            free(control.data);
            if (!ok && slot >= 0)
            {
                singmux_tcp_stream_discard(slot);
            }
            xTaskNotify(control.reply_task, ok ? (uint32_t)(slot + 1) : 0, eSetValueWithOverwrite);
        }
        else if (control.slot >= 0 && control.slot < SINGMUX_TCP_STREAM_MAX &&
                 s_singmux_tcp_streams[control.slot].in_use &&
                 s_singmux_tcp_streams[control.slot].stream_id == control.stream_id)
        {
            singmux_tcp_stream_t *stream = &s_singmux_tcp_streams[control.slot];
            bool                  ok     = s_singmux_tunnel >= 0;
            if (control.type == SINGMUX_CONTROL_DATA && control.data && control.data->length)
            {
                ok = singmux_send_frame(s_singmux_tunnel, SMUX_CMD_PSH, stream->stream_id,
                                        control.data->data, control.data->length);
                if (ok)
                {
                    bandwidth_record_upload(control.data->length);
                }
            }
            else if (control.type == SINGMUX_CONTROL_CLOSE)
            {
                if (s_singmux_tunnel >= 0)
                {
                    singmux_send_frame(s_singmux_tunnel, SMUX_CMD_FIN, stream->stream_id, NULL, 0);
                }
                singmux_tcp_stream_detach(control.slot);
                xTaskNotify(control.reply_task, 1, eSetValueWithOverwrite);
            }
            free(control.data);
            if (!ok && control.type == SINGMUX_CONTROL_DATA)
            {
                /* Keep the queue alive until its relay receives the sentinel
                 * and acknowledges CLOSE; deleting it here races xQueueReceive. */
                singmux_tcp_notify_closed(control.slot);
            }
        }
        else
        {
            free(control.data);
        }
    }
}

static void transparent_udp_manager_task(void *arg)
{
    (void)arg;
    uint8_t smux_receive_burst = 0;
    for (;;)
    {
        if (s_transport_reset_requested)
        {
            if (s_singmux_tunnel >= 0)
            {
                close(s_singmux_tunnel);
                s_singmux_tunnel = -1;
            }
            s_singmux_rx_length              = 0;
            s_singmux_vless_response_pending = false;
            for (int i = 0; i < UDP_ASSOCIATION_MAX; ++i)
            {
                if (s_udp_associations[i].in_use)
                {
                    udp_association_release(i);
                }
            }
            s_transport_reset_requested = false;
        }
        bool use_vless = transparent_mode_uses_vless();
        singmux_process_control();
        /* Do not add the normal ingress wait to an active TCP download.  More
         * importantly, singmux_receive_available() parses one socket read at a
         * time, so each pass frees reassembly space before accepting more. */
        bool smux_receive_pending = use_vless && s_config.singmux_enabled &&
                                    s_singmux_tunnel >= 0 && singmux_socket_readable();
        /* Give control and UDP equal bounded service.  Draining all TCP controls first can
           indefinitely starve queued XUDP traffic when relay tasks remain busy. */
        for (size_t processed = 0; processed < UDP_MANAGER_BATCH_MAX; ++processed)
        {
            udp_ingress_t ingress;
            if (xQueueReceive(s_udp_manager_queue, &ingress,
                              pdMS_TO_TICKS(processed == 0 && !smux_receive_pending ? 20 : 0)) !=
                pdTRUE)
            {
                break;
            }
            int slot = udp_association_find(ingress.flow.client_ip, ingress.flow.client_port);
            if (slot < 0)
            {
                for (int i = 0; i < UDP_ASSOCIATION_MAX; ++i)
                {
                    if (!s_udp_associations[i].in_use)
                    {
                        slot = i;
                        break;
                    }
                }
                if (slot >= 0)
                {
                    s_udp_associations[slot] = (udp_association_t){.in_use = true,
                                                                   .client = ingress.client,
                                                                   .flow   = ingress.flow,
                                                                   .tunnel = -1,
                                                                   .last_activity_ms = now_ms()};
                    s_udp_associations[slot].rx_buffer =
                        heap_caps_malloc(UDP_RX_BUFFER_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                    if (!s_udp_associations[slot].rx_buffer)
                    {
                        udp_association_release(slot), slot = -1;
                    }
                    else
                    {
                        s_udp_active_associations++;
                    }
                }
            }
            if (slot < 0)
            {
                ESP_LOGW(TAG, "persistent XUDP association table full; dropping datagram");
                free(ingress.datagram);
            }
            else
            {
                udp_association_t *association = &s_udp_associations[slot];
                bool               sent        = false;
                if (use_vless && s_config.singmux_enabled)
                {
                    if (s_singmux_tunnel < 0)
                    {
                        s_singmux_tunnel         = open_singmux_session();
                        s_singmux_next_stream_id = 3;
                        s_singmux_rx_length      = 0;
                        if (!s_singmux_rx_buffer)
                        {
                            s_singmux_rx_buffer = heap_caps_malloc(
                                SINGMUX_RX_BUFFER_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                        }
                    }
                    uint8_t request[16 + UDP_DATAGRAM_MAX];
                    size_t  request_length = 0;
                    if (s_singmux_tunnel >= 0 && s_singmux_rx_buffer)
                    {
                        if (!association->singmux_stream_id)
                        {
                            association->singmux_stream_id = s_singmux_next_stream_id;
                            s_singmux_next_stream_id += 2;
                            association->singmux_response_pending = true;
                            sent =
                                singmux_encode_udp_request(
                                    request, sizeof(request), &request_length,
                                    association->flow.original_ip, association->flow.original_port,
                                    ingress.datagram->payload, ingress.datagram->length, true) &&
                                /* smux SYN never carries data; the stream request follows in PSH.
                                 */
                                singmux_send_frame(s_singmux_tunnel, SMUX_CMD_SYN,
                                                   association->singmux_stream_id, NULL, 0) &&
                                singmux_send_frame(s_singmux_tunnel, SMUX_CMD_PSH,
                                                   association->singmux_stream_id, request,
                                                   request_length);
                        }
                        else
                        {
                            request[0] = ingress.datagram->length >> 8;
                            request[1] = ingress.datagram->length;
                            memcpy(request + 2, ingress.datagram->payload,
                                   ingress.datagram->length);
                            sent = singmux_send_frame(s_singmux_tunnel, SMUX_CMD_PSH,
                                                      association->singmux_stream_id, request,
                                                      ingress.datagram->length + 2);
                        }
                    }
                }
                else if (use_vless)
                {
                    if (association->tunnel < 0)
                    {
                        association->tunnel                 = open_vless_mux_stream();
                        association->request_written        = false;
                        association->vless_response_pending = association->tunnel >= 0;
                    }
                    uint8_t frame[16 + UDP_DATAGRAM_MAX];
                    size_t  frame_length = 0;
                    sent =
                        association->tunnel >= 0 &&
                        (association->request_written
                             ? xudp_encode_ipv4_keep(
                                   frame, sizeof(frame), &frame_length,
                                   association->flow.original_ip, association->flow.original_port,
                                   ingress.datagram->payload, ingress.datagram->length)
                             : xudp_encode_ipv4(
                                   frame, sizeof(frame), &frame_length,
                                   association->flow.original_ip, association->flow.original_port,
                                   ingress.datagram->payload, ingress.datagram->length));
                    if (sent)
                    {
                        sent = socket_send_all(association->tunnel, frame, frame_length);
                    }
                }
                else
                {
                    if (association->tunnel < 0)
                    {
                        association->tunnel = open_direct_udp_stream(
                            association->flow.original_ip, association->flow.original_port);
                    }
                    sent = association->tunnel >= 0 &&
                           udp_socket_send_datagram(association->tunnel, ingress.datagram->payload,
                                                    ingress.datagram->length);
                }
                if (sent)
                {
                    bandwidth_record_upload(ingress.datagram->length);
                }
                free(ingress.datagram);
                if (!sent)
                {
                    s_udp_tunnel_failures++;
                    ESP_LOGW(TAG, "persistent XUDP send failed for remote UDP port %u",
                             association->flow.original_port);
                    udp_association_release(slot);
                }
                else
                {
                    association->request_written  = true;
                    association->last_activity_ms = now_ms();
                    transparent_udp_touch(association->flow.client_ip,
                                          association->flow.client_port);
                }
            }
        }
        fd_set reads;
        FD_ZERO(&reads);
        int max_fd = -1;
        if (use_vless && s_config.singmux_enabled && s_singmux_tunnel >= 0)
        {
            FD_SET(s_singmux_tunnel, &reads);
            max_fd = s_singmux_tunnel;
        }
        for (int i = 0; (!use_vless || !s_config.singmux_enabled) && i < UDP_ASSOCIATION_MAX; ++i)
        {
            if (s_udp_associations[i].in_use && s_udp_associations[i].tunnel >= 0)
            {
                FD_SET(s_udp_associations[i].tunnel, &reads);
                if (s_udp_associations[i].tunnel > max_fd)
                {
                    max_fd = s_udp_associations[i].tunnel;
                }
            }
        }
        struct timeval poll_timeout = {.tv_sec = 0, .tv_usec = 0};
        if (max_fd >= 0 && select(max_fd + 1, &reads, NULL, NULL, &poll_timeout) > 0)
        {
            if (use_vless && s_config.singmux_enabled && s_singmux_tunnel >= 0 &&
                FD_ISSET(s_singmux_tunnel, &reads) && !singmux_receive_available())
            {
                s_singmux_stats.sessions_closed++;
                s_singmux_stats.last_session_close_ms = now_ms();
                ESP_LOGW(TAG,
                         "sing-box smux session closed (EOF=%u socket=%u protocol=%u errno=%d); "
                         "associations will reconnect on demand",
                         (unsigned)s_singmux_stats.close_eof,
                         (unsigned)s_singmux_stats.close_socket_error,
                         (unsigned)s_singmux_stats.close_protocol_error,
                         s_singmux_stats.last_socket_errno);
                close(s_singmux_tunnel);
                s_singmux_tunnel    = -1;
                s_singmux_rx_length = 0;
                for (int i = 0; i < UDP_ASSOCIATION_MAX; ++i)
                {
                    if (s_udp_associations[i].in_use)
                    {
                        s_udp_associations[i].singmux_stream_id        = 0,
                        s_udp_associations[i].singmux_response_pending = false;
                    }
                }
                singmux_tcp_notify_all_closed();
            }
            for (int i = 0; (!use_vless || !s_config.singmux_enabled) && i < UDP_ASSOCIATION_MAX;
                 ++i)
            {
                if (s_udp_associations[i].in_use && s_udp_associations[i].tunnel >= 0 &&
                    FD_ISSET(s_udp_associations[i].tunnel, &reads))
                {
                    udp_association_t *association = &s_udp_associations[i];
                    if (!(use_vless ? xudp_receive_available(association)
                                    : direct_udp_receive_available(association)))
                    {
                        s_udp_tunnel_failures++;
                        ESP_LOGW(TAG,
                                 "transparent %s UDP association closed for remote UDP port %u",
                                 use_vless ? "XUDP" : "upstream", association->flow.original_port);
                        udp_association_release(i);
                    }
                }
            }
        }
        uint32_t now = now_ms();
        for (int i = 0; i < UDP_ASSOCIATION_MAX; ++i)
        {
            if (s_udp_associations[i].in_use &&
                now - s_udp_associations[i].last_activity_ms > 120000)
            {
                udp_association_release(i);
            }
        }
        /* A continuously readable smux socket otherwise keeps this priority-5
         * task runnable forever and starves same-priority HTTP/relay tasks.
         * Four 4 KiB passes per tick preserves responsiveness without imposing
         * a roughly 400 KiB/s ceiling on a sustained download. */
        if (smux_receive_pending)
        {
            if (++smux_receive_burst >= 4)
            {
                smux_receive_burst = 0;
                s_singmux_stats.scheduler_yields++;
                vTaskDelay(1);
            }
        }
        else
        {
            smux_receive_burst = 0;
        }
    }
}

static void transparent_udp_server_task(void *arg)
{
    (void)arg;
    s_udp_relay_socket         = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in address = {.sin_family      = AF_INET,
                                  .sin_port        = htons(TRANSPARENT_UDP_RELAY_PORT),
                                  .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (s_udp_relay_socket < 0 ||
        bind(s_udp_relay_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        ESP_LOGE(TAG, "transparent UDP relay listener failed");
        vTaskDelete(NULL);
    }
    s_udp_manager_queue     = xQueueCreate(UDP_MANAGER_QUEUE_DEPTH, sizeof(udp_ingress_t));
    s_singmux_control_queue = xQueueCreate(SINGMUX_CONTROL_QUEUE_DEPTH, sizeof(singmux_control_t));
    if (!s_udp_manager_queue || !s_singmux_control_queue)
    {
        ESP_LOGE(TAG, "persistent XUDP/smux manager queue allocation failed");
        vTaskDelete(NULL);
    }
    xTaskCreate(transparent_udp_manager_task, "transparent_xudp_mgr", 6144, NULL, 5, NULL);
    ESP_LOGI(TAG, "transparent UDP relay listening on UDP port %u", TRANSPARENT_UDP_RELAY_PORT);
    for (;;)
    {
        udp_datagram_t *datagram =
            heap_caps_malloc(sizeof(*datagram), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!datagram)
        {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        struct sockaddr_in client        = {0};
        socklen_t          client_length = sizeof(client);
        int received = recvfrom(s_udp_relay_socket, datagram->payload, sizeof(datagram->payload), 0,
                                (struct sockaddr *)&client, &client_length);
        if (received <= 0)
        {
            free(datagram);
            continue;
        }
        uint16_t               client_port = ntohs(client.sin_port);
        transparent_udp_flow_t flow;
        if (!transparent_udp_get(client.sin_addr.s_addr, client_port, &flow))
        {
            free(datagram);
            continue;
        }
        datagram->length      = (size_t)received;
        udp_ingress_t ingress = {.client = client, .flow = flow, .datagram = datagram};
        if (xQueueSend(s_udp_manager_queue, &ingress, pdMS_TO_TICKS(UDP_QUEUE_SEND_WAIT_MS)) !=
            pdTRUE)
        {
            s_udp_queue_drops++;
            uint32_t now = now_ms();
            if (now - s_udp_last_backpressure_log_ms >= 5000)
            {
                s_udp_last_backpressure_log_ms = now;
                ESP_LOGW(TAG, "XUDP ingress back-pressure: queue=%u/%u drops=%u",
                         (unsigned)uxQueueMessagesWaiting(s_udp_manager_queue),
                         UDP_MANAGER_QUEUE_DEPTH, (unsigned)s_udp_queue_drops);
            }
            free(datagram);
        }
    }
}

static void transparent_server_task(void *arg)
{
    (void)arg;
    int                listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in address  = {
         .sin_family = AF_INET, .sin_port = htons(15001), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, TRANSPARENT_TCP_LISTEN_BACKLOG) < 0)
    {
        ESP_LOGE(TAG, "transparent relay listener failed");
        vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "transparent TCP relay listening on port 15001");
    for (;;)
    {
        int client = accept(listener, NULL, NULL);
        if (client >= 0 && create_stream_task(transparent_client_task, "transparent_client",
                                              (void *)(intptr_t)client) != pdPASS)
        {
            ESP_LOGW(TAG, "transparent stream task allocation failed");
            close(client);
        }
    }
}

/* Verifies plain VLESS TCP by requesting google.com:80 through the configured server. */
static esp_err_t vless_test_get(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    char    message[128] = "VLESS test failed";
    uint8_t uuid[16];
    int     socket_fd = -1;

    if (!s_has_upstream)
    {
        snprintf(message, sizeof(message), "Upstream Wi-Fi is not connected");
    }
    else if (!s_config.vless_host[0] || !transport_tcp_uuid_to_bytes(s_config.vless_uuid, uuid))
    {
        snprintf(message, sizeof(message), "VLESS configuration is incomplete");
    }
    else
    {
        char port[6];
        snprintf(port, sizeof(port), "%u", s_config.vless_port);
        struct addrinfo  hints     = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
        struct addrinfo *addresses = NULL;
        int              lookup    = getaddrinfo(s_config.vless_host, port, &hints, &addresses);
        if (lookup != 0)
        {
            snprintf(message, sizeof(message), "Could not resolve VLESS server");
        }
        else
        {
            socket_fd =
                socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
            if (socket_fd < 0 || connect(socket_fd, addresses->ai_addr, addresses->ai_addrlen) != 0)
            {
                snprintf(message, sizeof(message), "Could not connect to VLESS server");
            }
            else
            {
                struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};
                setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                const char domain[]      = "google.com";
                uint8_t    header[64]    = {0};
                size_t     header_length = 0;
                header[header_length++]  = 0;
                memcpy(header + header_length, uuid, sizeof(uuid));
                header_length += sizeof(uuid);
                header[header_length++] = 0;
                header[header_length++] = 1;
                header[header_length++] = 0;
                header[header_length++] = 80;
                header[header_length++] = 2;
                header[header_length++] = sizeof(domain) - 1;
                memcpy(header + header_length, domain, sizeof(domain) - 1);
                header_length += sizeof(domain) - 1;
                const uint8_t request[] =
                    "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
                uint8_t response_header[2];
                uint8_t response[128] = {0};
                if (!socket_send_all(socket_fd, header, header_length) ||
                    !socket_send_all(socket_fd, request, sizeof(request) - 1))
                {
                    snprintf(message, sizeof(message), "Could not send VLESS request");
                }
                else if (!socket_recv_all(socket_fd, response_header, sizeof(response_header)) ||
                         response_header[0] != 0)
                {
                    snprintf(message, sizeof(message), "VLESS server rejected the request");
                }
                else if (recv(socket_fd, response, sizeof(response) - 1, 0) <= 0 ||
                         strstr((char *)response, "HTTP/") == NULL)
                {
                    snprintf(message, sizeof(message),
                             "VLESS stream opened but Google returned no HTTP response");
                }
                else
                {
                    snprintf(message, sizeof(message),
                             "VLESS test passed: google.com responded through the tunnel");
                }
            }
            freeaddrinfo(addresses);
        }
    }
    if (socket_fd >= 0)
    {
        close(socket_fd);
    }
    ESP_LOGI(TAG, "%s", message);
    char response[180];
    snprintf(response, sizeof(response), "{\"message\":\"%s\"}", message);
    return send_json(req, response);
}

static esp_err_t admin_password_post(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    if (req->content_len == 0 || req->content_len > 200)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid password form");
    }
    char body[201] = {0};
    int  total     = 0;
    while (total < req->content_len)
    {
        int received = httpd_req_recv(req, body + total, req->content_len - total);
        if (received <= 0)
        {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Incomplete request");
        }
        total += received;
    }
    char current_password[65] = {0};
    char new_password[65]     = {0};
    if (!form_value(body, "current_admin_password", current_password, sizeof(current_password)) ||
        !form_value(body, "new_admin_password", new_password, sizeof(new_password)))
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                   "Current and new passwords required");
    }
    uint8_t current_hash[32];
    hash_admin_password(current_password, current_hash);
    if (!password_hash_matches(current_hash, s_admin_password_hash))
    {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Current password is incorrect");
    }
    if (strlen(new_password) < 12)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                   "New password must be at least 12 characters");
    }
    esp_err_t result = save_admin_password_hash(new_password, s_admin_password_hash);
    if (result != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not save administrator password: %s", esp_err_to_name(result));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Could not save administrator password");
    }
    ESP_LOGI(TAG, "Web config: administrator password changed");
    return send_json(req,
                     "{\"message\":\"Administrator password changed. Reload and sign in again.\"}");
}

static esp_err_t config_post(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    config_section_t section = (config_section_t)(uintptr_t)req->user_ctx;
    if (req->content_len == 0 || req->content_len > 700)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid form size");
    }
    char body[701] = {0};
    int  total     = 0;
    while (total < req->content_len)
    {
        int received = httpd_req_recv(req, body + total, req->content_len - total);
        if (received <= 0)
        {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Incomplete request");
        }
        total += received;
    }
    if (total != req->content_len)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Incomplete request");
    }
    char            port_text[8]       = {0};
    char            vless_uri[256]     = {0};
    char            password_value[65] = {0};
    char            open_network[8]    = {0};
    bool            have_password      = false;
    bool            open_requested     = false;
    router_config_t previous           = s_config;
    router_config_t candidate          = s_config;
    if (section == CONFIG_SECTION_UPSTREAM)
    {
        have_password  = form_value(body, "password", password_value, sizeof(password_value));
        open_requested = form_value(body, "open_network", open_network, sizeof(open_network)) &&
                         (strcmp(open_network, "1") == 0 || strcmp(open_network, "true") == 0 ||
                          strcmp(open_network, "on") == 0);
    }
    parse_config_form(body, &candidate, port_text, sizeof(port_text), vless_uri, sizeof(vless_uri));
    if (section == CONFIG_SECTION_VLESS && vless_uri[0] &&
        !parse_vless_tcp_uri(vless_uri, &candidate))
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                   "Unsupported VLESS URI; use TCP with encryption=none");
    }
    long port = port_text[0] ? strtol(port_text, NULL, 10) : candidate.vless_port;
    if (section == CONFIG_SECTION_VLESS && vless_uri[0])
    {
        port = candidate.vless_port;
    }
    if (section == CONFIG_SECTION_ACCESS_POINT)
    {
        if (!candidate.ap_ssid[0] || strlen(candidate.ap_password) < 8 ||
            !parse_access_point_ipv4(configured_or_default(candidate.ap_ip, DEFAULT_AP_IPV4), NULL))
        {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                       "AP SSID, an AP password of at least 8 characters, and an "
                                       "IPv4 address ending in .1 are required");
        }
    }
    else if (section == CONFIG_SECTION_UPSTREAM)
    {
        if (!candidate.upstream_ssid[0])
        {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "An upstream SSID is required");
        }
        router_config_store_upstream(&candidate, candidate.upstream_ssid,
                                     open_requested ? "" : password_value,
                                     !open_requested && (!have_password || !password_value[0]));
    }
    else
    {
        ESP_LOGI(TAG, "VLESS form fields: host=%d uuid=%d port=%ld",
                 candidate.vless_host[0] != '\0', candidate.vless_uuid[0] != '\0', port);
        if (!candidate.vless_host[0] || !candidate.vless_uuid[0] || port < 1 || port > 65535)
        {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                       "Host, UUID, and valid port required");
        }
        candidate.vless_port = (uint16_t)port;
    }
    s_config = candidate;
    if (section == CONFIG_SECTION_VLESS && s_singmux_tunnel >= 0)
    {
        close(s_singmux_tunnel);
        s_singmux_tunnel    = -1;
        s_singmux_rx_length = 0;
        for (int i = 0; i < UDP_ASSOCIATION_MAX; ++i)
        {
            if (s_udp_associations[i].in_use)
            {
                s_udp_associations[i].singmux_stream_id        = 0,
                s_udp_associations[i].singmux_response_pending = false;
            }
        }
        singmux_tcp_notify_all_closed();
    }
    esp_err_t save_error = save_router_config(&s_config);
    if (save_error != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not save configuration to NVS: %s", esp_err_to_name(save_error));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Could not save configuration");
    }
    if (section == CONFIG_SECTION_UPSTREAM)
    {
        bool password_changed =
            text_changed(previous.upstream_password, s_config.upstream_password);
        ESP_LOGI(TAG, "Saved upstream Wi-Fi SSID '%s' to NVS", s_config.upstream_ssid);
        ESP_LOGI(TAG, "Web config: upstream saved ssid='%s' open=%s password_%s saved_profiles=%u",
                 s_config.upstream_ssid, s_config.upstream_password[0] ? "no" : "yes",
                 password_changed ? "changed" : "unchanged",
                 (unsigned)s_config.upstream_network_count);
        if (s_configuration_mode)
        {
            s_configuration_mode = false;
            ESP_LOGI(TAG, "Leaving configuration mode; connecting to the saved upstream Wi-Fi");
        }
        /* Send the response before changing the STA channel. Reconnecting first
           can interrupt the AP client that submitted this request. */
        esp_err_t response =
            send_json(req, "{\"message\":\"Upstream Wi-Fi saved. Connecting...\"}");
        esp_wifi_disconnect();
        connect_upstream();
        return response;
    }
    if (section == CONFIG_SECTION_ACCESS_POINT)
    {
        ESP_LOGI(TAG, "Web config: AP saved ssid='%s'%s%s%s gateway='%s'", s_config.ap_ssid,
                 text_changed(previous.ap_ssid, s_config.ap_ssid) ? " ssid_changed" : "",
                 text_changed(previous.ap_password, s_config.ap_password) ? " password_changed"
                                                                          : "",
                 text_changed(previous.ap_ip, s_config.ap_ip) ? " gateway_changed" : "",
                 configured_ap_ipv4(&s_config));
        esp_err_t response = send_json(req, "{\"message\":\"Access point saved. Reconnect using "
                                            "the updated Wi-Fi settings and gateway.\"}");
        if (response == ESP_OK &&
            xTaskCreate(apply_access_point_task, "apply_ap", 2048, NULL, 3, NULL) != pdPASS)
        {
            ESP_LOGW(TAG,
                     "Access point settings saved, but deferred AP apply task could not start");
        }
        return response;
    }
    ESP_LOGI(TAG, "Web config: VLESS saved host='%s' port=%u dns='%s' mux=%s%s%s%s",
             s_config.vless_host, s_config.vless_port, s_config.dns_resolver,
             s_config.singmux_enabled ? "on" : "off",
             text_changed(previous.vless_host, s_config.vless_host) ? " host_changed" : "",
             previous.vless_port != s_config.vless_port ? " port_changed" : "",
             text_changed(previous.dns_resolver, s_config.dns_resolver) ? " dns_changed" : "",
             previous.singmux_enabled != s_config.singmux_enabled ? " mux_changed" : "");
    return send_json(req, "{\"message\":\"VLESS configuration saved.\"}");
}

/* Physical serial and the BOOT button already support a temporary direct
   route.  Expose the same recovery diagnostic through authenticated local
   management so a held USB console cannot prevent an A/B throughput test. */
static esp_err_t route_post(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    if (req->content_len == 0 || req->content_len > 32)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Use mode=vless or mode=direct");
    }
    char body[33] = {0};
    int  total    = 0;
    while (total < req->content_len)
    {
        int received = httpd_req_recv(req, body + total, req->content_len - total);
        if (received <= 0)
        {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Incomplete route form");
        }
        total += received;
    }
    char mode[12] = {0};
    if (!form_value(body, "mode", mode, sizeof(mode)) ||
        (strcmp(mode, "vless") != 0 && strcmp(mode, "direct") != 0))
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Use mode=vless or mode=direct");
    }
    set_transparent_mode(strcmp(mode, "direct") == 0 ? TRANSPARENT_MODE_UPSTREAM
                                                     : TRANSPARENT_MODE_VLESS);
    ESP_LOGW(TAG, "Authenticated local route test selected %s for this boot", mode);
    return send_json(
        req, transparent_mode_uses_vless()
                 ? "{\"message\":\"VLESS route active for this boot.\"}"
                 : "{\"message\":\"DIRECT route active for this boot; traffic bypasses VLESS.\"}");
}

static void json_string(httpd_req_t *req, const char *text)
{
    httpd_resp_sendstr_chunk(req, "\"");
    for (; *text; text++)
    {
        if (*text == '\"' || *text == '\\')
        {
            char escaped[3] = {'\\', *text, 0};
            httpd_resp_sendstr_chunk(req, escaped);
        }
        else if ((unsigned char)*text >= 0x20)
        {
            char c[2] = {*text, 0};
            httpd_resp_sendstr_chunk(req, c);
        }
    }
    httpd_resp_sendstr_chunk(req, "\"");
}

static esp_err_t send_scan_results(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr_chunk(req, "[");
    for (int i = 0; i < s_scan_record_count; ++i)
    {
        if (i)
        {
            httpd_resp_sendstr_chunk(req, ",");
        }
        httpd_resp_sendstr_chunk(req, "{\"ssid\":");
        json_string(req, (const char *)s_scan_records[i].ssid);
        char suffix[32];
        snprintf(suffix, sizeof(suffix), ",\"rssi\":%d}", s_scan_records[i].rssi);
        httpd_resp_sendstr_chunk(req, suffix);
    }
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t scan_results_get(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    if (!s_scan_results_available)
    {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No Wi-Fi scan results available");
    }
    return send_scan_results(req);
}

static esp_err_t scan_get(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    wifi_scan_config_t scan = {
        .show_hidden      = false,
        .scan_type        = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active = {.min = 100, .max = 300},
    };
    ESP_LOGI(TAG, "Wi-Fi scan requested from the setup page");
    esp_err_t err = esp_wifi_scan_start(&scan, true);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Wi-Fi scan failed: %s", esp_err_to_name(err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Wi-Fi scan unavailable");
    }
    uint16_t count = 0;
    err            = esp_wifi_scan_get_ap_num(&count);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not read scan count: %s", esp_err_to_name(err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Could not read Wi-Fi scan results");
    }
    ESP_LOGI(TAG, "Wi-Fi scan complete: %u network(s) found", count);
    if (count > 20)
    {
        ESP_LOGW(TAG, "Showing the first 20 networks in the web page and console");
        count = 20;
    }
    wifi_ap_record_t records[20];
    err = esp_wifi_scan_get_ap_records(&count, records);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not read scan records: %s", esp_err_to_name(err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Could not read Wi-Fi scan results");
    }
    s_scan_record_count = 0;
    for (int i = 0; i < count; ++i)
    {
        int existing = -1;
        for (int index = 0; index < s_scan_record_count; ++index)
        {
            if (strcmp((const char *)s_scan_records[index].ssid, (const char *)records[i].ssid) ==
                0)
            {
                existing = index;
                break;
            }
        }
        if (existing < 0)
        {
            s_scan_records[s_scan_record_count++] = records[i];
        }
        else if (records[i].rssi > s_scan_records[existing].rssi)
        {
            s_scan_records[existing] = records[i];
        }
    }
    ESP_LOGI(TAG, "Wi-Fi scan results: %u unique SSID(s), %u duplicate BSSID(s) removed",
             s_scan_record_count, count - s_scan_record_count);
    for (int i = 0; i < s_scan_record_count; ++i)
    {
        ESP_LOGI(TAG, "AP %d: SSID='%s', RSSI=%d dBm, channel=%u, auth=%d", i + 1,
                 (const char *)s_scan_records[i].ssid, s_scan_records[i].rssi,
                 s_scan_records[i].primary, s_scan_records[i].authmode);
    }
    s_scan_results_available = true;
    return send_scan_results(req);
}

/** Restarts after the HTTP success response has had time to reach the browser. */
static void ota_restart_task(void *argument)
{
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(750));
    esp_restart();
}

static void apply_access_point_task(void *argument)
{
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(250));
    apply_access_point_config();
    vTaskDelete(NULL);
}

/** Streams an authenticated application image into the inactive OTA partition. */
static esp_err_t ota_post(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    if (req->content_len == 0)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "An OTA firmware image is required");
    }

    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    if (!partition || (size_t)req->content_len > partition->size)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                   "OTA image is too large for the inactive partition");
    }

    esp_ota_handle_t handle = 0;
    esp_err_t        error  = esp_ota_begin(partition, req->content_len, &handle);
    if (error != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not begin OTA update: %s", esp_err_to_name(error));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Could not start OTA update");
    }

    uint8_t buffer[OTA_UPLOAD_BUFFER_SIZE];
    int     remaining = req->content_len;
    while (remaining > 0)
    {
        int received = httpd_req_recv(req, (char *)buffer,
                                      remaining < (int)sizeof(buffer) ? remaining : sizeof(buffer));
        if (received == HTTPD_SOCK_ERR_TIMEOUT)
        {
            continue;
        }
        if (received <= 0 || esp_ota_write(handle, buffer, received) != ESP_OK)
        {
            ESP_LOGE(TAG, "OTA upload interrupted or write failed");
            esp_ota_abort(handle);
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA upload failed");
        }
        remaining -= received;
    }

    error = esp_ota_end(handle);
    if (error == ESP_OK)
    {
        error = esp_ota_set_boot_partition(partition);
    }
    if (error != ESP_OK)
    {
        ESP_LOGE(TAG, "OTA image validation or boot selection failed: %s", esp_err_to_name(error));
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                   "OTA image validation or activation failed");
    }

    ESP_LOGI(TAG, "OTA image accepted; rebooting into partition '%s'", partition->label);
    esp_err_t response = send_json(req, "{\"message\":\"Firmware accepted. Rebooting now...\"}");
    if (response == ESP_OK &&
        xTaskCreate(ota_restart_task, "ota_restart", 2048, NULL, 3, NULL) != pdPASS)
    {
        ESP_LOGW(TAG, "OTA image selected, but automatic reboot task could not start");
    }
    return response;
}

static esp_err_t upstream_delete_post(httpd_req_t *req)
{
    if (require_admin_auth(req) != ESP_OK)
    {
        return ESP_FAIL;
    }
    if (req->content_len == 0 || req->content_len > 200)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid upstream delete form");
    }
    char body[201] = {0};
    int  total     = 0;
    while (total < req->content_len)
    {
        int received = httpd_req_recv(req, body + total, req->content_len - total);
        if (received <= 0)
        {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Incomplete request");
        }
        total += received;
    }
    char ssid[33] = {0};
    if (!form_value(body, "ssid", ssid, sizeof(ssid)) || !ssid[0])
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "An upstream SSID is required");
    }

    router_config_t candidate = s_config;
    if (!router_config_delete_upstream(&candidate, ssid))
    {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Saved upstream profile not found");
    }

    s_config             = candidate;
    esp_err_t save_error = save_router_config(&s_config);
    if (save_error != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not save configuration to NVS: %s", esp_err_to_name(save_error));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Could not save configuration");
    }

    if (s_config.upstream_ssid[0])
    {
        ESP_LOGI(TAG,
                 "Web config: upstream profile deleted ssid='%s' next_active='%s' remaining=%u",
                 ssid, s_config.upstream_ssid, (unsigned)s_config.upstream_network_count);
        ESP_LOGI(TAG, "Deleted upstream Wi-Fi profile '%s'; connecting to '%s'", ssid,
                 s_config.upstream_ssid);
        esp_err_t response =
            send_json(req, "{\"message\":\"Upstream profile deleted. Connecting...\"}");
        esp_wifi_disconnect();
        connect_upstream();
        return response;
    }

    ESP_LOGI(TAG, "Web config: upstream profile deleted ssid='%s' remaining=0", ssid);
    ESP_LOGI(TAG, "Deleted upstream Wi-Fi profile '%s'; no upstream profiles remain", ssid);
    esp_wifi_disconnect();
    return send_json(req, "{\"message\":\"Upstream profile deleted. No saved upstreams remain.\"}");
}

static void start_http_server(void)
{
    httpd_handle_t server   = NULL;
    httpd_config_t config   = HTTPD_DEFAULT_CONFIG();
    config.stack_size       = 8192;
    config.max_uri_handlers = 15;
    config.lru_purge_enable = true;
    config.uri_match_fn     = httpd_uri_match_wildcard;
    ESP_ERROR_CHECK(httpd_start(&server, &config));
    const httpd_uri_t root    = {.uri = "/", .method = HTTP_GET, .handler = root_get};
    const httpd_uri_t cfg_get = {.uri = "/api/config", .method = HTTP_GET, .handler = config_get};
    const httpd_uri_t upstream_post   = {.uri      = "/api/upstream",
                                         .method   = HTTP_POST,
                                         .handler  = config_post,
                                         .user_ctx = (void *)CONFIG_SECTION_UPSTREAM};
    const httpd_uri_t upstream_delete = {
        .uri = "/api/upstream-delete", .method = HTTP_POST, .handler = upstream_delete_post};
    const httpd_uri_t vless_post     = {.uri      = "/api/vless",
                                        .method   = HTTP_POST,
                                        .handler  = config_post,
                                        .user_ctx = (void *)CONFIG_SECTION_VLESS};
    const httpd_uri_t route_post_uri = {
        .uri = "/api/route", .method = HTTP_POST, .handler = route_post};
    const httpd_uri_t ap_post            = {.uri      = "/api/access-point",
                                            .method   = HTTP_POST,
                                            .handler  = config_post,
                                            .user_ctx = (void *)CONFIG_SECTION_ACCESS_POINT};
    const httpd_uri_t admin_password_uri = {
        .uri = "/api/admin-password", .method = HTTP_POST, .handler = admin_password_post};
    const httpd_uri_t vless_test = {
        .uri = "/api/test-vless", .method = HTTP_GET, .handler = vless_test_get};
    const httpd_uri_t xudp_test = {
        .uri = "/api/test-xudp", .method = HTTP_GET, .handler = xudp_test_get};
    const httpd_uri_t scan         = {.uri = "/api/scan", .method = HTTP_GET, .handler = scan_get};
    const httpd_uri_t scan_results = {
        .uri = "/api/scan-results", .method = HTTP_GET, .handler = scan_results_get};
    const httpd_uri_t ota     = {.uri = "/api/ota", .method = HTTP_POST, .handler = ota_post};
    const httpd_uri_t captive = {.uri = "/*", .method = HTTP_GET, .handler = root_get};
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &root));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &cfg_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &upstream_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &upstream_delete));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &vless_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &route_post_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ap_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &admin_password_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &vless_test));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &xudp_test));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &scan));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &scan_results));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ota));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &captive));
}

static bool dns_name(const uint8_t *packet, int bytes, int *offset, char name[254])
{
    int out = 0;
    while (*offset < bytes && packet[*offset])
    {
        int label = packet[(*offset)++];
        if (label > 63 || *offset + label > bytes || out + label + 1 >= 254)
        {
            return false;
        }
        if (out)
        {
            name[out++] = '.';
        }
        memcpy(name + out, packet + *offset, label);
        out += label;
        *offset += label;
    }
    if (*offset >= bytes)
    {
        return false;
    }
    (*offset)++;
    name[out] = '\0';
    return out > 0;
}

static bool dns_vless_query(uint8_t *packet, int *bytes)
{
    if (!s_config.dns_resolver[0] || !s_has_upstream)
    {
        return false;
    }
    int tunnel =
        transport_tcp_open_vless_stream(&s_config, s_has_upstream, s_config.dns_resolver, 53);
    if (tunnel < 0)
    {
        return false;
    }
    uint8_t length[2] = {*bytes >> 8, *bytes};
    bool    ok = socket_send_all(tunnel, length, 2) && socket_send_all(tunnel, packet, *bytes);
    uint8_t vless[2];
    if (ok)
    {
        ok = socket_recv_all(tunnel, vless, 2) && vless[0] == 0;
    }
    static uint8_t addon[255];
    if (ok && vless[1])
    {
        ok = socket_recv_all(tunnel, addon, vless[1]);
    }
    if (ok)
    {
        ok = socket_recv_all(tunnel, length, 2);
    }
    int response_length = ((int)length[0] << 8) | length[1];
    if (ok && (response_length < 12 || response_length > 512))
    {
        ok = false;
    }
    if (ok)
    {
        ok = socket_recv_all(tunnel, packet, response_length);
    }
    close(tunnel);
    if (!ok)
    {
        return false;
    }
    *bytes = response_length;
    dns_cache_response_records(packet, *bytes);
    return true;
}

/* Uses configured DNS-over-VLESS in VLESS mode, upstream DNS in upstream-only
    mode, and captive-portal answers while upstream is unavailable. */
static void captive_dns_task(void *arg)
{
    (void)arg;
    int                sock    = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in address = {
        .sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        ESP_LOGE(TAG, "DNS bind failed");
        vTaskDelete(NULL);
    }
    for (;;)
    {
        static uint8_t     packet[512];
        struct sockaddr_in client;
        socklen_t          len = sizeof(client);
        int bytes = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&client, &len);
        if (bytes < 12)
        {
            continue;
        }
        if ((transparent_mode_uses_vless() && dns_vless_query(packet, &bytes)) ||
            (!transparent_mode_uses_vless() && dns_direct_query(packet, &bytes)))
        {
            sendto(sock, packet, bytes, 0, (struct sockaddr *)&client, len);
            continue;
        }
        int qend = 12;
        while (qend < bytes && packet[qend] != 0)
        {
            qend += packet[qend] + 1;
        }
        qend += 5;
        if (qend > bytes || packet[4] != 0 || packet[5] != 1)
        {
            continue;
        }
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0;
        packet[7] = 1;
        packet[8] = packet[9] = packet[10] = packet[11] = 0;
        uint32_t      ap_ip                             = access_point_ipv4_addr();
        const uint8_t answer[]                          = {0xc0,
                                                           0x0c,
                                                           0x00,
                                                           0x01,
                                                           0x00,
                                                           0x01,
                                                           0x00,
                                                           0x00,
                                                           0x00,
                                                           0x3c,
                                                           0x00,
                                                           0x04,
                                                           (uint8_t)(ap_ip & 0xff),
                                                           (uint8_t)((ap_ip >> 8) & 0xff),
                                                           (uint8_t)((ap_ip >> 16) & 0xff),
                                                           (uint8_t)((ap_ip >> 24) & 0xff)};
        if (qend + (int)sizeof(answer) <= sizeof(packet))
        {
            memcpy(packet + qend, answer, sizeof(answer));
            sendto(sock, packet, qend + sizeof(answer), 0, (struct sockaddr *)&client, len);
        }
    }
}

static void reset_transparent_transport_state(void)
{
    s_transport_reset_requested = true;
    singmux_tcp_notify_all_closed();
}

static void set_transparent_mode(transparent_mode_t mode)
{
    if (s_transparent_mode == mode)
    {
        return;
    }
    s_transparent_mode = mode;
    reset_transparent_transport_state();
    refresh_transparent_interception_state();
    if (!s_configuration_mode)
    {
        status_led_show_mode(s_transparent_mode, s_has_upstream);
    }
}

static void enter_configuration_mode(void)
{
    if (s_configuration_mode)
    {
        return;
    }
    s_configuration_mode = true;
    s_has_upstream       = false;
    reset_transparent_transport_state();
    refresh_transparent_interception_state();
    status_led_set_rgb(18, 14, 0);
    ESP_LOGW(TAG, "Configuration mode enabled: upstream Wi-Fi disconnected; open http://%s",
             configured_ap_ipv4(&s_config));
    esp_wifi_disconnect();
    if (xTaskCreate(apply_access_point_task, "config_ap", 2048, NULL, 3, NULL) != pdPASS)
    {
        ESP_LOGW(TAG,
                 "Configuration mode enabled, but setup AP channel reset task could not start");
    }
}

static void factory_reset_button_task(void *arg)
{
    (void)arg;
    gpio_config_t button = {
        .pin_bit_mask = 1ULL << BOOT_BUTTON_GPIO,
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&button));

    int  held_ticks          = 0;
    bool reset_warning_shown = false;
    int  config_blink_ticks  = 0;
    bool config_led_on       = true;

    bool armed_after_release = false;
    for (;;)
    {
        /* GPIO0 may still be held low by the serial bootloader when the firmware
           starts. Do not treat that as a user click which would disable routing. */
        if (!armed_after_release)
        {
            if (gpio_get_level(BOOT_BUTTON_GPIO) != 0)
            {
                armed_after_release = true;
                ESP_LOGI(TAG, "BOOT button ready: short click toggles routing; one-second hold "
                              "enters configuration mode; five-second hold factory-resets");
            }
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        if (gpio_get_level(BOOT_BUTTON_GPIO) == 0)
        {
            held_ticks++;
            if (held_ticks == 1)
            {
                ESP_LOGI(TAG,
                         "BOOT pressed; release within 1 second to toggle routing, hold 1 second "
                         "for configuration mode, or 5 seconds to factory reset");
            }
            if (held_ticks == 20)
            {
                enter_configuration_mode();
            }
            if (held_ticks == 80 && !reset_warning_shown)
            {
                status_led_set_rgb(18, 0, 0);
                reset_warning_shown = true;
                ESP_LOGW(TAG, "Keep holding BOOT for one more second to factory reset");
            }
            if (held_ticks >= 100)
            {
                ESP_LOGW(TAG, "Factory reset requested; clearing router configuration");
                nvs_handle_t nvs;
                if (nvs_open(CONFIG_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK)
                {
                    nvs_erase_all(nvs);
                    nvs_commit(nvs);
                    nvs_close(nvs);
                }
                vTaskDelay(pdMS_TO_TICKS(250));
                esp_restart();
            }
        }
        else
        {
            if (held_ticks > 0 && held_ticks < 20)
            {
                set_transparent_mode(transparent_mode_uses_vless() ? TRANSPARENT_MODE_UPSTREAM
                                                                   : TRANSPARENT_MODE_VLESS);
                ESP_LOGI(TAG, "Short BOOT click: %s mode",
                         transparent_mode_uses_vless() ? "transparent VLESS router"
                                                       : "transparent upstream router");
            }
            else if (held_ticks > 0 && reset_warning_shown)
            {
                if (!s_configuration_mode)
                {
                    status_led_show_mode(s_transparent_mode, s_has_upstream);
                }
            }
            held_ticks          = 0;
            reset_warning_shown = false;
        }
        if (s_configuration_mode && !reset_warning_shown)
        {
            if (++config_blink_ticks >= 10)
            {
                config_blink_ticks = 0;
                config_led_on      = !config_led_on;
                status_led_set_rgb(config_led_on ? 18 : 0, config_led_on ? 14 : 0, 0);
            }
        }
        else if (!s_configuration_mode)
        {
            config_blink_ticks = 0;
            config_led_on      = false;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

static int udp_association_find_singmux_stream(uint32_t stream_id)
{
    for (int i = 0; i < UDP_ASSOCIATION_MAX; ++i)
    {
        if (s_udp_associations[i].in_use && s_udp_associations[i].singmux_stream_id == stream_id)
        {
            return i;
        }
    }
    return -1;
}

/* Local USB/UART configuration path. It is intentionally not subject to portal
   authentication
 * because physical serial access is the recovery mechanism. */
static void serial_console_task(void *arg)
{
    (void)arg;
    char line[384];
    ESP_LOGI(TAG, "Serial commands: help; status; diag; route; wifi; ap; apip; vless; vless-uri; "
                  "dns; mux; admin");
    for (;;)
    {
        if (!fgets(line, sizeof(line), stdin))
        {
            clearerr(stdin);
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        char *command = strtok(line, " \t\r\n");
        char *first   = strtok(NULL, " \t\r\n");
        char *second  = strtok(NULL, " \t\r\n");
        char *rest    = strtok(NULL, "\r\n");
        while (rest && (*rest == ' ' || *rest == '\t'))
        {
            rest++;
        }
        if (!command)
        {
            continue;
        }
        if (strcmp(command, "help") == 0)
        {
            ESP_LOGI(
                TAG,
                "status; diag; route <vless|direct>; wifi <ssid> [password]; ap <ssid> <password>");
            ESP_LOGI(TAG, "apip <IPv4 ending in .1>");
            ESP_LOGI(TAG, "vless <host> <port> <uuid>; vless-uri <uri>; dns <host|clear>");
            ESP_LOGI(TAG, "mux <on|off>; admin <new-password>");
            continue;
        }
        if (strcmp(command, "status") == 0)
        {
            ESP_LOGI(TAG,
                     "AP='%s' ip='%s'; upstream='%s'; mode='%s'; VLESS host='%s' port=%u; "
                     "DNS='%s'; smux=%s",
                     configured_or_default(s_config.ap_ssid, AP_SSID),
                     configured_ap_ipv4(&s_config), s_config.upstream_ssid, transparent_mode_name(),
                     s_config.vless_host, s_config.vless_port, s_config.dns_resolver,
                     s_config.singmux_enabled ? "enabled" : "disabled");
            continue;
        }
        if (strcmp(command, "diag") == 0)
        {
            serial_diagnostics();
            continue;
        }
        if (strcmp(command, "route") == 0)
        {
            if (!first || second || (strcmp(first, "vless") != 0 && strcmp(first, "direct") != 0))
            {
                ESP_LOGW(TAG, "Usage: route <vless|direct>");
                continue;
            }
            set_transparent_mode(strcmp(first, "vless") == 0 ? TRANSPARENT_MODE_VLESS
                                                             : TRANSPARENT_MODE_UPSTREAM);
            ESP_LOGW(TAG, "Route is %s for this boot; direct bypasses VLESS for TCP and UDP",
                     transparent_mode_uses_vless() ? "VLESS" : "DIRECT");
            continue;
        }
        if (strcmp(command, "mux") == 0)
        {
            if (!first || (strcmp(first, "on") != 0 && strcmp(first, "off") != 0))
            {
                ESP_LOGW(TAG, "Usage: mux <on|off>");
                continue;
            }
            s_config.singmux_enabled = strcmp(first, "on") == 0;
            if (save_router_config(&s_config) == ESP_OK)
            {
                ESP_LOGI(TAG, "sing-box smux %s",
                         s_config.singmux_enabled ? "enabled" : "disabled");
            }
            else
            {
                ESP_LOGE(TAG, "Could not save sing-box smux setting");
            }
            continue;
        }
        if (strcmp(command, "admin") == 0)
        {
            if (!first || strlen(first) < 12 || strlen(first) > 64 || second)
            {
                ESP_LOGW(TAG, "Usage: admin <new-password> (12-64 characters, no spaces)");
                continue;
            }
            esp_err_t result = save_admin_password_hash(first, s_admin_password_hash);
            if (result == ESP_OK)
            {
                ESP_LOGI(TAG, "Portal administrator password changed");
            }
            else
            {
                ESP_LOGE(TAG, "Could not save administrator password: %s", esp_err_to_name(result));
            }
            continue;
        }
        router_config_t candidate          = s_config;
        bool            reconnect_upstream = false;
        bool            apply_ap           = false;
        bool            changed_vless      = false;
        if (strcmp(command, "wifi") == 0)
        {
            if (!first || (second && strlen(second) > 64) || strlen(first) > 32)
            {
                ESP_LOGW(TAG, "Usage: wifi <ssid> [password]");
                continue;
            }
            router_config_store_upstream(&candidate, first, second ? second : "", false);
            reconnect_upstream = true;
        }
        else if (strcmp(command, "ap") == 0)
        {
            if (!first || !second || strlen(first) > 32 || strlen(second) < 8 ||
                strlen(second) > 64)
            {
                ESP_LOGW(TAG, "Usage: ap <ssid> <password>");
                continue;
            }
            strlcpy(candidate.ap_ssid, first, sizeof(candidate.ap_ssid));
            strlcpy(candidate.ap_password, second, sizeof(candidate.ap_password));
            apply_ap = true;
        }
        else if (strcmp(command, "apip") == 0)
        {
            if (!first || second || !parse_access_point_ipv4(first, NULL))
            {
                ESP_LOGW(TAG, "Usage: apip <IPv4 ending in .1>");
                continue;
            }
            strlcpy(candidate.ap_ip, first, sizeof(candidate.ap_ip));
            apply_ap = true;
        }
        else if (strcmp(command, "dns") == 0)
        {
            if (!first || second || strlen(first) >= sizeof(candidate.dns_resolver))
            {
                ESP_LOGW(TAG, "Usage: dns <hostname|clear>");
                continue;
            }
            if (strcmp(first, "clear") == 0)
            {
                candidate.dns_resolver[0] = '\0';
            }
            else
            {
                strlcpy(candidate.dns_resolver, first, sizeof(candidate.dns_resolver));
            }
            changed_vless = true;
        }
        else if (strcmp(command, "vless") == 0)
        {
            char *uuid = rest;
            char *end  = NULL;
            long  port = second ? strtol(second, &end, 10) : 0;
            if (!first || !second || !uuid || !uuid[0] || !end || *end || port < 1 ||
                port > 65535 || strlen(first) >= sizeof(candidate.vless_host) ||
                strlen(uuid) >= sizeof(candidate.vless_uuid))
            {
                ESP_LOGW(TAG, "Usage: vless <host> <port> <uuid>");
                continue;
            }
            strlcpy(candidate.vless_host, first, sizeof(candidate.vless_host));
            strlcpy(candidate.vless_uuid, uuid, sizeof(candidate.vless_uuid));
            candidate.vless_port = (uint16_t)port;
            changed_vless        = true;
        }
        else if (strcmp(command, "vless-uri") == 0)
        {
            if (!first || second || !parse_vless_tcp_uri(first, &candidate))
            {
                ESP_LOGW(TAG, "Usage: vless-uri vless://UUID@HOST:PORT?encryption=none&type=tcp");
                continue;
            }
            changed_vless = true;
        }
        else
        {
            ESP_LOGW(TAG, "Unknown command; enter help");
            continue;
        }
        s_config      = candidate;
        esp_err_t err = save_router_config(&s_config);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "Serial configuration save failed: %s", esp_err_to_name(err));
            continue;
        }
        if (changed_vless && s_singmux_tunnel >= 0)
        {
            close(s_singmux_tunnel);
            s_singmux_tunnel    = -1;
            s_singmux_rx_length = 0;
            singmux_tcp_notify_all_closed();
        }
        if (apply_ap)
        {
            apply_access_point_config();
            ESP_LOGI(TAG, "Router AP saved; reconnect using SSID '%s' at http://%s",
                     s_config.ap_ssid, configured_ap_ipv4(&s_config));
        }
        if (reconnect_upstream)
        {
            s_configuration_mode = false;
            ESP_LOGI(TAG, "Upstream Wi-Fi saved for SSID '%s'; connecting", s_config.upstream_ssid);
            esp_wifi_disconnect();
            connect_upstream();
        }
        if (changed_vless)
        {
            ESP_LOGI(TAG, "VLESS configuration saved");
        }
    }
}

static bool singmux_deliver_udp(udp_association_t *association, const uint8_t *payload,
                                size_t payload_length)
{
    if (payload_length > UDP_RX_BUFFER_MAX - association->rx_length)
    {
        return false;
    }
    memcpy(association->rx_buffer + association->rx_length, payload, payload_length);
    association->rx_length += payload_length;
    size_t consumed = 0;
    if (association->singmux_response_pending)
    {
        if (!association->rx_length)
        {
            return true;
        }
        if (association->rx_buffer[0] != 0)
        {
            return false;
        }
        consumed                              = 1;
        association->singmux_response_pending = false;
    }
    while (association->rx_length - consumed >= 2)
    {
        size_t packet_length =
            ((size_t)association->rx_buffer[consumed] << 8) | association->rx_buffer[consumed + 1];
        if (packet_length > UDP_DATAGRAM_MAX)
        {
            return false;
        }
        if (association->rx_length - consumed < packet_length + 2)
        {
            break;
        }
        if (packet_length)
        {
            sendto(s_udp_relay_socket, association->rx_buffer + consumed + 2, packet_length, 0,
                   (struct sockaddr *)&association->client, sizeof(association->client));
            bandwidth_record_download(packet_length);
            transparent_udp_touch(association->flow.client_ip, association->flow.client_port);
            association->last_activity_ms = now_ms();
        }
        consumed += packet_length + 2;
    }
    if (consumed)
    {
        memmove(association->rx_buffer, association->rx_buffer + consumed,
                association->rx_length - consumed);
        association->rx_length -= consumed;
    }
    return true;
}

static bool singmux_receive_available(void)
{
    int bytes = recv(s_singmux_tunnel, s_singmux_socket_read_buffer,
                     sizeof(s_singmux_socket_read_buffer), MSG_DONTWAIT);
    if (bytes > 0)
    {
        s_singmux_stats.rx_reads++;
        if ((size_t)bytes > SINGMUX_RX_BUFFER_MAX - s_singmux_rx_length)
        {
            s_singmux_stats.close_protocol_error++;
            ESP_LOGW(TAG, "smux reassembly buffer full (%u bytes)", (unsigned)s_singmux_rx_length);
            return false;
        }
        memcpy(s_singmux_rx_buffer + s_singmux_rx_length, s_singmux_socket_read_buffer, bytes);
        s_singmux_rx_length += (size_t)bytes;
        if (s_singmux_rx_length > s_singmux_stats.rx_reassembly_high_water)
        {
            s_singmux_stats.rx_reassembly_high_water = (uint32_t)s_singmux_rx_length;
        }
        s_singmux_stats.rx_wire_bytes += (size_t)bytes;
    }
    else if (bytes == 0)
    {
        s_singmux_stats.close_eof++;
        return false;
    }
    else if (errno != EAGAIN && errno != EWOULDBLOCK)
    {
        s_singmux_stats.close_socket_error++;
        s_singmux_stats.last_socket_errno = errno;
        return false;
    }
    size_t consumed = 0;
    if (s_singmux_vless_response_pending)
    {
        if (s_singmux_rx_length < 2)
        {
            return true;
        }
        size_t addon_length = s_singmux_rx_buffer[1];
        if (s_singmux_rx_buffer[0] != 0 || s_singmux_rx_length < addon_length + 2)
        {
            s_singmux_stats.close_protocol_error++;
            return false;
        }
        consumed                         = addon_length + 2;
        s_singmux_vless_response_pending = false;
    }
    while (s_singmux_rx_length - consumed >= SMUX_HEADER_SIZE)
    {
        uint8_t  command;
        uint32_t stream_id;
        uint16_t payload_length;
        uint8_t *frame = s_singmux_rx_buffer + consumed;
        if (!singmux_decode_smux_header(frame, &command, &stream_id, &payload_length))
        {
            s_singmux_stats.close_protocol_error++;
            return false;
        }
        if (s_singmux_rx_length - consumed < SMUX_HEADER_SIZE + payload_length)
        {
            break;
        }
        int slot = udp_association_find_singmux_stream(stream_id);
        if (slot >= 0)
        {
            udp_association_t *association = &s_udp_associations[slot];
            if (command == SMUX_CMD_PSH &&
                !singmux_deliver_udp(association, frame + SMUX_HEADER_SIZE, payload_length))
            {
                s_singmux_stats.close_protocol_error++;
                return false;
            }
            if (command == SMUX_CMD_FIN)
            {
                udp_association_release(slot);
            }
        }
        else
        {
            int tcp_slot = singmux_tcp_stream_find(stream_id);
            if (tcp_slot >= 0)
            {
                if (command == SMUX_CMD_PSH &&
                    !singmux_tcp_deliver(tcp_slot, frame + SMUX_HEADER_SIZE, payload_length))
                {
                    s_singmux_stats.close_protocol_error++;
                    return false;
                }
                if (command == SMUX_CMD_FIN)
                {
                    singmux_tcp_notify_closed(tcp_slot);
                }
            }
        }
        s_singmux_stats.rx_frames++;
        consumed += SMUX_HEADER_SIZE + payload_length;
    }
    if (consumed)
    {
        memmove(s_singmux_rx_buffer, s_singmux_rx_buffer + consumed,
                s_singmux_rx_length - consumed);
        s_singmux_rx_length -= consumed;
    }
    return true;
}

static bool singmux_socket_readable(void)
{
    if (s_singmux_tunnel < 0)
    {
        return false;
    }
    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(s_singmux_tunnel, &reads);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 0};
    return select(s_singmux_tunnel + 1, &reads, NULL, NULL, &timeout) > 0 &&
           FD_ISSET(s_singmux_tunnel, &reads);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_LOGI(TAG, "heap at boot: internal=%u bytes, PSRAM=%u bytes",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    load_router_config(&s_config, TAG);
    load_admin_password_hash(s_admin_password_hash, TAG);
    status_led_init(TAG);
    status_led_boot_indicator(s_transparent_mode, s_has_upstream);
    transparent_tcp_init();
    s_has_upstream = false;
    refresh_transparent_interception_state();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_ap_netif = esp_netif_create_default_wifi_ap();
    transparent_tcp_set_ap_netif(esp_netif_get_netif_impl(s_ap_netif));
    s_sta_netif             = esp_netif_create_default_wifi_sta();
    wifi_init_config_t wifi = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, network_event,
                                                        NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        network_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    apply_access_point_config();
    ESP_ERROR_CHECK(esp_wifi_start());
    /* STA modem sleep adds latency and can throttle AP+STA forwarding.  A
       mains/USB-powered router should prefer predictable forwarding latency. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    initialize_device_health_monitoring();
    xTaskCreate(captive_dns_task, "captive_dns", 6144, NULL, 4, NULL);
    xTaskCreate(factory_reset_button_task, "factory_reset", 2048, NULL, 4, NULL);
    xTaskCreate(serial_console_task, "serial_console", 4096, NULL, 4, NULL);
    xTaskCreate(bandwidth_sampler_task, "bandwidth_sampler", 2048, NULL, 3, NULL);
    xTaskCreate(socks_server_task, "socks_server", 4096, NULL, 5, NULL);
    xTaskCreate(transparent_server_task, "transparent_server", 6144, NULL, 5, NULL);
    xTaskCreate(transparent_udp_server_task, "transparent_udp_server", 4096, NULL, 5, NULL);
    xTaskCreate(transparent_maintenance_task, "transparent_maint", 2048, NULL, 4, NULL);
    start_http_server();
    ESP_LOGI(TAG, "Setup AP '%s' ready at http://%s",
             configured_or_default(s_config.ap_ssid, AP_SSID), configured_ap_ipv4(&s_config));
}

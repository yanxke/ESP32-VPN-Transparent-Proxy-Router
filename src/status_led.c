#include <stdlib.h>
#include <sys/cdefs.h>

#include "driver/gpio.h"
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "status_led.h"

/* Most ESP32-S3 R8N16 boards expose their single WS2812 RGB LED on GPIO48.
 * Override this at build time, for example: -DRGB_LED_GPIO=47. */
#ifndef RGB_LED_GPIO
#define RGB_LED_GPIO GPIO_NUM_48
#endif

typedef struct
{
    rmt_encoder_t     base;
    rmt_encoder_t    *bytes_encoder;
    rmt_encoder_t    *copy_encoder;
    int               state;
    rmt_symbol_word_t reset_code;
} ws2812_encoder_t;

static const char          *s_tag;
static rmt_channel_handle_t s_rgb_channel;
static rmt_encoder_handle_t s_rgb_encoder;
static SemaphoreHandle_t    s_rgb_lock;
static bool                 s_rgb_ready;

RMT_ENCODER_FUNC_ATTR
static size_t ws2812_encode(rmt_encoder_t *encoder, rmt_channel_handle_t channel, const void *data,
                            size_t data_size, rmt_encode_state_t *ret_state)
{
    ws2812_encoder_t  *ws2812        = __containerof(encoder, ws2812_encoder_t, base);
    rmt_encode_state_t session_state = RMT_ENCODING_RESET;
    rmt_encode_state_t state         = RMT_ENCODING_RESET;
    size_t             symbols       = 0;

    switch (ws2812->state)
    {
    case 0:
        symbols += ws2812->bytes_encoder->encode(ws2812->bytes_encoder, channel, data, data_size,
                                                 &session_state);
        if (session_state & RMT_ENCODING_COMPLETE)
        {
            ws2812->state = 1;
        }
        if (session_state & RMT_ENCODING_MEM_FULL)
        {
            state |= RMT_ENCODING_MEM_FULL;
            goto done;
        }
        /* fall through */
    case 1:
        symbols += ws2812->copy_encoder->encode(ws2812->copy_encoder, channel, &ws2812->reset_code,
                                                sizeof(ws2812->reset_code), &session_state);
        if (session_state & RMT_ENCODING_COMPLETE)
        {
            state |= RMT_ENCODING_COMPLETE;
            ws2812->state = RMT_ENCODING_RESET;
        }
        if (session_state & RMT_ENCODING_MEM_FULL)
        {
            state |= RMT_ENCODING_MEM_FULL;
        }
        break;
    }
done:
    *ret_state = state;
    return symbols;
}

RMT_ENCODER_FUNC_ATTR
static esp_err_t ws2812_encoder_reset(rmt_encoder_t *encoder)
{
    ws2812_encoder_t *ws2812 = __containerof(encoder, ws2812_encoder_t, base);
    rmt_encoder_reset(ws2812->bytes_encoder);
    rmt_encoder_reset(ws2812->copy_encoder);
    ws2812->state = RMT_ENCODING_RESET;
    return ESP_OK;
}

static esp_err_t ws2812_encoder_delete(rmt_encoder_t *encoder)
{
    ws2812_encoder_t *ws2812 = __containerof(encoder, ws2812_encoder_t, base);
    rmt_del_encoder(ws2812->bytes_encoder);
    rmt_del_encoder(ws2812->copy_encoder);
    free(ws2812);
    return ESP_OK;
}

static esp_err_t ws2812_encoder_create(rmt_encoder_handle_t *result)
{
    ws2812_encoder_t *ws2812 = rmt_alloc_encoder_mem(sizeof(*ws2812));
    if (!ws2812)
    {
        return ESP_ERR_NO_MEM;
    }
    ws2812->base.encode              = ws2812_encode;
    ws2812->base.reset               = ws2812_encoder_reset;
    ws2812->base.del                 = ws2812_encoder_delete;
    rmt_bytes_encoder_config_t bytes = {
        .bit0            = {.level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9},
        .bit1            = {.level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3},
        .flags.msb_first = 1,
    };
    esp_err_t err = rmt_new_bytes_encoder(&bytes, &ws2812->bytes_encoder);
    if (err == ESP_OK)
    {
        rmt_copy_encoder_config_t copy = {};
        err                            = rmt_new_copy_encoder(&copy, &ws2812->copy_encoder);
    }
    if (err != ESP_OK)
    {
        ws2812_encoder_delete(&ws2812->base);
        return err;
    }
    ws2812->reset_code =
        (rmt_symbol_word_t){.level0 = 0, .duration0 = 250, .level1 = 0, .duration1 = 250};
    *result = &ws2812->base;
    return ESP_OK;
}

void status_led_set_rgb(uint8_t red, uint8_t green, uint8_t blue)
{
    if (!s_rgb_ready)
    {
        return;
    }
    /* The Waveshare ESP32-S3-Zero's GPIO21 LED uses RGB byte order; the
       R8N16 board's WS2812 uses the usual GRB order. */
#ifdef RGB_LED_ORDER_RGB
    const uint8_t rgb[] = {red, green, blue};
#else
    const uint8_t rgb[] = {green, red, blue};
#endif
    if (!s_rgb_lock || xSemaphoreTake(s_rgb_lock, pdMS_TO_TICKS(25)) != pdTRUE)
    {
        return;
    }
    rmt_transmit_config_t transmit = {0};
    if (rmt_transmit(s_rgb_channel, s_rgb_encoder, rgb, sizeof(rgb), &transmit) == ESP_OK)
    {
        (void)rmt_tx_wait_all_done(s_rgb_channel, pdMS_TO_TICKS(20));
    }
    xSemaphoreGive(s_rgb_lock);
}

void status_led_show_mode(transparent_mode_t mode, bool has_upstream)
{
    if (mode == TRANSPARENT_MODE_UPSTREAM)
    {
        if (has_upstream)
        {
            status_led_set_rgb(0, 12, 18);
        }
        else
        {
            status_led_set_rgb(0, 0, 18);
        }
    }
    else if (has_upstream)
    {
        status_led_set_rgb(0, 18, 0);
    }
    else
    {
        status_led_set_rgb(18, 14, 0);
    }
}

void status_led_boot_indicator(transparent_mode_t mode, bool has_upstream)
{
    for (int i = 0; i < 2; ++i)
    {
        status_led_set_rgb(18, 14, 0);
        vTaskDelay(pdMS_TO_TICKS(250));
        status_led_set_rgb(0, 0, 0);
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    status_led_show_mode(mode, has_upstream);
}

void status_led_init(const char *tag)
{
    s_tag                           = tag;
    rmt_tx_channel_config_t channel = {
        .gpio_num          = RGB_LED_GPIO,
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .resolution_hz     = 10 * 1000 * 1000,
        .mem_block_symbols = 64,
        .trans_queue_depth = 1,
    };
    esp_err_t err = rmt_new_tx_channel(&channel, &s_rgb_channel);
    if (err == ESP_OK)
    {
        err = ws2812_encoder_create(&s_rgb_encoder);
    }
    if (err == ESP_OK)
    {
        err = rmt_enable(s_rgb_channel);
    }
    if (err != ESP_OK)
    {
        ESP_LOGW(s_tag, "RGB LED unavailable on GPIO%d: %s", RGB_LED_GPIO, esp_err_to_name(err));
        return;
    }
    s_rgb_lock = xSemaphoreCreateMutex();
    if (!s_rgb_lock)
    {
        ESP_LOGW(s_tag, "RGB LED lock unavailable");
        return;
    }
    s_rgb_ready = true;
}

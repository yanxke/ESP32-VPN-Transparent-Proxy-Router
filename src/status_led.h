#ifndef STATUS_LED_H
#define STATUS_LED_H

#include <stdbool.h>
#include <stdint.h>

#include "router_config.h"

void status_led_init(const char *tag);
void status_led_show_mode(transparent_mode_t mode, bool has_upstream);
void status_led_boot_indicator(transparent_mode_t mode, bool has_upstream);
void status_led_set_rgb(uint8_t red, uint8_t green, uint8_t blue);

#endif
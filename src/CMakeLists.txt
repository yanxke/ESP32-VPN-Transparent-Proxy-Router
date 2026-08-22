idf_component_register(SRCS "main.c" "router_config.c" "status_led.c" "portal_page.c"
                            "transport_tcp.c"
                            "transparent_tcp.c" "xudp_codec.c" "singmux_codec.c"
                       REQUIRES esp_wifi esp_netif esp_event nvs_flash esp_http_server lwip esp_driver_rmt esp_driver_tsens app_update)

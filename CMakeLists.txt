cmake_minimum_required(VERSION 3.16.0)
set(PROJECT_VER "0.1.0")
include_directories(${CMAKE_SOURCE_DIR}/include)
add_compile_definitions(ESP_IDF_LWIP_HOOK_FILENAME="lwip_router_hook.h")
# ESP-IDF reserves low descriptors for stdio/VFS. Keep a descriptor range large
# enough for the 96 lwIP sockets plus those reserved descriptors.
add_compile_definitions(FD_SETSIZE=128)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ESP32-VLESS-Transparent-Proxy-Router)

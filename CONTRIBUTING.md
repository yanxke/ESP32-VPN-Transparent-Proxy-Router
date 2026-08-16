# Contributing

## Development requirements

- PlatformIO with the Espressif32 platform
- ESP32-S3 R8N16 or R8N8 target
- A VLESS test server using plain TCP; sing-box multiplex testing additionally requires inbound multiplexing enabled

## Build checks

Run the following before submitting a change:

```text
pio run -e esp32s3_r8n16
pio run -e esp32s3_r8n8
```

Do not commit `.pio`, credentials, UUIDs, Wi-Fi passwords, device-specific upload ports, or captured packet logs. Keep `VLESS_TRAFFIC_LOGS` disabled in normal builds.

## Change guidelines

- Preserve fail-closed behavior: unsupported traffic must not bypass VLESS through the upstream network.
- Keep packet-path allocations bounded. Use PSRAM for large relay buffers and retain internal RAM for Wi-Fi and lwIP.
- Document protocol compatibility and hardware test results in `README.md` when behavior changes.
- Test transparent TCP, DNS, and UDP independently. A successful portal request is not an end-to-end tunnel test.

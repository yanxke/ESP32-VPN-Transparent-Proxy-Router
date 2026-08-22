# Device test and update guide

## Target and connection

- The connected board is the `esp32s3_r8n8` environment on `COM3`.
- The router AP normally serves its authenticated portal at `http://192.168.4.1`.
- Preserve NVS: do not run `erase`, `erase_flash`, or any equivalent command unless explicitly asked. It contains the router, Wi-Fi, VLESS, and administrator configuration.

## Build and USB flash

Build with:

```powershell
pio run -e esp32s3_r8n8
```

Flash the built application through USB with:

```powershell
pio run -e esp32s3_r8n8 -t upload --upload-port COM3
```

If COM3 is busy, do not repeatedly retry or reset devices. First close PlatformIO/VS Code serial monitors and any other program using the port, then retry. USB upload normally preserves NVS.

## Serial monitoring and diagnostics

Use 115200 baud. Open one monitor only:

```powershell
pio device monitor --port COM3 --baud 115200
```

At the firmware console, run `diag` twice about one second apart during a transfer. Record payload rates, smux sessions open/closed, EOF/socket/protocol close causes, smux wire bytes/frames, TCP receive-queue high-water/full counts, control timeouts, and free internal/PSRAM.

Close the monitor before uploading firmware; it holds COM3 exclusively.

## Web diagnostics and OTA

The authenticated status endpoint is `GET /api/config`; use Basic authentication supplied by the device owner. It includes the same smux and bandwidth counters as `diag` and can be sampled before/after a test.

Builds create an application-only OTA image at `dist/esp32-vless-router-esp32s3_r8n8-ota.bin`. Upload it through the portal's Firmware update section or authenticated `POST /api/ota` with `Content-Type: application/octet-stream`.

Use OTA only when the image fits the inactive OTA partition. If the portal reports that the image is too large, do not retry; use USB flashing instead. Never upload the merged `dist/...r8n8.bin` image through `/api/ota`.

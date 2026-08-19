# Browser-based flashing

Every successful build creates a board-specific merged image:

```text
dist/esp32-vless-router-esp32s3_r8n16.bin
dist/esp32-vless-router-esp32s3_r8n8.bin
```

It also creates a matching versioned archive such as `dist/esp32-vless-router-esp32s3_r8n16-git-<hash>[-dirty].zip` or `dist/esp32-vless-router-esp32s3_r8n8-git-<hash>[-dirty].zip` containing the full image, the application-only OTA image, and this guide.

This is a merged image containing the bootloader, partition table, and application. Flash this one file at address `0x0`.

It also installs the dual-slot OTA layout required for portal updates. Because this single merged file spans the NVS region, record the router configuration before flashing it. Later builds produce a separate OTA image for the same board target, such as `dist/esp32-vless-router-esp32s3_r8n16-ota.bin` or `dist/esp32-vless-router-esp32s3_r8n8-ota.bin`; upload that application-only file from the authenticated **Firmware update** section at the router gateway, `http://192.168.4.1` by default. Do not use the OTA file with esptool-js, and do not upload the merged `0x0` image through the portal.

## Flash with esptool-js

1. Use Chrome, Edge, or another browser with Web Serial support. Safari is not supported by esptool-js.
2. Open [Espressif esptool-js](https://espressif.github.io/esptool-js/).
3. Connect the ESP32-S3 by USB and select its serial device in **Connect**.
4. In **Program**, add one file row:

   | Flash address | File |
   | --- | --- |
   | `0x0` | The merged image for your board, for example `dist/esp32-vless-router-esp32s3_r8n16.bin` or `dist/esp32-vless-router-esp32s3_r8n8.bin` |

5. Leave the flash mode, frequency, and size at the values detected by the tool unless your board vendor specifies otherwise.
6. Click **Program** and wait for verification to finish. Disconnect the web flasher, then reset or power-cycle the board.

After flashing, join the router AP and open the router gateway, `http://192.168.4.1`
by default. The portal uses HTTP Basic authentication; the factory credentials
are `admin` / `changeme`. Change the portal password immediately after signing
in.

If the browser cannot connect, hold the board's BOOT button while resetting it, then try **Connect** again. This is only the ESP32 ROM download mode; it does not erase configuration by itself.

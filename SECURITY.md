# Security policy

## Supported environment

This firmware is for a privately controlled ESP32-S3 R8N16 device and a trusted
VLESS server. It is not designed to expose its setup portal to an untrusted LAN
or the Internet.

## Threat model and current limitations

- The portal and all portal diagnostics require HTTP Basic authentication. The
  factory credentials are `admin` / `changeme`; change them immediately after
  first sign-in. The portal uses HTTP, not HTTPS, so Basic-auth credentials are
  not protected from an attacker able to observe AP traffic.
- VLESS UUIDs and Wi-Fi passwords are stored in ESP-IDF NVS. They are not
  returned by the portal, but NVS encryption is not enabled. The administrator
  password is stored as a SHA-256 hash in the same unencrypted NVS partition.
- Only plain VLESS-over-TCP is implemented. TLS, Reality, WebSocket, and IPv6 are unsupported.
- The firmware does not intentionally route client traffic directly to the upstream Wi-Fi. Unsupported traffic is dropped rather than sent outside VLESS.

## Deployment guidance

Use a unique AP password, change the factory portal password, restrict physical
access, and expose the AP only where untrusted users cannot join it. Treat the
setup portal as an administrative interface. Do not publish a firmware image
containing configured credentials.

## Reporting a vulnerability

Do not include credentials, UUIDs, public IP addresses, or full VLESS URIs in an issue. Open a minimal reproducible report with firmware revision, board revision, and sanitized serial logs.

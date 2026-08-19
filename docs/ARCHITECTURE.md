# Architecture

## Data path

```text
Wi-Fi client
  -> SoftAP / DHCP (configurable 192.168.X.1/24, default 192.168.4.1)
  -> custom lwIP IPv4 interception
  -> transparent TCP relay or UDP association manager
  -> VLESS TCP transport or direct upstream Wi-Fi forwarding
  -> configured VLESS server or upstream network
```

The AP and local portal remain local. IPv4 TCP flows are tracked so the reply tuple can be restored for the client. UDP flows are mapped to bounded persistent associations. IPv6 is disabled rather than partly routed.

## TCP

Without multiplexing, each captured TCP connection uses one VLESS TCP stream. The relay prefers a domain destination from the DNS cache, HTTP `Host`, or TLS SNI; it falls back to the original IPv4 destination when none is available.

With sing-box multiplexing enabled, one manager owns the VLESS connection to `sp.mux.sing-box.arpa:444`. Client relay tasks submit control/data records to that manager. The manager serializes smux writes and demultiplexes received frames into bounded per-stream queues. This avoids competing readers on one TCP socket.

## UDP

Direct mode uses VLESS XUDP with one persistent VLESS stream per active association. Sing-box multiplex mode carries persistent UDP associations as smux streams. Datagram ingress is queued and overload is dropped rather than blocking unrelated flows.

## Configuration

The portal is served at the configured AP gateway address, `http://192.168.4.1`
by default, and every portal or diagnostic route requires HTTP Basic
authentication. Factory credentials are `admin` / `changeme`; the administrator
can change the password on the main portal.
Configuration is persisted in NVS. Secret fields are write-only in the portal:
a reload never returns saved passwords or the UUID. The administrator password
is stored as a SHA-256 hash, but NVS encryption and HTTPS are not implemented.

Short BOOT press switches between transparent VLESS routing and transparent
upstream-only routing for the current boot. Holding BOOT for five seconds
erases all saved configuration, including the administrator password hash, and
restarts the device; it restores the factory portal credentials.

The USB/UART console at 115200 is a physical recovery and administration path.
It bypasses portal authentication, accepts `help` for command syntax, and can
configure the router AP, upstream Wi-Fi, VLESS profile, DNS resolver, smux
setting, and administrator password. `status` reports non-secret configuration
including whether smux is enabled; the console never prints stored passwords or
the VLESS UUID.

# C Code Guide

## Quality gate

The supported C baseline is C11. Run the following before every change:

```powershell
pwsh -File tools/lint.ps1
pio run -e esp32s3_r8n16
pio run -e esp32s3_r8n8
```

On Linux or macOS:

```text
./tools/lint.sh
pio run -e esp32s3_r8n16
pio run -e esp32s3_r8n8
```

Use `pwsh -File tools/lint.ps1 -Fix` to apply the repository formatter. Pass `-EnvironmentName esp32s3_r8n8` or `./tools/lint.sh esp32s3_r8n8` to lint the R8N8 build directory instead of the default R8N16 one. The gate uses `clang-format` for layout, `clang-tidy` for mandatory control-flow braces, and PlatformIO's managed `cppcheck` package for static analysis. PlatformIO downloads cppcheck automatically on its first lint run.

## Router-path design rules

1. Keep network packet parsing in C and validate every externally supplied length before use.
2. Do not allocate from unbounded client input. Fixed-size queues, flow tables, and PSRAM-backed buffers define the traffic budget.
3. Only the UDP/smux manager reads or writes the shared smux socket. Client tasks communicate with it through queues, preventing concurrent frame corruption.
4. Preserve fail-closed behavior. A parse, queue, tunnel, or configuration failure drops the affected traffic; it must not fall back to the upstream Wi-Fi path.
5. Use `uint32_t` for IPv4 addresses in network byte order and document conversion boundaries.
6. Public helpers use `bool` or `esp_err_t` to report failure. Callers own resources unless the API documentation explicitly transfers ownership.
7. Use braces for every `if`, `else`, `for`, `while`, and `do` body. This is enforced by clang-tidy.

## Module map

| Module | Responsibility |
| --- | --- |
| `main.c` | Configuration portal, Wi-Fi lifecycle, VLESS transport, TCP/UDP relay tasks, and smux manager. |
| `transparent_tcp.c` | lwIP interception, flow tables, reply-tuple restoration, and DNS name cache. |
| `xudp_codec.c` | Bounds-checked direct VLESS XUDP frame serialization and parsing. |
| `singmux_codec.c` | Bounds-checked sing-box smux headers and stream-request serialization. |

`main.c` deliberately centralizes runtime ownership. It is split into sections in this order: configuration, portal, Wi-Fi, VLESS transport, transparent TCP, UDP/smux manager, diagnostics, and startup. New code should remain in the section owning its resources rather than introducing cross-module global access.

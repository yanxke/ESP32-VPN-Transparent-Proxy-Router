#!/usr/bin/env bash
# Run repository formatting and static-analysis checks on Linux or macOS.
set -euo pipefail

readonly ENVIRONMENT_NAME="${1:-esp32s3_r8n16}"

readonly SOURCES=(
    src/main.c
    src/transparent_tcp.c
    src/xudp_codec.c
    src/singmux_codec.c
    src/transparent_tcp.h
    src/xudp_codec.h
    src/singmux_codec.h
    include/lwip_router_hook.h
)

if ! command -v clang-format >/dev/null; then
    echo "clang-format is required." >&2
    exit 1
fi

if ! command -v clang-tidy >/dev/null; then
    echo "clang-tidy is required." >&2
    exit 1
fi

if ! command -v pio >/dev/null; then
    echo "PlatformIO (pio) is required." >&2
    exit 1
fi

if [[ "${1:-}" == "--fix" ]]; then
    clang-format -i --style=file "${SOURCES[@]}"
elif [[ $# -gt 1 ]]; then
    echo "Usage: $0 [environment-name|--fix]" >&2
    exit 2
else
    clang-format --dry-run --Werror --style=file "${SOURCES[@]}"
fi

# ESP-IDF's Xtensa flags are not fully understood by host clang. Treat only
# this check's diagnostics as failures; the actual firmware build validates
# the generated code with the ESP-IDF toolchain.
tidy_output="$(clang-tidy -p .pio/build/${ENVIRONMENT_NAME} --config-file=.clang-tidy \
    src/main.c src/transparent_tcp.c src/xudp_codec.c src/singmux_codec.c 2>&1 || true)"
if grep -q 'readability-braces-around-statements' <<<"${tidy_output}"; then
    printf '%s\n' "${tidy_output}" >&2
    exit 1
fi

pio check -e "${ENVIRONMENT_NAME}" --fail-on-defect medium

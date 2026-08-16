param(
    [switch]$Fix,
    [string]$EnvironmentName = 'esp32s3_r8n16'
)

$ErrorActionPreference = 'Stop'
$sources = @('src/main.c', 'src/transparent_tcp.c', 'src/xudp_codec.c', 'src/singmux_codec.c',
             'src/transparent_tcp.h', 'src/xudp_codec.h', 'src/singmux_codec.h', 'include/lwip_router_hook.h')

if (-not (Get-Command clang-format -ErrorAction SilentlyContinue)) {
    throw 'clang-format is required. Install LLVM and add its bin directory to PATH.'
}

if ($Fix) {
    & clang-format -i --style=file $sources
} else {
    & clang-format --dry-run --Werror --style=file $sources
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$buildDir = ".pio/build/$EnvironmentName"

$tidyOutput = & clang-tidy -p $buildDir --config-file=.clang-tidy $sources 2>&1 | Out-String
if ($tidyOutput -match 'readability-braces-around-statements') {
    Write-Error $tidyOutput
    exit 1
}

& pio check -e $EnvironmentName --fail-on-defect medium
exit $LASTEXITCODE

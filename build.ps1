# Build btcminer.exe (single file, Windows).
#
# C++17 + AVX2. Requires MinGW-w64 g++ on PATH (tested with WinLibs g++ 16.1.0,
# UCRT). No CMake, no .NET, no Python.
#
#   .\build.ps1              # build dist\btcminer.exe (static, ~2.9 MB)
#   .\build.ps1 -Clean       # remove build/ and dist/ before building
#   .\build.ps1 -Tools       # also build build\bench.exe + build\check.exe
#
# If script execution is disabled: powershell -ExecutionPolicy Bypass -File .\build.ps1

param(
    [switch]$Clean,
    [switch]$Tools
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if ($Clean) {
    Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# C++ build
# ---------------------------------------------------------------------------
$compiler = Get-Command g++ -ErrorAction SilentlyContinue
if (-not $compiler) {
    throw "g++ not found on PATH. Install MinGW-w64 (e.g. WinLibs) and reopen the terminal."
}

Write-Host "compiler: $($compiler.Source)"
& g++ --version | Select-Object -First 1

$common = @("-O3", "-std=c++17", "-Wall", "-Wextra")
New-Item -ItemType Directory -Force build | Out-Null

function Build-Object {
    param(
        [string]$Source,
        [string]$Object,
        [string[]]$Extra = @()
    )
    $arguments = $common + $Extra + @("-c", $Source, "-o", $Object)
    & g++ @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "compile failed: $Source"
    }
    Write-Host "  ok $Source"
}

Build-Object -Source "cpp/sha256.cpp"      -Object "build/sha256.o"
Build-Object -Source "cpp/sha256_avx2.cpp" -Object "build/sha256_avx2.o" -Extra @("-mavx2")
foreach ($name in @("util", "json", "job", "stratum", "worker", "miner", "main")) {
    Build-Object -Source "cpp/$name.cpp" -Object "build/$name.o"
}

$objects = @(
    "build/util.o", "build/json.o", "build/job.o", "build/stratum.o",
    "build/worker.o", "build/miner.o", "build/main.o",
    "build/sha256.o", "build/sha256_avx2.o"
)

if ($Tools) {
    Build-Object -Source "cpp/tools/bench.cpp" -Object "build/tools_bench.o"
    & g++ -O3 -std=c++17 "build/tools_bench.o" "build/sha256.o" "build/sha256_avx2.o" `
        -o "build/bench.exe"
    if ($LASTEXITCODE -ne 0) { throw "link failed: bench.exe" }
    Write-Host "  ok build/bench.exe"

    Build-Object -Source "cpp/tools/check.cpp" -Object "build/tools_check.o"
    & g++ -O3 -std=c++17 "build/tools_check.o" "build/json.o" "build/job.o" `
        "build/util.o" "build/sha256.o" "build/sha256_avx2.o" -o "build/check.exe"
    if ($LASTEXITCODE -ne 0) { throw "link failed: check.exe" }
    Write-Host "  ok build/check.exe"
}

New-Item -ItemType Directory -Force dist | Out-Null
& g++ -O3 -std=c++17 -static -static-libgcc -static-libstdc++ `
    $objects -o "dist/btcminer.exe" -lws2_32
if ($LASTEXITCODE -ne 0) {
    throw "link failed: dist/btcminer.exe"
}

# The self-test must pass right after the build. Capture its output to a file
# and temporarily relax $ErrorActionPreference, because PowerShell treats any
# stderr line from a native program as an error while in "Stop" mode.
$log = Join-Path $env:TEMP "btcminer-build-selftest.log"
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& ".\dist\btcminer.exe" --self-test *> $log
$selfTestExit = $LASTEXITCODE
$ErrorActionPreference = $previousPreference
if ($selfTestExit -ne 0) {
    Get-Content $log | Write-Host
    throw "self-test failed (see $log)"
}

$exe = Join-Path $PSScriptRoot "dist\btcminer.exe"
$size = [math]::Round((Get-Item $exe).Length / 1MB, 2)
Write-Host ""
Write-Host "OK: $exe ($size MB, static)" -ForegroundColor Green
Write-Host "Smoke test: .\dist\btcminer.exe --self-test"
Write-Host "Benchmark : .\dist\btcminer.exe --benchmark 15"

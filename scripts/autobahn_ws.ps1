# Runs the official Autobahn WebSocket test suite against the Courierust
# server, so the conformance evidence comes from a third-party harness and
# not only from this repository's own tests.
#
#   .\scripts\autobahn_ws.ps1
#
# What it does
#   1. builds `examples/ws_autobahn` (the fixed-port echo endpoint)
#   2. starts it in the background on $Port
#   3. generates a fuzzingclient config and runs the official
#      `crossbario/autobahn-testsuite` Docker image against it
#   4. prints where the report landed and how to read it
#
# It never writes a pass/fail summary of its own: the report is Autobahn's,
# and `index.json` is the evidence. Anything else would be a claim this
# script is not entitled to make.
#
# Requirements: Docker (Docker Desktop on Windows) and a release build.
# On Linux, `--network host` is used so the container reaches the host
# endpoint; on Windows/macOS the host is `host.docker.internal`.

[CmdletBinding()]
param(
    [int]$Port = 9001,
    [string]$Image = "crossbario/autobahn-testsuite:latest"
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$reportDir = Join-Path $repo "target\autobahn"
$configDir = Join-Path $reportDir "config"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $reportDir "reports") | Out-Null

Write-Host "building the Autobahn endpoint (release)..." -ForegroundColor Cyan
Push-Location $repo
try {
    cargo build --release --example ws_autobahn
} finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0) { throw "the example failed to build" }

# Autobahn dials the endpoint from inside the container, so the host it
# must use depends on the platform's container networking.
$isLinux = $PSVersionTable.Platform -eq "Unix"
$dockerHost = if ($isLinux) { "127.0.0.1" } else { "host.docker.internal" }
$networkArgs = if ($isLinux) { @("--network", "host") } else { @() }

$endpoint = "ws://${dockerHost}:${Port}/"
Write-Host "endpoint: $endpoint" -ForegroundColor Cyan

$config = @{
    outdir     = "/autobahn/reports"
    servers    = @(@{ agent = "courierust"; url = $endpoint })
    cases      = @("*")
    exclude-cases = @()
    # The suite's limits/performance block sends messages far larger than
    # any production server accepts; this server enforces 16 MiB by
    # default, so those cases report `non-strict` rather than a pass. They
    # are reported, not hidden.
    "exclude-agent-cases" = @{}
} | ConvertTo-Json -Depth 6
Set-Content -Path (Join-Path $configDir "fuzzingclient.json") -Value $config -Encoding utf8

Write-Host "starting the endpoint..." -ForegroundColor Cyan
$env:WS_AUTOBAHN_ADDR = "0.0.0.0:$Port"
$endpointBinary = Join-Path $repo "target\release\examples\ws_autobahn.exe"
if (-not (Test-Path $endpointBinary)) { $endpointBinary = Join-Path $repo "target\release\examples\ws_autobahn" }
$server = Start-Process -FilePath $endpointBinary -PassThru -NoNewWindow
Start-Sleep -Seconds 2
if ($server.HasExited) { throw "the endpoint exited immediately (port $Port already in use?)" }

try {
    Write-Host "running Autobahn ($Image)..." -ForegroundColor Cyan
    $mount = "${reportDir}:/autobahn"
    docker run --rm @networkArgs -v $mount $Image wstest -m fuzzingclient -s /autobahn/config/fuzzingclient.json
    if ($LASTEXITCODE -ne 0) { throw "the Autobahn container exited with $LASTEXITCODE" }
} finally {
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

$index = Join-Path $reportDir "reports\index.json"
if (Test-Path $index) {
    Write-Host ""
    Write-Host "report: $index" -ForegroundColor Green
    Write-Host "Open it directly, or read the per-case detail under $(Split-Path -Parent $index)."
    Write-Host ""
    Write-Host "How to read it: every case must be 'OK'; 'NON-STRICT' means the" -ForegroundColor Yellow
    Write-Host "connection was failed in a slightly different way than the script" -ForegroundColor Yellow
    Write-Host "expected (usually still conformant), and 'FAILED' is a real defect." -ForegroundColor Yellow
    Write-Host "The limits/perf cases (9.*) are expected to be NON-STRICT for any" -ForegroundColor Yellow
    Write-Host "server that enforces a maximum message size." -ForegroundColor Yellow
} else {
    throw "Autobahn did not produce $index"
}

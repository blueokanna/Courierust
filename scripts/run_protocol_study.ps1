param(
    [ValidateRange(2, 20)][int]$Runs = 5,
    [ValidateRange(1, 1000000)][int]$Requests = 128,
    [ValidateRange(0, 3600000)][int]$DurationMs = 1000,
    [ValidateRange(10, 3600)][int]$SuiteTimeoutSeconds = 900,
    [ValidateSet('compare', 'grpc', 'tls', 'ws', 'h3', 'interop')][string[]]$Suites = @('compare', 'grpc', 'tls', 'ws', 'h3', 'interop'),
    [string]$Cases = '',
    [string]$Bytes = '',
    [string]$Servers = '',
    [ValidateRange(2, 1024)][int]$StreamMessages = 4,
    [ValidateRange(0, 100)][int]$ReadDelayMs = 0,
    [ValidateRange(2, 20)][int]$Repetitions = 4,
    [ValidateRange(1, 10000)][int]$Warmup = 8,
    [ValidateRange(0, 3600)][int]$CooldownSeconds = 0,
    [switch]$ResponseSweep,
    [string]$OutputDirectory = 'target/protocol-study'
)

# Each suite starts in a new process in every run. Never run suites in parallel.
$ErrorActionPreference = 'Stop'
$previousSweep = $env:BENCH_RESPONSE_SWEEP
$previousNodelay = $env:GRPC_SERVER_NODELAY
try {
    $firstSourceHashes = $null
    $env:BENCH_RESPONSE_SWEEP = if ($ResponseSweep) { '1' } else { '0' }
    $env:GRPC_SERVER_NODELAY = '1'
    for ($run = 1; $run -le $Runs; $run++) {
        if ($run -gt 1 -and $CooldownSeconds -gt 0) {
            Write-Output "Cooling down for $CooldownSeconds seconds before the next independent process."
            # Slice long waits so cancellation and status reporting stay responsive.
            $remaining = $CooldownSeconds
            while ($remaining -gt 0) {
                $seconds = [math]::Min($remaining, 30)
                Start-Sleep -Seconds $seconds
                $remaining -= $seconds
            }
        }
        $directory = Join-Path $OutputDirectory ('run-{0:d3}' -f $run)
        Write-Output "Independent run $run / $Runs"
        & (Join-Path $PSScriptRoot 'run_protocol_comparisons.ps1') `
            -Requests $Requests -Repetitions $Repetitions -Warmup $Warmup `
            -DurationMs $DurationMs -SuiteTimeoutSeconds $SuiteTimeoutSeconds -Suites $Suites `
            -Cases $Cases -Bytes $Bytes -Servers $Servers -StreamMessages $StreamMessages -ReadDelayMs $ReadDelayMs -ReverseOrder:($run % 2 -eq 0) `
            -OutputDirectory $directory
        $manifest = Join-Path (Join-Path $PSScriptRoot '..') (Join-Path $directory 'source-sha256.txt')
        $sourceHashes = [IO.File]::ReadAllText([IO.Path]::GetFullPath($manifest))
        $settingsPath = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($manifest))) 'study-settings.json'
        [IO.File]::WriteAllText($settingsPath, (@{
            independent_run = $run; runs = $Runs; cooldown_seconds = $CooldownSeconds
        } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        if ($null -eq $firstSourceHashes) {
            $firstSourceHashes = $sourceHashes
        } elseif ($firstSourceHashes -cne $sourceHashes) {
            throw 'Sources differ between independent runs. Keep the logs, but do not aggregate them as repeats of one revision.'
        }
    }
} finally {
    $env:BENCH_RESPONSE_SWEEP = $previousSweep
    $env:GRPC_SERVER_NODELAY = $previousNodelay
}

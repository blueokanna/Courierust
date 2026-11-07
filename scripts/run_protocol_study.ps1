param(
    [ValidateRange(2, 20)][int]$Runs = 3,
    [ValidateRange(1, 1000000)][int]$Requests = 128,
    [ValidateRange(2, 20)][int]$Repetitions = 4,
    [ValidateRange(1, 10000)][int]$Warmup = 8,
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
        $directory = Join-Path $OutputDirectory ('run-{0:d3}' -f $run)
        Write-Output "Independent run $run / $Runs"
        & (Join-Path $PSScriptRoot 'run_protocol_comparisons.ps1') `
            -Requests $Requests -Repetitions $Repetitions -Warmup $Warmup `
            -OutputDirectory $directory
        $manifest = Join-Path (Join-Path $PSScriptRoot '..') (Join-Path $directory 'source-sha256.txt')
        $sourceHashes = [IO.File]::ReadAllText([IO.Path]::GetFullPath($manifest))
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

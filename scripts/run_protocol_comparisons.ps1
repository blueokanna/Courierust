param(
    [ValidateRange(1, 1000000)][int]$Requests = 1000,
    [ValidateRange(0, 3600000)][int]$DurationMs = 1000,
    [ValidateSet('compare', 'grpc', 'tls', 'ws', 'h3', 'interop')][string[]]$Suites = @('compare', 'grpc', 'tls', 'ws', 'h3', 'interop'),
    [string]$Cases = '',
    [string]$Bytes = '',
    [string]$Servers = '',
    [ValidateRange(2, 1024)][int]$StreamMessages = 4,
    [ValidateRange(0, 100)][int]$ReadDelayMs = 0,
    [switch]$ReverseOrder,
    [ValidateRange(2, 20)][int]$Repetitions = 4,
    [ValidateRange(1, 10000)][int]$Warmup = 16,
    [ValidateRange(10, 3600)][int]$SuiteTimeoutSeconds = 900,
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')][string]$Toolchain = '1.98.0',
    [string]$OutputDirectory = 'target/protocol-comparison'
)

$ErrorActionPreference = 'Stop'
if ($Repetitions % 2 -ne 0) { throw 'Use an even repetition count to balance execution order.' }
$repoDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $repoDirectory
$outputPath = [System.IO.Path]::GetFullPath((Join-Path $repoDirectory $OutputDirectory))
if (-not $outputPath.StartsWith($repoDirectory + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be inside this checkout.'
}
if (Test-Path -LiteralPath $outputPath) {
    if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -gt 0) {
        throw 'OutputDirectory is not empty. Choose a new directory to preserve previous evidence.'
    }
}
[void][System.IO.Directory]::CreateDirectory($outputPath)
$utf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8
$suites = @($Suites | Select-Object -Unique)
if ($suites.Count -eq 0) { throw 'Select at least one suite.' }
if (($Cases -or $Bytes -or $Servers) -and @($suites | Where-Object { $_ -notin @('grpc', 'tls') }).Count) {
    throw 'Case filters are supported only by the gRPC and TLS suites.'
}
function Get-SourceHashes {
    # Decode git's NUL-delimited UTF-8 output explicitly. PowerShell 5's
    # console code page can otherwise silently discard non-ASCII paths.
    $inventory = [Diagnostics.Process]::new()
    $inventory.StartInfo.FileName = 'git'
    $inventory.StartInfo.Arguments = 'ls-files -z -co --exclude-standard'
    $inventory.StartInfo.WorkingDirectory = $repoDirectory
    $inventory.StartInfo.UseShellExecute = $false
    $inventory.StartInfo.CreateNoWindow = $true
    $inventory.StartInfo.RedirectStandardOutput = $true
    $inventory.StartInfo.RedirectStandardError = $true
    $inventory.StartInfo.StandardOutputEncoding = $utf8
    try {
        [void]$inventory.Start()
        $errors = $inventory.StandardError.ReadToEndAsync()
        $paths = $inventory.StandardOutput.ReadToEnd()
        $inventory.WaitForExit()
        if ($inventory.ExitCode -ne 0) { throw "Source inventory failed: $($errors.GetAwaiter().GetResult())" }
    } finally { $inventory.Dispose() }
    $paths.Split([char[]]@([char]0), [StringSplitOptions]::RemoveEmptyEntries) | Sort-Object -Unique | ForEach-Object {
        if (Test-Path -LiteralPath $_ -PathType Leaf) {
            $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
            "$($hash.Hash) $_"
        } else {
            "MISSING $_"
        }
    }
}
$sourceHashes = @(Get-SourceHashes)
[IO.File]::WriteAllLines((Join-Path $outputPath 'source-before-build.txt'), [string[]]$sourceHashes, $utf8)
$buildArguments = @("+$Toolchain", 'bench', '--manifest-path', 'benches/Cargo.toml', '--locked', '--no-run', '--message-format=json')
foreach ($suite in $suites) { $buildArguments += @('--bench', $suite) }
# PowerShell 5 treats native stderr as ErrorRecord even when Cargo succeeds.
$ErrorActionPreference = 'Continue'
$artifacts = & cargo @buildArguments 2> (Join-Path $outputPath 'build.log')
$buildExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
[System.IO.File]::WriteAllLines((Join-Path $outputPath 'build-artifacts.jsonl'), [string[]]$artifacts, $utf8)
if ($buildExit -ne 0) { throw "Build failed ($buildExit); see build.log." }
$afterBuild = @(Get-SourceHashes)
[IO.File]::WriteAllLines((Join-Path $outputPath 'source-after-build.txt'), [string[]]$afterBuild, $utf8)
if (($sourceHashes -join "`n") -cne ($afterBuild -join "`n")) {
    throw 'Sources changed during compilation. Rerun after edits finish; this build cannot be attributed to one snapshot.'
}
$executables = @{}
foreach ($line in $artifacts) {
    $artifact = $line | ConvertFrom-Json
    if ($artifact.reason -eq 'compiler-artifact' -and $artifact.executable -and $artifact.target.kind -contains 'bench') {
        $executables[$artifact.target.name] = $artifact.executable
    }
}

$provenance = @(
    "UTC: $([DateTime]::UtcNow.ToString('o'))",
    "OS: $([Environment]::OSVersion)",
    "CPU: $env:PROCESSOR_IDENTIFIER",
    "Logical CPUs: $([Environment]::ProcessorCount)",
    "Requests per repetition in count mode: $Requests; gRPC/TLS duration ms: $DurationMs; repetitions: $Repetitions; warmup: $Warmup",
    "gRPC messages per stream: $StreamMessages; consumer delay ms: $ReadDelayMs",
    "Suites: $($suites -join ','); cases: $Cases; bytes: $Bytes; servers: $Servers; reverse order: $ReverseOrder",
    'Resource sampling: whole benchmark process (clients and servers combined), approximately once per second; CPU is cumulative processor time, memory is bytes',
    "RUSTFLAGS: $env:RUSTFLAGS",
    "Suite timeout seconds: $SuiteTimeoutSeconds"
    "BENCH_RESPONSE_SWEEP: $env:BENCH_RESPONSE_SWEEP; GRPC_SERVER_NODELAY: 1; BENCH_TLS_DIAGNOSTICS: 0"
)
$provenance += & git rev-parse HEAD
$provenance += & git status --short
$provenance += & rustc "+$Toolchain" --version --verbose
$provenance += & cargo "+$Toolchain" tree --manifest-path benches/Cargo.toml --locked --depth 1
$provenance += Get-FileHash Cargo.lock, benches/Cargo.lock -Algorithm SHA256 | ForEach-Object { "$($_.Hash) $($_.Path)" }
$provenance += $executables.Values | ForEach-Object { Get-FileHash -LiteralPath $_ -Algorithm SHA256 } | ForEach-Object { "$($_.Hash) $($_.Path)" }
[System.IO.File]::WriteAllLines((Join-Path $outputPath 'benchmark-environment.log'), [string[]]$provenance, $utf8)
[System.IO.File]::WriteAllLines((Join-Path $outputPath 'source-sha256.txt'), [string[]]$sourceHashes, $utf8)
$metadata = & cargo "+$Toolchain" metadata --manifest-path benches/Cargo.toml --locked --format-version 1
if ($LASTEXITCODE -ne 0) { throw 'Dependency provenance could not be captured.' }
[System.IO.File]::WriteAllText((Join-Path $outputPath 'benchmark-dependencies.json'), ($metadata -join "`n"), $utf8)

$outcomes = @{}
$durations = @{}
foreach ($suite in $suites) {
    if (-not $executables.ContainsKey($suite)) { throw "Cargo did not produce $suite." }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo.FileName = $executables[$suite]
    $process.StartInfo.WorkingDirectory = $repoDirectory
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.EnvironmentVariables['BENCH_REQUESTS'] = "$Requests"
    $process.StartInfo.EnvironmentVariables['GRPC_STREAM_MESSAGES'] = "$StreamMessages"
    $process.StartInfo.EnvironmentVariables['GRPC_READ_DELAY_MS'] = "$ReadDelayMs"
    $process.StartInfo.EnvironmentVariables['BENCH_DURATION_MS'] = "$DurationMs"
    $process.StartInfo.EnvironmentVariables['BENCH_REVERSE_ORDER'] = if ($ReverseOrder) { '1' } else { '0' }
    foreach ($selection in @(@('BENCH_CASES', $Cases), @('BENCH_BYTES', $Bytes), @('BENCH_SERVERS', $Servers))) {
        if ($selection[1]) { $process.StartInfo.EnvironmentVariables[$selection[0]] = $selection[1] }
        else { $process.StartInfo.EnvironmentVariables.Remove($selection[0]) }
    }
    $process.StartInfo.EnvironmentVariables['BENCH_REPETITIONS'] = "$Repetitions"
    $process.StartInfo.EnvironmentVariables['BENCH_WARMUP'] = "$Warmup"
    $process.StartInfo.EnvironmentVariables['WS_BENCH_SECTION'] = 'compare'
    $process.StartInfo.EnvironmentVariables['GRPC_SERVER_NODELAY'] = '1'
    $process.StartInfo.EnvironmentVariables['BENCH_TLS_DIAGNOSTICS'] = '0'
    foreach ($variable in @('H3_SWEEP', 'H3_SWEEP_CHILD', 'H3_SCENARIOS')) {
        $process.StartInfo.EnvironmentVariables.Remove($variable)
    }
    Write-Output "Running $suite ..."
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    $clock = [Diagnostics.Stopwatch]::StartNew()
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $resources = [Collections.Generic.List[object]]::new()
    while (-not $process.WaitForExit(1000)) {
        if ($clock.Elapsed.TotalSeconds -ge $SuiteTimeoutSeconds) {
            $process.Kill()
            $process.WaitForExit()
            $outcomes[$suite] = 124
            break
        }
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                $resources.Add([pscustomobject]@{
                    utc = [DateTime]::UtcNow.ToString('o')
                    elapsed_seconds = $clock.Elapsed.TotalSeconds
                    cpu_seconds = $process.TotalProcessorTime.TotalSeconds
                    working_set_bytes = $process.WorkingSet64
                    private_bytes = $process.PrivateMemorySize64
                    threads = $process.Threads.Count
                    handles = $process.HandleCount
                })
            }
        } catch [InvalidOperationException] {
            if (-not $process.HasExited) { throw }
        }
    }
    if (-not $outcomes.ContainsKey($suite)) { $outcomes[$suite] = $process.ExitCode }
    [IO.File]::WriteAllText((Join-Path $outputPath "$suite.resources.json"), (ConvertTo-Json -InputObject @($resources.ToArray()) -Depth 3), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $outputPath "$suite.log"), $stdout.GetAwaiter().GetResult(), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $outputPath "$suite.stderr.log"), $stderr.GetAwaiter().GetResult(), $utf8)
    $process.Dispose()
    $clock.Stop()
    $durations[$suite] = @{ started_utc = $startedUtc; elapsed_seconds = $clock.Elapsed.TotalSeconds }
    Write-Output "$suite exit: $($outcomes[$suite])"
}
[System.IO.File]::WriteAllText((Join-Path $outputPath 'suite-status.json'), ($outcomes | ConvertTo-Json), $utf8)
[System.IO.File]::WriteAllText((Join-Path $outputPath 'suite-timing.json'), ($durations | ConvertTo-Json), $utf8)

if ($suites.Count -ne 6) {
    Write-Output "Focused evidence: $outputPath"
    if (@($outcomes.Values | Where-Object { $_ -ne 0 }).Count -gt 0) { throw 'At least one selected suite failed; retain and inspect its logs.' }
    return
}

$bashCommand = 'bash'
if ($env:OS -eq 'Windows_NT') {
    $gitDirectory = Split-Path (Split-Path (Get-Command git).Source -Parent) -Parent
    $bashCommand = Join-Path $gitDirectory 'bin/bash.exe'
    if (-not (Test-Path -LiteralPath $bashCommand)) { throw 'Git Bash is required to render the report.' }
}
$reportDirectory = $outputPath.Replace('\', '/')
$env:BENCHMARK_GRPC_LOG = "$reportDirectory/grpc.log"
$env:BENCHMARK_TLS_COMPARE_LOG = "$reportDirectory/tls.log"
$env:BENCHMARK_WS_LOG = "$reportDirectory/ws.log"
$env:BENCHMARK_ENVIRONMENT_LOG = "$reportDirectory/benchmark-environment.log"
$env:BENCHMARK_COMPARE_EXIT = "$($outcomes['compare'])"
$env:BENCHMARK_GRPC_EXIT = "$($outcomes['grpc'])"
$env:BENCHMARK_TLS_COMPARE_EXIT = "$($outcomes['tls'])"
$env:BENCHMARK_WS_EXIT = "$($outcomes['ws'])"
$env:BENCHMARK_H3_EXIT = "$($outcomes['h3'])"
$env:BENCHMARK_INTEROP_EXIT = "$($outcomes['interop'])"
& $bashCommand scripts/generate_benchmark_report.sh `
    "$reportDirectory/throughput.log" "$reportDirectory/compare.log" `
    "$reportDirectory/concurrency.log" "$reportDirectory/interop.log" `
    "$reportDirectory/network.log" "$reportDirectory/fuzz.log" `
    "$reportDirectory/h3.log" "$reportDirectory/tls-interop.log" `
    "$reportDirectory/complexity.log" "$reportDirectory/REPORT.md"
if ($LASTEXITCODE -ne 0) { throw 'Report rendering failed.' }
Write-Output "Evidence: $outputPath"
if (@($outcomes.Values | Where-Object { $_ -ne 0 }).Count -gt 0) {
    throw 'At least one suite failed. Successful rows do not override that failure; inspect the stderr logs.'
}

param(
    [ValidateRange(1, 1000000)][int]$Requests = 1000,
    [ValidateRange(2, 20)][int]$Repetitions = 4,
    [ValidateRange(1, 10000)][int]$Warmup = 16,
    [ValidateRange(10, 3600)][int]$SuiteTimeoutSeconds = 900,
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')][string]$Toolchain = '1.98.0',
    [string]$OutputDirectory = 'target/protocol-comparison'
)

# Build before measuring, run suites sequentially, and preserve failures.
# Cargo's JSON artifacts identify the exact executable; no stale-binary glob.
$ErrorActionPreference = 'Stop'
if ($Repetitions % 2 -ne 0) { throw 'Use an even repetition count to balance execution order.' }
$repoDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $repoDirectory
$outputPath = [System.IO.Path]::GetFullPath((Join-Path $repoDirectory $OutputDirectory))
if (-not $outputPath.StartsWith($repoDirectory + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be inside this checkout.'
}
[void][System.IO.Directory]::CreateDirectory($outputPath)
$utf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8
$suites = @('compare', 'grpc', 'tls', 'ws', 'h3', 'interop')
$buildArguments = @("+$Toolchain", 'bench', '--manifest-path', 'benches/Cargo.toml', '--locked', '--no-run', '--message-format=json')
foreach ($suite in $suites) { $buildArguments += @('--bench', $suite) }
# PowerShell 5 treats native stderr as ErrorRecord even when Cargo succeeds.
$ErrorActionPreference = 'Continue'
$artifacts = & cargo @buildArguments 2> (Join-Path $outputPath 'build.log')
$buildExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
[System.IO.File]::WriteAllLines((Join-Path $outputPath 'build-artifacts.jsonl'), [string[]]$artifacts, $utf8)
if ($buildExit -ne 0) { throw "Build failed ($buildExit); see build.log." }
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
    "Requests per repetition: $Requests; repetitions: $Repetitions; warmup: $Warmup",
    "RUSTFLAGS: $env:RUSTFLAGS",
    "Suite timeout seconds: $SuiteTimeoutSeconds"
)
$provenance += & git rev-parse HEAD
$provenance += & git status --short
$provenance += & rustc "+$Toolchain" --version --verbose
$provenance += & cargo "+$Toolchain" tree --manifest-path benches/Cargo.toml --locked --depth 1
$provenance += Get-FileHash Cargo.lock, benches/Cargo.lock -Algorithm SHA256 | ForEach-Object { "$($_.Hash) $($_.Path)" }
[System.IO.File]::WriteAllLines((Join-Path $outputPath 'benchmark-environment.log'), [string[]]$provenance, $utf8)
$sourcePaths = (& git ls-files -z -co --exclude-standard) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Source inventory could not be captured.' }
$sourceHashes = $sourcePaths.Split([char[]]@([char]0), [StringSplitOptions]::RemoveEmptyEntries) | Sort-Object -Unique | ForEach-Object {
    if (Test-Path -LiteralPath $_ -PathType Leaf) {
        $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
        "$($hash.Hash) $_"
    }
}
[System.IO.File]::WriteAllLines((Join-Path $outputPath 'source-sha256.txt'), [string[]]$sourceHashes, $utf8)
$metadata = & cargo "+$Toolchain" metadata --manifest-path benches/Cargo.toml --locked --format-version 1
if ($LASTEXITCODE -ne 0) { throw 'Dependency provenance could not be captured.' }
[System.IO.File]::WriteAllText((Join-Path $outputPath 'benchmark-dependencies.json'), ($metadata -join "`n"), $utf8)

$outcomes = @{}
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
    $process.StartInfo.EnvironmentVariables['BENCH_REPETITIONS'] = "$Repetitions"
    $process.StartInfo.EnvironmentVariables['BENCH_WARMUP'] = "$Warmup"
    $process.StartInfo.EnvironmentVariables['WS_BENCH_SECTION'] = 'compare'
    foreach ($variable in @('H3_SWEEP', 'H3_SWEEP_CHILD', 'H3_SCENARIOS')) {
        $process.StartInfo.EnvironmentVariables.Remove($variable)
    }
    Write-Output "Running $suite ..."
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if ($process.WaitForExit($SuiteTimeoutSeconds * 1000)) {
        $outcomes[$suite] = $process.ExitCode
    } else {
        $process.Kill()
        $process.WaitForExit()
        $outcomes[$suite] = 124
    }
    [System.IO.File]::WriteAllText((Join-Path $outputPath "$suite.log"), $stdout.GetAwaiter().GetResult(), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $outputPath "$suite.stderr.log"), $stderr.GetAwaiter().GetResult(), $utf8)
    $process.Dispose()
    Write-Output "$suite exit: $($outcomes[$suite])"
}
[System.IO.File]::WriteAllText((Join-Path $outputPath 'suite-status.json'), ($outcomes | ConvertTo-Json), $utf8)

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

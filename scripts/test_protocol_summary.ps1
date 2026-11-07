# Synthetic parser fixtures, never performance evidence.
$ErrorActionPreference = 'Stop'
$root = Join-Path (Join-Path $PSScriptRoot '../target') ('summary-fixtures-' + [guid]::NewGuid().ToString('N'))
$utf8 = [Text.UTF8Encoding]::new($false)
function New-Fixture([string]$Name, [string]$Fault = '') {
    $directory = Join-Path $root $Name
    foreach ($run in 1..2) {
        $path = Join-Path $directory "run-00$run"
        [void][IO.Directory]::CreateDirectory($path)
        [IO.File]::WriteAllText((Join-Path $path 'source-sha256.txt'), 'synthetic-test-source', $utf8)
        $status = if ($Fault -eq 'failure' -and $run -eq 2) { '{"grpc":124}' } else { '{"grpc":0}' }
        [IO.File]::WriteAllText((Join-Path $path 'suite-status.json'), $status, $utf8)
        $rows = foreach ($rep in 1..2) {
            $budget = if ($Fault -eq 'budget' -and $run -eq 2) { 2000 } else { 1000 }
            $id = if ($Fault -eq 'duplicate') { 1 } else { $rep }
            $elapsed = if ($Fault -eq 'short') { 999 } else { $budget }
            $count = 100 * $run + $rep
            "COMPARISON|protocol=grpc-h2|case=Bidi|client=test|server=test|bytes=1024|workers=1|warmup=4|mode=reuse|status=ok|repetition=$id|measurement=duration|target_ms=$budget|target_requests=0|requests=$count|elapsed_ms=$elapsed|rps=$count"
        }
        [IO.File]::WriteAllLines((Join-Path $path 'grpc.log'), [string[]]$rows, $utf8)
    }
    return $directory
}
$valid = New-Fixture 'valid'
& (Join-Path $PSScriptRoot 'summarize_protocol_study.ps1') -Directory $valid
$summary = @(Get-Content -LiteralPath (Join-Path $valid 'statistics.json') -Raw | ConvertFrom-Json)
if ($summary.Count -ne 1 -or $summary[0].completed_requests -ne 606 -or $summary[0].rows -ne 4) {
    throw 'Variable completed counts were not aggregated by their duration budget.'
}
foreach ($fault in @('budget', 'duplicate', 'short', 'failure')) {
    $fixture = New-Fixture $fault $fault
    $rejected = $false
    try { & (Join-Path $PSScriptRoot 'summarize_protocol_study.ps1') -Directory $fixture }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Invalid fixture was accepted: $fault" }
}
Write-Output 'Summary regressions passed: variable counts, mixed budgets, duplicate repetitions, short windows and failed suites.'

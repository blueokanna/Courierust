param([string]$Directory = 'target/protocol-study')

$ErrorActionPreference = 'Stop'
$directoryPath = [IO.Path]::GetFullPath($Directory)
$runs = @(Get-ChildItem -LiteralPath $directoryPath -Directory -Filter 'run-*' | Sort-Object Name)
if ($runs.Count -lt 2) { throw 'At least two independent runs are required.' }
$firstManifest = $null
$selectedSuites = $null
foreach ($run in $runs) {
    $manifest = [IO.File]::ReadAllText((Join-Path $run.FullName 'source-sha256.txt'))
    if ([string]::IsNullOrWhiteSpace($manifest)) { throw "Empty source inventory in $($run.Name)." }
    if ($null -eq $firstManifest) {
        $firstManifest = $manifest
    } elseif ($manifest -cne $firstManifest) {
        throw 'Mixed source snapshots cannot be aggregated as repeats of one revision.'
    }
    $status = Get-Content -LiteralPath (Join-Path $run.FullName 'suite-status.json') -Raw | ConvertFrom-Json
    $suiteNames = @($status.PSObject.Properties.Name | Sort-Object)
    if ($suiteNames.Count -eq 0) { throw 'No selected suites in status file.' }
    if ($null -eq $selectedSuites) { $selectedSuites = $suiteNames }
    elseif (($selectedSuites -join ',') -cne ($suiteNames -join ',')) { throw 'Suite selections differ between runs.' }
    foreach ($suite in $selectedSuites) {
        if ($null -eq $status.$suite -or $status.$suite -ne 0) {
            throw "Failed or missing suite $suite in $($run.Name); partial results cannot be aggregated."
        }
    }
}
function Get-Median($Values) {
    $sorted = @($Values | Sort-Object)
    if ($sorted.Count -eq 0) { throw 'Cannot summarize an empty sample.' }
    $middle = [int][math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2) { return $sorted[$middle] }
    return ($sorted[$middle - 1] + $sorted[$middle]) / 2
}
$summaries = @()
foreach ($suite in @($selectedSuites | Where-Object { $_ -in @('tls', 'grpc', 'compare', 'ws') })) {
    $rows = @()
    foreach ($run in $runs) {
        foreach ($line in Get-Content -LiteralPath (Join-Path $run.FullName "$suite.log")) {
            if ($line -notmatch '^(COMPARISON|RESULT)\|') { continue }
            $row = @{ run = $run.Name; suite = $suite; record = $Matches[1] }
            foreach ($field in ($line.Split('|') | Select-Object -Skip 1)) {
                $parts = $field.Split('=', 2)
                if ($parts.Count -ne 2) { throw "Malformed result in $($run.Name)/$suite." }
                $row[$parts[0]] = $parts[1]
            }
            # Diagnostics and unavailable comparisons remain in the raw report.
            if ($row.status -notin @('ok', 'valid')) { continue }
            $rps = [double]::Parse($row.rps, [Globalization.CultureInfo]::InvariantCulture)
            if ([double]::IsNaN($rps) -or [double]::IsInfinity($rps) -or $rps -le 0) {
                throw "Invalid throughput in $($run.Name)/$suite."
            }
            # Actual request counts vary in duration mode; group by the
            # declared stopping rule, never by the observed throughput.
            if (-not $row.measurement) {
                $row.measurement = 'requests'
                $row.target_requests = $row.requests
                $row.target_ms = '0'
            }
            if ($row.measurement -notin @('requests', 'duration')) { throw 'Unknown measurement mode.' }
            if ($row.measurement -eq 'duration') {
                $elapsed = [double]::Parse($row.elapsed_ms, [Globalization.CultureInfo]::InvariantCulture)
                if ([long]$row.target_ms -le 0 -or $elapsed -lt [long]$row.target_ms -or [long]$row.requests -le 0) {
                    throw 'Duration result did not meet its declared budget.'
                }
            } elseif ([long]$row.requests -ne [long]$row.target_requests -or [long]$row.requests -le 0) {
                throw 'Request result did not meet its declared budget.'
            }
            $row.rps = $rps
            $rows += [pscustomobject]$row
        }
    }
    if ($rows.Count -eq 0) { throw "No valid comparison rows for $suite." }
    $groupKeys = @('protocol', 'case', 'client', 'server', 'bytes', 'workers', 'layer',
        'measurement', 'target_requests', 'target_ms', 'warmup', 'mode', 'repetitions', 'pool_policy', 'pool_value', 'server_threads', 'stream_messages', 'read_delay_ms')
    foreach ($group in ($rows | Group-Object -Property $groupKeys)) {
        $first = $group.Group[0]
        $perRun = @($group.Group | Group-Object run)
        $counts = @($perRun | ForEach-Object { $_.Count } | Select-Object -Unique)
        if ($perRun.Count -ne $runs.Count -or $counts.Count -ne 1) {
            throw "Incomplete or unequal repetitions for $($group.Name)."
        }
        if ($first.record -eq 'COMPARISON') {
            foreach ($observations in $perRun) {
                $ids = @($observations.Group.repetition | ForEach-Object { [int]$_ } | Sort-Object -Unique)
                if ($ids.Count -ne $observations.Count -or $ids.Count -lt 2 -or
                    $ids[0] -ne 1 -or $ids[-1] -ne $ids.Count) {
                    throw 'Duplicate, missing or insufficient repetition identifiers.'
                }
            }
        }
        $medians = @($perRun | ForEach-Object { Get-Median @($_.Group.rps) })
        $range = $medians | Measure-Object -Minimum -Maximum
        $summaries += [pscustomobject][ordered]@{
            suite = $suite; protocol = $first.protocol; case = $first.case
            client = $first.client; server = $first.server; bytes = [int]$first.bytes
            workers = [int]$first.workers; layer = $first.layer; runs = $perRun.Count; rows = $group.Count
            stream_messages = [long]$first.stream_messages; read_delay_ms = [long]$first.read_delay_ms
            measurement = $first.measurement; target_ms = [long]$first.target_ms; target_requests = [long]$first.target_requests
            completed_requests = [long](($group.Group.requests | ForEach-Object { [long]$_ } | Measure-Object -Sum).Sum)
            median_rps = [math]::Round((Get-Median $medians), 2)
            minimum_run_median = [math]::Round($range.Minimum, 2)
            maximum_run_median = [math]::Round($range.Maximum, 2)
            run_medians = $medians
        }
    }
}
$output = Join-Path $directoryPath 'statistics.json'
[IO.File]::WriteAllText($output, ($summaries | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
Write-Output "Statistics: $output"

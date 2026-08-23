$ErrorActionPreference = "Continue"
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
$out = $args[0]
$cmdArgs = @()
for ($i = 1; $i -lt $args.Count; $i++) { $cmdArgs += $args[$i] }
$proc = Start-Process -FilePath $cargo -ArgumentList $cmdArgs -NoNewWindow -Wait -RedirectStandardOutput "$out.out" -RedirectStandardError "$out.err" -PassThru
$stdout = if (Test-Path "$out.out") { Get-Content "$out.out" -Raw } else { "" }
$stderr = if (Test-Path "$out.err") { Get-Content "$out.err" -Raw } else { "" }
$combined = "EXIT=$($proc.ExitCode)`n--- STDOUT ---`n$stdout`n--- STDERR ---`n$stderr"
[System.IO.File]::WriteAllText("$out.txt", $combined, [System.Text.Encoding]::UTF8)
Write-Output "done: $out.txt"

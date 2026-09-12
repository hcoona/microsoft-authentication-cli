param([ValidatePattern('^[0-9]{2}$')][string] $AttemptName)
$ErrorActionPreference = 'Stop'
$attempt = "C:\Temp\azureauth-native-aot-diagnostics\round-03\attempts\$AttemptName"
$watch = [Diagnostics.Stopwatch]::StartNew()
$result = [ordered]@{ controllerAbsent = $false; compilerAbsent = $false; quiescenceConfirmed = $false }
# Emergency use only. Never treat WSL exit or a missing PID as Job quiescence.
try {
    foreach ($role in @('controller', 'compiler')) {
        $receipt = Get-Content -LiteralPath "$attempt\$role.json" -Raw | ConvertFrom-Json
        $process = $null
        try { $process = [Diagnostics.Process]::GetProcessById([int]$receipt.pid) }
        catch [ArgumentException] { $result[$role + 'Absent'] = $true; continue }
        try {
            # Retain the process handle and verify its incarnation before termination.
            if ($process.Handle -eq [IntPtr]::Zero -or
                $process.StartTime.ToUniversalTime().ToString('o') -cne $receipt.started) {
                throw 'Unverified process identity'
            }
            $process.Kill()
            $remaining = [Math]::Max(0, 9000 - [int]$watch.ElapsedMilliseconds)
            $result[$role + 'Absent'] = $process.WaitForExit($remaining)
        } finally { $process.Dispose() }
    }
} catch {
    $result.failureType = $_.Exception.GetType().FullName
} finally {
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    $result | ConvertTo-Json | Set-Content -LiteralPath "$attempt\emergency.json" -Encoding UTF8
}

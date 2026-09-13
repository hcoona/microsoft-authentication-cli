param([Parameter(Mandatory = $true)][ValidatePattern('^[0-9]{4}$')][string] $ActionName)
$ErrorActionPreference = 'Stop'
$action = "C:\Temp\azureauth-windows-slice-108\actions\$ActionName"
$watch = [Diagnostics.Stopwatch]::StartNew()
$result = [ordered]@{ controllerAbsent = $false; compilerAbsent = $false; quiescenceConfirmed = $false }
# Emergency only: a lost controller or Linux parent does not prove Job quiescence.
# Always stop the loop, retain state, and require review after this path.
try {
    foreach ($role in @('controller', 'compiler')) {
        $path = "$action\$role.json"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $receipt = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $process = $null
        try { $process = [Diagnostics.Process]::GetProcessById([int]$receipt.pid) }
        catch [ArgumentException] { $result[$role + 'Absent'] = $true; continue }
        try {
            if ($process.Handle -eq [IntPtr]::Zero -or
                $process.StartTime.ToUniversalTime().ToString('o') -cne $receipt.started) {
                throw 'Unverified process incarnation'
            }
            $process.Kill()
            $remaining = [Math]::Max(0, 9000 - [int]$watch.ElapsedMilliseconds)
            $result[$role + 'Absent'] = $process.WaitForExit($remaining)
        } finally { $process.Dispose() }
    }
} catch { $result.failureType = $_.Exception.GetType().FullName }
finally {
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json))
    $stream = [IO.File]::Open("$action\emergency.json", [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}
exit 1

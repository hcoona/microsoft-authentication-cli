# Inert carrier for a single independently admitted public-status operation.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('HostMetadata', 'CutoffLoad', 'PrivatePinsLoad', 'PrivatePersonal', 'PrivateWork')][string] $OperationName,
    [Parameter(Mandatory)][scriptblock] $Operation
)
$CarrierAdmitted = $false
if (-not $CarrierAdmitted) { return }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$culture = [Globalization.CultureInfo]::InvariantCulture
$frequency = [Diagnostics.Stopwatch]::Frequency
$seconds = if ($OperationName -cin @('PrivatePersonal', 'PrivateWork')) { 120 } else { 30 }
$maximum = if ($OperationName -ceq 'HostMetadata') { 2048 } else { 4096 }
$started = 0L
$returned = 0L
$originalReturned = $false
$statusAccepted = $false
$status = $null
try {
    if ($frequency -le 0 -or -not [Diagnostics.Stopwatch]::IsHighResolution) {
        throw 'Original return refused.'
    }
    $started = [Diagnostics.Stopwatch]::GetTimestamp()
    $status = @(& $Operation)
    # Capture after the enclosed script, including status serialization, naturally returns.
    $returned = [Diagnostics.Stopwatch]::GetTimestamp()
    $originalReturned = $true
    if ($status.Count -ne 1 -or $status[0] -isnot [string] -or
        [Text.Encoding]::UTF8.GetByteCount($status[0]) -gt $maximum -or
        $status[0].Contains("`r") -or $status[0].Contains("`n")) {
        throw 'Original return refused.'
    }
    $statusAccepted = $true
} catch {
    # Never export exception text or unadmitted output.
}
$timely = ($originalReturned -and $started -gt 0 -and $returned -ge $started -and
    [decimal]($returned - $started) -lt ([decimal]$frequency * $seconds))
$frame = [ordered]@{
    schema = 'selected-account-public-original-return-v1'; operation = $OperationName
    originalReturned = $originalReturned; completeStatus = $statusAccepted; timely = $timely
    startTicks = $started.ToString($culture); returnTicks = $returned.ToString($culture)
    stopwatchFrequency = $frequency.ToString($culture)
}
# The timing frame describes the enclosed original, not this carrier's later console output.
# Complete carrier return and continued console/runspace require operator observation.
try {
    $timing = $frame | ConvertTo-Json -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($timing) -gt 1024) { return }
    if ($statusAccepted) { [Console]::WriteLine([string]$status[0]) }
    [Console]::WriteLine([string]$timing)
} catch {
    # Missing output or console return is failure; no retry/reset follows.
}

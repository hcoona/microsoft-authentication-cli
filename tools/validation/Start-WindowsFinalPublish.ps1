# Original Windows controller bootstrap; requires separate fixed-literal admission.
param([string] $ActionName, [string] $ReservationSha256, [string] $InvocationSha256, [string] $AuthoritySha256)
$script:FinalBootstrapDraftOnly = $false
if ($script:FinalBootstrapDraftOnly) { throw 'DRAFT_ONLY: final bootstrap has no accepted execution binding' }
$bootstrapWatch = [Diagnostics.Stopwatch]::StartNew()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2

function Assert-BootstrapBudget {
    if ($bootstrapWatch.ElapsedMilliseconds -ge 2400000 -or
        ($null -ne $deadlineCounter -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadlineCounter)) {
        throw 'Original bootstrap clock expired'
    }
}

function Assert-BootstrapDirect([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse bootstrap input' }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        elseif ($item -is [IO.FileInfo]) { $item = $item.Directory }
        else { throw 'Unexpected filesystem input type' }
    }
}

function Get-BootstrapHash([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Read-BootstrapBytes([string] $Path, [int] $Maximum = 8388608) {
    Assert-BootstrapBudget
    Assert-BootstrapDirect $Path
    Assert-BootstrapBudget
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -gt $Maximum) { throw 'Bootstrap receipt exceeds bound' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            Assert-BootstrapBudget
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'Incomplete bootstrap input' }
            $offset += $count
        }
        Assert-BootstrapBudget
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Read-BootstrapJson([string] $Path, [string] $Expected) {
    if ($Expected -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound bootstrap input hash' }
    $bytes = Read-BootstrapBytes $Path
    if ((Get-BootstrapHash $bytes) -cne $Expected) { throw 'Bootstrap input identity changed' }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $value = $text | ConvertFrom-Json
    if ($text -cne (($value | ConvertTo-Json -Depth 40 -Compress) + "`n")) { throw 'Noncanonical bootstrap input' }
    return $value
}

function Save-BootstrapJson([string] $Path, $Value) {
    Assert-BootstrapBudget
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20))
    Assert-BootstrapBudget
    $stream = [IO.File]::Open(($Path + '.pending'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        Assert-BootstrapBudget
        $stream.Write($bytes, 0, $bytes.Length)
        Assert-BootstrapBudget
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Assert-BootstrapBudget
    [IO.File]::Move(($Path + '.pending'), $Path)
    Assert-BootstrapBudget
}

if ($ActionName -cne '0093') { throw 'Invalid final action number' }
foreach ($hash in @($ReservationSha256, $InvocationSha256, $AuthoritySha256)) {
    if ($hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound bootstrap binding' }
}
$action = 'C:\Temp\azureauth-windows-slice-108\actions\' + $ActionName
$controller = $null
$deadlineCounter = $null
$normal = $false
$result = [ordered]@{
    schema = 'final-publish-controller-exit-v2'; reservationSha256 = $ReservationSha256
    bootstrapPid = $null; bootstrapCreationFileTime = $null; bootstrapSession = $null
    invocationSha256 = $InvocationSha256; controllerPid = $null; controllerStartUtc = $null
    controllerExitObserved = $false; controllerExitCode = $null; controllerTerminationRequested = $false
    normalCompletion = $false; safetyStop = $true; windowsResultSha256 = $null
    readySha256 = $null; replySha256 = $null; observedCounter = $null; deadlineCounter = $null; failureType = $null
}
try {
    $self = [Diagnostics.Process]::GetCurrentProcess()
    try {
        $result.bootstrapPid = $self.Id
        $result.bootstrapCreationFileTime = $self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $result.bootstrapSession = $self.SessionId
    } finally { $self.Dispose() }
    $authority = Read-BootstrapJson "$action\authority.json" $AuthoritySha256
    $invocation = Read-BootstrapJson "$action\invocation.json" $InvocationSha256
    $start = Read-BootstrapJson "$action\started.json" $ReservationSha256
    if ($authority.schema -cne 'final-publish-external-authority-v3' -or
        $invocation.schema -cne 'final-publish-invocation-v2' -or
        $invocation.action -cne $ActionName -or $invocation.actionPath -cne $action -or
        $invocation.reservationSha256 -cne $ReservationSha256 -or $invocation.authoritySha256 -cne $AuthoritySha256 -or
        $start.schema -cne 'final-publish-reservation-v2' -or $start.action -cne 'final-publish' -or
        $start.number -cne $ActionName -or $start.authoritySha256 -cne $AuthoritySha256 -or
        $start.endpoint -cne $invocation.endpoint -or $start.publishCharge -ne 1 -or
        $start.preparationCharge -ne 0 -or $start.buildTestCharge -ne 0 -or $start.reservedProcessScenarios -ne 1) {
        throw 'Original bootstrap reservation join changed'
    }
    if ((Get-BootstrapHash (Read-BootstrapBytes $PSCommandPath)) -cne $authority.components.bootstrap.sha256) {
        throw 'Original bootstrap source changed'
    }
    $controllerPath = "$action\controller\Invoke-WindowsFinalPublish.draft.ps1"
    if ((Get-BootstrapHash (Read-BootstrapBytes $controllerPath)) -cne $authority.components.controller.sha256) {
        throw 'Original controller source changed'
    }
    foreach ($name in @('controller-exit.json', 'controller-exit.json.pending', 'windows-result.json',
                         'windows-result.json.pending', 'clock-ready.json', 'clock-remaining.json', 'cancel')) {
        if (Test-Path -LiteralPath "$action\$name") { throw 'Prior controller output or cancellation exists' }
    }
    if (-not [Diagnostics.Stopwatch]::IsHighResolution -or $bootstrapWatch.ElapsedMilliseconds -ge 2400000) {
        throw 'Original bootstrap clock unavailable or expired'
    }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $controllerPath + '" -ActionName ' + $ActionName +
        ' -ReservationSha256 ' + $ReservationSha256 + ' -InvocationSha256 ' + $InvocationSha256 + ' -AuthoritySha256 ' + $AuthoritySha256
    $info.UseShellExecute = $false
    $info.WorkingDirectory = $action
    $info.EnvironmentVariables.Clear()
    foreach ($property in $invocation.environment.PSObject.Properties) {
        $info.EnvironmentVariables.Add($property.Name, [string]$property.Value)
    }
    if ($info.EnvironmentVariables.Count -ne 35) { throw 'Bootstrap child environment shape changed' }
    # Keep this exact Process object/handle. Never reopen by PID, scan the host,
    # Kill, CloseMainWindow, or use a terminating Job around the controller.
    $controller = [Diagnostics.Process]::new()
    $controller.StartInfo = $info
    Assert-BootstrapBudget
    if (-not $controller.Start()) { throw 'Original Windows controller creation failed' }
    [void]$controller.Handle
    $result.controllerPid = $controller.Id
    $result.controllerStartUtc = $controller.StartTime.ToUniversalTime().ToString('o')
    $handshakeEnd = [Math]::Min(2400000L, $bootstrapWatch.ElapsedMilliseconds + 20000L)
    $readyBytes = $null
    $replyBytes = $null
    while ($null -eq $replyBytes) {
        if ($bootstrapWatch.ElapsedMilliseconds -ge $handshakeEnd -or (Test-Path -LiteralPath "$action\cancel")) {
            throw 'Original bootstrap clock handshake failed'
        }
        if ($controller.HasExited) { throw 'Original controller exited before clock handoff' }
        if (Test-Path -LiteralPath "$action\clock-ready.json") {
            $readyBytes = Read-BootstrapBytes "$action\clock-ready.json" 4096
        }
        if ($null -ne $readyBytes -and (Test-Path -LiteralPath "$action\clock-remaining.json")) {
            $candidate = Read-BootstrapBytes "$action\clock-remaining.json" 4096
            if ($candidate.Length -gt 0 -and $candidate[$candidate.Length - 1] -eq 10) { $replyBytes = $candidate }
        }
        Start-Sleep -Milliseconds 25
    }
    $ready = [Text.UTF8Encoding]::new($false, $true).GetString($readyBytes) | ConvertFrom-Json
    $reply = [Text.UTF8Encoding]::new($false, $true).GetString($replyBytes) | ConvertFrom-Json
    if ($ready.schema -cne 'final-publish-clock-ready-v1' -or $ready.action -cne $ActionName -or
        $ready.reservationSha256 -cne $ReservationSha256 -or $ready.invocationSha256 -cne $InvocationSha256 -or
        $ready.endpoint -cne $start.endpoint -or $ready.controllerPid -ne $controller.Id -or
        $ready.controllerStartUtc -cne $result.controllerStartUtc -or
        $ready.windowsClockFrequency -ne [Diagnostics.Stopwatch]::Frequency -or
        $reply.schema -cne 'final-publish-clock-remaining-v1' -or $reply.action -cne $ActionName -or
        $reply.reservationSha256 -cne $ReservationSha256 -or $reply.invocationSha256 -cne $InvocationSha256 -or
        $reply.endpoint -cne $start.endpoint -or $reply.readySha256 -cne (Get-BootstrapHash $readyBytes) -or
        ($reply.remainingMilliseconds -isnot [int] -and $reply.remainingMilliseconds -isnot [long]) -or
        $reply.remainingMilliseconds -le 0 -or $reply.remainingMilliseconds -gt 1900000) { throw 'Original bootstrap clock binding changed' }
    $counter = [decimal]$ready.windowsReadyCounter + [Math]::Floor(([decimal]$reply.remainingMilliseconds * [decimal]$ready.windowsClockFrequency) / 1000) - 1
    if ($counter -gt [long]::MaxValue -or $counter -le 0) { throw 'Invalid original bootstrap deadline' }
    $deadlineCounter = [long]$counter
    $result.deadlineCounter = $deadlineCounter
    $result.readySha256 = Get-BootstrapHash $readyBytes
    $result.replySha256 = Get-BootstrapHash $replyBytes
    while (-not $controller.HasExited) {
        if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadlineCounter -or $bootstrapWatch.ElapsedMilliseconds -ge 2400000 -or
            (Test-Path -LiteralPath "$action\cancel")) { throw 'Original Windows controller exit not observed within its clock' }
        Start-Sleep -Milliseconds 25
    }
    $result.controllerExitObserved = $true
    $result.controllerExitCode = $controller.ExitCode
    $result.observedCounter = [Diagnostics.Stopwatch]::GetTimestamp()
    if ($result.controllerExitCode -ne 0 -or $result.observedCounter -ge $deadlineCounter -or
        $bootstrapWatch.ElapsedMilliseconds -ge 2400000 -or (Test-Path -LiteralPath "$action\cancel")) { throw 'Original controller failed or exited late' }
    $windowsBytes = Read-BootstrapBytes "$action\windows-result.json" 65536
    $windows = [Text.UTF8Encoding]::new($false, $true).GetString($windowsBytes) | ConvertFrom-Json
    if ($windows.schema -cne 'final-publish-windows-result-v1' -or $windows.reservationSha256 -cne $ReservationSha256 -or
        $windows.normalCompletion -ne $true -or $windows.quiescent -ne $true -or $windows.safetyStop -ne $false -or
        $windows.exitCode -ne 0 -or $windows.rootTerminationRequested -ne $false -or $windows.jobTerminationRequested -ne $false) {
        throw 'Original Windows publication completion is incomplete'
    }
    $result.windowsResultSha256 = Get-BootstrapHash $windowsBytes
    if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadlineCounter -or $bootstrapWatch.ElapsedMilliseconds -ge 2400000) {
        throw 'Original completion receipt arrived late'
    }
    $normal = $true
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $normal = $false
} finally {
    # A late zero exit cannot erase failure. Closing this retained Process object
    # releases local handles only; it does not terminate the controller or Job.
    if ($null -ne $controller) {
        try { $controller.Dispose() } catch { $normal = $false; $result.failureType = $_.Exception.GetType().FullName }
    }
    Assert-BootstrapBudget
    $result.normalCompletion = $normal
    $result.safetyStop = -not $normal
    $result.controllerTerminationRequested = $false
    Save-BootstrapJson "$action\controller-exit.json" $result
}
# Finalization must fit the same original clocks. Keep the durable receipt
# unchanged if this final decision fails or its checks throw.
if (-not $normal -or $null -eq $deadlineCounter) { exit 1 }
try {
    if ((Test-Path -LiteralPath "$action\cancel") -or
        $bootstrapWatch.ElapsedMilliseconds -ge 2400000 -or
        [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadlineCounter) { exit 1 }
} catch { exit 1 }
exit 0

# Source-only controller for the native R1/R6 product acceptance pair.
# An accepted real-effects protocol and exact input/call review precede activation.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PlanPath,
    [Parameter(Mandatory)][string] $PlanSha256,
    [Parameter(Mandatory)][ValidateRange(1, 4)][int] $Attempt,
    [Parameter(Mandatory)][string] $ControllerSha256,
    [switch] $Controller,
    [Parameter(Mandatory)][long] $InvocationStartTicks,
    [string] $ReservationSha256 = ''
)

$entryTicks = [Diagnostics.Stopwatch]::GetTimestamp()
$ExecutionAdmitted = $false
if (-not $ExecutionAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v3'
$frequency = [Diagnostics.Stopwatch]::Frequency
$callStart = $InvocationStartTicks
$child = $null
$started = $false
$stopped = $false
$closed = $false
$receiptRoot = $null
$pins = [Collections.Generic.List[IDisposable]]::new()
$status = [ordered]@{
    schema = 'selected-account-controller-v1'; attempt = $Attempt
    passed = $false; supervisorExited = $false; supervisorExitCode = -1
    streamsClosed = $false; stopAttempted = $false; ownedClosure = $false
    noExperimentLive = $false; failure = 'admission'
}

function Need([bool] $Condition) {
    if (-not $Condition) { throw 'Selected-account admission refused.' }
}

function Before([int] $Seconds) {
    Need ($callStart -gt 0 -and $callStart -le $entryTicks -and
        ([Diagnostics.Stopwatch]::GetTimestamp() - $callStart) / $frequency -lt $Seconds)
}

function Read-Pinned([string] $Path, [int] $Maximum, [string] $ExpectedHash) {
    $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $pins.Add($file)
    Need ($file.Length -gt 0 -and $file.Length -le $Maximum)
    $bytes = [byte[]]::new([int] $file.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        Before 20
        $read = $file.Read($bytes, $offset, $bytes.Length - $offset)
        Need ($read -gt 0)
        $offset += $read
    }
    Need ($file.ReadByte() -eq -1)
    if ($ExpectedHash) {
        Need ($ExpectedHash -cmatch '\A[0-9a-f]{64}\z')
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $actual = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        Need ($actual -ceq $ExpectedHash)
    }
    return ,$bytes
}

function Write-NewJson([string] $Path, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12 -Compress) + "`n")
    Need ($bytes.Length -le 262144)
    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
    finally { $file.Dispose() }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Quote-Argument([string] $Value) {
    # All controller arguments are public paths, hashes, fixed labels or decimal ticks.
    Need ($Value -notmatch '[\x00-\x1f"%]' -and -not $Value.EndsWith('\'))
    return '"' + $Value + '"'
}

function Invoke-Outer {
    # Run in the admitted existing console; the only new shell is the controller.
    # Original-call admission binds this source before invocation, not just its path.
    $process = $null
    $launched = $false
    $complete = $false
    $outerReceipt = $null
    $safe = [ordered]@{
        schema = 'selected-account-outer-v1'; attempt = $Attempt
        passed = $false; controllerExited = $false; streamsClosed = $false
        stopAttempted = $false; noExperimentLive = $false; failure = 'admission'
        invocationStartTicks = $callStart; stopwatchFrequency = $frequency
        controllerPid = 0; controllerCreatedFileTime = 0
    }
    try {
        Before 20
        Need (-not $Controller -and $ReservationSha256 -ceq '')
        Need ([Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -eq 'Desktop')
        Need ($PlanPath -ceq ($root + '\control\selected-account-plan-' + $Attempt + '.json'))
        $script = $root + '\control\Invoke-WindowsSelectedAccount.ps1'
        Need ($PSCommandPath -ceq $script)
        $null = Read-Pinned $script 65536 $ControllerSha256
        $shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $null = Read-Pinned $shell 1048576 '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e'
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $public = $utf8.GetString((Read-Pinned $PlanPath 262144 $PlanSha256)) | ConvertFrom-Json
        $group = if ($Attempt % 2 -eq 1) { 'R1' } else { 'R6' }
        Need ($public.schema -ceq 'confidential-native-account-admission-v1' -and
            $public.group -ceq $group -and $public.admitted -eq $true -and
            $public.accountEffectsAccepted -eq $true -and
            $public.nonce -cmatch '\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z')
        $outerReceipt = $root + '\records\' + $group + '-' + $public.nonce + '\outer-terminal.json'
        for ($prior = 1; $prior -lt $Attempt; $prior++) {
            Need ([IO.File]::Exists($root + '\records\selected-account-attempt-' + $prior + '.json'))
        }
        # The complete debit precedes the new shell, including failed shell starts.
        $reservation = Write-NewJson ($root + '\records\selected-account-attempt-' + $Attempt + '.json') ([ordered]@{
            schema = 'selected-account-attempt-v1'; attempt = $Attempt; group = $group
            nonce = $public.nonce; planSha256 = $PlanSha256; controllerSha256 = $ControllerSha256
            invocationStartTicks = $callStart; productLaunchReservation = 1
            callerProcessReservation = 2; controllerReservation = 1; outerInvocationReservation = 1
        })
        Before 20
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $shell
        $info.Arguments = '-NoLogo -NoProfile -NonInteractive -File ' + (Quote-Argument $script) +
            ' -PlanPath ' + (Quote-Argument $PlanPath) + ' -PlanSha256 ' + (Quote-Argument $PlanSha256) +
            ' -Attempt ' + $Attempt + ' -ControllerSha256 ' + (Quote-Argument $ControllerSha256) +
            ' -Controller -InvocationStartTicks ' + $callStart.ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -ReservationSha256 ' + (Quote-Argument $reservation)
        $info.WorkingDirectory = $root
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $false
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $info
        $safe.failure = 'launch'
        Need ($process.Start())
        $launched = $true
        $null = $process.Handle
        $safe.controllerPid = $process.Id
        $safe.controllerCreatedFileTime = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
        $stdout = $process.StandardOutput.BaseStream.ReadAsync([byte[]]::new(1), 0, 1)
        $stderr = $process.StandardError.BaseStream.ReadAsync([byte[]]::new(1), 0, 1)
        $safe.failure = 'supervision'
        while (([Diagnostics.Stopwatch]::GetTimestamp() - $callStart) / $frequency -lt 170) {
            if ($stdout.IsCompleted) { Need ($stdout.GetAwaiter().GetResult() -eq 0) }
            if ($stderr.IsCompleted) { Need ($stderr.GetAwaiter().GetResult() -eq 0) }
            if ($process.HasExited -and $stdout.IsCompleted -and $stderr.IsCompleted) {
                $complete = $true
                $safe.controllerExited = $true
                $safe.streamsClosed = $true
                break
            }
            [Threading.Thread]::Sleep(10)
        }
        Need $complete
        Before 170
        Need ($process.ExitCode -eq 0)
        $safe.passed = $true
        $safe.failure = 'none'
    } catch {
        # No exception, captured byte, environment or private input is exported.
    } finally {
        if ($launched -and -not $complete) {
            $safe.stopAttempted = $true
            try {
                if (-not $process.HasExited) { $process.Kill() }
                $remaining = [Math]::Max(0, [Math]::Min(5000,
                    [Math]::Floor(175000 - 1000 * ([Diagnostics.Stopwatch]::GetTimestamp() - $callStart) / $frequency)))
                $safe.controllerExited = $process.WaitForExit([int] $remaining)
            } catch { }
            # Controller exit does not prove native worker/product/Job completion.
        }
        if ($process) { $process.Dispose() }
        foreach ($pin in $pins) { $pin.Dispose() }
        try {
            Before 180
            if ($outerReceipt) { $null = Write-NewJson $outerReceipt $safe }
            Before 180
        } catch { $safe.passed = $false }
    }
    # An overrun fails even if a receipt write completed after its cutoff.
    if ($safe.passed) { return 0 }
    return 1
}

if (-not $Controller) { exit (Invoke-Outer) }

try {
    Before 20
    Need ([Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -eq 'Desktop')
    Need ($PlanPath -ceq ($root + '\control\selected-account-plan-' + $Attempt + '.json'))
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $plan = $encoding.GetString((Read-Pinned $PlanPath 262144 $PlanSha256)) | ConvertFrom-Json
    $group = if ($Attempt % 2 -eq 1) { 'R1' } else { 'R6' }
    Need ($plan.schema -ceq 'confidential-native-account-admission-v1' -and
        $plan.group -ceq $group -and $plan.admitted -eq $true -and $plan.accountEffectsAccepted -eq $true)
    Need ($plan.environmentMode -ceq 'constructed-current-user-profile-v1' -and
        $plan.effects.productLaunches -eq 1 -and $plan.effects.callerProcesses -eq 2 -and
        $plan.effects.exemptOuterPowerShellCount -eq 1 -and $plan.effects.etwAttempts -eq 0)
    Need ($plan.nonce -cmatch '\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z')
    foreach ($name in @('protocolSha256', 'riskDecisionSha256', 'sourceAcceptanceSha256', 'closureAcceptanceSha256')) {
        Need ($plan.$name -cmatch '\A[0-9a-f]{64}\z')
    }
    # Exact-call review owns the complete, hash-bound public inventory and private
    # selector identity. This controller never reads or prints the private document.
    Need ($plan.callerPins.Count -eq 194)
    $callerPin = @($plan.callerPins | Where-Object { $_.relative -ceq 'artifact\NativeCaller.exe' })
    Need ($callerPin.Count -eq 1)
    $caller = $root + '\artifact\NativeCaller.exe'
    $null = Read-Pinned $caller 1048576 $callerPin[0].sha256
    $receiptRoot = $root + '\records\' + $group + '-' + $plan.nonce
    Need ([IO.Directory]::Exists($receiptRoot))
    # The four fixed reservations are cumulative across controllers, source fixes
    # and readiness handoffs. Exact-call review also joins all previous outcomes.
    $reservationPath = $root + '\records\selected-account-attempt-' + $Attempt + '.json'
    for ($prior = 1; $prior -lt $Attempt; $prior++) {
        Need ([IO.File]::Exists($root + '\records\selected-account-attempt-' + $prior + '.json'))
    }
    $reserved = $encoding.GetString((Read-Pinned $reservationPath 4096 $ReservationSha256)) | ConvertFrom-Json
    Need ($reserved.schema -ceq 'selected-account-attempt-v1' -and $reserved.attempt -eq $Attempt -and
        $reserved.group -ceq $group -and $reserved.nonce -ceq $plan.nonce -and
        $reserved.planSha256 -ceq $PlanSha256 -and $reserved.controllerSha256 -ceq $ControllerSha256 -and
        $reserved.invocationStartTicks -eq $callStart -and $reserved.productLaunchReservation -eq 1 -and
        $reserved.callerProcessReservation -eq 2 -and $reserved.controllerReservation -eq 1 -and
        $reserved.outerInvocationReservation -eq 1)
    Before 20

    $start = [Diagnostics.Stopwatch]::GetTimestamp()
    $plan.batchStartTicks = $start
    $plan.batchEndTicks = $start + 1800L * $frequency
    $plan.stopwatchFrequency = $frequency
    # Admission shares the outer epoch. Native completion is at most epoch + 160s.
    $workEnd = $start + 130L * $frequency
    $finalEnd = $workEnd + 10L * $frequency
    $controlPath = $root + '\control\' + $group + '-' + $plan.nonce + '.json'
    $controlHash = Write-NewJson $controlPath $plan
    $null = Read-Pinned $controlPath 262144 $controlHash
    $arguments = @('--supervisor', $group, $plan.nonce, $controlPath, $controlHash,
        $plan.batchEndTicks.ToString([Globalization.CultureInfo]::InvariantCulture),
        $workEnd.ToString([Globalization.CultureInfo]::InvariantCulture),
        $finalEnd.ToString([Globalization.CultureInfo]::InvariantCulture))
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $caller
    $info.Arguments = (($arguments | ForEach-Object { Quote-Argument $_ }) -join ' ')
    $info.WorkingDirectory = $root
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    # The admitted outer PowerShell is attached to an existing ordinary console.
    $info.CreateNoWindow = $false
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $info
    $status.failure = 'launch'
    Before 20
    Need ($child.Start())
    $started = $true
    $null = $child.Handle
    # Both streams must be empty; one asynchronous byte read per stream is enough
    # to observe EOF or reject output without retaining any provider diagnostics.
    $outByte = [byte[]]::new(1); $errByte = [byte[]]::new(1)
    $outRead = $child.StandardOutput.BaseStream.ReadAsync($outByte, 0, 1)
    $errRead = $child.StandardError.BaseStream.ReadAsync($errByte, 0, 1)
    $identity = [ordered]@{
        schema = 'confidential-native-created-role-v1'; group = $group; role = 'supervisor'
        nonce = $plan.nonce; admissionSha256 = $controlHash; pid = $child.Id
        createdFileTime = $child.StartTime.ToUniversalTime().ToFileTimeUtc()
        batchEndTicks = $plan.batchEndTicks; workEndTicks = $workEnd; finalEndTicks = $finalEnd
        noExperimentLive = $false
    }
    $identityTemporary = $receiptRoot + '\supervisor-identity.pending.json'
    $null = Write-NewJson $identityTemporary $identity
    [IO.File]::Move($identityTemporary, $receiptRoot + '\supervisor-identity.json')
    $status.failure = 'supervision'
    while ([Diagnostics.Stopwatch]::GetTimestamp() -lt $finalEnd) {
        if ($outRead.IsCompleted) { Need ($outRead.GetAwaiter().GetResult() -eq 0) }
        if ($errRead.IsCompleted) { Need ($errRead.GetAwaiter().GetResult() -eq 0) }
        if ($child.HasExited -and $outRead.IsCompleted -and $errRead.IsCompleted) {
            $closed = $true
            break
        }
        [Threading.Thread]::Sleep(10)
    }
    Need $closed
    Before 165
    $status.supervisorExited = $true
    $status.supervisorExitCode = $child.ExitCode
    $status.streamsClosed = $true
    $status.failure = 'terminal'
    $terminalPath = $receiptRoot + '\' + $group + '-terminal.json'
    # NativeCaller emits only this safe receipt after its worker, product, streams
    # and owned Job have drained. Do not collect product stdout or private inputs.
    $terminalFile = [IO.File]::OpenRead($terminalPath)
    try {
        Need ($terminalFile.Length -gt 0 -and $terminalFile.Length -le 4096)
        $reader = [IO.StreamReader]::new($terminalFile, $encoding, $false)
        try { $terminal = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    } finally { $terminalFile.Dispose() }
    Need ($terminal.schema -ceq 'confidential-native-case-v1' -and $terminal.slot -ceq $group -and
        $terminal.nonce -ceq $plan.nonce -and $terminal.protocolSha256 -ceq $plan.protocolSha256 -and
        $terminal.reservation -eq $false -and $terminal.scopedJobZero -eq $true -and $terminal.safeWorkerEof -eq $true)
    $status.ownedClosure = $true
    Need ($child.ExitCode -eq 0 -and $terminal.passed -eq $true -and $terminal.outcome -ceq 'Success' -and
        $terminal.protocolValid -eq $true -and $terminal.metadataValid -eq $true -and $terminal.stopAttempted -eq $false)
    Need ($terminal.apiRoute -cin @('Silent', 'Interactive'))
    if ($group -eq 'R6') { Need ($terminal.apiRoute -ceq 'Silent') }
    $status.passed = $true
    $status.failure = 'none'
} catch {
    # Never emit exceptions, command lines, environment, private inputs or raw output.
} finally {
    if ($started -and -not $closed) {
        $status.stopAttempted = $true
        try {
            if (-not $child.HasExited) { $child.Kill() }
            $remaining = [Math]::Max(0, [Math]::Min(5000,
                [Math]::Floor(165000 - 1000 * ([Diagnostics.Stopwatch]::GetTimestamp() - $callStart) / $frequency)))
            $stopped = $child.WaitForExit([int] $remaining)
            $status.supervisorExited = $stopped
        } catch { }
        # Parent exit/last-close Job termination is not evidence that the product
        # and worker drained. Any missing terminal leaves ownedClosure false.
    }
    if ($child) { $child.Dispose() }
    foreach ($pin in $pins) { $pin.Dispose() }
    if ($receiptRoot) {
        try {
            Before 170
            $null = Write-NewJson ($receiptRoot + '\controller-terminal.json') $status
            Before 170
        } catch { $status.passed = $false }
    }
}
if ($status.passed) { exit 0 }
exit 1

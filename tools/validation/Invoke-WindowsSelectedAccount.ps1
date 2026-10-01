# Source-only controller for the native R1/R6 product acceptance pair.
# An accepted real-effects protocol and exact input/call review precede activation.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PlanPath,
    [Parameter(Mandatory)][string] $PlanSha256,
    [Parameter(Mandatory)][ValidateRange(1, 4)][int] $Attempt
)

$ExecutionAdmitted = $false
if (-not $ExecutionAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v1'
$clock = [Diagnostics.Stopwatch]::StartNew()
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

function Read-Pinned([string] $Path, [int] $Maximum, [string] $ExpectedHash) {
    $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $pins.Add($file)
    Need ($file.Length -gt 0 -and $file.Length -le $Maximum)
    $bytes = [byte[]]::new([int] $file.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        Need ($clock.Elapsed.TotalSeconds -lt 20)
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

try {
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
    Need ($clock.Elapsed.TotalSeconds -lt 20)
    $null = Write-NewJson $reservationPath ([ordered]@{
        schema = 'selected-account-attempt-v1'; attempt = $Attempt; group = $group
        nonce = $plan.nonce; planSha256 = $PlanSha256; productLaunchReservation = 1
        callerProcessReservation = 2; controllerReservation = 1
    })

    $frequency = [Diagnostics.Stopwatch]::Frequency
    $start = [Diagnostics.Stopwatch]::GetTimestamp()
    $plan.batchStartTicks = $start
    $plan.batchEndTicks = $start + 1800L * $frequency
    $plan.stopwatchFrequency = $frequency
    # These are native deadlines only. Exact-call admission must separately bound
    # the complete outer invocation, including admission, stop and receipt cleanup.
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
            $stopped = $child.WaitForExit(5000)
            $status.supervisorExited = $stopped
        } catch { }
        # Parent exit/last-close Job termination is not evidence that the product
        # and worker drained. Any missing terminal leaves ownedClosure false.
    }
    if ($child) { $child.Dispose() }
    foreach ($pin in $pins) { $pin.Dispose() }
    if ($receiptRoot) {
        try { $null = Write-NewJson ($receiptRoot + '\controller-terminal.json') $status } catch { }
    }
}
if ($status.passed) { exit 0 }
exit 1

# Invoke once from the admitted existing Windows PowerShell console.
# Public helper compilation/loading and exact type/assembly admission precede use.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PlanPath,
    [Parameter(Mandatory)][string] $PlanSha256,
    [Parameter(Mandatory)][ValidateRange(1, 4)][int] $Attempt,
    [ValidateSet('Personal', 'Work')][string] $AccountRole = 'Personal',
    [Parameter(Mandatory)][string] $ControllerSha256,
    [Parameter(Mandatory)][Type] $CutoffType
)

$ExecutionAdmitted = $false
if (-not $ExecutionAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v3'
$accountPrefix = if ($AccountRole -ceq 'Work') { 'work-account' } else { 'selected-account' }
$primaryGroup = if ($AccountRole -ceq 'Work') { 'R7' } else { 'R1' }
$reuseGroup = if ($AccountRole -ceq 'Work') { 'R8' } else { 'R6' }
$frequency = [Diagnostics.Stopwatch]::Frequency
$lease = $null
$invoked = $false
$returned = $false
$originalExitCode = 125
$originalReturnTicks = 0L
$e0 = 0L
$receipt = $null
$pins = [Collections.Generic.List[IDisposable]]::new()
$passed = $false

function Need([bool] $Condition) {
    if (-not $Condition) { throw 'Selected-account original refused.' }
}

function Read-PinnedPublic([string] $Path, [int] $Maximum, [string] $ExpectedHash) {
    Need ($ExpectedHash -cmatch '\A[0-9a-f]{64}\z')
    $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $pins.Add($file)
    Need ($file.Length -gt 0 -and $file.Length -le $Maximum)
    $bytes = [byte[]]::new([int] $file.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $count = $file.Read($bytes, $offset, $bytes.Length - $offset)
        Need ($count -gt 0)
        $offset += $count
    }
    Need ($file.ReadByte() -eq -1)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    Need ($actual -ceq $ExpectedHash)
    return ,$bytes
}

try {
    # Exact-call admission pins this original source, the loaded helper artifact,
    # its single retained Type, current host/user/environment and private input.
    # This script does not compile/load a replacement helper or read selectors.
    Need ($AccountRole -cin @('Personal', 'Work') -and
        [Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -eq 'Desktop' -and
        $CutoffType.FullName -ceq 'SelectedAccountControllerCutoff' -and
        -not $CutoffType.Assembly.IsDynamic -and $frequency -gt 0)
    $consoleMethod = $CutoffType.GetMethod('HasExistingConsoleInput',
        [Reflection.BindingFlags]'Public, Static')
    Need ($null -ne $consoleMethod -and [bool] $consoleMethod.Invoke($null, $null))
    Need ($PSCommandPath -ceq ($root + '\control\Invoke-WindowsSelectedAccountOriginal.ps1') -and
        $PlanPath -ceq ($root + '\control\' + $accountPrefix + '-plan-' + $Attempt + '.json'))
    $controller = $root + '\control\Invoke-WindowsSelectedAccountCutoff.ps1'
    $null = Read-PinnedPublic $controller 65536 $ControllerSha256
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $plan = $encoding.GetString((Read-PinnedPublic $PlanPath 262144 $PlanSha256)) | ConvertFrom-Json
    $group = if ($Attempt % 2 -eq 1) { $primaryGroup } else { $reuseGroup }
    Need ($plan.schema -ceq 'confidential-native-account-admission-v1' -and $plan.group -ceq $group -and
        $plan.admitted -eq $true -and $plan.accountEffectsAccepted -eq $true -and
        $plan.nonce -cmatch '\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z')
    $receipt = $root + '\records\' + $group + '-' + $plan.nonce + '\original-terminal.json'
    Need (-not [IO.File]::Exists($receipt))
    # One original epoch precedes lease arming and the sole controller-script call.
    # Capture its original return and exit code before any cleanup or receipt I/O.
    $e0 = [Diagnostics.Stopwatch]::GetTimestamp()
    $lease = [Activator]::CreateInstance($CutoffType, [object[]] @([long] $e0))
    Need ($null -ne $lease -and $lease.Armed -and -not $lease.Failed)
    $global:LASTEXITCODE = 125
    $invoked = $true
    & $controller -PlanPath $PlanPath -PlanSha256 $PlanSha256 -Attempt $Attempt `
        -ControllerSha256 $ControllerSha256 -AccountRole $AccountRole -InvocationStartTicks $e0 -CutoffLease $lease
    $originalExitCode = $LASTEXITCODE
    $originalReturnTicks = [Diagnostics.Stopwatch]::GetTimestamp()
    $returned = $true
    Need ($originalExitCode -eq 0 -and $originalReturnTicks -ge $e0 -and
        ($originalReturnTicks - $e0) / $frequency -lt 180 -and
        $lease.Bound -and $lease.ExitObserved -and $lease.CleanupComplete -and
        -not $lease.Failed -and -not $lease.StopClaimed -and
        -not $lease.TerminationAttempted -and -not $lease.FallbackFired)
    $passed = $true
} catch {
    # Never export raw exceptions, provider text, environment or private inputs.
} finally {
    if ($null -ne $lease -and -not $lease.CleanupComplete) {
        try { $null = $lease.Finish($false) } catch { }
        $passed = $false
    }
    foreach ($pin in $pins) { $pin.Dispose() }
    if ($e0 -gt 0 -and $receipt) {
        try {
            Need (([Diagnostics.Stopwatch]::GetTimestamp() - $e0) / $frequency -lt 180)
            $safe = [ordered]@{
                schema = 'selected-account-original-v1'; attempt = $Attempt
                invocationStartTicks = $e0; stopwatchFrequency = $frequency
                invoked = $invoked; returned = $returned; originalExitCode = $originalExitCode
                originalReturnTicks = $originalReturnTicks; passed = $passed
                cutoffCleanupComplete = ($null -ne $lease -and $lease.CleanupComplete)
                cutoffFailed = ($null -eq $lease -or $lease.Failed)
                noExperimentLive = $false
            }
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($safe | ConvertTo-Json -Compress) + "`n")
            Need ($bytes.Length -le 4096)
            $file = [IO.File]::Open($receipt, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
            finally { $file.Dispose() }
            Need (([Diagnostics.Stopwatch]::GetTimestamp() - $e0) / $frequency -lt 180)
        } catch { $passed = $false }
    }
}
if ($passed) { exit 0 }
exit 1

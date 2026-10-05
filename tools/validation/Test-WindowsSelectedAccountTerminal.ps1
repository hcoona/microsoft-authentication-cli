# Two public state challenges in one credential-free, tool-owned PowerShell session.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Initialize', 'Challenge')][string] $Phase,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string] $Nonce
)
$ProbeAdmitted = $false
if (-not $ProbeAdmitted) { return }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$self = $null
$closed = $true
$passed = $false
$sameRunspace = $false
$sameProcess = $false
$unused = $false
$inputRedirected = $null
$pidObserved = 0
$sessionObserved = 0
$creationObserved = '0'
$start = [Diagnostics.Stopwatch]::GetTimestamp()
$frequency = [Diagnostics.Stopwatch]::Frequency
$ordinal = if ($Phase -ceq 'Initialize') { 1 } else { 2 }
function Need([bool] $Value) { if (-not $Value) { throw 'Terminal probe refused.' } }
try {
    Need ($frequency -gt 0 -and [Environment]::Is64BitProcess -and
        [Environment]::UserInteractive -and $Host.Name -ceq 'ConsoleHost' -and
        $PSVersionTable.PSEdition -ceq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1 -and
        [Threading.Thread]::CurrentThread.GetApartmentState() -eq [Threading.ApartmentState]::STA)
    $runspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
    Need ($null -ne $runspace)
    $self = [Diagnostics.Process]::GetCurrentProcess()
    $pidObserved = $self.Id
    $sessionObserved = $self.SessionId
    $creationObserved = $self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(
        [Globalization.CultureInfo]::InvariantCulture)
    Need ($pidObserved -eq $PID -and $pidObserved -gt 0 -and $sessionObserved -gt 0)
    $inputRedirected = [Console]::IsInputRedirected
    $unused = $true
    foreach ($name in @('AzureAuth108CutoffLoadAttempted', 'AzureAuth108CutoffType',
            'AzureAuth108PrivatePinsLoadAttempted', 'AzureAuth108PrivatePinsType')) {
        if ($null -ne (Get-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue)) {
            $unused = $false
        }
    }
    Need $unused
    if ($ordinal -eq 1) {
        Need ($null -eq (Get-Variable -Name AzureAuth108TerminalProbe -Scope Global -ErrorAction SilentlyContinue))
        # The runspace is borrowed, not created or disposed by this probe.
        New-Variable -Name AzureAuth108TerminalProbe -Scope Global -Option Constant -Value ([pscustomobject]@{
            nonce = $Nonce; runspace = $runspace; processPid = $pidObserved
            session = $sessionObserved; creationFileTime = $creationObserved
            startTicks = $start; frequency = $frequency; ordinal = 0
        })
    }
    $state = $global:AzureAuth108TerminalProbe
    Need ($state.nonce -ceq $Nonce -and $state.ordinal -eq ($ordinal - 1) -and
        $state.frequency -eq $frequency -and $start -ge $state.startTicks -and
        ($start - $state.startTicks) / $frequency -lt 30)
    $sameRunspace = [object]::ReferenceEquals($state.runspace, $runspace)
    $sameProcess = ($state.processPid -eq $pidObserved -and $state.session -eq $sessionObserved -and
        $state.creationFileTime -ceq $creationObserved)
    Need ($sameRunspace -and $sameProcess)
    $state.ordinal = $ordinal
    $passed = $true
} catch {
    # Never export exception text, identities of users/accounts, environment or diagnostics.
} finally {
    if ($null -ne $self) { try { $self.Dispose() } catch { $closed = $false } }
}
$returned = [Diagnostics.Stopwatch]::GetTimestamp()
$passed = $passed -and $closed -and $frequency -gt 0 -and $returned -ge $start -and
    ($returned - $start) / $frequency -lt 10
$invariant = [Globalization.CultureInfo]::InvariantCulture
$status = [pscustomobject]@{
    schema = 'selected-account-terminal-probe-v1'; phase = $Phase; nonce = $Nonce; ordinal = $ordinal
    passed = $passed; sameRunspaceReference = $sameRunspace; sameProcess = $sameProcess
    unusedLoadState = $unused; inputRedirected = $inputRedirected; allHandlesClosed = $closed
    processPid = $pidObserved; session = $sessionObserved; creationFileTime = $creationObserved
    startTicks = $start.ToString($invariant); returnTicks = $returned.ToString($invariant)
    stopwatchFrequency = $frequency.ToString($invariant)
} | ConvertTo-Json -Compress
if ([Text.Encoding]::UTF8.GetByteCount($status) -le 2048) {
    [Console]::WriteLine('AA108_TERMINAL_PROBE:' + $status)
}

# One public kernel-clock observation through the unchanged normal launcher.
[CmdletBinding()]
param(
    [ValidateSet('Controller')][string] $Mode,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string] $AuthoritySha256
)
$ClockObservationAdmitted = $false
if (-not $ClockObservationAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$watch = [Diagnostics.Stopwatch]::StartNew()
$root = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0187'
$held = [Collections.Generic.List[IDisposable]]::new()
$requested = 0L
$result = [ordered]@{
    schema = 'selected-account-kernel-clock-v1'; passed = $false
    authoritySha256 = $AuthoritySha256; failure = 'admission'
    tickBeforeMs = $null; tickAfterMs = $null; utc = $null
    controllerPid = $null; controllerCreationFileTime = $null; controllerSession = $null
    allHandlesClosed = $false; productStarted = $false; accountAccess = $false
}

function Need([bool] $Condition) { if (-not $Condition) { throw 'Clock observation refused.' } }
function Before([int] $Seconds = 20) { Need ($watch.Elapsed.TotalSeconds -lt $Seconds) }
function Hash-Bytes([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Read-Public([string] $Leaf, [string] $ExpectedHash) {
    Before
    Need ($Leaf -cin @('authority.json', 'Invoke-WindowsNamedGuardFixtures.ps1'))
    $path = $root + '\' + $Leaf
    for ($current = $path; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
        Need (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    }
    $file = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $held.Add($file)
    Need ($file.Length -gt 0 -and $file.Length -le 65536)
    $bytes = [byte[]]::new([int] $file.Length)
    Need ($script:requested + $bytes.Length + 1 -le 262144)
    $script:requested += $bytes.Length + 1
    Before
    Need ($file.Read($bytes, 0, $bytes.Length) -eq $bytes.Length)
    Before
    Need ($file.ReadByte() -eq -1 -and $file.Length -eq $bytes.Length -and
        (Hash-Bytes $bytes) -ceq $ExpectedHash)
    return ,$bytes
}

try {
    Need ($Mode -ceq 'Controller' -and $PSScriptRoot -ceq $root -and
        $PSCommandPath -ceq ($root + '\Invoke-WindowsNamedGuardFixtures.ps1') -and
        [Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -ceq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $authority = $utf8.GetString((Read-Public 'authority.json' $AuthoritySha256)) | ConvertFrom-Json
    Need ($authority.schema -ceq 'selected-account-kernel-clock-authority-v1' -and
        $authority.action -ceq '0187' -and $authority.hostRole -ceq 'designated-windows-interactive-host' -and
        $authority.controllerSha256 -cmatch '\A[0-9a-f]{64}\z')
    $null = Read-Public 'Invoke-WindowsNamedGuardFixtures.ps1' $authority.controllerSha256
    $result.failure = 'compiler'
    # This is one existing Framework helper compilation, with no observer or ETW API.
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class SelectedAccountKernelClock
{
    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern ulong GetTickCount64();
}
'@ -Language CSharp -ErrorAction Stop
    Before
    $result.failure = 'clock'
    $first = [SelectedAccountKernelClock]::GetTickCount64()
    $utc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $last = [SelectedAccountKernelClock]::GetTickCount64()
    Need ($last -ge $first -and $last - $first -le 1000)
    # Decimal strings preserve the full native counter across JSON transports.
    $result.tickBeforeMs = $first.ToString([Globalization.CultureInfo]::InvariantCulture)
    $result.tickAfterMs = $last.ToString([Globalization.CultureInfo]::InvariantCulture)
    $result.utc = $utc
    $self = [Diagnostics.Process]::GetCurrentProcess()
    $held.Add($self)
    $result.controllerPid = $self.Id
    $result.controllerCreationFileTime = $self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(
        [Globalization.CultureInfo]::InvariantCulture)
    $result.controllerSession = $self.SessionId
    Before
    $result.failure = $null
    $result.passed = $true
} catch {
    # Only a fixed phase is retained; no exception text or platform diagnostics.
} finally {
    $closed = $true
    while ($held.Count -gt 0) {
        $lastIndex = $held.Count - 1; $item = $held[$lastIndex]; $held.RemoveAt($lastIndex)
        try { $item.Dispose() } catch { $closed = $false }
    }
    $result.allHandlesClosed = $closed
    $result.passed = $result.passed -and $closed -and $watch.Elapsed.TotalSeconds -lt 25
}

try {
    Before 30
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Depth 4 -Compress) + "`n")
    Need ($bytes.Length -le 8192)
    $receipt = [IO.File]::Open(($root + '\clock-result.json'), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $receipt.Write($bytes, 0, $bytes.Length); $receipt.Flush($true) }
    finally { $receipt.Dispose() }
    Before 30
} catch { exit 1 }
if ($result.passed) { exit 0 }
exit 1

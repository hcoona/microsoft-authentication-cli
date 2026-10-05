# Load once in the independently admitted existing ordinary PowerShell process.
# Actual compilation/materialization and exact loader/source/input/call review precede use.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][int] $ExpectedPid,
    [Parameter(Mandatory)][int] $ExpectedSession,
    [Parameter(Mandatory)][long] $ExpectedCreationFileTime,
    [Parameter(Mandatory)][ValidateRange(1, 1048576)][int] $ExpectedLibraryLength,
    [Parameter(Mandatory)][ValidatePattern("\A[0-9a-f]{64}\z")][string] $ExpectedLibrarySha256
)
$LoadingAdmitted = $false
if (-not $LoadingAdmitted) { return }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$libraryPath = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v5\control\SelectedAccountPrivateInputPins.dll'
$libraryLength = $ExpectedLibraryLength
$libraryHash = $ExpectedLibrarySha256
$watch = [Diagnostics.Stopwatch]::StartNew()
$file = $null
$self = $null
$loaded = $false
$closed = $true
$passed = $false
$readRequests = 0
$requestedReadBytes = 0L
function Need([bool] $Condition) { if (-not $Condition) { throw 'Cutoff loading refused.' } }
function Before { Need ($watch.Elapsed.TotalSeconds -lt 25) }
function Charge-Read([int] $Count) {
    Before
    Need ($Count -gt 0 -and $readRequests -lt 512 -and $requestedReadBytes + $Count -le 4194304)
    $script:readRequests++
    $script:requestedReadBytes += $Count
}
try {
    Before
    Need ([Environment]::Is64BitProcess -and [Environment]::UserInteractive -and
        $PSVersionTable.PSEdition -ceq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1 -and
        $PID -eq $ExpectedPid)
    $self = [Diagnostics.Process]::GetCurrentProcess()
    Need ($self.Id -eq $ExpectedPid -and $self.SessionId -eq $ExpectedSession -and
        $self.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $ExpectedCreationFileTime)
    # A constant attempt marker refuses a second load in this same process,
    # including after a partially successful load or failed finalization.
    Need ($null -eq (Get-Variable -Name AzureAuth108PrivatePinsLoadAttempted -Scope Global -ErrorAction SilentlyContinue) -and
        $null -eq (Get-Variable -Name AzureAuth108PrivatePinsType -Scope Global -ErrorAction SilentlyContinue))
    $assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
    Need ($assemblies.Length -le 512)
    foreach ($assembly in $assemblies) {
        Before
        Need ($null -eq $assembly.GetType('SelectedAccountPrivateInputPins', $false, $false))
    }
    New-Variable -Name AzureAuth108PrivatePinsLoadAttempted -Scope Global -Option Constant -Value $true
    for ($current = $libraryPath; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
        Before
        Need (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    }
    $file = [IO.File]::Open($libraryPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    Need ($file.Length -eq $libraryLength)
    $bytes = [byte[]]::new($libraryLength)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        Before
        Charge-Read ($bytes.Length - $offset)
        $used = $file.Read($bytes, $offset, $bytes.Length - $offset)
        Need ($used -gt 0)
        $offset += $used
    }
    Before
    Charge-Read 1
    Need ($file.ReadByte() -eq -1 -and $file.Length -eq $libraryLength)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actualHash = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    Need ($actualHash -ceq $libraryHash)
    Before
    # Load precisely the checked in-memory image once. No constructor or helper method runs.
    $assembly = [Reflection.Assembly]::Load($bytes)
    $loaded = $true
    $type = $assembly.GetType('SelectedAccountPrivateInputPins', $true, $false)
    Need ($type.FullName -ceq 'SelectedAccountPrivateInputPins' -and
        -not $assembly.IsDynamic -and [object]::ReferenceEquals($type.Assembly, $assembly))
    # A global constant strongly retains the one exact runtime Type for all later calls.
    New-Variable -Name AzureAuth108PrivatePinsType -Scope Global -Option Constant -Value $type
    Need ([object]::ReferenceEquals($global:AzureAuth108PrivatePinsType, $type))
    Before
    $passed = $true
} catch {
    # Retain the attempt marker/Type if created. Never print loader text or try another load.
} finally {
    if ($null -ne $file) { try { $file.Dispose() } catch { $closed = $false } }
    if ($null -ne $self) { try { $self.Dispose() } catch { $closed = $false } }
    $passed = $passed -and $closed -and $watch.Elapsed.TotalSeconds -lt 30
}
# This small public status cannot admit a lease, console method, private inputs or accounts.
[pscustomobject]@{
    schema = 'selected-account-private-pins-load-v1'; passed = $passed
    loaded = $loaded; allHandlesClosed = $closed
    sameTypeRetained = ($null -ne (Get-Variable -Name AzureAuth108PrivatePinsType -Scope Global -ErrorAction SilentlyContinue))
    processPid = $ExpectedPid; session = $ExpectedSession; creationFileTime = $ExpectedCreationFileTime
    libraryBytes = $libraryLength; librarySha256 = $libraryHash
    elapsedMilliseconds = $watch.ElapsedMilliseconds
    readRequests = $readRequests; requestedReadBytes = $requestedReadBytes
    accountAccess = $false; productStarted = $false; leaseCreated = $false
} | ConvertTo-Json -Compress

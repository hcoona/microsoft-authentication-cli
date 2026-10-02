# Public compile-only preparation through the unchanged normal0070 launcher.
[CmdletBinding()]
param(
    [ValidateSet('Controller')][string] $Mode,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string] $AuthoritySha256
)
$CutoffCompilationAdmitted = $false
if (-not $CutoffCompilationAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0188'
$watch = [Diagnostics.Stopwatch]::StartNew()
$held = [Collections.Generic.List[IDisposable]]::new()
$requested = 0L
$result = [ordered]@{
    schema = 'selected-account-cutoff-compilation-v1'; passed = $false
    authoritySha256 = $AuthoritySha256; sourceSha256 = $null; artifactSha256 = $null
    artifactBytes = 0; allHandlesClosed = $false; failure = 'admission'
    controllerPid = 0; controllerCreationFileTime = $null; controllerSession = -1
    productStarted = $false; accountAccess = $false; leaseCreated = $false
}

function Need([bool] $Condition) { if (-not $Condition) { throw 'Cutoff preparation refused.' } }
function Before([int] $Seconds = 20) { Need ($watch.Elapsed.TotalSeconds -lt $Seconds) }
function Hash-Bytes([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Read-Public([string] $Leaf, [int] $Maximum, [string] $ExpectedHash) {
    Before
    Need ($Leaf -cin @('authority.json', 'Invoke-WindowsNamedGuardFixtures.ps1',
        'SelectedAccountControllerCutoff.cs', 'cutoff.generated.dll', 'SelectedAccountControllerCutoff.dll'))
    $path = $root + '\' + $Leaf
    for ($current = $path; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
        Need (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    }
    $file = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $held.Add($file)
    Need ($file.Length -gt 0 -and $file.Length -le $Maximum)
    $bytes = [byte[]]::new([int] $file.Length)
    Need ($script:requested + $bytes.Length + 1 -le 4194304)
    $script:requested += $bytes.Length + 1
    Before
    Need ($file.Read($bytes, 0, $bytes.Length) -eq $bytes.Length)
    Before
    Need ($file.ReadByte() -eq -1 -and $file.Length -eq $bytes.Length)
    if ($ExpectedHash) {
        Need ($ExpectedHash -cmatch '\A[0-9a-f]{64}\z' -and (Hash-Bytes $bytes) -ceq $ExpectedHash)
    }
    return ,$bytes
}

try {
    Need ($Mode -ceq 'Controller' -and $PSScriptRoot -ceq $root -and
        $PSCommandPath -ceq ($root + '\Invoke-WindowsNamedGuardFixtures.ps1') -and
        [Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -ceq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $authority = $encoding.GetString((Read-Public 'authority.json' 65536 $AuthoritySha256)) | ConvertFrom-Json
    Need ($authority.schema -ceq 'selected-account-cutoff-compilation-authority-v1' -and
        $authority.action -ceq '0188' -and $authority.hostRole -ceq 'designated-windows-interactive-host' -and
        $authority.controllerSha256 -cmatch '\A[0-9a-f]{64}\z' -and
        $authority.sourceSha256 -cmatch '\A[0-9a-f]{64}\z')
    $null = Read-Public 'Invoke-WindowsNamedGuardFixtures.ps1' 65536 $authority.controllerSha256
    $sourceBytes = Read-Public 'SelectedAccountControllerCutoff.cs' 65536 $authority.sourceSha256
    $source = $encoding.GetString($sourceBytes)
    $result.sourceSha256 = $authority.sourceSha256
    # Process-local temporary paths also apply to the one compiler child.
    # The admitted launcher holds this fresh public root against rename/delete.
    Before
    $env:TEMP = $root
    $env:TMP = $root
    Need ([IO.Path]::GetTempPath() -ceq ($root + '\'))
    $generated = $root + '\cutoff.generated.dll'
    $artifact = $root + '\SelectedAccountControllerCutoff.dll'
    Need (-not [IO.File]::Exists($generated) -and -not [IO.File]::Exists($artifact))
    Before
    $result.failure = 'compiler'
    # Exactly one default Framework source batch/library compilation. No lease
    # constructor, console query, timer or native helper method is invoked here.
    Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly $generated -OutputType Library -ErrorAction Stop
    Before
    $result.failure = 'artifact'
    $bytes = Read-Public 'cutoff.generated.dll' 1048576 ''
    $digest = Hash-Bytes $bytes
    $file = [IO.File]::Open($artifact, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { Before; $file.Write($bytes, 0, $bytes.Length); $file.Flush($true); Before }
    finally { $file.Dispose() }
    $mirror = Read-Public 'SelectedAccountControllerCutoff.dll' 1048576 $digest
    Need ($mirror.Length -eq $bytes.Length)
    $result.artifactBytes = $bytes.Length
    $result.artifactSha256 = $digest
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
    # Fixed phase only; do not emit exceptions or compiler diagnostics.
} finally {
    $closed = $true
    while ($held.Count -gt 0) {
        $index = $held.Count - 1; $item = $held[$index]; $held.RemoveAt($index)
        try { $item.Dispose() } catch { $closed = $false }
    }
    $result.allHandlesClosed = $closed
    $result.passed = $result.passed -and $closed -and $watch.Elapsed.TotalSeconds -lt 25
}

try {
    Before 30
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Depth 4 -Compress) + "`n")
    Need ($bytes.Length -le 8192)
    $receipt = [IO.File]::Open(($root + '\cutoff-compilation-result.json'), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $receipt.Write($bytes, 0, $bytes.Length); $receipt.Flush($true) }
    finally { $receipt.Dispose() }
    Before 30
} catch { exit 1 }
if ($result.passed) { exit 0 }
exit 1

# Source-only diagnosis of one public runtime file under the existing normal Job launcher.
[CmdletBinding()]
param(
    [ValidateSet('Controller')][string] $Mode,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string] $AuthoritySha256
)
$PreparationAdmitted = $false
if (-not $PreparationAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$watch = [Diagnostics.Stopwatch]::StartNew()
$stage = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0194'
$sourcePath = 'C:\Temp\azureauth-windows-slice-108\confidential-checks-v23\toolchain\shared\Microsoft.NETCore.App\10.0.12\System.Collections.NonGeneric.dll'
$target = 'C:\Temp\azureauth-windows-slice-108\public-copy-diagnosis-0194'
$sourceBytes = 104232L
$sourceSha256 = 'aa4d5216d066c91cb489f63c6cbfcaf1f47b6e74e070db45639d3460454fc60b'
$pins = $null
$bootstrap = [Collections.Generic.List[IDisposable]]::new()
$bootstrapReads = 0L
$bootstrapRequestedReadBytes = 0L
$wrapperPhase = 0
$result = [ordered]@{
    schema = 'selected-account-single-copy-diagnosis-v1'; passed = $false
    authoritySha256 = $AuthoritySha256; failure = 'admission'; copyCompleted = $false
    allHandlesClosed = $false; noExperimentLive = $false
    productStarted = $false; accountAccess = $false; diagnostic = $null
}

function Need([bool] $Condition) { if (-not $Condition) { throw 'Public diagnosis refused.' } }
function Before([int] $Seconds = 300) { Need ($watch.Elapsed.TotalSeconds -lt $Seconds) }
function Hash-Bytes([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Bootstrap-Read([string] $Leaf, [int] $Maximum, [string] $Hash) {
    Before
    Need ($Leaf -cin @('authority.json', 'Invoke-WindowsNamedGuardFixtures.ps1', 'SelectedAccountMaterializationPins.cs'))
    $path = $stage + '\' + $Leaf
    for ($current = $path; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
        Need (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    }
    $file = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $bootstrap.Add($file)
    Need ($file.Length -gt 0 -and $file.Length -le $Maximum)
    $bytes = [byte[]]::new([int] $file.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        Before
        $request = $bytes.Length - $offset
        Need ($bootstrapReads -lt 8192 -and $bootstrapRequestedReadBytes + $request -le 8388608)
        $script:bootstrapReads++; $script:bootstrapRequestedReadBytes += $request
        $count = $file.Read($bytes, $offset, $request)
        Need ($count -gt 0); $offset += $count
    }
    Before
    Need ($bootstrapReads -lt 8192 -and $bootstrapRequestedReadBytes + 1 -le 8388608)
    $script:bootstrapReads++; $script:bootstrapRequestedReadBytes++
    Need ($file.ReadByte() -eq -1 -and $file.Length -eq $bytes.Length -and (Hash-Bytes $bytes) -ceq $Hash)
    return ,$bytes
}

try {
    Need ($Mode -ceq 'Controller' -and $PSScriptRoot -ceq $stage -and
        $PSCommandPath -ceq ($stage + '\Invoke-WindowsNamedGuardFixtures.ps1') -and
        [Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -ceq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $authority = $utf8.GetString((Bootstrap-Read 'authority.json' 65536 $AuthoritySha256)) | ConvertFrom-Json
    Need ($authority.schema -ceq 'selected-account-single-copy-authority-v1' -and
        $authority.action -ceq '0194' -and $authority.target -ceq $target -and
        $authority.sourcePath -ceq $sourcePath -and $authority.sourceBytes -eq $sourceBytes -and
        $authority.sourceSha256 -ceq $sourceSha256 -and $authority.publicSourceAccepted -eq $true -and
        $authority.controllerSha256 -cmatch '\A[0-9a-f]{64}\z' -and
        $authority.nativeSourceSha256 -cmatch '\A[0-9a-f]{64}\z')
    $null = Bootstrap-Read 'Invoke-WindowsNamedGuardFixtures.ps1' 65536 $authority.controllerSha256
    $source = Bootstrap-Read 'SelectedAccountMaterializationPins.cs' 32768 $authority.nativeSourceSha256
    $result.failure = 'native-source'
    Add-Type -TypeDefinition $utf8.GetString($source) -Language CSharp -ErrorAction Stop
    Before
    $pins = [SelectedAccountMaterializationPins]::new([Action] { Before })
    $pins.HoldDirectory($stage)
    $result.failure = 'create'
    $pins.CreateDirectoryExclusive($target)
    $result.failure = 'copy'; $wrapperPhase = 1
    $null = $pins.Copy($sourcePath, ($target + '\System.Collections.NonGeneric.dll'), $sourceBytes, $sourceSha256)
    $result.copyCompleted = $true; $wrapperPhase = 2
    $pins.CheckAll(); Before
    $wrapperPhase = 3; $result.passed = $true; $result.failure = 'none'
} catch {
    if ($null -ne $pins) { $pins.RecordManagedFault($_.Exception.HResult) }
    # Only fixed numeric context is recorded; no exception, file content or identity value.
} finally {
    if ($null -ne $pins) {
        $result.diagnostic = [ordered]@{
            wrapperPhase = $wrapperPhase; nativePhase = $pins.phase; heldOrdinal = $pins.heldOrdinal
            errorKind = $pins.errorKind; errorCode = $pins.errorCode
            identityMismatchMask = $pins.identityMismatchMask; snapshotMismatchMask = $pins.snapshotMismatchMask
            opens = $pins.opens; metadata = $pins.metadata; reads = $pins.reads; writes = $pins.writes
            requestedReadBytes = $pins.requestedReadBytes; writtenBytes = $pins.writtenBytes
        }
    }
    $closed = $true
    if ($null -ne $pins) { try { $pins.Dispose() } catch { $closed = $false } }
    while ($bootstrap.Count -gt 0) {
        $last = $bootstrap.Count - 1; $file = $bootstrap[$last]; $bootstrap.RemoveAt($last)
        try { $file.Dispose() } catch { $closed = $false }
    }
    $result.allHandlesClosed = $closed
    $result.passed = $result.passed -and $closed -and $watch.Elapsed.TotalSeconds -lt 310
}

try {
    Before 320
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Depth 6 -Compress) + "`n")
    Need ($bytes.Length -le 4096)
    $receipt = [IO.File]::Open(($stage + '\materialization-result.json'), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $receipt.Write($bytes, 0, $bytes.Length); $receipt.Flush($true) }
    finally { $receipt.Dispose() }
    Before 320
} catch { exit 1 }
if ($result.passed) { exit 0 }
exit 1

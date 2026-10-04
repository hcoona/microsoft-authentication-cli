# Materialize three cutoff controls using the unchanged normal 0070 launcher.
# It is copied to that launcher's fixed controller filename only after admission.
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
$stage = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0213'
$libraryDonor = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0188'
$target = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v5'
$pins = $null
$bootstrap = [Collections.Generic.List[IDisposable]]::new()
$bootstrapReads = 0L
$bootstrapRequestedReadBytes = 0L
$copyOrdinal = 0
$completedCopies = 0
$wrapperPhase = 0
$result = [ordered]@{
    schema = 'selected-account-cutoff-public-materialization-v1'; passed = $false
    authoritySha256 = $AuthoritySha256; target = $target; rows = @()
    failure = 'admission'; allHandlesClosed = $false; noExperimentLive = $false
    productStarted = $false; accountAccess = $false; diagnostic = $null; loaderSource = $null
}

function Need([bool] $Condition) { if (-not $Condition) { throw 'Public preparation refused.' } }
function Before([int] $Seconds = 300) { Need ($watch.Elapsed.TotalSeconds -lt $Seconds) }
function Hash-Bytes([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Charge-BootstrapRead([int] $Bytes) {
    Before
    Need ($Bytes -gt 0 -and $bootstrapReads -lt 8192 -and
        $bootstrapRequestedReadBytes + $Bytes -le 8388608)
    $script:bootstrapReads++
    $script:bootstrapRequestedReadBytes += $Bytes
}
function Bootstrap-Read([string] $Leaf, [int] $Maximum, [string] $Hash) {
    Before
    Need ($Leaf -cmatch '\A[a-zA-Z0-9.-]+\z')
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
        Charge-BootstrapRead $request
        $count = $file.Read($bytes, $offset, $request)
        Need ($count -gt 0); $offset += $count
    }
    Charge-BootstrapRead 1
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
    Need ($authority.schema -ceq 'selected-account-cutoff-public-materialization-authority-v1' -and
        $authority.action -ceq '0213' -and $authority.target -ceq $target -and
        $authority.libraryDonor -ceq $libraryDonor -and
        $authority.compilationAccepted -eq $true -and $authority.publicRootAccepted -eq $true -and
        $authority.libraryBytes -eq 10240 -and
        $authority.librarySha256 -ceq 'fbc44808765c99086c35d23c245c7c42db2cb9760c60912a7f71b6ecfd2afb64')
    $null = Bootstrap-Read 'Invoke-WindowsNamedGuardFixtures.ps1' 65536 $authority.controllerSha256
    $source = Bootstrap-Read 'SelectedAccountMaterializationPins.cs' 32768 $authority.nativeSourceSha256
    $result.failure = 'native-source'
    # Reuse the exact accepted public file-check source and existing default compiler.
    # Do not load the cutoff library, construct a lease or start a product/caller.
    Add-Type -TypeDefinition $utf8.GetString($source) -Language CSharp -ErrorAction Stop
    Before
    $pins = [SelectedAccountMaterializationPins]::new([Action] { Before })
    $pins.HoldDirectory($stage); $pins.HoldDirectory($libraryDonor)
    $pins.HoldDirectory($target + '\control')
    Need ($authority.loaderBytes -gt 0 -and $authority.loaderBytes -le 65536 -and
        $authority.loaderSha256 -cmatch '\A[0-9a-f]{64}\z')
    $loader = $pins.Pin(($stage + '\Initialize-WindowsSelectedAccountCutoffLoad.ps1'),
        [long] $authority.loaderBytes, $authority.loaderSha256)
    $result.loaderSource = [ordered]@{ name = 'Initialize-WindowsSelectedAccountCutoffLoad.ps1'
        bytes = [long] $authority.loaderBytes; sha256 = $authority.loaderSha256; identity = $loader.identity }
    $copies = @(
        [pscustomobject]@{ source = $libraryDonor + '\SelectedAccountControllerCutoff.dll'
            relative = 'control\SelectedAccountControllerCutoff.dll'; bytes = 10240L
            sha256 = $authority.librarySha256; role = 'cutoff-library' },
        [pscustomobject]@{ source = $stage + '\Invoke-WindowsSelectedAccountCutoff.ps1'
            relative = 'control\Invoke-WindowsSelectedAccountCutoff.ps1'; bytes = [long] $authority.cutoffBytes
            sha256 = $authority.cutoffSha256; role = 'cutoff-controller' },
        [pscustomobject]@{ source = $stage + '\Invoke-WindowsSelectedAccountOriginal.ps1'
            relative = 'control\Invoke-WindowsSelectedAccountOriginal.ps1'; bytes = [long] $authority.originalBytes
            sha256 = $authority.originalSha256; role = 'original-controller' }
    )
    Need ($copies.Count -eq 3 -and ($copies | Measure-Object -Property bytes -Sum).Sum -le 1048576)
    foreach ($copy in $copies) {
        Need ($copy.bytes -gt 0 -and $copy.bytes -le 65536 -and
            $copy.sha256 -cmatch '\A[0-9a-f]{64}\z')
    }
    $result.failure = 'copy'
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($copy in $copies) {
        $copyOrdinal++; $wrapperPhase = 1; $pins.SetPhase(0)
        Before
        $held = $pins.Copy($copy.source, ($target + '\' + $copy.relative), $copy.bytes, $copy.sha256)
        $wrapperPhase = 2; $pins.SetPhase(500)
        $rows.Add([pscustomobject]@{ relative = $copy.relative; bytes = $copy.bytes
            sha256 = $copy.sha256; identity = $held.identity; sourceIdentity = $held.sourceIdentity; role = $copy.role })
        $completedCopies++
    }
    $copyOrdinal = 0; $wrapperPhase = 3
    $pins.CheckAll(); $wrapperPhase = 4; Before
    $result.rows = $rows.ToArray()
    $result.counts = [ordered]@{ opens = $pins.opens; metadata = $pins.metadata; reads = $pins.reads
        writes = $pins.writes; requestedReadBytes = $pins.requestedReadBytes; writtenBytes = $pins.writtenBytes
        bootstrapReads = $bootstrapReads; bootstrapRequestedReadBytes = $bootstrapRequestedReadBytes }
    $result.passed = $true; $result.failure = 'none'
} catch {
    if ($null -ne $pins) { $pins.RecordManagedFault($_.Exception.HResult) }
    # Fixed numeric context only; no exception text, paths or payload/private data.
} finally {
    if ($null -ne $pins) {
        $result.diagnostic = [ordered]@{ copyOrdinal = $copyOrdinal; completedCopies = $completedCopies
            wrapperPhase = $wrapperPhase; nativePhase = $pins.phase; heldOrdinal = $pins.heldOrdinal
            errorKind = $pins.errorKind; errorCode = $pins.errorCode
            identityMismatchMask = $pins.identityMismatchMask
            snapshotMismatchMask = $pins.snapshotMismatchMask
            outputStage = $pins.outputStage; firstReadChangeCount = $pins.firstReadChangeCount
            sealedOutputs = $pins.sealedOutputs
            outputChangeTimeDifferenceCount = $pins.outputChangeTimeDifferenceCount
            opens = $pins.opens; metadata = $pins.metadata; reads = $pins.reads; writes = $pins.writes
            requestedReadBytes = $pins.requestedReadBytes; writtenBytes = $pins.writtenBytes }
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

# A result is provisional until timely original return and launcher Job/EOF closure
# are independently accepted. This one receipt does not grant account execution.
try {
    Before 320
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Depth 12 -Compress) + "`n")
    Need ($bytes.Length -le 262144)
    $receipt = [IO.File]::Open(($stage + '\cutoff-materialization-result.json'), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $receipt.Write($bytes, 0, $bytes.Length); $receipt.Flush($true) }
    finally { $receipt.Dispose() }
    Before 320
} catch { exit 1 }
if ($result.passed) { exit 0 }
exit 1

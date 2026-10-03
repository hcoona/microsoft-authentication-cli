# Public preparation adapter for the unchanged normal 0070 launcher.
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
$stage = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0193'
$donor = 'C:\Temp\azureauth-windows-slice-108\confidential-checks-v23'
$target = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v2'
$pins = $null
$bootstrap = [Collections.Generic.List[IDisposable]]::new()
$bootstrapReads = 0L
$bootstrapRequestedReadBytes = 0L
$copyOrdinal = 0
$completedCopies = 0
$wrapperPhase = 0
$result = [ordered]@{
    schema = 'selected-account-public-materialization-v3'; passed = $false
    authoritySha256 = $AuthoritySha256; target = $target; rows = @()
    failure = 'admission'; allHandlesClosed = $false; noExperimentLive = $false
    productStarted = $false; accountAccess = $false; diagnostic = $null
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
    Need ($authority.schema -ceq 'selected-account-public-preparation-authority-v2' -and
        $authority.action -ceq '0193' -and $authority.target -ceq $target -and
        $authority.donor -ceq $donor -and $authority.productContextAccepted -eq $true -and
        $authority.callerSourceCommit -cmatch '\A[0-9a-f]{40}\z' -and
        $authority.callerRootSourceSha256 -ceq '5a5340432ddc83b454c1889442f80afccc1bf58d293a75034fa572fb2e1550f4')
    $null = Bootstrap-Read 'Invoke-WindowsNamedGuardFixtures.ps1' 65536 $authority.controllerSha256
    $source = Bootstrap-Read 'SelectedAccountMaterializationPins.cs' 32768 $authority.nativeSourceSha256
    $inventoryBytes = Bootstrap-Read 'caller-inventory.json' 65536 $authority.callerInventorySha256
    $inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
    Need ($inventory.schema -ceq 'selected-account-caller-materialization-v2' -and
        $inventory.sourceCommit -ceq $authority.callerSourceCommit -and $inventory.rows.Count -eq 194 -and
        ($authority.callerInventoryTotalBytes -is [int] -or $authority.callerInventoryTotalBytes -is [long]) -and
        $authority.callerInventoryTotalBytes -gt 0 -and $authority.callerInventoryTotalBytes -le 100663296 -and
        ($inventory.rows | Measure-Object -Property bytes -Sum).Sum -eq $authority.callerInventoryTotalBytes)
    $result.failure = 'native-source'
    # Compile only the public Win32 preparation type. The existing launcher Job
    # owns the shell and any compiler descendants; no product or caller is started.
    Add-Type -TypeDefinition $utf8.GetString($source) -Language CSharp -ErrorAction Stop
    Before
    $pins = [SelectedAccountMaterializationPins]::new([Action] { Before })
    $pins.HoldDirectory($stage); $pins.HoldDirectory($donor)
    $result.failure = 'create'
    $pins.CreateDirectoryExclusive($target)
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $copies = [Collections.Generic.List[object]]::new()
    foreach ($row in $inventory.rows) {
        Need ($row.relative -cmatch '\A(?:toolchain|source|control|artifact)\\[a-zA-Z0-9_.\\-]+\z' -and
            $paths.Add($row.relative) -and $row.bytes -gt 0 -and $row.bytes -le 67108864 -and
            $row.sha256 -cmatch '\A[0-9a-f]{64}\z')
        Need (-not $row.relative.StartsWith('artifact\', [StringComparison]::Ordinal) -or
            $row.relative -cin @('artifact\NativeCaller.exe', 'artifact\NativeCaller.dll',
                'artifact\NativeCaller.pdb', 'artifact\NativeCaller.deps.json', 'artifact\NativeCaller.runtimeconfig.json'))
        $copies.Add([pscustomobject]@{ source = $donor + '\' + $row.relative
            relative = $row.relative; bytes = [long] $row.bytes; sha256 = $row.sha256; role = 'caller' })
    }
    $public = @(
        @('Authentication.Cli.exe', 'product\Authentication.Cli.exe', 8885248,
            '02993d94c5145f32274a8763f27d632e2dcc8e6a06d257551b1501eed9689cc7', 'product'),
        @('msalruntime.dll', 'product\msalruntime.dll', 2949656,
            '9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79', 'product'),
        @('selected-account-profile.json', 'product\selected-account-profile.json', 568,
            'b7b26fb3bcedeca62087dc3818e858dd9184ca37dbc9eb0abcbd310a839a2c75', 'profile'),
        @('Invoke-WindowsSelectedAccount.ps1', 'control\Invoke-WindowsSelectedAccount.ps1',
            $authority.accountControllerBytes, $authority.accountControllerSha256, 'controller'),
        @('R1.template.json', 'control\R1.template.json', $authority.r1TemplateBytes, $authority.r1TemplateSha256, 'template'),
        @('R6.template.json', 'control\R6.template.json', $authority.r6TemplateBytes, $authority.r6TemplateSha256, 'template')
    )
    foreach ($row in $public) {
        Need ($paths.Add($row[1]))
        $copies.Add([pscustomobject]@{ source = $stage + '\' + $row[0]; relative = $row[1]
            bytes = [long] $row[2]; sha256 = $row[3]; role = $row[4] })
    }
    Need ($copies.Count -eq 200 -and ($copies | Measure-Object -Property bytes -Sum).Sum -le 100663296)
    foreach ($copy in $copies) {
        $parent = [IO.Path]::GetDirectoryName($target + '\' + $copy.relative)
        while ($parent -cne $target) {
            Need ($parent.StartsWith($target + '\', [StringComparison]::Ordinal))
            $null = $directories.Add($parent); $parent = [IO.Path]::GetDirectoryName($parent)
        }
    }
    $null = $directories.Add($target + '\records')
    Need ($directories.Count -le 64)
    foreach ($directory in ($directories | Sort-Object { $_.Length }, { $_ })) {
        $pins.CreateDirectoryExclusive($directory)
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
    $receipt = [IO.File]::Open(($stage + '\materialization-result.json'), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $receipt.Write($bytes, 0, $bytes.Length); $receipt.Flush($true) }
    finally { $receipt.Dispose() }
    Before 320
} catch { exit 1 }
if ($result.passed) { exit 0 }
exit 1

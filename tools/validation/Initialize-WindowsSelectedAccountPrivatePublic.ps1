# Public private-input helper and Work-template preparation through the unchanged normal0070 launcher.
[CmdletBinding()]
param(
    [ValidateSet('Controller')][string] $Mode,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string] $AuthoritySha256
)
$PrivatePublicPreparationAdmitted = $false
if (-not $PrivatePublicPreparationAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0216'
$artifactRoot = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0214'
$artifact = $artifactRoot + '\SelectedAccountPrivateInputPins.dll'
$watch = [Diagnostics.Stopwatch]::StartNew()
$held = [Collections.Generic.List[IDisposable]]::new()
$pins = $null
$target = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v5'
$requested = 0L
$result = [ordered]@{
    schema = 'selected-account-private-public-preparation-v1'; passed = $false
    authoritySha256 = $AuthoritySha256; sourceSha256 = $null; artifactSha256 = $null
    artifactBytes = 0; artifactInput = $null; compilerReused = $false
    allHandlesClosed = $false; failure = 'admission'
    controllerPid = 0; controllerCreationFileTime = $null; controllerSession = -1
    productStarted = $false; accountAccess = $false; leaseCreated = $false
    rootAnchor = $null; cutoffInputs = @(); cutoffFailure = $null
}

function Need([bool] $Condition) { if (-not $Condition) { throw 'Cutoff preparation refused.' } }
function Before([int] $Seconds = 90) { Need ($watch.Elapsed.TotalSeconds -lt $Seconds) }
function Hash-Bytes([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Read-Public([string] $Leaf, [int] $Maximum, [string] $ExpectedHash, [string] $SourceRoot = $root) {
    Before
    Need ($Leaf -cin @('authority.json', 'Invoke-WindowsNamedGuardFixtures.ps1',
        'SelectedAccountPrivateInputPins.cs', 'SelectedAccountPrivateInputPins.dll',
        'Initialize-WindowsSelectedAccountPrivate.ps1', 'Initialize-WindowsSelectedAccountPrivateLoad.ps1',
        'Invoke-WindowsSelectedAccountTimedOperation.ps1',
        'R7.template.json', 'R8.template.json'))
    Need ($SourceRoot -ceq $root -or ($SourceRoot -ceq $artifactRoot -and
        $Leaf -ceq 'SelectedAccountPrivateInputPins.dll' -and $Maximum -eq 15872 -and
        $ExpectedHash -ceq 'd70765f1608c6d2c92e5d4fcee2f903fa8c75bebc48dfa7e31a6e9dcebff1f62'))
    $path = $SourceRoot + '\' + $Leaf
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
    Need ($authority.schema -ceq 'selected-account-private-public-preparation-authority-v1' -and
        $authority.action -ceq '0216' -and $authority.hostRole -ceq 'designated-windows-interactive-host' -and
        $authority.target -ceq $target -and $authority.publicRootAccepted -eq $true -and
        $authority.cutoffMaterializationAccepted -eq $true -and
        $authority.controllerSha256 -cmatch '\A[0-9a-f]{64}\z' -and
        $authority.sourceSha256 -cmatch '\A[0-9a-f]{64}\z')
    $null = Read-Public 'Invoke-WindowsNamedGuardFixtures.ps1' 65536 $authority.controllerSha256
    $sourceBytes = Read-Public 'SelectedAccountPrivateInputPins.cs' 65536 $authority.sourceSha256
    $result.sourceSha256 = $authority.sourceSha256
    Need ($sourceBytes.Length -eq 24977 -and
        $authority.sourceSha256 -ceq '6fab7560138e865afa0d2423f6b07f7eb36d745d117de5adaded6135e08afd3b')
    # Keep process-local temporary work inside the fresh contained public root.
    Before
    $env:TEMP = $root
    $env:TMP = $root
    Need ([IO.Path]::GetTempPath() -ceq ($root + '\'))
    $result.failure = 'retained-artifact'
    Need ($authority.retainedArtifact.path -ceq $artifact -and $authority.retainedArtifact.bytes -eq 15872 -and
        $authority.retainedArtifact.sha256 -ceq 'd70765f1608c6d2c92e5d4fcee2f903fa8c75bebc48dfa7e31a6e9dcebff1f62' -and
        $authority.retainedArtifact.partialCompilerOutcomeSha256 -ceq
            '54e882b8d20bed5a1e5ca5e1354ce511c7319237942609823fd97828932e06b1')
    # One checked historical input, held without write/delete sharing. No compiler,
    # generated library, mirror write or occupied-stage repair is performed.
    $digest = $authority.retainedArtifact.sha256
    $bytes = Read-Public 'SelectedAccountPrivateInputPins.dll' 15872 $digest $artifactRoot
    Need ($bytes.Length -eq 15872)
    $result.artifactBytes = $bytes.Length
    $result.artifactSha256 = $digest

    # The checked-image bootstrap load is confined to this public child. Its first
    # native Pin establishes current artifact correspondence before target mutation.
    # No WritePrivate, selector, lease, account, product or provider method runs here.
    $assembly = [Reflection.Assembly]::Load($bytes)
    $type = $assembly.GetType('SelectedAccountPrivateInputPins', $true, $false)
    Need ($type.FullName -ceq 'SelectedAccountPrivateInputPins' -and -not $assembly.IsDynamic)
    $pins = [Activator]::CreateInstance($type, [object[]] @([Action] { Before }))
    $pins.HoldDirectory($root); $pins.HoldDirectory($target + '\control')
    $retained = $pins.Pin($artifact, 15872L, $digest)
    $result.artifactInput = [ordered]@{ path = $artifact; bytes = 15872L; sha256 = $digest
        identity = $retained.identity; historicalInput = $true; currentIdentityChecksStrict = $true }
    $result.compilerReused = $true
    $result.failure = 'root-anchor'
    Need ($authority.rootAnchorBytes -eq 17534 -and
        $authority.rootAnchorSha256 -ceq '38eb5dcc7b8951793cbe5445ca567ab7cf776547c3b99314e7131279095fb583')
    $anchor = $pins.Pin(($target + '\control\Invoke-WindowsSelectedAccount.ps1'),
        17534L, $authority.rootAnchorSha256)
    # Reuse the accepted destination anchor and ONLY its historical ChangeTime
    # qualification. Every fresh Pin/CheckAll comparison remains strict.
    $expectedAnchor = [SelectedAccountPrivateFileIdentity]::new()
    foreach ($field in @('volume', 'index', 'attributes', 'links', 'created', 'modified', 'length')) {
        $expectedAnchor.$field = $authority.rootAnchorIdentity.$field
    }
    $expectedAnchor.changed = $anchor.identity.changed
    Need ($anchor.identity.Same($expectedAnchor))
    $result.rootAnchor = [ordered]@{ relative = 'control\Invoke-WindowsSelectedAccount.ps1'
        bytes = 17534L; sha256 = $authority.rootAnchorSha256
        acceptedIdentity = $authority.rootAnchorIdentity; currentIdentity = $anchor.identity
        historicalChangeTimeQualified = $true; currentIdentityChecksStrict = $true }

    # Observe all four fixed inputs before their historical comparisons or mutation.
    # Pin retains strict current eight-field checks; no historical baseline is renewed.
    $result.failure = 'cutoff-inputs'
    $cutoffInputs = @(
        @('cutoff-library', ($target + '\control\SelectedAccountControllerCutoff.dll'), 10240L,
            'fbc44808765c99086c35d23c245c7c42db2cb9760c60912a7f71b6ecfd2afb64'),
        @('cutoff-controller', ($target + '\control\Invoke-WindowsSelectedAccountCutoff.ps1'), 20736L,
            '8d498b0b26a947a94d07534b369af3e1c1946aabe231487f9ff5a3d2091b8534'),
        @('original-controller', ($target + '\control\Invoke-WindowsSelectedAccountOriginal.ps1'), 6562L,
            '523b6f7a07de2a43f569e898ced0af5e289898c1a6640765be2bccf7243ba8bf'),
        @('cutoff-loader', 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0213\Initialize-WindowsSelectedAccountCutoffLoad.ps1',
            5337L, 'ae67d76cbea001f288527200dd6d1a7caeb8054888c83ec43e901840dafcca5d')
    )
    $result.cutoffFailure = [ordered]@{ ordinal = $null; role = $null; predicate = 'authority-count'; fields = @() }
    Need ($authority.cutoffInputs.Count -eq 4)
    $currentInputs = [Collections.Generic.List[object]]::new()
    for ($ordinal = 0; $ordinal -lt $cutoffInputs.Count; $ordinal++) {
        $inputRow = $cutoffInputs[$ordinal]; $accepted = $authority.cutoffInputs[$ordinal]
        $result.cutoffFailure = [ordered]@{ ordinal = $ordinal; role = $inputRow[0]
            predicate = 'authority-row'; fields = @() }
        Need ($accepted.role -ceq $inputRow[0] -and $accepted.path -ceq $inputRow[1] -and
            $accepted.bytes -eq $inputRow[2] -and $accepted.sha256 -ceq $inputRow[3])
        $result.cutoffFailure.predicate = 'pin'
        $current = $pins.Pin($inputRow[1], $inputRow[2], $inputRow[3])
        $mismatches = [Collections.Generic.List[string]]::new()
        foreach ($field in @('volume', 'index', 'attributes', 'links', 'created', 'modified', 'changed', 'length')) {
            if ($current.identity.$field -ne $accepted.identity.$field) { $mismatches.Add($field) }
        }
        $currentInputs.Add([pscustomobject]@{ role = $inputRow[0]; path = $inputRow[1]
            bytes = $inputRow[2]; sha256 = $inputRow[3]; acceptedIdentity = $accepted.identity
            currentIdentity = $current.identity; historicalMismatchFields = $mismatches.ToArray()
            historicalChangeTimeQualified = $false; currentIdentityChecksStrict = $true })
        # Retain successful observations even if a later Pin refuses.
        $result.cutoffInputs = $currentInputs.ToArray()
    }
    for ($ordinal = 0; $ordinal -lt $currentInputs.Count; $ordinal++) {
        $observed = $currentInputs[$ordinal]
        $blockingFields = @($observed.historicalMismatchFields | Where-Object { $_ -cne 'changed' })
        $result.cutoffFailure = [ordered]@{ ordinal = $ordinal; role = $observed.role
            predicate = 'historical-identity'; fields = $blockingFields }
        $expected = [SelectedAccountPrivateFileIdentity]::new()
        foreach ($field in @('volume', 'index', 'attributes', 'links', 'created', 'modified', 'length')) {
            $expected.$field = $observed.acceptedIdentity.$field
        }
        # Qualify only these four historical ChangeTime comparisons. Every fresh
        # Pin and CheckAll still compares all eight fields, including ChangeTime.
        $expected.changed = $observed.currentIdentity.changed
        Need ($observed.currentIdentity.Same($expected))
        $observed.historicalChangeTimeQualified = $true
    }
    $result.cutoffFailure = [ordered]@{ ordinal = $null; role = $null; predicate = 'final-current-checks'; fields = @() }
    $pins.CheckAll(); Before
    $result.cutoffFailure = $null
    $result.failure = 'copy'
    $pins.CreateDirectoryExclusive($target + '\private')
    $rows = [Collections.Generic.List[object]]::new()
    $copies = @(
        @('SelectedAccountPrivateInputPins.dll', $bytes.Length, $digest),
        @('Initialize-WindowsSelectedAccountPrivate.ps1', $authority.privateInitializerBytes, $authority.privateInitializerSha256),
        @('Initialize-WindowsSelectedAccountPrivateLoad.ps1', $authority.privateLoaderBytes, $authority.privateLoaderSha256),
        @('Invoke-WindowsSelectedAccountTimedOperation.ps1', $authority.timingCarrierBytes, $authority.timingCarrierSha256),
        @('R7.template.json', 746, 'c40c7d775cbf29fc800aff232bda74b079b84333c7d15bf3842b68d2f3c5f18c'),
        @('R8.template.json', 751, '07d03b9987297875e4cdfc7b7b11d0a70503259faf31624f30232c6815d876d0')
    )
    foreach ($copy in $copies) {
        Before
        Need ($copy[1] -gt 0 -and $copy[1] -le 1048576 -and $copy[2] -cmatch '\A[0-9a-f]{64}\z')
        $sourcePath = if ($copy[0] -ceq 'SelectedAccountPrivateInputPins.dll') { $artifact }
            else { $root + '\' + $copy[0] }
        $file = $pins.Copy($sourcePath, $target + '\control\' + $copy[0], $copy[1], $copy[2])
        $rows.Add([pscustomobject]@{ relative = 'control\' + $copy[0]; bytes = $copy[1]; sha256 = $copy[2]
            identity = $file.identity; sourceIdentity = $file.sourceIdentity })
    }
    $pins.CheckAll(); Before
    $result['rows'] = $rows.ToArray()
    $result['counts'] = [ordered]@{ requestedReadBytes = $pins.requestedReadBytes; writtenBytes = $pins.writtenBytes
        reads = $pins.reads; writes = $pins.writes; opens = $pins.opens; metadata = $pins.metadata
        bootstrapRequestedReadBytes = $requested }

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
    # Retain only the existing fixed numeric fault context for a native refusal.
    # No exception, path survey or raw diagnostic text enters the receipt.
    if ($null -ne $pins -and $null -ne $result.cutoffFailure -and
        $result.cutoffFailure.predicate -cin @('pin', 'final-current-checks')) {
        $result.cutoffFailure['native'] = [ordered]@{ phase = $pins.phase; heldOrdinal = $pins.heldOrdinal
            errorKind = $pins.errorKind; errorCode = $pins.errorCode
            identityMismatchMask = $pins.identityMismatchMask; snapshotMismatchMask = $pins.snapshotMismatchMask }
    }
} finally {
    $closed = $true
    if ($null -ne $pins) { try { $pins.Dispose() } catch { $closed = $false } }
    while ($held.Count -gt 0) {
        $index = $held.Count - 1; $item = $held[$index]; $held.RemoveAt($index)
        try { $item.Dispose() } catch { $closed = $false }
    }
    $result.allHandlesClosed = $closed
    $result.passed = $result.passed -and $closed -and $watch.Elapsed.TotalSeconds -lt 100
}

try {
    Before 110
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Depth 6 -Compress) + "`n")
    Need ($bytes.Length -le 32768)
    $receipt = [IO.File]::Open(($root + '\private-public-preparation-result.json'), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $receipt.Write($bytes, 0, $bytes.Length); $receipt.Flush($true) }
    finally { $receipt.Dispose() }
    Before 110
} catch { exit 1 }
if ($result.passed) { exit 0 }
exit 1

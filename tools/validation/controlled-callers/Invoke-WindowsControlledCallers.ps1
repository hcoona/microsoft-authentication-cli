# Inert controller adapter for the existing normal launcher; no account roles.
param(
    [ValidateSet('Controller')][string] $Mode,
    [ValidatePattern('^[0-9a-f]{64}$')][string] $AuthoritySha256
)
$ControlledCallersDraftOnly = $true
if ($ControlledCallersDraftOnly) { throw 'DRAFT_ONLY: controlled callers are not admitted' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2

$watch = [Diagnostics.Stopwatch]::StartNew()
$root = $PSScriptRoot
$stageRoot = 'C:\Temp\azureauth-windows-slice-108\confidential-checks-v7'
$rootBound = $false
$phase = 'authority'
$child = $null
$capture = $null
$captureSaved = $false
$phaseName = $null
$inputPins = [Collections.Generic.List[IO.FileStream]]::new()
$held = [Collections.Generic.Dictionary[string,IO.FileStream]]::new([StringComparer]::Ordinal)
$inputs = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$writtenNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$writeBytes = 0L
$readPayloadBytes = 0L
$readPasses = 0
$capturedTotal = 0L
$startsAttempted = 0
$targets = @('NativeCaller', 'DirectObserver', 'SyntheticSubject', 'FixtureDriver')
$result = [ordered]@{
    schema = 'controlled-callers-controller-result-v1'; authoritySha256 = $AuthoritySha256
    operation = $null; sourceCommit = $null; nonce = $null; phases = @(); apphosts = @()
    passed = $false; startsAttempted = 0; readPasses = 0; readPayloadBytes = 0
    writeBytesBeforeAggregate = 0; writeReservationsBeforeAggregate = 0; cancellationRequested = $false
    cancellationMarkerConfirmed = $false; failureType = $null; failureLine = $null
    finalizationFailureType = $null; phase = $phase; elapsedMilliseconds = 0
    artifactAccepted = $false; scenarioAccepted = $false
    scopedJobQuiescenceEstablished = $false; noExperimentLive = $false
}

function Assert-Time([long] $Limit) {
    if ($watch.ElapsedMilliseconds -ge $Limit) { throw 'Original controller deadline' }
    if (Test-Path -LiteralPath "$root\cancel") { throw 'Original invocation cancelled' }
}

function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked controlled path' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory }
        elseif ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        else { throw 'Nonfilesystem controlled path' }
    }
}

function Hash-Bytes([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Charge-Read([long] $Bytes) {
    $script:readPasses++
    $script:readPayloadBytes += $Bytes
    if ($readPasses -gt 512 -or $readPayloadBytes -gt 268435456) { throw 'Controller read bound' }
}

function Read-Held([IO.FileStream] $Stream, [int] $Maximum) {
    Assert-Time 60000
    if ($Stream.Length -lt 1 -or $Stream.Length -gt $Maximum) { throw 'Control length bound' }
    Charge-Read $Stream.Length
    $Stream.Position = 0
    $bytes = [byte[]]::new([int]$Stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        Assert-Time 60000
        $count = $Stream.Read($bytes, $offset, [Math]::Min(65536, $bytes.Length - $offset))
        if ($count -le 0) { throw 'Incomplete held control' }
        $offset += $count
    }
    if ($Stream.ReadByte() -ne -1 -or $Stream.Length -ne $bytes.Length) { throw 'Changed held control' }
    $Stream.Position = 0
    return ,$bytes
}

function Hold-Control([string] $Path, [int] $Maximum, [string] $Sha256) {
    Assert-Time 60000
    Assert-Direct $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    $inputPins.Add($stream)
    $bytes = Read-Held $stream $Maximum
    if ((Hash-Bytes $bytes) -cne $Sha256) { throw 'Changed admitted control' }
    Assert-Direct $Path
    return ,$bytes
}

function Pin-Input([string] $Relative, [long] $Length, [string] $Sha256) {
    Assert-Time 60000
    if ($Length -le 0 -or $Length -gt 67108864 -or $Sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Unbounded selected input'
    }
    $path = "$stageRoot\$Relative"
    Assert-Direct $path
    $stream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
    $inputPins.Add($stream)
    if ($stream.Length -ne $Length) { throw 'Changed selected length' }
    Charge-Read $Length
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $buffer = [byte[]]::new(65536)
        $total = 0L
        while ($total -lt $Length) {
            Assert-Time 60000
            $count = $stream.Read($buffer, 0, [int][Math]::Min(65536L, $Length - $total))
            if ($count -le 0) { throw 'Incomplete selected input' }
            [void]$hash.TransformBlock($buffer, 0, $count, $buffer, 0)
            $total += $count
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $Length) { throw 'Changed selected input' }
        [void]$hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
        if (([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant() -cne $Sha256) {
            throw 'Changed selected content'
        }
        Assert-Direct $path
        $stream.Position = 0
        $held.Add($Relative, $stream)
    } finally { $hash.Dispose() }
}

function Reserve-Write([string] $Name, [long] $Bytes) {
    if (-not $rootBound -or $watch.ElapsedMilliseconds -ge 325000 -or $Bytes -lt 0 -or
        -not $writtenNames.Add($Name) -or $writtenNames.Count -gt 36) { throw 'Exclusive output bound' }
    $script:writeBytes += $Bytes
    if ($writeBytes -gt 2097152) { throw 'Controller output payload bound' }
}

function Save-NewBytes([string] $Name, [byte[]] $Bytes, [int] $Maximum) {
    if ($Bytes.Length -gt $Maximum -or $Name -cnotmatch '^[a-z][a-z0-9.-]*$') { throw 'Output name or size' }
    Reserve-Write ('receipt/' + $Name) $Bytes.Length
    $path = "$root\$Name"
    $stream = [IO.File]::Open(($path + '.pending'), 'CreateNew', 'Write', 'Read')
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ($watch.ElapsedMilliseconds -ge 325000) { throw 'Original persistence deadline' }
    [IO.File]::Move(($path + '.pending'), $path)
}

function Save-NewJson([string] $Name, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12 -Compress) + "`n")
    Save-NewBytes $Name $bytes 32768
}

function Request-OriginalJobCancellation {
    if (-not $rootBound) { throw 'Cancellation root is unbound' }
    $script:result.cancellationRequested = $true
    try {
        Reserve-Write 'receipt/cancel' 0
        $stream = [IO.File]::Open("$root\cancel", 'CreateNew', 'Write', 'Read')
        try { $stream.Flush($true) } finally { $stream.Dispose() }
        $script:result.cancellationMarkerConfirmed = $true
    } catch [IO.IOException] {
        if (Test-Path -LiteralPath "$root\cancel") {
            Assert-Direct "$root\cancel"
            $item = Get-Item -LiteralPath "$root\cancel" -Force
            if ($item -is [IO.FileInfo] -and $item.Length -eq 0) { $script:result.cancellationMarkerConfirmed = $true }
        }
    }
}

function Receive-Child([long] $OriginalCutoff, [int] $Maximum) {
    $streams = @($child.StandardOutput.BaseStream, $child.StandardError.BaseStream)
    $request = 4096
    if ($Maximum -eq 0) { $request = 1 }
    $buffers = @([byte[]]::new($request), [byte[]]::new($request))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $tasks = @($streams[0].ReadAsync($buffers[0], 0, $request), $streams[1].ReadAsync($buffers[1], 0, $request))
    $done = @($false, $false)
    $disposition = 'read-failure'
    $unexpectedBytes = 0
    try {
        while (-not ($child.HasExited -and $done[0] -and $done[1])) {
            Assert-Time $OriginalCutoff
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true }
                    else {
                        if ($capturedTotal + $data[0].Length + $data[1].Length + $count -gt $Maximum) {
                            $unexpectedBytes = $count
                            $disposition = 'output-limit'; throw 'Controlled capture bound'
                        }
                        $data[$index].Write($buffers[$index], 0, $count)
                        $tasks[$index] = $streams[$index].ReadAsync($buffers[$index], 0, $request)
                    }
                }
            }
            Start-Sleep -Milliseconds 10
        }
        $disposition = 'complete'
    } finally {
        $script:capture = [pscustomobject]@{
            stdout = $data[0].ToArray(); stderr = $data[1].ToArray()
            stdoutEof = $done[0]; stderrEof = $done[1]; disposition = $disposition
            unexpectedReadBytes = $unexpectedBytes
        }
        $data[0].Dispose(); $data[1].Dispose()
    }
}

function Save-PhaseCapture {
    if ($null -eq $capture -or $captureSaved) { return }
    $script:captureSaved = $true
    Save-NewBytes ($phaseName + '.stdout.bin') $capture.stdout 65536
    Save-NewBytes ($phaseName + '.stderr.bin') $capture.stderr 65536
    $script:capturedTotal += $capture.stdout.Length + $capture.stderr.Length
}

function Invoke-SelectedChild([string] $Name, [string] $Executable, [string] $Arguments,
    [long] $OriginalCutoff, [int] $Maximum) {
    Assert-Time $OriginalCutoff
    $script:phaseName = $Name
    $script:phase = $Name + '-intent'
    $script:capture = $null
    $script:captureSaved = $false
    Save-NewJson ($Name + '-invocation.json') ([ordered]@{
        schema = 'controlled-callers-invocation-v1'; authoritySha256 = $AuthoritySha256
        executable = $Executable; arguments = $Arguments; workingDirectory = $stageRoot
        originalControllerCutoffMilliseconds = $OriginalCutoff; expectedExitCode = 0
        environmentMode = 'unchanged-normal-launcher-bootstrap'; phase = $Name
    })
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable; $info.Arguments = $Arguments; $info.WorkingDirectory = $stageRoot
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    # Inherit the already admitted normal launcher's bounded environment. No new
    # profile, runtime injection, shell, process kind, or environment survey.
    $script:child = [Diagnostics.Process]::new()
    $child.StartInfo = $info
    $script:startsAttempted++
    if ($startsAttempted -gt $(if ($result.operation -ceq 'compile') { 4 } else { 1 })) { throw 'Sole phase start bound' }
    Assert-Time $OriginalCutoff
    if (-not $child.Start() -or $child.Handle -eq [IntPtr]::Zero) { throw 'Controlled child start failed' }
    Save-NewJson ($Name + '-started.json') ([ordered]@{
        schema = 'controlled-callers-started-v1'; authoritySha256 = $AuthoritySha256; phase = $Name
        pid = $child.Id; creationFileTime = $child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        handleRetained = $true; creationMode = 'ordinary-child-without-breakaway'
    })
    $script:phase = $Name + '-capture'
    Receive-Child $OriginalCutoff $Maximum
    $outcome = [ordered]@{
        phase = $Name; exited = $child.HasExited; exitCode = $child.ExitCode
        stdoutEof = $capture.stdoutEof; stderrEof = $capture.stderrEof
        stdoutBytes = $capture.stdout.Length; stderrBytes = $capture.stderr.Length
        captureDisposition = $capture.disposition; unexpectedReadBytes = $capture.unexpectedReadBytes
    }
    $script:result.phases += $outcome
    Save-PhaseCapture
    Save-NewJson ($Name + '-result.json') $outcome
    if ($outcome.exitCode -ne 0 -or -not $outcome.stdoutEof -or -not $outcome.stderrEof) { throw 'Controlled child failed' }
    $child.Dispose(); $script:child = $null
}

# The following apphost functions are copied unchanged from the independently
# reviewed in-process constructor fragment. The controller's closed entry guard
# replaces the fragment's standalone startup guard; it is never dot-sourced.
function Get-ByteHash([byte[]] $Bytes) {
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($digest.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $digest.Dispose() }
}
function Set-UniquePlaceholder([byte[]] $Image, [byte[]] $Pattern, [byte[]] $Replacement) {
    if ($Replacement.Length -ge $Pattern.Length) { throw 'apphost-replacement-bound' }
    # ASCII decoding is length-preserving. Non-ASCII bytes cannot match either ASCII pattern.
    $whole = [Text.Encoding]::ASCII.GetString($Image)
    $needle = [Text.Encoding]::ASCII.GetString($Pattern)
    $offset = $whole.IndexOf($needle, [StringComparison]::Ordinal)
    if ($offset -lt 0 -or $whole.IndexOf($needle, $offset + 1, [StringComparison]::Ordinal) -ge 0) {
        throw 'apphost-placeholder-count'
    }
    [Array]::Clear($Image, $offset, $Pattern.Length)
    [Array]::Copy($Replacement, 0, $Image, $offset, $Replacement.Length)
}
function New-BoundConsoleAppHost([byte[]] $HeldTemplateBytes, [string] $DllLeaf, [string] $ExclusiveDestination) {
    if ($HeldTemplateBytes.Length -ne 160768 -or (Get-ByteHash $HeldTemplateBytes) -ne
        '0649f1bebacef4f17b6694201abc6dde152c333468d2314b4f7104d34d70c7aa') { throw 'apphost-template-pin' }
    if ($DllLeaf -cnotin @('NativeCaller.dll', 'DirectObserver.dll', 'SyntheticSubject.dll', 'FixtureDriver.dll')) {
        throw 'apphost-target'
    }
    # The accepted owner/pin adapter must establish the destination's no-reparse,
    # exclusive ancestor boundary. This function accepts no replacement or retry.
    [byte[]] $image = $HeldTemplateBytes.Clone()
    [byte[]] $namePattern = [Text.Encoding]::ASCII.GetBytes('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
    Set-UniquePlaceholder $image $namePattern ([Text.Encoding]::UTF8.GetBytes($DllLeaf))
    [byte[]] $searchPattern = [Text.Encoding]::ASCII.GetBytes(([char]0).ToString() + [char]0 + '19ff3e9c3602ae8e841925bb461a0adb064a1f1903667a5e0d87e8f608f425ac')
    [byte[]] $relative = [Text.Encoding]::UTF8.GetBytes('..\toolchain')
    [byte[]] $search = New-Object byte[] ($relative.Length + 3)
    $search[0] = 2 # AppRelative only; no environment-variable or global fallback.
    [Array]::Copy($relative, 0, $search, 2, $relative.Length)
    Set-UniquePlaceholder $image $searchPattern $search
    $file = [IO.FileStream]::new($ExclusiveDestination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $file.Write($image, 0, $image.Length); $file.Flush($true) }
    finally { $file.Dispose() }
    return [pscustomobject]@{ bytes = $image.Length; sha256 = Get-ByteHash $image }
}

try {
    if ($Mode -cne 'Controller' -or $root -cnotmatch '^C:\\Temp\\azureauth-windows-slice-108\\named-fixtures-[0-9]{4}$' -or
        [int]$root.Substring($root.Length - 4) -le 120 -or $PSCommandPath -cne "$root\Invoke-WindowsNamedGuardFixtures.ps1" -or
        $env:PSModuleAnalysisCachePath -cne 'NUL') { throw 'Unbound controlled controller' }
    $rootBound = $true
    $authorityBytes = Hold-Control "$root\authority.json" 65536 $AuthoritySha256
    $authority = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes) | ConvertFrom-Json
    $keys = @('schema', 'accepted', 'action', 'nonce', 'operation', 'sourceCommit', 'protocolSha256',
        'checkpointSha256', 'checkpointAcceptanceSha256', 'sourceReviewSha256', 'inputAcceptanceSha256',
        'inventorySha256', 'controllerSha256', 'sourceMapSha256', 'fixtureAdmissionSha256',
        'compileOutputAcceptanceSha256', 'preparationCharge', 'buildTestCharge', 'syntheticCharge',
        'exemptOuterPowerShellCount', 'accountEffectsAdmitted', 'noExperimentLive')
    $actualKeys = @($authority.PSObject.Properties.Name)
    if ($actualKeys.Count -ne $keys.Count) { throw 'Authority field count' }
    foreach ($key in $actualKeys) { if ($key -cnotin $keys) { throw 'Unexpected authority field' } }
    foreach ($key in @('accepted', 'accountEffectsAdmitted', 'noExperimentLive')) {
        if ($authority.$key -isnot [bool]) { throw 'Authority Boolean type' }
    }
    foreach ($key in @('preparationCharge', 'buildTestCharge', 'syntheticCharge', 'exemptOuterPowerShellCount')) {
        if ($authority.$key -isnot [int] -and $authority.$key -isnot [long]) { throw 'Authority integer type' }
    }
    if ($authority.schema -cne 'controlled-callers-controller-authority-v1' -or $authority.accepted -ne $true -or
        $authority.action -cne $root.Substring($root.Length - 4) -or $authority.operation -cnotin @('compile', 'native') -or
        $authority.sourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $authority.nonce -cnotmatch '^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$' -or
        $authority.preparationCharge -ne 0 -or $authority.buildTestCharge -ne 1 -or
        $authority.syntheticCharge -ne $(if ($authority.operation -ceq 'compile') { 1 } else { 12 }) -or
        $authority.exemptOuterPowerShellCount -ne 1 -or $authority.accountEffectsAdmitted -ne $false -or
        $authority.noExperimentLive -ne $false) { throw 'Unaccepted controlled authority' }
    foreach ($key in @('protocolSha256', 'checkpointSha256', 'checkpointAcceptanceSha256', 'sourceReviewSha256',
        'inputAcceptanceSha256', 'inventorySha256', 'controllerSha256', 'sourceMapSha256')) {
        if ($authority.$key -cnotmatch '^[0-9a-f]{64}$' -or $authority.$key -ceq ('0' * 64)) { throw 'Missing independent binding' }
    }
    if ($authority.operation -ceq 'compile') {
        if ($null -ne $authority.fixtureAdmissionSha256 -or $null -ne $authority.compileOutputAcceptanceSha256) { throw 'Compile cannot use runtime admission' }
    } else {
        foreach ($key in @('fixtureAdmissionSha256', 'compileOutputAcceptanceSha256')) {
            if ($authority.$key -cnotmatch '^[0-9a-f]{64}$' -or $authority.$key -ceq ('0' * 64)) { throw 'Missing artifact prerequisite' }
        }
    }
    $result.operation = $authority.operation; $result.sourceCommit = $authority.sourceCommit; $result.nonce = $authority.nonce
    [void](Hold-Control $PSCommandPath 65536 $authority.controllerSha256)
    $catalogBytes = Hold-Control "$root\controller-input-catalog.tsv" 131072 'ba96e46f4c70b508605ebef73e9f674b074adfa03704732aea1781dd62da779c'
    $catalog = [Text.UTF8Encoding]::new($false, $true).GetString($catalogBytes)
    $expected = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $catalogLines = $catalog.TrimEnd([char]10).Split("`n")
    if (-not $catalog.EndsWith("`n") -or $catalog.Contains("`r") -or $catalogLines.Length -ne 615) { throw 'Catalog shape' }
    foreach ($line in $catalogLines) {
        $fields = $line.Split("`t")
        if ($fields.Length -ne 5) { throw 'Catalog row' }
        if ($fields[0] -ceq $authority.operation) { $expected.Add($fields[1], $fields) }
    }
    $expectedCount = $(if ($authority.operation -ceq 'compile') { 413 } else { 202 })
    if ($expected.Count -ne $expectedCount) { throw 'Catalog cardinality' }
    $inventoryBytes = Hold-Control "$root\inventory.tsv" 131072 $authority.inventorySha256
    $inventory = [Text.UTF8Encoding]::new($false, $true).GetString($inventoryBytes)
    $lines = $inventory.TrimEnd([char]10).Split("`n")
    if (-not $inventory.EndsWith("`n") -or $inventory.Contains("`r") -or $lines.Length -ne $expectedCount) { throw 'Inventory shape' }
    $total = 0L
    foreach ($line in $lines) {
        $fields = $line.Split("`t")
        if ($fields.Length -ne 3 -or -not $expected.ContainsKey($fields[0]) -or $inputs.ContainsKey($fields[0]) -or
            $fields[1] -cnotmatch '^[1-9][0-9]{0,8}$' -or $fields[2] -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound inventory row' }
        $rule = $expected[$fields[0]]; $length = [long]$fields[1]
        if ($length -gt [long]$rule[4] -or ([long]$rule[2] -ge 0 -and $length -ne [long]$rule[2]) -or
            ($rule[3] -cne '-' -and $fields[2] -cne $rule[3])) { throw 'Changed literal catalog pin' }
        $total += $length
        if ($total -gt $(if ($authority.operation -ceq 'compile') { 134217728 } else { 100663296 })) { throw 'Input aggregate bound' }
        Pin-Input $fields[0] $length $fields[2]
        $inputs.Add($fields[0], [pscustomobject]@{ bytes = $length; sha256 = $fields[2] })
    }
    $phase = 'admitted'
    Assert-Direct "$stageRoot\artifact"
    Assert-Direct "$stageRoot\records"
    if ($authority.operation -ceq 'compile') {
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries("$stageRoot\artifact").GetEnumerator()
        try { if ($enumerator.MoveNext()) { throw 'Nonfresh compiler artifact directory' } }
        finally { $enumerator.Dispose() }
        # Read construction inputs under the same first-minute admission cutoff.
        $template = Read-Held $held['template\apphost.exe'] 160768
        $metadata = @{}
        foreach ($target in $targets) {
            foreach ($suffix in @('deps.json', 'runtimeconfig.json')) {
                $metadata["$target.$suffix"] = Read-Held $held["control\$target.$suffix"] 4096
            }
        }
        foreach ($target in $targets) {
            $arguments = 'exec --fx-version 10.0.12 --roll-forward Disable "' + $stageRoot +
                '\toolchain\compiler\csc.dll" /noconfig "@' + $stageRoot + '\control\' + $target + '.rsp"'
            # All four starts share the original entry+240 s cutoff, including input reads.
            Invoke-SelectedChild ('compile-' + $target.ToLowerInvariant()) "$stageRoot\toolchain\dotnet.exe" $arguments 240000 65536
        }
        $phase = 'apphost-construction'
        foreach ($target in $targets) {
            Assert-Time 250000
            Assert-Direct "$stageRoot\artifact"
            Reserve-Write ('artifact/' + $target + '.exe') 160768
            $apphost = New-BoundConsoleAppHost $template ($target + '.dll') "$stageRoot\artifact\$target.exe"
            $result.apphosts += [ordered]@{ target = $target; bytes = $apphost.bytes; sha256 = $apphost.sha256 }
            foreach ($suffix in @('deps.json', 'runtimeconfig.json')) {
                Assert-Time 250000
                $bytes = $metadata["$target.$suffix"]
                Reserve-Write ('artifact/' + $target + '.' + $suffix) $bytes.Length
                $stream = [IO.File]::Open("$stageRoot\artifact\$target.$suffix", 'CreateNew', 'Write', 'Read')
                try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
                finally { $stream.Dispose() }
            }
        }
    } else {
        $fixtureBytes = Hold-Control "$stageRoot\control\fixture-admission.json" 262144 $authority.fixtureAdmissionSha256
        $fixture = [Text.UTF8Encoding]::new($false, $true).GetString($fixtureBytes) | ConvertFrom-Json
        if ($fixture.admitted -isnot [bool] -or $fixture.schema -cne 'confidential-fixture-admission-v2' -or $fixture.admitted -ne $true -or
            $fixture.identityMode -cne 'synthetic-first-held-v1' -or
            $fixture.scope -cne 'synthetic-native-only' -or $fixture.batchNonce -cne $authority.nonce -or
            $fixture.protocolSha256 -cne $authority.protocolSha256 -or @($fixture.pins).Count -ne 202) { throw 'Synthetic fixture admission' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($pin in $fixture.pins) {
            if (-not $inputs.ContainsKey($pin.relative) -or -not $seen.Add($pin.relative) -or
                $pin.bytes -ne $inputs[$pin.relative].bytes -or $pin.sha256 -cne $inputs[$pin.relative].sha256) { throw 'Fixture input hold mismatch' }
        }
        $arguments = '"' + $stageRoot + '\control\fixture-admission.json" ' + $authority.fixtureAdmissionSha256
        # The driver retains its original 300+10 s bound; this earlier enclosing
        # entry+310 s cutoff can shorten it, and never waits for independent review.
        Invoke-SelectedChild 'native-batch' "$stageRoot\artifact\FixtureDriver.exe" $arguments 310000 0
    }
    Assert-Time 315000
    $phase = 'captured'
    $result.passed = $true
} catch {
    $result.passed = $false
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureLine = $_.InvocationInfo.ScriptLineNumber
} finally {
    $result.phase = $phase
    $result.startsAttempted = $startsAttempted; $result.readPasses = $readPasses
    $result.readPayloadBytes = $readPayloadBytes
    $result.elapsedMilliseconds = $watch.ElapsedMilliseconds
    $firstFailureAttempted = $false
    if (-not $result.passed) {
        $firstFailureAttempted = $true
        try { Save-NewJson 'controlled-first-failure.json' $result }
        catch { $result.finalizationFailureType = $_.Exception.GetType().FullName }
    }
    try { Save-PhaseCapture }
    catch {
        $result.passed = $false
        $result.finalizationFailureType = $_.Exception.GetType().FullName
    }
    if (-not $result.passed) {
        try { Request-OriginalJobCancellation }
        catch { $result.finalizationFailureType = $_.Exception.GetType().FullName }
    }
    # These counters intentionally exclude the aggregate's own single write.
    # A reserved but failed output stays charged and is never overwritten.
    $result.writeBytesBeforeAggregate = $writeBytes
    $result.writeReservationsBeforeAggregate = $writtenNames.Count
    $result.elapsedMilliseconds = $watch.ElapsedMilliseconds
    try { Save-NewJson 'controlled-result.json' $result }
    catch {
        $result.passed = $false
        $result.finalizationFailureType = $_.Exception.GetType().FullName
        [Console]::Error.WriteLine('Controlled caller finalization failed.')
        if (-not $firstFailureAttempted) {
            $firstFailureAttempted = $true
            try { Save-NewJson 'controlled-first-failure.json' $result } catch { }
        }
        if (-not $result.cancellationRequested) { try { Request-OriginalJobCancellation } catch { } }
    }
    if ($null -ne $child) { $child.Dispose() }
    foreach ($stream in $inputPins) { $stream.Dispose() }
}
if (-not $result.passed) { exit 1 }
exit 0

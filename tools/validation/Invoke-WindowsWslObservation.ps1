# Inert source proposal. The accepted normal launcher remains unchanged.
param(
    [ValidateSet('Controller')][string] $Mode,
    [ValidatePattern('^[0-9a-f]{64}$')][string] $AuthoritySha256
)
$WslObservationDraftOnly = $true
if ($WslObservationDraftOnly) { throw 'DRAFT_ONLY: retained scenario execution is not admitted' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2

$root = $PSScriptRoot
$rootBound = $false
$watch = [Diagnostics.Stopwatch]::StartNew()
$phase = 'authority'
$inputPins = [Collections.Generic.List[IO.FileStream]]::new()
$child = $null
$capture = $null
$observerWatch = $null
$authority = $null
$result = [ordered]@{
    schema = 'retained-wsl-controller-result-v1'
    authoritySha256 = $AuthoritySha256
    mode = $null
    passed = $false
    observerProcessStarted = $false
    observerHandleRetained = $false
    observerExited = $false
    stdoutEof = $false
    stderrEof = $false
    exitCode = $null
    captureDisposition = 'not-started'
    stdoutBytes = 0
    stderrBytes = 0
    cancellationRequested = $false
    cancellationMarkerConfirmed = $false
    failureType = $null
    failureLine = $null
    finalizationFailureType = $null
    phase = $phase
    elapsedMilliseconds = 0
    observerElapsedMilliseconds = 0
    scopedJobQuiescenceEstablished = $false
    noExperimentLive = $false
}

function Assert-ControllerBudget([long] $Limit) {
    if ($watch.ElapsedMilliseconds -ge $Limit) { throw 'Controller phase expired' }
    if (Test-Path -LiteralPath "$root\cancel") { throw 'Original caller cancelled' }
}

function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked scenario path' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory }
        elseif ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        else { throw 'Nonfilesystem scenario path' }
    }
}

function Read-Bounded([string] $Path, [int] $Maximum) {
    Assert-ControllerBudget 30000
    Assert-Direct $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $Maximum) { throw 'Input length bound' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            Assert-ControllerBudget 30000
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'Incomplete scenario input' }
            $offset += $count
        }
        if ($stream.ReadByte() -ne -1) { throw 'Growing scenario input' }
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Hash-Bytes([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Pin-Input([string] $Path, [long] $Length, [string] $Sha256) {
    Assert-ControllerBudget 30000
    if ($Length -lt 1 -or $Length -gt 134217728 -or $Sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Unbounded scenario input'
    }
    Assert-Direct $Path
    # FileShare.Read denies writes/deletion while this exact reviewed input is held.
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    $hash = [Security.Cryptography.SHA256]::Create()
    $retained = $false
    try {
        if ($stream.Length -ne $Length) { throw 'Changed scenario input length' }
        $buffer = [byte[]]::new(65536)
        $total = 0L
        while ($total -lt $Length) {
            Assert-ControllerBudget 30000
            $count = $stream.Read($buffer, 0, [int][Math]::Min(65536L, $Length - $total))
            if ($count -eq 0) { throw 'Incomplete pinned input' }
            [void]$hash.TransformBlock($buffer, 0, $count, $buffer, 0)
            $total += $count
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $Length) { throw 'Changed pinned input' }
        [void]$hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
        if (([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant() -cne $Sha256) {
            throw 'Changed scenario input hash'
        }
        $stream.Position = 0
        $script:inputPins.Add($stream)
        $retained = $true
    } finally {
        $hash.Dispose()
        if (-not $retained) { $stream.Dispose() }
    }
}

function Save-NewBytes([string] $Name, [byte[]] $Bytes, [int] $Maximum) {
    if (-not $rootBound -or $watch.ElapsedMilliseconds -ge 90000 -or $Bytes.Length -gt $Maximum -or
        $Name -cnotmatch '^[a-z][a-z0-9.-]*$') { throw 'Scenario output bound' }
    $path = Join-Path $root $Name
    $stream = [IO.File]::Open(($path + '.pending'), 'CreateNew', 'Write', 'Read')
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ($watch.ElapsedMilliseconds -ge 90000) { throw 'Scenario persistence expired' }
    [IO.File]::Move(($path + '.pending'), $path)
}

function Save-NewJson([string] $Name, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12 -Compress) + "`n")
    Save-NewBytes $Name $bytes 32768
}

function Request-OriginalJobCancellation {
    if (-not $rootBound) { throw 'Cancellation root is unbound' }
    $script:result.cancellationRequested = $true
    # This marker addresses only this fresh invocation. The retained normal launcher
    # owns Job termination; this controller neither enumerates nor kills processes.
    try {
        $stream = [IO.File]::Open("$root\cancel", 'CreateNew', 'Write', 'Read')
        try { $stream.Flush($true) } finally { $stream.Dispose() }
        $script:result.cancellationMarkerConfirmed = $true
    } catch [IO.IOException] {
        if (Test-Path -LiteralPath "$root\cancel") {
            Assert-Direct "$root\cancel"
            $item = Get-Item -LiteralPath "$root\cancel" -Force
            if ($item -is [IO.FileInfo] -and $item.Length -eq 0) {
                $script:result.cancellationMarkerConfirmed = $true
            }
        }
    }
}

function Receive-Observer {
    $streams = @($child.StandardOutput.BaseStream, $child.StandardError.BaseStream)
    $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $tasks = @($streams[0].ReadAsync($buffers[0], 0, 4096), $streams[1].ReadAsync($buffers[1], 0, 4096))
    $done = @($false, $false)
    $disposition = 'read-failure'
    try {
        while (-not ($child.HasExited -and $done[0] -and $done[1])) {
            Assert-ControllerBudget 75000
            if ($observerWatch.ElapsedMilliseconds -ge 40000) {
                $disposition = 'observer-timeout'; throw 'Observer observer expired'
            }
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true }
                    else {
                        if ($data[0].Length + $data[1].Length + $count -gt 16384) {
                            $disposition = 'output-limit'; throw 'Observer capture overflow'
                        }
                        $data[$index].Write($buffers[$index], 0, $count)
                        $tasks[$index] = $streams[$index].ReadAsync($buffers[$index], 0, 4096)
                    }
                }
            }
            Start-Sleep -Milliseconds 25
        }
        $disposition = 'complete'
    } finally {
        $script:capture = [pscustomobject]@{
            stdout = $data[0].ToArray(); stderr = $data[1].ToArray()
            stdoutEof = $done[0]; stderrEof = $done[1]
            disposition = $disposition; elapsedMilliseconds = $observerWatch.ElapsedMilliseconds
        }
        $data[0].Dispose(); $data[1].Dispose()
    }
}

try {
    if ($Mode -cne 'Controller' -or $root -cnotmatch
        '^C:\\Temp\\azureauth-windows-slice-108\\named-fixtures-[0-9]{4}$' -or
        [int]$root.Substring($root.Length - 4) -le 110 -or
        $PSCommandPath -cne "$root\Invoke-WindowsNamedGuardFixtures.ps1" -or
        $env:PSModuleAnalysisCachePath -cne 'NUL') { throw 'Unbound observer controller' }
    $rootBound = $true
    $authorityBytes = Read-Bounded "$root\authority.json" 16384
    if ((Hash-Bytes $authorityBytes) -cne $AuthoritySha256) { throw 'Changed authority' }
    $authority = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes) | ConvertFrom-Json
    $required = @('schema', 'mode', 'root', 'nonce', 'sessionGuid', 'observerSha256', 'productSha256',
        'msalruntimeSha256', 'artifactAcceptanceSha256', 'calibrationAcceptanceSha256',
        'inventorySha256', 'controllerSha256')
    $names = @($authority.PSObject.Properties.Name)
    if ($names.Count -ne $required.Count) { throw 'Authority member count' }
    foreach ($name in $required) {
        if ($names -cnotcontains $name -or $authority.$name -isnot [string]) { throw 'Authority string field' }
    }
    if ($authority.schema -cne 'wsl-observer-authority-v1' -or $authority.root -cne $root -or
        $authority.mode -cnotin @('calibration', 'direct-wsl') -or
        $authority.nonce -cnotmatch '^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$' -or
        $authority.sessionGuid -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') {
        throw 'Finite observer authority'
    }
    foreach ($name in @('observerSha256', 'productSha256', 'msalruntimeSha256', 'artifactAcceptanceSha256',
        'calibrationAcceptanceSha256', 'inventorySha256', 'controllerSha256')) {
        if ($authority.$name -cnotmatch '^[0-9a-f]{64}$') { throw 'Authority hash' }
    }
    $zero = '0' * 64
    if ($authority.observerSha256 -ceq $zero -or $authority.inventorySha256 -ceq $zero -or
        $authority.controllerSha256 -ceq $zero) { throw 'Missing source/input binding' }
    $charge = 4
    $expectedJobTotal = 4
    if ($authority.mode -ceq 'calibration') {
        foreach ($name in @('productSha256', 'msalruntimeSha256', 'artifactAcceptanceSha256', 'calibrationAcceptanceSha256')) {
            if ($authority.$name -cne $zero) { throw 'Calibration is control-only' }
        }
    } else {
        $charge = 3
        $expectedJobTotal = 2
        if ($authority.productSha256 -cne '02993d94c5145f32274a8763f27d632e2dcc8e6a06d257551b1501eed9689cc7' -or
            $authority.msalruntimeSha256 -cne '9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79' -or
            $authority.artifactAcceptanceSha256 -ceq $zero -or $authority.calibrationAcceptanceSha256 -ceq $zero) {
            throw 'Missing accepted native artifact/calibration'
        }
    }
    $result.mode = $authority.mode
    if ((Hash-Bytes (Read-Bounded $PSCommandPath 65536)) -cne $authority.controllerSha256) {
        throw 'Changed observer controller'
    }
    $phase = 'bound-inputs'
    $inventoryBytes = Read-Bounded "$root\inventory.tsv" 65536
    if ((Hash-Bytes $inventoryBytes) -cne $authority.inventorySha256) { throw 'Changed complete input inventory' }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($inventoryBytes)
    if (-not $text.EndsWith("`n") -or $text.Contains("`r")) { throw 'Noncanonical input inventory' }
    $lines = $text.Substring(0, $text.Length - 1).Split("`n")
    if ($lines.Length -lt 3 -or $lines.Length -gt 128) { throw 'Inventory cardinality' }
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $roles = @{}
    $hashes = @{}
    $total = 0L
    foreach ($line in $lines) {
        $fields = $line.Split("`t")
        if ($fields.Length -ne 4 -or $fields[0] -cnotin @('observer', 'control-gated', 'control-fast', 'native', 'msalruntime', 'asset') -or
            -not $fields[1].StartsWith(($root + '\'), [StringComparison]::Ordinal) -or
            $fields[1] -cnotmatch '^C:\\Temp\\azureauth-windows-slice-108\\[A-Za-z0-9 _.,=\\-]+$' -or
            $fields[1].Contains('..') -or $fields[1].EndsWith('\') -or
            $fields[2] -cnotmatch '^[1-9][0-9]{0,8}$' -or $fields[3] -cnotmatch '^[0-9a-f]{64}$' -or
            -not $paths.Add($fields[1])) { throw 'Unbound inventory entry' }
        if ($fields[0] -cne 'asset') {
            if ($roles.ContainsKey($fields[0])) { throw 'Duplicate role' }
            $roles[$fields[0]] = $fields[1]
            $hashes[$fields[0]] = $fields[3]
        } elseif (-not $fields[1].StartsWith(($root + '\native\'), [StringComparison]::Ordinal)) {
            throw 'Native companion boundary'
        }
        $length = [long]$fields[2]
        $total += $length
        if ($total -gt 536870912) { throw 'Aggregate input bound' }
        Pin-Input $fields[1] $length $fields[3]
    }
    if ($roles.observer -cne "$root\observer.exe" -or $hashes.observer -cne $authority.observerSha256 -or
        $roles.Count -ne 3) { throw 'Observer roles' }
    if ($authority.mode -ceq 'calibration') {
        if ($lines.Length -ne 3 -or $roles['control-gated'] -cne "$root\control-gated.exe" -or
            $roles['control-fast'] -cne "$root\control-fast.exe" -or
            $hashes['control-gated'] -cne $authority.observerSha256 -or
            $hashes['control-fast'] -cne $authority.observerSha256) { throw 'Distinct calibrated control images' }
    } elseif ($roles.native -cne "$root\native\azureauth.exe" -or
        $roles.msalruntime -cne "$root\native\msalruntime.dll" -or
        $hashes.native -cne $authority.productSha256 -or $hashes.msalruntime -cne $authority.msalruntimeSha256) {
        throw 'Exact native inputs'
    }
    foreach ($name in @('temp', 'home', 'home\roaming', 'home\local', 'empty-program-files')) {
        $path = Join-Path $root $name
        Assert-Direct $path
        if ((Get-Item -LiteralPath $path -Force) -isnot [IO.DirectoryInfo]) { throw 'Missing dedicated directory' }
    }
    foreach ($name in @('temp', 'home\roaming', 'home\local', 'empty-program-files')) {
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries((Join-Path $root $name)).GetEnumerator()
        try { if ($enumerator.MoveNext()) { throw 'Nonfresh observer directory' } }
        finally { $enumerator.Dispose() }
    }
    $environment = @{
        SystemRoot = 'C:\Windows'; WINDIR = 'C:\Windows'; SystemDrive = 'C:'
        ComSpec = 'C:\Windows\System32\cmd.exe'; OS = 'Windows_NT'; PROCESSOR_ARCHITECTURE = 'AMD64'
        PATH = 'C:\Windows\System32'
        PROGRAMFILES = "$root\empty-program-files"; 'PROGRAMFILES(X86)' = "$root\empty-program-files"
        USERPROFILE = "$root\home"; APPDATA = "$root\home\roaming"; LOCALAPPDATA = "$root\home\local"
        TMP = "$root\temp"; TEMP = "$root\temp"
    }
    $arguments = '--mode ' + $authority.mode + ' --root "' + $root + '" --authority-sha256 ' + $AuthoritySha256
    Assert-ControllerBudget 30000
    $phase = 'observer-start-intent'
    Save-NewJson 'observer-invocation.json' ([ordered]@{
        schema = 'retained-wsl-observer-invocation-v1'; authoritySha256 = $AuthoritySha256
        executable = $roles.observer; arguments = $arguments; workingDirectory = $root
        environment = $environment; observerSeconds = 30; transportSeconds = 40; controllerSeconds = 90
        expectedExitCode = 0; syntheticCharge = $charge; deliberateWindowsStarts = ($charge + 1)
        expectedJobTotalProcesses = $expectedJobTotal
    })
    Assert-ControllerBudget 30000
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $roles.observer
    $info.Arguments = $arguments
    $info.WorkingDirectory = $root
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables.Clear()
    foreach ($key in $environment.Keys) { $info.EnvironmentVariables[$key] = $environment[$key] }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $info
    $observerWatch = [Diagnostics.Stopwatch]::StartNew()
    if (-not $child.Start()) { throw 'Observer start failed' }
    $result.observerProcessStarted = $true
    if ($child.Handle -eq [IntPtr]::Zero) { throw 'Missing retained observer handle' }
    $result.observerHandleRetained = $true
    $child.StandardInput.Close()
    Save-NewJson 'observer-started.json' ([ordered]@{
        schema = 'retained-wsl-observer-started-v1'; authoritySha256 = $AuthoritySha256
        pid = $child.Id; creationFileTime = $child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        session = $child.SessionId; executable = $roles.observer
        handleRetained = $true; creationMode = 'ordinary-child-without-breakaway'
    })
    $phase = 'observer-capture'
    Receive-Observer
    $result.observerExited = $child.HasExited
    $result.exitCode = $child.ExitCode
    $result.observerElapsedMilliseconds = $observerWatch.ElapsedMilliseconds
    if ($result.observerElapsedMilliseconds -ge 40000 -or $child.ExitCode -ne 0 -or -not $capture.stdoutEof -or -not $capture.stderrEof -or
        $capture.stdout.Length -ne 0 -or $capture.stderr.Length -ne 0) { throw 'Observer batch failed' }
    $phase = 'captured'
    $result.passed = $true
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureLine = $_.InvocationInfo.ScriptLineNumber
    $result.passed = $false
} finally {
    $result.phase = $phase
    # These are bounded snapshots of bytes already read into this controller's
    # memory. Their retention establishes neither child exit nor Job quiescence.
    try {
        if (-not $result.passed) {
            # Persist the original cause before the cancel marker can terminate us.
            $result.elapsedMilliseconds = $watch.ElapsedMilliseconds
            Save-NewJson 'observer-controller-failure.json' $result
        }
        if ($null -ne $capture) {
            $result.stdoutEof = $capture.stdoutEof
            $result.stderrEof = $capture.stderrEof
            $result.captureDisposition = $capture.disposition
            $result.stdoutBytes = $capture.stdout.Length
            $result.stderrBytes = $capture.stderr.Length
            Save-NewBytes 'observer.stdout.bin' $capture.stdout 16384
            Save-NewBytes 'observer.stderr.bin' $capture.stderr 16384
        }
        if (-not $result.passed) { Request-OriginalJobCancellation }
        $result.elapsedMilliseconds = $watch.ElapsedMilliseconds
        Save-NewJson 'observer-controller-result.json' $result
    } catch {
        $result.passed = $false
        $result.finalizationFailureType = $_.Exception.GetType().FullName
        # Original exception labels remain separate from a persistence failure.
        # No exception message, input path, or subject output reaches this channel.
        $diagnostic = [ordered]@{
            schema = 'retained-windows-controller-failure-v1'; phase = $phase
            failureType = $result.failureType; failureLine = $result.failureLine
            finalizationFailureType = $result.finalizationFailureType
        } | ConvertTo-Json -Compress
        [Console]::Error.WriteLine($diagnostic)
        try { Request-OriginalJobCancellation } catch { }
    }
    if ($null -ne $child) { $child.Dispose() }
    foreach ($stream in $inputPins) { $stream.Dispose() }
}
if (-not $result.passed) { exit 1 }
exit 0

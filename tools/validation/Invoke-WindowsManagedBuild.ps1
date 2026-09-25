# Inert source proposal. The accepted normal launcher remains unchanged.
param(
    [ValidateSet('Controller')][string] $Mode,
    [ValidatePattern('^[0-9a-f]{64}$')][string] $AuthoritySha256
)
$ManagedBuildDraftOnly = $true
if ($ManagedBuildDraftOnly) { throw 'DRAFT_ONLY: managed build execution is not admitted' }
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
$runnerWatch = $null
$authority = $null
$result = [ordered]@{
    schema = 'retained-windows-managed-build-result-v1'
    authoritySha256 = $AuthoritySha256
    sourceCommit = $null
    operation = $null
    phases = @()
    passed = $false
    cancellationRequested = $false
    cancellationMarkerConfirmed = $false
    failureType = $null
    failureLine = $null
    finalizationFailureType = $null
    phase = $phase
    elapsedMilliseconds = 0
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
    Assert-ControllerBudget 60000
    Assert-Direct $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $Maximum) { throw 'Input length bound' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            Assert-ControllerBudget 60000
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
    Assert-ControllerBudget 60000
    if ($Length -lt 0 -or $Length -gt 134217728 -or $Sha256 -cnotmatch '^[0-9a-f]{64}$') {
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
            Assert-ControllerBudget 60000
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
    if (-not $rootBound -or $watch.ElapsedMilliseconds -ge 300000 -or $Bytes.Length -gt $Maximum -or
        $Name -cnotmatch '^[a-z][a-z0-9.-]*$') { throw 'Scenario output bound' }
    $path = Join-Path $root $Name
    $stream = [IO.File]::Open(($path + '.pending'), 'CreateNew', 'Write', 'Read')
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ($watch.ElapsedMilliseconds -ge 300000) { throw 'Scenario persistence expired' }
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

function Receive-ManagedRunner {
    $streams = @($child.StandardOutput.BaseStream, $child.StandardError.BaseStream)
    $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $tasks = @($streams[0].ReadAsync($buffers[0], 0, 4096), $streams[1].ReadAsync($buffers[1], 0, 4096))
    $done = @($false, $false)
    $disposition = 'read-failure'
    try {
        while (-not ($child.HasExited -and $done[0] -and $done[1])) {
            Assert-ControllerBudget 275000
            if ($runnerWatch.ElapsedMilliseconds -ge 190000) {
                $disposition = 'runner-timeout'; throw 'Managed runner expired'
            }
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true }
                    else {
                        if ($script:capturedTotal + $data[0].Length + $data[1].Length + $count -gt 8388608) {
                            $disposition = 'output-limit'; throw 'Managed capture overflow'
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
            disposition = $disposition; elapsedMilliseconds = $runnerWatch.ElapsedMilliseconds
        }
        $data[0].Dispose(); $data[1].Dispose()
    }
}

$capturedTotal = 0L
$phaseName = $null
$captureSaved = $false

function Save-PhaseCapture {
    if ($null -eq $capture -or $captureSaved) { return }
    # Mark the single retention attempt before either fallible write.
    $script:captureSaved = $true
    Save-NewBytes ($phaseName + '.stdout.bin') $capture.stdout 8388608
    Save-NewBytes ($phaseName + '.stderr.bin') $capture.stderr 8388608
    $script:capturedTotal += $capture.stdout.Length + $capture.stderr.Length
}

try {
    if ($Mode -cne 'Controller' -or $root -cnotmatch
        '^C:\\Temp\\azureauth-windows-slice-108\\named-fixtures-[0-9]{4}$' -or
        [int]$root.Substring($root.Length - 4) -le 110 -or
        $PSCommandPath -cne "$root\Invoke-WindowsNamedGuardFixtures.ps1" -or
        $env:PSModuleAnalysisCachePath -cne 'NUL') { throw 'Unbound managed build controller' }
    $rootBound = $true
    $authorityBytes = Read-Bounded "$root\authority.json" 65536
    if ((Hash-Bytes $authorityBytes) -cne $AuthoritySha256) { throw 'Changed authority' }
    $authority = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes) | ConvertFrom-Json
    if ($authority.schema -cne 'retained-windows-managed-build-authority-v1' -or
        $authority.accepted -ne $true -or $authority.action -cne $root.Substring($root.Length - 4) -or
        $authority.operation -cnotin @('restore', 'build') -or $authority.sourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $authority.preparationCharge -ne [int]($authority.operation -ceq 'restore') -or
        $authority.buildTestCharge -ne [int]($authority.operation -ceq 'build') -or
        $authority.syntheticCharge -ne 1 -or $authority.exemptOuterPowerShellCount -ne 1 -or
        $authority.runnerSeconds -ne 190 -or $authority.wrapperSeconds -ne 300 -or
        $authority.maximumCaptureBytes -ne 8388608 -or $authority.noExperimentLive -ne $false) {
        throw 'Unaccepted finite build authority'
    }
    foreach ($name in @('checkpointSha256', 'checkpointAcceptanceSha256', 'inputAcceptanceSha256',
        'sourceReviewSha256', 'inventorySha256', 'controllerSha256')) {
        if ($authority.$name -cnotmatch '^[0-9a-f]{64}$') { throw 'Missing independent binding' }
    }
    if ($authority.subjectAction -cnotmatch '^[0-9]{4}$' -or [int]$authority.subjectAction -le 110 -or
        ($authority.operation -ceq 'restore' -and $authority.subjectAction -cne $authority.action) -or
        ($authority.operation -ceq 'build' -and [int]$authority.subjectAction -ge [int]$authority.action)) {
        throw 'Unbound separately reviewed restore tree'
    }
    $subjectRoot = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-' + $authority.subjectAction
    $result.operation = $authority.operation
    $result.sourceCommit = $authority.sourceCommit
    if ((Hash-Bytes (Read-Bounded $PSCommandPath 65536)) -cne $authority.controllerSha256) {
        throw 'Changed controller source'
    }
    $phase = 'bound-inputs'
    $inventoryBytes = Read-Bounded "$root\inventory.tsv" 1048576
    if ((Hash-Bytes $inventoryBytes) -cne $authority.inventorySha256) { throw 'Changed build inventory' }
    $inventoryText = [Text.UTF8Encoding]::new($false, $true).GetString($inventoryBytes)
    if (-not $inventoryText.EndsWith("`n") -or $inventoryText.Contains("`r")) { throw 'Noncanonical inventory' }
    $lines = $inventoryText.Substring(0, $inventoryText.Length - 1).Split("`n")
    if ($lines.Length -lt 20 -or $lines.Length -gt 4096) { throw 'Inventory cardinality bound' }
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $total = 0L
    $dotnet = $null
    $sourceCount = 0
    $cacheCount = 0
    foreach ($line in $lines) {
        $fields = $line.Split("`t")
        if ($fields.Length -ne 4 -or $fields[0] -cnotin @('dotnet', 'tool', 'source', 'cache', 'metadata') -or
            $fields[1] -cnotmatch '^C:\\(?:Program Files\\dotnet\\|Temp\\azureauth-windows-slice-108\\)[A-Za-z0-9 _.,=\\-]+$' -or
            $fields[1].Contains('..') -or $fields[1].EndsWith('\') -or
            $fields[2] -cnotmatch '^(?:0|[1-9][0-9]{0,8})$' -or $fields[3] -cnotmatch '^[0-9a-f]{64}$' -or
            -not $paths.Add($fields[1])) { throw 'Unbound inventory leaf' }
        if ($fields[0] -ceq 'dotnet') {
            if ($null -ne $dotnet -or $fields[1] -cne 'C:\Program Files\dotnet\dotnet.exe') {
                throw 'Unbound SDK host'
            }
            $dotnet = $fields[1]
        } elseif ($fields[0] -ceq 'tool') {
            if (-not $fields[1].StartsWith('C:\Program Files\dotnet\', [StringComparison]::Ordinal)) {
                throw 'Unbound installed tool'
            }
        } elseif ($fields[0] -ceq 'source') {
            if (-not $fields[1].StartsWith("$subjectRoot\subject\", [StringComparison]::Ordinal)) {
                throw 'Unbound fresh source'
            }
            $sourceCount++
        } else {
            $prefix = "$subjectRoot\packages\"
            if ($fields[0] -ceq 'metadata') {
                if ($authority.operation -cne 'build') { throw 'Restore cannot reuse metadata' }
                $prefix = "$subjectRoot\subject\"
            } else { $cacheCount++ }
            if (-not $fields[1].StartsWith($prefix, [StringComparison]::Ordinal)) {
                throw 'Unbound complete cache or newly restored metadata'
            }
        }
        $length = [long]$fields[2]
        if ($length -eq 0 -and $fields[0] -cne 'cache') { throw 'Only admitted cache leaves may be empty' }
        $total += $length
        if ($total -gt 2147483648) { throw 'Complete build input aggregate bound' }
        Pin-Input $fields[1] $length $fields[3]
    }
    if ($null -eq $dotnet -or $sourceCount -lt 10 -or $cacheCount -lt 1) { throw 'Incomplete build roles' }
    foreach ($name in @('results', 'temp', 'home', 'home\roaming',
        'home\local', 'home\http', 'home\plugins', 'empty-program-files')) {
        $path = Join-Path $root $name
        Assert-Direct $path
        if ((Get-Item -LiteralPath $path -Force) -isnot [IO.DirectoryInfo]) { throw 'Missing dedicated directory' }
    }
    foreach ($name in @('results', 'temp', 'home\roaming', 'home\local', 'home\http',
        'home\plugins', 'empty-program-files')) {
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries((Join-Path $root $name)).GetEnumerator()
        try { if ($enumerator.MoveNext()) { throw 'Nonfresh build output directory' } }
        finally { $enumerator.Dispose() }
    }
    foreach ($name in @('subject', 'empty-feed', 'packages')) {
        Assert-Direct (Join-Path $subjectRoot $name)
    }
    $entries = [IO.Directory]::EnumerateFileSystemEntries("$subjectRoot\empty-feed").GetEnumerator()
    try { if ($entries.MoveNext()) { throw 'Offline fallback feed is not empty' } }
    finally { $entries.Dispose() }
    # Generate only this invocation's credential-free local-feed configuration.
    $config = '<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear />' +
        '<add key="retained-public" value="' + $subjectRoot + '\empty-feed" /></packageSources>' +
        '<packageSourceMapping><clear /><packageSource key="retained-public"><package pattern="*" /></packageSource>' +
        '</packageSourceMapping><fallbackPackageFolders><clear /></fallbackPackageFolders></configuration>'
    Save-NewBytes 'offline.config' ([Text.UTF8Encoding]::new($false).GetBytes($config)) 8192
    $environment = @{
        SystemRoot = 'C:\Windows'; WINDIR = 'C:\Windows'; SystemDrive = 'C:'
        ComSpec = 'C:\Windows\System32\cmd.exe'; OS = 'Windows_NT'; PROCESSOR_ARCHITECTURE = 'AMD64'
        PATH = 'C:\Program Files\dotnet;C:\Windows\System32'
        PROGRAMFILES = "$root\empty-program-files"; 'PROGRAMFILES(X86)' = "$root\empty-program-files"
        USERPROFILE = "$root\home"; APPDATA = "$root\home\roaming"; LOCALAPPDATA = "$root\home\local"
        TMP = "$root\temp"; TEMP = "$root\temp"; DOTNET_CLI_HOME = "$root\home"
        DOTNET_ROOT = 'C:\Program Files\dotnet'; DOTNET_ROLL_FORWARD = 'Disable'
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'; TESTINGPLATFORM_TELEMETRY_OPTOUT = '1'
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'; DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
        DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = 'false'; DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = 'true'
        DOTNET_CLI_USE_MSBUILD_SERVER = '0'; MSBUILDDISABLENODEREUSE = '1'
        MSBuildEnableWorkloadResolver = 'false'; DOTNET_NOLOGO = '1'; DOTNET_CLI_UI_LANGUAGE = 'en-US'
        NUGET_PACKAGES = "$subjectRoot\packages"; NUGET_HTTP_CACHE_PATH = "$root\home\http"
        NUGET_PLUGINS_CACHE_PATH = "$root\home\plugins"; NUGET_CERT_REVOCATION_MODE = 'offline'
    }
    $common = ' --disable-build-servers --verbosity minimal -p:UseSharedCompilation=false -m:1 -nr:false -noAutoResponse' +
        ' -p:NuGetAudit=false -p:EnableSourceControlManagerQueries=false -p:EnableSourceLink=false' +
        ' -p:RestoreFallbackFolders= -p:RestoreAdditionalProjectSources= -p:RestoreAdditionalProjectFallbackFolders=' +
        ' -p:SourceRevisionId=' + $authority.sourceCommit
    $commands = [ordered]@{
        restore = 'restore Windows.slnx --locked-mode --disable-parallel --no-http-cache --configfile "' +
            $root + '\offline.config" --source "' + $subjectRoot + '\empty-feed" --packages "' + $subjectRoot + '\packages"' + $common
        build = 'build Windows.slnx -c Release --no-restore' + $common +
            ' "-bl:' + $root + '\results\managed-build.binlog;ProjectImports=None"'
    }
    Assert-ControllerBudget 60000
    # Exactly one phase runs. Restore must close and receive independent review before a later build.
    $runnerWatch = [Diagnostics.Stopwatch]::StartNew()
    foreach ($phaseName in @($authority.operation)) {
        $phase = $phaseName + '-start-intent'
        $capture = $null
        $captureSaved = $false
        Assert-ControllerBudget 275000
        if ($runnerWatch.ElapsedMilliseconds -ge 190000) { throw 'Combined build phases expired' }
        Save-NewJson ($phaseName + '-invocation.json') ([ordered]@{
            schema = 'retained-windows-build-invocation-v1'; authoritySha256 = $AuthoritySha256
            executable = $dotnet; arguments = $commands[$phaseName]; workingDirectory = "$subjectRoot\subject"
            environment = $environment; runnerSeconds = 190; expectedExitCode = 0; phase = $phaseName
        })
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $dotnet
        $info.Arguments = $commands[$phaseName]
        $info.WorkingDirectory = "$subjectRoot\subject"
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.EnvironmentVariables.Clear()
        foreach ($key in $environment.Keys) { $info.EnvironmentVariables[$key] = $environment[$key] }
        $child = [Diagnostics.Process]::new()
        $child.StartInfo = $info
        if (-not $child.Start()) { throw 'Managed build phase start failed' }
        if ($child.Handle -eq [IntPtr]::Zero) { throw 'Missing retained phase handle' }
        $started = [ordered]@{
            schema = 'retained-windows-build-started-v1'; authoritySha256 = $AuthoritySha256
            pid = $child.Id; creationFileTime = $child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
            session = $child.SessionId; executable = $dotnet; phase = $phaseName
            handleRetained = $true; creationMode = 'ordinary-child-without-breakaway'
        }
        Save-NewJson ($phaseName + '-started.json') $started
        $phase = $phaseName + '-capture'
        Receive-ManagedRunner
        $phaseResult = [ordered]@{
            phase = $phaseName; exited = $child.HasExited; exitCode = $child.ExitCode
            stdoutEof = $capture.stdoutEof; stderrEof = $capture.stderrEof
            captureDisposition = $capture.disposition
            stdoutBytes = $capture.stdout.Length; stderrBytes = $capture.stderr.Length
        }
        $result.phases += $phaseResult
        Save-PhaseCapture
        Save-NewJson ($phaseName + '-result.json') $phaseResult
        if ($phaseResult.exitCode -ne 0 -or -not $phaseResult.stdoutEof -or -not $phaseResult.stderrEof) {
            throw 'Managed build phase failed'
        }
        $child.Dispose()
        $child = $null
    }
    Assert-ControllerBudget 275000
    $phase = 'captured'
    $result.passed = $true
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureLine = $_.InvocationInfo.ScriptLineNumber
    $result.passed = $false
} finally {
    $result.phase = $phase
    try {
        if (-not $result.passed) {
            $result.elapsedMilliseconds = $watch.ElapsedMilliseconds
            Save-NewJson 'build-failure.json' $result
        }
        Save-PhaseCapture
        if (-not $result.passed) { Request-OriginalJobCancellation }
        $result.elapsedMilliseconds = $watch.ElapsedMilliseconds
        Save-NewJson 'build-result.json' $result
    } catch {
        $result.passed = $false
        $result.finalizationFailureType = $_.Exception.GetType().FullName
        [Console]::Error.WriteLine('Managed build finalization failed.')
        try { Request-OriginalJobCancellation } catch { }
    }
    if ($null -ne $child) { $child.Dispose() }
    foreach ($stream in $inputPins) { $stream.Dispose() }
}
if (-not $result.passed) { exit 1 }
exit 0

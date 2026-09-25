# Inert source proposal. The accepted normal launcher remains unchanged.
param(
    [ValidateSet('Controller')][string] $Mode,
    [ValidatePattern('^[0-9a-f]{64}$')][string] $AuthoritySha256
)
$RetainedScenariosDraftOnly = $true
if ($RetainedScenariosDraftOnly) { throw 'DRAFT_ONLY: retained scenario execution is not admitted' }
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
    schema = 'retained-windows-scenarios-result-v1'
    authoritySha256 = $AuthoritySha256
    suite = $null
    passed = $false
    managedProcessStarted = $false
    managedHandleRetained = $false
    managedExited = $false
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
            if ($runnerWatch.ElapsedMilliseconds -ge 240000) {
                $disposition = 'runner-timeout'; throw 'Managed runner expired'
            }
            if ((Test-Path -LiteralPath "$root\temp\process-safety-stop.json") -or
                (Test-Path -LiteralPath "$root\temp\owned-host-safety-stop.json")) {
                $disposition = 'fixture-safety-stop'; throw 'Owned fixture safety stop'
            }
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true }
                    else {
                        if ($data[0].Length + $data[1].Length + $count -gt 8388608) {
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

try {
    if ($Mode -cne 'Controller' -or $root -cnotmatch
        '^C:\\Temp\\azureauth-windows-slice-108\\named-fixtures-[0-9]{4}$' -or
        [int]$root.Substring($root.Length - 4) -le 110 -or
        $PSCommandPath -cne "$root\Invoke-WindowsNamedGuardFixtures.ps1" -or
        $env:PSModuleAnalysisCachePath -cne 'NUL') { throw 'Unbound retained controller' }
    $rootBound = $true
    $authorityBytes = Read-Bounded "$root\authority.json" 65536
    if ((Hash-Bytes $authorityBytes) -cne $AuthoritySha256) { throw 'Changed authority' }
    $authority = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes) | ConvertFrom-Json
    if ($authority.schema -cne 'retained-windows-scenarios-authority-v1' -or
        $authority.accepted -ne $true -or $authority.action -cne $root.Substring($root.Length - 4) -or
        $authority.suite -cnotin @('cli22', 'native-profile2') -or
        $authority.productCommit -cne '503360753accd0829801953823b1b57a4f852440' -or
        $authority.nativeEvidenceBasis -cne 'original-0110-retained-candidate' -or
        $authority.nativeArtifactAccepted -ne $true -or $authority.buildTestCharge -ne 1 -or
        $authority.runnerSeconds -ne 240 -or $authority.wrapperSeconds -ne 300 -or
        $authority.maximumCaptureBytes -ne 8388608 -or $authority.noExperimentLive -ne $false) {
        throw 'Unaccepted finite scenario authority'
    }
    foreach ($name in @('checkpointSha256', 'checkpointAcceptanceSha256', 'nativeAcceptanceSha256',
        'managedBuildAcceptanceSha256', 'sourceReviewSha256',
        'inventorySha256', 'controllerSha256')) {
        if ($authority.$name -cnotmatch '^[0-9a-f]{64}$') { throw 'Missing independent binding' }
    }
    $charge = 14
    $starts = 15
    if ($authority.suite -ceq 'native-profile2') { $charge = 4; $starts = 5 }
    if ($authority.syntheticCharge -ne $charge -or $authority.deliberateWindowsStarts -ne $starts -or
        $authority.expectedJobTotalProcesses -ne $charge -or $authority.exemptOuterPowerShellCount -ne 1) {
        throw 'Incomplete retained topology reservation'
    }
    $result.suite = $authority.suite
    if ((Hash-Bytes (Read-Bounded $PSCommandPath 65536)) -cne $authority.controllerSha256) {
        throw 'Changed controller source'
    }

    $phase = 'bound-inputs'
    $inventoryBytes = Read-Bounded "$root\inventory.tsv" 65536
    if ((Hash-Bytes $inventoryBytes) -cne $authority.inventorySha256) { throw 'Changed complete input inventory' }
    $inventoryText = [Text.UTF8Encoding]::new($false, $true).GetString($inventoryBytes)
    if (-not $inventoryText.EndsWith("`n") -or $inventoryText.Contains("`r")) { throw 'Noncanonical input inventory' }
    $lines = $inventoryText.Substring(0, $inventoryText.Length - 1).Split("`n")
    if ($lines.Length -lt 4 -or $lines.Length -gt 128) { throw 'Inventory cardinality bound' }
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $roles = @{}
    $total = 0L
    foreach ($line in $lines) {
        $fields = $line.Split("`t")
        if ($fields.Length -ne 4 -or $fields[0] -cnotin @('dotnet', 'runner', 'native', 'asset') -or
            $fields[1] -cnotmatch '^C:\\(?:Program Files\\dotnet\\|Temp\\azureauth-windows-slice-108\\)[A-Za-z0-9 _.,=\\-]+$' -or
            $fields[1].Contains('..') -or $fields[1].EndsWith('\') -or
            $fields[2] -cnotmatch '^[1-9][0-9]{0,8}$' -or $fields[3] -cnotmatch '^[0-9a-f]{64}$' -or
            -not $paths.Add($fields[1])) { throw 'Unbound inventory entry' }
        if ($fields[0] -cne 'asset') {
            if ($roles.ContainsKey($fields[0])) { throw 'Duplicate executable role' }
            $roles[$fields[0]] = $fields[1]
        }
        $length = [long]$fields[2]
        $total += $length
        if ($total -gt 536870912) { throw 'Complete input aggregate bound' }
        Pin-Input $fields[1] $length $fields[3]
    }
    if ($roles.Count -ne 3 -or $roles.dotnet -cne 'C:\Program Files\dotnet\dotnet.exe' -or
        $roles.runner -cne "$root\managed\Authentication.Windows.Scenarios.dll" -or
        $roles.native -cne "$root\native\azureauth.exe") { throw 'Unbound entry roles' }
    foreach ($name in @('managed', 'native', 'results', 'temp', 'home', 'home\roaming', 'home\local', 'empty-program-files')) {
        $path = Join-Path $root $name
        Assert-Direct $path
        if ((Get-Item -LiteralPath $path -Force) -isnot [IO.DirectoryInfo]) { throw 'Missing dedicated directory' }
    }
    foreach ($name in @('results', 'temp', 'home\roaming', 'home\local', 'empty-program-files')) {
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries((Join-Path $root $name)).GetEnumerator()
        try { if ($enumerator.MoveNext()) { throw 'Nonfresh scenario output directory' } }
        finally { $enumerator.Dispose() }
    }

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
    }
    $arguments = '"' + $roles.runner + '" --native-profile-cases "' + $roles.native + '"'
    if ($authority.suite -ceq 'cli22') {
        $fileMethods = @('ExplicitFilePreservesSelectedProfileAndRequest', 'FileSizeLimitAppliesBeforeAuthentication',
            'ReplacingFileAfterAdmissionCannotChangeTheInFlightProfile', 'UnreadableOrInvalidFileStopsBeforeProviderConstruction')
        $processMethods = @('RootHelpCompletesWithoutAuthentication', 'MalformedAuthenticationReturnsTheBootstrapFailure',
            'SelectedRequestReturnsOneSuccessDespiteBrokenDiagnostics', 'FlaggedRegularFileStopsBeforeProfileAndProvider',
            'AlreadyClosedLifetimePipeCancelsBeforeAuthentication', 'WriterClosureRejectsLateSuccessAndEndsTheProcess',
            'ClosedStdinWithoutTheFlagDoesNotCancel', 'LifetimePipePayloadIsIgnoredAndClosureStillCancels',
            'DeadlineEndsUncooperativeWorkWithinTheProcessBound', 'BrokenResultReaderEndsWithTransportFailure',
            'UndrainedResultPipeCannotKeepTheProcessAlive',
            'BlockedDiagnosticsDoNotChangeTheAuthenticationResultOrKeepTheProcessAlive')
        $selectors = @($fileMethods | ForEach-Object { 'FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.' + $_ })
        $selectors += @($processMethods | ForEach-Object { 'FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.' + $_ })
        $filter = $selectors -join '|'
        $arguments = '"' + $roles.runner + '" --native-cli-executable "' + $roles.native +
            '" --report-trx --results-directory "' + $root + '\results" --filter "' + $filter + '"'
    }
    Assert-ControllerBudget 30000
    $phase = 'managed-start-intent'
    Save-NewJson 'managed-invocation.json' ([ordered]@{
        schema = 'retained-windows-managed-invocation-v1'; authoritySha256 = $AuthoritySha256
        executable = $roles.dotnet; arguments = $arguments; workingDirectory = "$root\managed"
        environment = $environment; runnerSeconds = 240; expectedExitCode = 0
        syntheticCharge = $charge; deliberateWindowsStarts = $starts
    })
    Assert-ControllerBudget 30000
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $roles.dotnet
    $info.Arguments = $arguments
    $info.WorkingDirectory = "$root\managed"
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables.Clear()
    foreach ($key in $environment.Keys) { $info.EnvironmentVariables[$key] = $environment[$key] }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $info
    $runnerWatch = [Diagnostics.Stopwatch]::StartNew()
    if (-not $child.Start()) { throw 'Managed runner start failed' }
    $result.managedProcessStarted = $true
    if ($child.Handle -eq [IntPtr]::Zero) { throw 'Missing retained managed handle' }
    $result.managedHandleRetained = $true
    Save-NewJson 'managed-started.json' ([ordered]@{
        schema = 'retained-windows-managed-started-v1'; authoritySha256 = $AuthoritySha256
        pid = $child.Id; creationFileTime = $child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        session = $child.SessionId; executable = $roles.dotnet
        handleRetained = $true; creationMode = 'ordinary-child-without-breakaway'
    })
    $phase = 'managed-capture'
    Receive-ManagedRunner
    $result.managedExited = $child.HasExited
    $result.exitCode = $child.ExitCode
    if ($child.ExitCode -ne 0 -or -not $capture.stdoutEof -or -not $capture.stderrEof) {
        throw 'Managed scenario batch failed'
    }
    if ((Test-Path -LiteralPath "$root\temp\process-safety-stop.json") -or
        (Test-Path -LiteralPath "$root\temp\owned-host-safety-stop.json")) { throw 'Final fixture safety stop' }
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
            Save-NewJson 'scenario-failure.json' $result
        }
        if ($null -ne $capture) {
            $result.stdoutEof = $capture.stdoutEof
            $result.stderrEof = $capture.stderrEof
            $result.captureDisposition = $capture.disposition
            $result.stdoutBytes = $capture.stdout.Length
            $result.stderrBytes = $capture.stderr.Length
            Save-NewBytes 'managed.stdout.bin' $capture.stdout 8388608
            Save-NewBytes 'managed.stderr.bin' $capture.stderr 8388608
        }
        if (-not $result.passed) { Request-OriginalJobCancellation }
        $result.elapsedMilliseconds = $watch.ElapsedMilliseconds
        Save-NewJson 'scenario-result.json' $result
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

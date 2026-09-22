# Prospective singleton fixtures. Source, protocol and exact call admission are required.
param(
    [ValidateSet('Controller', 'Case', 'Payload')][string] $Mode = 'Controller',
    [ValidateSet('live')][string] $CaseName,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string] $AuthoritySha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2
if ($env:PSModuleAnalysisCachePath -cne 'NUL') { throw 'Fixture startup cache control is absent' }
$watch = [Diagnostics.Stopwatch]::StartNew()
$root = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0077'
$shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$script:writtenBytes = 0
$script:readBytes = 0

function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked fixture path' }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        elseif ($item -is [IO.FileInfo]) { $item = $item.Directory }
        else { throw 'Fixture path is not a filesystem entry' }
    }
}

function Get-Hash([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Read-Bytes([string] $Path, [int] $Maximum) {
    Assert-Direct $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -gt $Maximum) { throw 'Fixture input too large' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $request = $bytes.Length - $offset
            $script:readBytes += $request
            if ($script:readBytes -gt 4194304) { throw 'Fixture input budget' }
            $count = $stream.Read($bytes, $offset, $request)
            if ($count -eq 0) { throw 'Incomplete fixture input' }
            $offset += $count
        }
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Read-Json([string] $Path, [int] $Maximum = 65536) {
    $bytes = Read-Bytes $Path $Maximum
    return ([Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json)
}

function Save-Json([string] $Path, $Value) {
    Assert-Direct ([IO.Path]::GetDirectoryName($Path))
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress) + "`n")
    $script:writtenBytes += $bytes.Length
    if ($bytes.Length -gt 65536 -or $script:writtenBytes -gt 262144) { throw 'Fixture output budget' }
    $stream = [IO.File]::Open(($Path + '.pending'), 'CreateNew', 'Write', 'Read')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    [IO.File]::Move(($Path + '.pending'), $Path)
}

function Assert-Time([long] $Milliseconds) {
    if ($watch.ElapsedMilliseconds -ge $Milliseconds -or (Test-Path -LiteralPath "$root\cancel")) {
        throw 'Fixture deadline or cancellation'
    }
}

function Get-FailureDetails($Record) {
    $text = $Record.ToString() + "`n" + $Record.ScriptStackTrace
    return $text.Substring(0, [Math]::Min(4096, $text.Length))
}

function Wait-FixtureJobQuiescence($Job, [Collections.IDictionary] $Observation) {
    $Observation.jobQuiescent = $false
    $Observation.jobObservationCount = 0
    $Observation.jobObservedActive = $null
    $Observation.jobObservedTotal = $null
    $Observation.jobLastObservedMilliseconds = $null
    $Observation.jobDrainStartedMilliseconds = $watch.ElapsedMilliseconds
    try {
        while ($true) {
            Assert-Time 20000
            $Observation.jobQuiescent = $Job.ObserveFinalPublishQuiescence()
            $Observation.jobObservationCount = $Observation.jobObservationCount + 1
            $Observation.jobObservedActive = $Job.FinalPublishObservedActive
            $Observation.jobObservedTotal = $Job.FinalPublishObservedTotal
            $Observation.jobLastObservedMilliseconds = $watch.ElapsedMilliseconds
            Assert-Time 20000
            if ($Observation.jobQuiescent) { return }
            Start-Sleep -Milliseconds 25
        }
    } finally { $Observation.jobDrainEndedMilliseconds = $watch.ElapsedMilliseconds }
}

function New-Environment([string] $Working) {
    return @{
        SystemRoot = 'C:\Windows'; windir = 'C:\Windows'; SystemDrive = 'C:'
        TEMP = $Working; TMP = $Working; USERPROFILE = $Working
        PATH = 'C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0'
        PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
        PSModuleAnalysisCachePath = 'NUL'
        POWERSHELL_TELEMETRY_OPTOUT = '1'; DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    }
}

function Get-Arguments([string] $ChildMode, [string] $Selected) {
    return '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        "$root\Invoke-WindowsNamedGuardFixtures.ps1" + '" -Mode ' + $ChildMode +
        ' -CaseName ' + $Selected + ' -AuthoritySha256 ' + $AuthoritySha256
}

$authorityBytes = Read-Bytes "$root\authority.json" 65536
if ((Get-Hash $authorityBytes) -cne $AuthoritySha256) { throw 'Fixture authority changed' }
$authorityText = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes)
$authority = $authorityText | ConvertFrom-Json
if ($authorityText -cne (($authority | ConvertTo-Json -Depth 20 -Compress) + "`n") -or
    $authority.schema -cne 'named-guard-fixtures-0077-v1' -or
    $authority.accepted -ne $true -or $authority.action -cne '0077' -or
    $authority.countsBefore.preparation -ne 19 -or $authority.countsBefore.buildTest -ne 98 -or
    $authority.countsBefore.publication -ne 2 -or $authority.countsBefore.synthetic -ne 101 -or
    $authority.failedFixtureDispositionSha256 -cne '1ecb4ef1ec1c0eea1afeaa71c6e705dd3962e6998a582bc118780d983e812dcf' -or
    $authority.buildTestCharge -ne 1 -or $authority.syntheticCharge -ne 3) {
    throw 'Unaccepted fixture allocation'
}
if ((Get-Hash (Read-Bytes $PSCommandPath 65536)) -cne $authority.controllerSha256) {
    throw 'Fixture source changed'
}
if ((Get-Hash (Read-Bytes $shell 1048576)) -cne
    '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e') {
    throw 'Pinned fixture PowerShell changed'
}
$sequence = @('live')
if (@($authority.cases.PSObject.Properties.Name).Count -ne 1) { throw 'Fixture case allocation' }
foreach ($selected in $sequence) {
    if ($authority.cases.$selected -cnotmatch '^Local\\azureauth-final-publish-108-0077-[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$') {
        throw 'Unbound fixture Job name'
    }
}
if (@($sequence | ForEach-Object { $authority.cases.$_ } | Select-Object -Unique).Count -ne 1) {
    throw 'Repeated fixture Job name'
}
if ($authority.failure0072DispositionSha256 -cne
    'a4efab71cbd10564c70251826e28195eb09d3497454982c0f314c388a2a88439') {
    throw 'Missing accepted original 0072 disposition'
}
Assert-Time 10000

if ($Mode -eq 'Payload') {
    if ($CaseName -cne 'live') { throw 'Unallocated payload' }
    $directory = "$root\$CaseName"
    $identity = Read-Json "$directory\before-resume.json"
    $current = [Diagnostics.Process]::GetCurrentProcess()
    try {
        if ($identity.pid -ne $current.Id -or
            $identity.creationFileTime -cne $current.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -or
            $identity.jobName -cne $authority.cases.$CaseName -or $identity.resumed -ne $false) {
            throw 'Payload began without its durable original identity'
        }
        Save-Json "$directory\payload-started.json" @{
            identityObserved = $true; pid = $current.Id; counter = [Diagnostics.Stopwatch]::GetTimestamp().ToString()
        }
    } finally { $current.Dispose() }
    # A fixed bounded child; no output, network, account APIs or further process.
    while ($watch.ElapsedMilliseconds -lt 45000 -and -not (Test-Path -LiteralPath "$directory\release")) {
        Start-Sleep -Milliseconds 25
    }
    exit 0
}

$dll = Read-Bytes "$root\WindowsFinalPublishGuard.dll" 24576
if ($dll.Length -ne 24576 -or (Get-Hash $dll) -cne
    'a18302e4658afc08b564be23c9b52995fba85c1a3345fba19662008efe30ae58') {
    throw 'Accepted actual guard changed'
}
[void][Reflection.Assembly]::Load($dll)

if ($Mode -eq 'Case') {
    if ($CaseName -cnotin $sequence) { throw 'Missing fixture case' }
    $directory = "$root\$CaseName"
    $name = $authority.cases.$CaseName
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 20L * [Diagnostics.Stopwatch]::Frequency
    $current = [Diagnostics.Process]::GetCurrentProcess()
    try { $session = $current.SessionId } finally { $current.Dispose() }
    $final = $null
    $caseResult = [ordered]@{ case = $CaseName; passed = $false; failureType = $null }
    try {
        if ($CaseName -cnotin @('missing', 'session')) {
            $final = [WindowsValidationJob]::CreateFinalPublishDraft($watch, $deadline, $name)
            if (-not $final.NamedJobRightsVerified -or $final.JobName -cne $name) { throw 'Named rights not verified' }
        }
        if ($CaseName -eq 'collision') {
            $collision = $false
            $unexpected = $null
            try { $unexpected = [WindowsValidationJob]::CreateFinalPublishDraft($watch, $deadline, $name) }
            catch {
                $cause = $_.Exception
                while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
                $collision = $cause -is [InvalidOperationException] -and $cause.Message -ceq 'Final Job name already exists'
            } finally { if ($null -ne $unexpected) { $unexpected.Dispose() } }
            if (-not $collision -or $final.ActiveProcesses -ne 0) { throw 'Collision did not preserve original Job' }
            $caseResult.collisionRejected = $true
        }
        if ($CaseName -cin @('live', 'disposed', 'callback')) {
            $callbackState = @{ invoked = $false }
            $beforeResume = [Action]{
                Assert-Time 20000
                Save-Json "$directory\before-resume.json" @{
                    jobName = $final.JobName; sessionId = $final.JobSessionId; pid = $final.Child.Id
                    creationFileTime = $final.RootCreationFileTime; resumed = $false
                    authoritySha256 = $AuthoritySha256; counter = [Diagnostics.Stopwatch]::GetTimestamp().ToString()
                }
                $callbackState.invoked = $true
                if ($CaseName -eq 'callback') { throw 'Intentional fixture callback failure' }
            }
            $caught = $false
            try {
                $actionWatch = [Diagnostics.Stopwatch]::StartNew()
                $final.StartFinalPublishDraft($shell, (Get-Arguments 'Payload' $CaseName), $directory,
                    (New-Environment $directory), $actionWatch, $beforeResume)
            } catch { if ($CaseName -ne 'callback') { throw }; $caught = $true }
            if ($CaseName -eq 'callback') {
                if (-not $caught -or -not $callbackState.invoked -or $final.FinalPublishExecutionMayHaveBegun -or
                    -not $final.NeverResumedRootTerminationRequested -or -not $final.NeverResumedRootTerminationSucceeded -or
                    -not $final.NeverResumedRootExitConfirmed -or -not $final.Child.HasExited -or
                    (Test-Path -LiteralPath "$directory\payload-started.json")) {
                    throw 'Original-handle never-resumed exit is unestablished'
                }
                $caseResult.neverResumedExitConfirmed = $true
                $caseResult.terminationRequested = $final.NeverResumedRootTerminationRequested
                $caseResult.terminationSucceeded = $final.NeverResumedRootTerminationSucceeded
                $caseResult.payloadExitObserved = $true
                $caseResult.payloadExitCode = $final.Child.ExitCode
                $caseResult.completionStage = 'wait-job-quiescence'
                Wait-FixtureJobQuiescence $final $caseResult
                $caseResult.completionStage = 'complete'
            } else {
                while (-not (Test-Path -LiteralPath "$directory\payload-started.json")) {
                    Assert-Time 15000
                    if ($final.Child.HasExited) { throw 'Payload exited before observation' }
                    Start-Sleep -Milliseconds 25
                }
                if ($CaseName -eq 'disposed') { $final.Dispose(); $final = $null }
            }
        }
        if ($CaseName -ne 'callback') {
            $expectedSession = $session
            if ($CaseName -eq 'session') { $expectedSession = -1 }
            $observationWatch = [Diagnostics.Stopwatch]::StartNew()
            $observed = [WindowsValidationJob]::ObserveNamedFinalPublish($name, $expectedSession,
                $observationWatch, $deadline, [Action[Collections.IDictionary]]{
                    param($value)
                    Save-Json "$directory\named-query.json" $value
                })
            $caseResult.queryStatus = $observed['status']
            if ($CaseName -eq 'missing') {
                if ($observed['status'] -cne 'not-found' -or $observed['openError'] -ne 2) { throw 'Missing-name mismatch' }
            } elseif ($CaseName -eq 'session') {
                if ($observed['status'] -cne 'session-mismatch' -or $null -ne $observed['audit'] -or
                    $null -ne $observed['openError']) { throw 'Session gate mismatch' }
            } else {
                $audit = $observed['audit']
                if ($observed['status'] -cne 'opened-query-only' -or $null -eq $audit -or
                    -not $audit['complete'] -or -not $audit['querySucceeded'] -or $audit['atomic']) {
                    throw 'Named observation incomplete'
                }
                $expectedMembers = 0
                if ($CaseName -cin @('live', 'disposed')) { $expectedMembers = 1 }
                if ($audit['assigned'] -ne $audit['returned'] -or
                    $audit['returned'] -ne @($audit['members']).Count -or
                    $audit['returned'] -lt $expectedMembers -or $audit['returned'] -gt 8 -or
                    ($expectedMembers -eq 0 -and $audit['returned'] -ne 0)) { throw 'Unexpected fixture Job membership' }
                if ($expectedMembers -eq 1) {
                    $identity = Read-Json "$directory\before-resume.json"
                    $matches = @($audit['members'] | Where-Object {
                        $_['pid'] -eq $identity.pid -and $_['creationFileTime'] -ceq $identity.creationFileTime
                    })
                    if ($matches.Count -ne 1) { throw 'Exact payload member is missing or duplicated' }
                    $member = $matches[0]
                    if ($member['pid'] -ne $identity.pid -or $member['creationFileTime'] -cne $identity.creationFileTime -or
                        $member['inJob'] -ne $true -or $member['status'] -cne 'observed-member' -or
                        $member['imageName'] -ine 'powershell.exe') { throw 'Reopened member identity mismatch' }
                    $caseResult.exactMemberObserved = $true
                }
            }
        }
        if ($CaseName -eq 'live') {
            $release = [IO.File]::Open("$directory\release", 'CreateNew', 'Write', 'Read')
            $release.Dispose()
            $caseResult.completionStage = 'wait-payload-exit'
            $caseResult.payloadExitObserved = $false
            $caseResult.payloadExitCode = $null
            while (-not $final.Child.HasExited) { Assert-Time 20000; Start-Sleep -Milliseconds 25 }
            $caseResult.payloadExitObserved = $true
            $caseResult.payloadExitCode = $final.Child.ExitCode
            if ($caseResult.payloadExitCode -ne 0) { throw 'Live fixture payload exited unsuccessfully' }
            # Original root completion does not establish whole-Job completion.
            $caseResult.completionStage = 'wait-job-quiescence'
            Wait-FixtureJobQuiescence $final $caseResult
            $caseResult.completionStage = 'complete'
        }
        Assert-Time 20000
        $caseResult.passed = $true
    } catch {
        $caseResult.failureType = $_.Exception.GetType().FullName
        $caseResult.failureDetails = Get-FailureDetails $_
    }
    finally {
        if ($null -ne $final) { $final.Dispose() }
        Save-Json "$directory\case-result.json" $caseResult
    }
    if (-not $caseResult.passed) { exit 1 }
    exit 0
}

$result = [ordered]@{ schema = 'named-guard-fixtures-result-v1'; passed = $false; quiescent = $false
    launcherFailureCases = @(); authoritySha256 = $AuthoritySha256; failureType = $null; cases = @() }
try {
    $controller = [Diagnostics.Process]::GetCurrentProcess()
    try {
        Save-Json "$root\windows-started.json" @{
            schema = 'named-guard-fixtures-started-v1'; authoritySha256 = $AuthoritySha256
            buildTestCharge = 1; syntheticCharge = 3; controllerPid = $PID
            controllerCreationFileTime = $controller.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
            controllerSession = $controller.SessionId
        }
    } finally { $controller.Dispose() }
    foreach ($selected in $sequence) {
        Assert-Time 180000
        $directory = "$root\$selected"
        if (Test-Path -LiteralPath $directory) { throw 'Fixture case already exists' }
        [void][IO.Directory]::CreateDirectory($directory)
        $outer = [WindowsValidationJob]::new()
        $completed = $false
        $stopped = $false
        $reads = $null
        $payload = $null
        $caseWatch = [Diagnostics.Stopwatch]::StartNew()
        $containment = [ordered]@{ case = $selected; jobName = $outer.JobName; sessionId = $outer.JobSessionId
            rootExit = $false; exitCode = $null; activeBeforeStop = $null; activeAfterStop = $null
            total = $null; terminationRequested = $false; terminationSucceeded = $false; quiescent = $false
            stdoutEof = $false; stderrEof = $false
            targetIdentity = $null; targetHandleHeld = $false; targetAliveBeforeStop = $false
            targetExitedAfterStop = $false; targetExitCode = $null; targetObservationError = $null }
        try {
            Save-Json "$directory\outer-job.json" $containment
            $outer.Start($shell, (Get-Arguments 'Case' $selected), $directory, (New-Environment $directory))
            Save-Json "$directory\outer-root.json" @{
                pid = $outer.Child.Id; creationFileTime = $outer.Child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
                jobName = $outer.JobName; sessionId = $outer.JobSessionId
            }
            # Fixed sources are silent. A single bounded async read per stream rejects any output.
            $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
            $reads = @($outer.Output.BaseStream.ReadAsync($buffers[0], 0, 4096),
                $outer.Error.BaseStream.ReadAsync($buffers[1], 0, 4096))
            while (-not $outer.Child.HasExited) {
                Assert-Time 180000
                if ($caseWatch.ElapsedMilliseconds -ge 20000) { throw 'Fixture case timeout' }
                foreach ($read in $reads) {
                    if ($read.IsCompleted -and $read.GetAwaiter().GetResult() -ne 0) { throw 'Unexpected fixture output' }
                }
                Start-Sleep -Milliseconds 25
            }
            $containment.rootExit = $true
            $containment.exitCode = $outer.Child.ExitCode
            $completed = $true
            if ($selected -eq 'disposed' -and $containment.exitCode -eq 0) {
                $identity = Read-Json "$directory\before-resume.json"
                if ($identity.authoritySha256 -cne $AuthoritySha256 -or
                    $identity.jobName -cne $authority.cases.$selected -or
                    $identity.sessionId -ne $outer.JobSessionId -or $identity.resumed -ne $false) {
                    throw 'Disposed target authority mismatch'
                }
                $payload = [Diagnostics.Process]::GetProcessById([int]$identity.pid)
                if ($payload.Handle -eq [IntPtr]::Zero) { throw 'Disposed target handle unavailable' }
                if ($payload.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -cne $identity.creationFileTime -or
                    $payload.SessionId -ne $identity.sessionId) { throw 'Disposed target identity mismatch' }
                $containment.targetIdentity = $identity
                $containment.targetHandleHeld = $true
            }
        } finally {
            try {
                # Observation failure must never bypass the original outer Stop.
                try {
                    if ($selected -eq 'disposed') {
                        if ($null -eq $payload -or -not $containment.targetHandleHeld) {
                            throw 'Disposed target identity was not established'
                        }
                        $containment.targetAliveBeforeStop = -not $payload.HasExited
                    }
                } catch { $containment.targetObservationError = Get-FailureDetails $_ }
                finally {
                    $stopped = $outer.Stop()
                }
                # This Job contains only the fixed fixture host and its fixed payload.
                # Final publication with potentially shared compiler work never uses this policy.
                $containment.activeBeforeStop = $outer.ActiveBeforeStop
                $containment.activeAfterStop = $outer.ActiveAfterStop
                $containment.total = $outer.TotalAfterStop
                $containment.terminationRequested = $outer.TerminationRequested
                $containment.terminationSucceeded = $outer.TerminationSucceeded
                $containment.quiescent = $stopped
                if ($selected -eq 'disposed' -and $containment.targetHandleHeld) {
                    try {
                        $containment.targetExitedAfterStop = $payload.HasExited
                        if ($containment.targetExitedAfterStop) { $containment.targetExitCode = $payload.ExitCode }
                    } catch { $containment.targetObservationError = Get-FailureDetails $_ }
                }
                if ($stopped -and $null -ne $reads) {
                    while (-not ($reads[0].IsCompleted -and $reads[1].IsCompleted)) {
                        if ($caseWatch.ElapsedMilliseconds -ge 30000 -or $watch.ElapsedMilliseconds -ge 180000) {
                            throw 'Fixture output completion unestablished'
                        }
                        Start-Sleep -Milliseconds 25
                    }
                    $containment.stdoutEof = $reads[0].GetAwaiter().GetResult() -eq 0
                    $containment.stderrEof = $reads[1].GetAwaiter().GetResult() -eq 0
                }
                Save-Json "$directory\containment.json" $containment
            } finally {
                try { if ($null -ne $payload) { $payload.Dispose() } }
                finally { $outer.Dispose() }
            }
        }
        if (-not $stopped -or -not $completed -or $containment.exitCode -ne 0 -or
            -not $containment.stdoutEof -or -not $containment.stderrEof) { throw 'Fixture containment or host failed' }
        $caseResult = Read-Json "$directory\case-result.json"
        if ($caseResult.passed -ne $true -or $caseResult.case -cne $selected) { throw 'Fixture assertion failed' }
        $expectedTotal = 1
        if ($selected -cin @('live', 'disposed', 'callback')) { $expectedTotal = 2 }
        if ($containment.total -lt $expectedTotal -or $containment.total -gt 8) { throw 'Fixture Job total outside its bound' }
        if ($selected -eq 'disposed' -and ($containment.activeBeforeStop -lt 1 -or
            $containment.activeBeforeStop -gt 8 -or $containment.activeAfterStop -ne 0 -or
            -not $containment.targetHandleHeld -or -not $containment.targetAliveBeforeStop -or
            -not $containment.targetExitedAfterStop -or $containment.targetExitCode -ne 1 -or
            $null -ne $containment.targetObservationError -or
            -not $containment.terminationRequested -or -not $containment.terminationSucceeded)) {
            throw 'Post-disposal outer termination was not observed'
        }
        if ($caseWatch.ElapsedMilliseconds -ge 30000) { throw 'Guard case completion deadline' }
        $result.cases += $containment
    }
    Assert-Time 300000
    $result.quiescent = $true
    $result.passed = $true
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureDetails = Get-FailureDetails $_
}
finally { Save-Json "$root\windows-result.json" $result }
# Only the corrected live case is allocated; no other case or negative driver runs.
# The original 300-second controller clock also bounds setup and persistence.
Assert-Time 310000
if (-not $result.passed) { exit 1 }
exit 0

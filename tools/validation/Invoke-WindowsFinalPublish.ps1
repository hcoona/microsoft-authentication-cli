# PRIVATE SOURCE CANDIDATE: not a controller admitted by any accepted protocol.
param()
$script:FinalPublishDraftOnly = $true
if ($script:FinalPublishDraftOnly) { throw 'DRAFT_ONLY: final-publish integration and guard build are unadmitted' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# No parameterized top-level launcher exists. Even removing the outer draft refusal
# leaves both admission hooks fail-closed until exact future source is reviewed.
function Assert-ExactFinalPublishAdmission($Binding) {
    throw 'UNBOUND: accepted protocol/source/graph/recipe/guard/capacity/reservation are required'
}

function Assert-ExactFinalPublishPostconditions($Binding, $Result) {
    throw 'UNBOUND: exact protected-input, diagnostic, artifact and original-completion checks are required'
}

function Save-Json([string] $Path, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Save-CompleteJson([string] $Path, $Value) {
    Save-Json ($Path + '.pending') $Value
    [IO.File]::Move(($Path + '.pending'), $Path)
}

function Save-Bytes([string] $Path, [byte[]] $Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-FinalPublishOutput($Process, $Streams, [int] $Seconds, $Watch, $ControllerWatch) {
    $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
    $tasks = @($Streams[0].ReadAsync($buffers[0], 0, 4096), $Streams[1].ReadAsync($buffers[1], 0, 4096))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $done = @($false, $false)
    $disposition = 'read-failure'
    try {
        while (-not ($Process.HasExited -and $done[0] -and $done[1])) {
            if (Test-Path -LiteralPath "$action\cancel") { $disposition = 'cancelled'; throw 'Caller cancellation' }
            if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { $disposition = 'controller-timeout'; throw 'Controller expired' }
            if ($Watch.Elapsed.TotalSeconds -ge $Seconds) { $disposition = 'timeout'; throw 'Execution timeout' }
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true } else {
                        if ($data[0].Length + $data[1].Length + $count -gt 8388608) {
                            $disposition = 'output-limit'; throw 'Output limit'
                        }
                        $data[$index].Write($buffers[$index], 0, $count)
                        $tasks[$index] = $Streams[$index].ReadAsync($buffers[$index], 0, 4096)
                    }
                }
            }
            Start-Sleep -Milliseconds 25
        }
        $disposition = 'complete'
    } finally {
        # Preserve the bounded prefix through a thrown timeout/cancellation/read failure.
        $script:capture = [pscustomobject]@{
            stdout = $data[0].ToArray(); stderr = $data[1].ToArray()
            seconds = [Math]::Round($Watch.Elapsed.TotalSeconds, 3); disposition = $disposition
        }
        $data[0].Dispose(); $data[1].Dispose()
    }
    return $script:capture
}

# Inserted in the already disabled final-publish controller before its invocation.
# All actual preparation and artifact acceptance identities remain unbound.
# They are outputs of the still-rejecting final admission authority loader, not
# self-referential source hash literals to insert into this same file.
$script:AcceptedFinalGuard = @{
    actionNumber = $null; sourceSha256 = $null; dllSha256 = $null
    guardBuildSha256 = $null; preparationWindowsResultSha256 = $null
    preparationWslResultSha256 = $null; preparationReservationSha256 = $null
    invocationSha256 = $null; compilerReceiptSha256 = $null
    artifactAcceptancePath = $null; artifactAcceptanceSha256 = $null
    expectedAssemblyFullName = $null; acceptedLoaderSourceSha256 = $null
}

function Assert-GuardDirect([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse guard input' }
        if ($item.PSIsContainer) { $item = $item.Parent } else { $item = $item.Directory }
    }
}

function Assert-GuardHash([string] $Path, [string] $Expected) {
    if ($Expected -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound final guard hash' }
    Assert-GuardDirect $Path
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected) {
        throw 'Final guard identity changed'
    }
}

function Import-ExactFinalGuard($Binding, $ControllerWatch) {
    if ($script:FinalPublishDraftOnly) { throw 'DRAFT_ONLY: final guard load is not admitted' }
    foreach ($value in $script:AcceptedFinalGuard.Values) {
        if ($null -eq $value) { throw 'UNBOUND: original preparation and artifact acceptance' }
    }
    if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired before loader' }
    if ($script:AcceptedFinalGuard.actionNumber -cnotmatch '^[0-9]{4}$' -or
        $script:AcceptedFinalGuard.actionNumber -ceq '0000') { throw 'Invalid guard preparation action' }
    $root = 'C:\Temp\azureauth-windows-slice-108\actions\' + $script:AcceptedFinalGuard.actionNumber
    $source = "$root\final-guard\source\WindowsValidationJob.cs"
    $dll = "$root\final-guard\WindowsFinalPublishGuard.dll"
    # Full final admission verifies the original WSL result and its linked original
    # Windows reservation. This loader never treats the WSL proxy's exit as proof.
    if ($Binding.guardPreparationWslResultSha256 -cne $script:AcceptedFinalGuard.preparationWslResultSha256 -or
        $Binding.guardArtifactAcceptanceSha256 -cne $script:AcceptedFinalGuard.artifactAcceptanceSha256) {
        throw 'Final admission does not bind accepted preparation'
    }
    Assert-GuardHash $PSCommandPath $script:AcceptedFinalGuard.acceptedLoaderSourceSha256
    Assert-GuardHash "$root\started.json" $script:AcceptedFinalGuard.preparationReservationSha256
    Assert-GuardHash "$root\invocation.json" $script:AcceptedFinalGuard.invocationSha256
    Assert-GuardHash "$root\compiler.json" $script:AcceptedFinalGuard.compilerReceiptSha256
    Assert-GuardHash "$root\windows-result.json" $script:AcceptedFinalGuard.preparationWindowsResultSha256
    Assert-GuardHash "$root\guard-build.json" $script:AcceptedFinalGuard.guardBuildSha256
    Assert-GuardHash $script:AcceptedFinalGuard.artifactAcceptancePath $script:AcceptedFinalGuard.artifactAcceptanceSha256
    Assert-GuardHash $source $script:AcceptedFinalGuard.sourceSha256
    Assert-GuardHash $dll $script:AcceptedFinalGuard.dllSha256
    $build = [IO.File]::ReadAllText("$root\guard-build.json") | ConvertFrom-Json
    if ($build.schema -cne 'final-guard-build-v1' -or
        $build.reservationSha256 -cne $script:AcceptedFinalGuard.preparationReservationSha256 -or
        $build.windowsResultSha256 -cne $script:AcceptedFinalGuard.preparationWindowsResultSha256 -or
        $build.invocationSha256 -cne $script:AcceptedFinalGuard.invocationSha256 -or
        $build.sourceSha256 -cne $script:AcceptedFinalGuard.sourceSha256 -or
        $build.dllSha256 -cne $script:AcceptedFinalGuard.dllSha256 -or $build.dllPath -cne $dll) {
        throw 'Compiled guard binding changed'
    }
    # Original guard-build stays artifactAccepted=false. A later independent review
    # binds it without rewriting that original compiler/collector evidence.
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        if ($null -ne $assembly.GetType('WindowsValidationJob', $false)) { throw 'A guard type is already loaded' }
    }
    if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired before assembly load' }
    Add-Type -Path $dll -ErrorAction Stop -WarningAction Stop
    $found = @()
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $type = $assembly.GetType('WindowsValidationJob', $false)
        if ($null -ne $type) { $found += $type }
    }
    if ($found.Count -ne 1) { throw 'Missing or ambiguous loaded guard type' }
    $loaded = $found[0].Assembly
    if (-not [string]::Equals($loaded.Location, $dll, [StringComparison]::OrdinalIgnoreCase) -or
        $loaded.FullName -cne $script:AcceptedFinalGuard.expectedAssemblyFullName) { throw 'Loaded guard identity changed' }
    Assert-GuardHash $dll $script:AcceptedFinalGuard.dllSha256
    if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired after assembly load' }
    return @{ path = $loaded.Location; fullName = $loaded.FullName
              dllSha256 = $script:AcceptedFinalGuard.dllSha256
              guardBuildSha256 = $script:AcceptedFinalGuard.guardBuildSha256 }
}

function Invoke-FinalPublishCandidate($Binding, $ControllerWatch) {
    if ($script:FinalPublishDraftOnly) { throw 'DRAFT_ONLY: no final-publish execution' }
    Assert-ExactFinalPublishAdmission $Binding
    $loadedGuard = Import-ExactFinalGuard $Binding $ControllerWatch
    Save-CompleteJson ($Binding.actionPath + '\guard-load.json') $loadedGuard
    # The future admission hook supplies only the exact v4 fixed recipe, verified
    # dedicated output paths, loaded guard identity and original running clock.
    $action = $Binding.actionPath
    $guard = $null
    $script:capture = $null
    $watch = $null
    $normal = $false
    $result = [ordered]@{
        safetyStop = $true; quiescent = $false; normalCompletion = $false
        artifactEligible = $false; continuation_allowed = $false
        exitCode = -1; captureCompleted = $false; captureDisposition = 'not-started'
        jobTerminationRequested = $false; jobTerminationSucceeded = $false
        rootTerminationRequested = $false; rootTerminationSucceeded = $false
        neverResumedRootExitConfirmed = $false; executionMayHaveBegun = $false
        retainedLiveWorkOrUnknown = $true; stage = 'admission'
        reservationSha256 = $Binding.reservationSha256
    }
    try {
        if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired before guard' }
        if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation before guard' }
        $guard = [WindowsValidationJob]::CreateFinalPublishDraft($ControllerWatch)
        $result.stage = 'subject'
        if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation before subject' }
        # This clock starts immediately before root creation and never restarts.
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $guard.StartFinalPublishDraft($Binding.executable, $Binding.nativeArguments, $Binding.workingDirectory, $Binding.environment, $watch)
        Save-Json "$action\subject.json" @{
            pid = $guard.Child.Id; started = $guard.Child.StartTime.ToUniversalTime().ToString('o')
        }
        $script:capture = Read-FinalPublishOutput $guard.Child @($guard.Output.BaseStream, $guard.Error.BaseStream) 600 $watch $ControllerWatch
        $result.exitCode = $guard.Child.ExitCode
        if ($result.exitCode -ne 0) { throw 'Final publish root failed' }
        $result.stage = 'normal-drain'
        $drainEnd = [Math]::Min(600000L, $watch.ElapsedMilliseconds + 2000L)
        while (-not $guard.ObserveFinalPublishQuiescence()) {
            if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation during final drain' }
            if ($watch.ElapsedMilliseconds -ge $drainEnd -or $ControllerWatch.ElapsedMilliseconds -ge 700000) {
                throw 'Final publish normal drain expired'
            }
            Start-Sleep -Milliseconds 25
        }
        if ($watch.ElapsedMilliseconds -gt ($drainEnd + 100) -or $watch.ElapsedMilliseconds -ge 600000 -or
            $ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Final publish observation exceeded original bound' }
        if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation at final observation' }
        if ($guard.TerminationRequested -or $guard.NeverResumedRootTerminationRequested) { throw 'Termination cannot establish success' }
        $result.activeProcessesAtNormalExit = $guard.FinalPublishObservedActive
        $result.captureCompleted = $true
        $result.captureDisposition = $script:capture.disposition
        # This source-only integration hook currently always rejects. A future
        # implementation must bind exact diagnostics/inputs/artifacts before success.
        Assert-ExactFinalPublishPostconditions $Binding $result
        $normal = $true
        $result.stage = 'normal-observed'
    } catch {
        $result.failureType = $_.Exception.GetType().FullName
        $result.failureLine = $_.InvocationInfo.ScriptLineNumber
        $normal = $false
    } finally {
        # Never call Stop, Kill, TerminateJobObject or the old emergency script.
        # The guard itself handles only a proven-never-resumed root during Start.
        if ($null -ne $guard) {
            $result.executionMayHaveBegun = $guard.FinalPublishExecutionMayHaveBegun
            $result.rootTerminationRequested = $guard.NeverResumedRootTerminationRequested
            $result.rootTerminationSucceeded = $guard.NeverResumedRootTerminationSucceeded
            $result.neverResumedRootExitConfirmed = $guard.NeverResumedRootExitConfirmed
            try {
                $result.quiescent = $guard.ObserveFinalPublishQuiescence()
                if ($ControllerWatch.ElapsedMilliseconds -ge 700000 -or
                    ($null -ne $watch -and $watch.ElapsedMilliseconds -ge 600000)) { $normal = $false }
            } catch {
                $result.quiescent = $false
                $result.accountingFailureType = $_.Exception.GetType().FullName
                $normal = $false
            }
            $result.lastJobActive = $guard.FinalPublishObservedActive
            $result.lastJobTotal = $guard.FinalPublishObservedTotal
            try { $guard.Dispose() } catch {
                $normal = $false
                $result.closeFailureType = $_.Exception.GetType().FullName
            }
        }
        # Zero after any earlier failure never erases that failure.
        $result.retainedLiveWorkOrUnknown = -not $result.quiescent
        $result.normalCompletion = $normal -and $result.quiescent -and -not $result.rootTerminationRequested
        $result.safetyStop = -not $result.normalCompletion
        # Eligibility and continuation also need the original outer completion and
        # independent actual-artifact acceptance. This candidate never grants either.
        $result.artifactEligible = $false
        $result.continuation_allowed = $false
        if ($null -ne $watch) { $result.seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3) }
        if ($null -ne $script:capture) {
            $result.captureDisposition = $script:capture.disposition
            $result.stdoutBytes = $script:capture.stdout.Length
            $result.stderrBytes = $script:capture.stderr.Length
            # Controller-owned bounded byte snapshots only; no subject-file survey
            # or reading mutable compiler outputs while retained work may be live.
            Save-Bytes "$action\stdout.bin" $script:capture.stdout
            Save-Bytes "$action\stderr.bin" $script:capture.stderr
        }
        $result.ended = (Get-Date).ToUniversalTime().ToString('o')
        Save-CompleteJson "$action\windows-result.json" $result
    }
    return $result
}

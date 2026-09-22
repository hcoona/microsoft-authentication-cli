# Dot-sourced by the admitted 0103 controller; no extra observer/helper process.
$publicationFlags = [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic
$publicationOpen = [WindowsValidationJob].GetMethod('OpenJobObject', $publicationFlags)
$publicationMember = [WindowsValidationJob].GetMethod('IsProcessInJob', $publicationFlags)
if ($null -eq $publicationOpen -or $null -eq $publicationMember) { throw 'Missing accepted membership declarations' }

function Assert-PublicationFixtureTime($CaseWatch, [int] $Limit = 40000) {
    Assert-Time 300000
    if ($CaseWatch.ElapsedMilliseconds -ge $Limit) { throw 'Publication fixture deadline' }
}

function Read-PublicationJournal([string] $Directory) {
    $raw = Read-Bytes "$Directory\launcher.jsonl" 65536
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($raw)
    if (-not $text.EndsWith("`n")) { throw 'Incomplete publication journal line' }
    return @($text.TrimEnd([char]10).Split([char]10) | ForEach-Object { $_ | ConvertFrom-Json })
}

function Open-PublicationSubject($Identity, [string] $CaseName) {
    if ($Identity.authoritySha256 -cne $AuthoritySha256 -or $Identity.case -cne $CaseName -or
        $Identity.creationFileTime -cnotmatch '^[1-9][0-9]{0,18}$' -or $Identity.pid -le 0) {
        throw 'Unbound synthetic process identity'
    }
    $process = [Diagnostics.Process]::GetProcessById([int]$Identity.pid)
    try {
        [void]$process.Handle
        if ($process.HasExited -or $process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -cne $Identity.creationFileTime -or
            $process.SessionId -ne $Identity.session) { throw 'Synthetic process incarnation changed' }
        return $process
    } catch { $process.Dispose(); throw }
}

function Assert-PublicationMembership($Subjects, [string] $Name, $Candidate) {
    $value = $publicationOpen.Invoke($null, [object[]]@([uint32]4, $false, $Name))
    $job = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]$value, $true)
    try {
        if ($job.IsInvalid) { throw 'Original fixture Job unavailable' }
        foreach ($subject in $Subjects) {
            $arguments = [object[]]@($subject.Handle, $job, $false)
            if (-not $publicationMember.Invoke($null, $arguments) -or -not $arguments[2]) {
                throw 'Known synthetic incarnation is outside the candidate Job'
            }
        }
    } finally { $job.Dispose() }
    # No observer Job handle remains when the candidate exits. Otherwise this test
    # could mask an erroneous KILL_ON_JOB_CLOSE flag in the candidate.
    if ($Candidate.HasExited) { throw 'Candidate exited before observer Job handle closure' }
}

function Invoke-LauncherFailureCases {
    $results = @()
    foreach ($name in @('journal-cancel')) {
        Assert-Time 260000
        $caseWatch = [Diagnostics.Stopwatch]::StartNew()
        $spec = $authority.failureCases.$name
        $directory = [string]$spec.root
        $number = $directory.Substring($directory.Length - 4)
        $jobName = 'Local\azureauth-publication-108-' + $number + '-' + $spec.suffix
        $candidate = $null
        $subjects = @()
        $locked = $null
        $lockHeld = $false
        $result = [ordered]@{ case = $name; passed = $false; jobName = $jobName; quiescent = $false }
        try {
            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = "$root\WindowsPublicationJobLauncher.exe"
            $start.Arguments = '--publication-fixture ' + $name + ' "' + $directory + '" ' +
                $spec.suffix + ' ' + $AuthoritySha256 + ' ' + $authority.failureControllerSha256 +
                ' ' + $spec.reservationSha256 + ' ' + $spec.invocationSha256
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $start.WorkingDirectory = $directory
            $start.EnvironmentVariables.Clear()
            foreach ($entry in (New-Environment $directory).GetEnumerator()) {
                $start.EnvironmentVariables.Add($entry.Key, $entry.Value)
            }
            $candidate = [Diagnostics.Process]::new()
            $candidate.StartInfo = $start
            if (-not $candidate.Start()) { throw 'Publication fixture launcher creation rejected' }
            [void]$candidate.Handle
            $result.launcherIdentity = @{
                pid = $candidate.Id; creationFileTime = $candidate.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
                session = $candidate.SessionId
            }
            $stdout = $candidate.StandardOutput.ReadToEndAsync()
            $stderr = $candidate.StandardError.ReadToEndAsync()
            if ($name -cne 'pre-resume') {
                while (-not (Test-Path -LiteralPath "$directory\root-ready.json")) {
                    Assert-PublicationFixtureTime $caseWatch 10000
                    if ($candidate.HasExited) { throw 'Candidate exited before synthetic readiness' }
                    Start-Sleep -Milliseconds 25
                }
                $ready = Read-Json "$directory\root-ready.json" 4096
                $subjects += Open-PublicationSubject $ready $name
                $result.rootIdentity = $ready
                if ($name -cne 'resume-unknown') {
                    $descendant = Read-Json "$directory\descendant-ready.json" 4096
                    if ($ready.descendantPid -ne $descendant.pid -or
                        $ready.descendantCreationFileTime -cne $descendant.creationFileTime) { throw 'Descendant readiness join changed' }
                    $subjects += Open-PublicationSubject $descendant $name
                    $result.descendantIdentity = $descendant
                }
                Assert-PublicationFixtureTime $caseWatch 10000
                Assert-PublicationMembership $subjects $jobName $candidate
                Assert-PublicationFixtureTime $caseWatch 10000
                $result.observerJobClosedBeforeCandidateExit = $true
                if ($name -ceq 'journal-cancel') {
                    Assert-Direct "$directory\launcher.jsonl"
                    $locked = [IO.File]::Open("$directory\launcher.jsonl", 'Open', 'Read', 'ReadWrite')
                    # Read through this already-held, writer-compatible handle.
                    # The ordinary completed-journal reader keeps its stricter sharing.
                    Assert-PublicationFixtureTime $caseWatch 10000
                    $prefixLength = $locked.Length
                    if ($prefixLength -le 0 -or $prefixLength -gt 65536) { throw 'Invalid live journal prefix length' }
                    $prefixBytes = [byte[]]::new([int]$prefixLength)
                    $prefixOffset = 0
                    while ($prefixOffset -lt $prefixBytes.Length) {
                        Assert-PublicationFixtureTime $caseWatch 10000
                        $request = $prefixBytes.Length - $prefixOffset
                        $script:readBytes += $request
                        if ($script:readBytes -gt 4194304) { throw 'Fixture input budget' }
                        $count = $locked.Read($prefixBytes, $prefixOffset, $request)
                        Assert-PublicationFixtureTime $caseWatch 10000
                        if ($count -eq 0) { throw 'Incomplete live journal prefix' }
                        $prefixOffset += $count
                    }
                    $prefixText = [Text.UTF8Encoding]::new($false, $true).GetString($prefixBytes)
                    if (-not $prefixText.EndsWith("`n")) { throw 'Incomplete live journal line' }
                    $prefix = @($prefixText.TrimEnd([char]10).Split([char]10) | ForEach-Object { $_ | ConvertFrom-Json })
                    if ($prefix.Count -ne 5 -or $prefix[-1].event -cne 'publication-resumed') {
                        throw 'Journal fault requires the complete resumed startup prefix'
                    }
                    Assert-PublicationFixtureTime $caseWatch 10000
                    $locked.Lock(0, 65536)
                    $lockHeld = $true
                    Assert-PublicationFixtureTime $caseWatch 10000
                    if ($locked.Length -ne $prefixLength) { throw 'Live journal prefix changed before lock' }
                    $result.journalLockAcquired = $true
                    Save-Json "$directory\cancel" @{ cancelled = $true }
                } elseif ($name -ceq 'normal' -or $name -ceq 'overflow' -or $name -ceq 'resume-unknown') {
                    Save-Json "$directory\release" @{ release = $true }
                }
                $result.triggerElapsedMilliseconds = $caseWatch.ElapsedMilliseconds
            }
            while (-not $candidate.HasExited -or -not $stdout.IsCompleted -or -not $stderr.IsCompleted) {
                Assert-PublicationFixtureTime $caseWatch 25000
                Start-Sleep -Milliseconds 25
            }
            $result.launcherExit = $candidate.ExitCode
            $result.stdout = $stdout.GetAwaiter().GetResult()
            $result.stderr = $stderr.GetAwaiter().GetResult()
            $result.stdoutEof = $true
            $result.stderrEof = $true
            $expectedExit = 1
            if ($name -ceq 'normal') { $expectedExit = 0 }
            if ($candidate.ExitCode -ne $expectedExit -or $result.stdout.Length -ne 0 -or $result.stderr.Length -gt 1024) {
                throw 'Unexpected publication fixture transport or exit'
            }
            if ($name -ceq 'journal-cancel') {
                if (-not $lockHeld -or $result.stderr -notmatch 'retainedLiveWorkOrUnknown=True; resumeAttempted=True') {
                    throw 'Missing bounded journal-failure fallback'
                }
                $result.journalLockHeldThroughCandidateExit = $true
                $locked.Unlock(0, 65536)
                $lockHeld = $false
            }
            $records = Read-PublicationJournal $directory
            $entry = $records[0]
            $suspended = @($records | Where-Object { $_.event -ceq 'publication-root-suspended' })
            if ($entry.event -cne 'publication-bootstrap' -or $entry.fixtureCase -cne $name -or
                $entry.jobName -cne $jobName -or $entry.authoritySha256 -cne $AuthoritySha256 -or
                $entry.reservationSha256 -cne $spec.reservationSha256 -or $entry.invocationSha256 -cne $spec.invocationSha256 -or
                $entry.pid -ne $result.launcherIdentity.pid -or
                $entry.creationFileTime -cne $result.launcherIdentity.creationFileTime -or
                $suspended.Count -ne 1 -or $suspended[0].inJob -ne $true) { throw 'Publication fixture journal identity changed' }
            if ($name -cne 'pre-resume' -and ($suspended[0].pid -ne $result.rootIdentity.pid -or
                $suspended[0].creationFileTime -cne $result.rootIdentity.creationFileTime)) { throw 'Suspended/root identity join failed' }
            if ($name -cne 'normal' -and $name -cne 'pre-resume') {
                # Positive survival after candidate owner exit, with every observer Job
                # handle already closed, is the no-kill-on-close observation.
                foreach ($subject in $subjects) {
                    if ($subject.HasExited) { throw 'Expected synthetic survivor did not outlive candidate owner' }
                }
                $result.allSubjectsAliveAfterCandidateExit = $true
                $result.survivalObservedMilliseconds = $caseWatch.ElapsedMilliseconds
            }
            if ($name -cne 'journal-cancel') {
                $retention = @($records | Where-Object { $_.event -ceq 'publication-retention' })
                $closure = @($records | Where-Object { $_.event -ceq 'publication-operating-interval-end' })
                $terminal = @($records | Where-Object { $_.event -ceq 'publication-launcher-exit' })
                if ($retention.Count -ne 1 -or $closure.Count -ne 1 -or $terminal.Count -ne 1 -or
                    $closure[0].jobHandleClosed -ne $true -or $retention[0].terminationAfterResumeAttempt -ne $false -or
                    $retention[0].originalJobHandleHeld -ne $true) { throw 'Publication fixture final lifecycle proof incomplete' }
                $result.retention = $retention[0]
                if ($name -ceq 'normal') {
                    if ($terminal[0].readyForExit -ne $true -or $retention[0].activeProcesses -ne 0 -or
                        $retention[0].rootExitCode -ne 0 -or $retention[0].auditComplete -ne $true) { throw 'Natural completion proof failed' }
                } elseif ($name -ceq 'pre-resume') {
                    if ($retention[0].resumeAttempted -ne $false -or $retention[0].neverResumedTerminationRequested -ne $true -or
                        $retention[0].neverResumedTerminationSucceeded -ne $true -or
                        $retention[0].neverResumedRootExitConfirmed -ne $true -or $retention[0].activeProcesses -ne 0) {
                        throw 'Never-resumed cleanup proof failed'
                    }
                    $result.suspendedIdentity = $suspended[0]
                } else {
                    if ($retention[0].resumeAttempted -ne $true -or $retention[0].neverResumedTerminationRequested -ne $false -or
                        $terminal[0].readyForExit -ne $false -or $retention[0].failureLatched -ne $true -or
                        $retention[0].retainedLiveWorkOrUnknown -ne $true) { throw 'Failure retention proof failed' }
                    if ($name -ceq 'resume-unknown' -and $retention[0].resumed -ne $false) { throw 'Unknown-resume fault was not exercised' }
                    if ($name -ceq 'timeout' -and $retention[0].finalizationStartedMilliseconds -lt 12000) { throw 'Deadline fault was not exercised' }
                    if ($name -ceq 'overflow') {
                        $capture = @($records | Where-Object { $_.event -ceq 'publication-capture' -and $_.stream -ceq 'stdout' })
                        if ($capture.Count -ne 1 -or $capture[0].overflowDetected -ne $true -or
                            $capture[0].confirmedFlushedBytes -ne 16384) { throw 'Output overflow proof failed' }
                        $prefix = Read-Bytes "$directory\launcher.stdout.bin" 16384
                        if ($prefix.Length -ne 16384 -or @($prefix | Where-Object { $_ -ne 88 }).Count -ne 0) { throw 'Output prefix changed' }
                    }
                }
            } elseif ($records.Count -ne 5) { throw 'Journal fault must preserve exactly its startup prefix' }
            foreach ($subject in $subjects) {
                while (-not $subject.HasExited) {
                    Assert-PublicationFixtureTime $caseWatch
                    Start-Sleep -Milliseconds 25
                }
                if ($subject.ExitCode -ne 0) { throw 'Synthetic subject did not exit naturally' }
            }
            Assert-PublicationFixtureTime $caseWatch
            $result.subjectsExitedNaturally = $name -cne 'pre-resume'
            $result.quiescent = $true
            $result.passed = $true
        } catch {
            $result.failureType = $_.Exception.GetType().FullName
            $result.failureDetails = Get-FailureDetails $_
        } finally {
            # Mandatory releases are attempted even after expiry or another close failure.
            if ($lockHeld) {
                try { $locked.Unlock(0, 65536) } catch {
                    $result.passed = $false; $result.closeFailureType = $_.Exception.GetType().FullName
                }
            }
            foreach ($owned in @($locked) + $subjects + @($candidate)) {
                if ($null -ne $owned) {
                    try { $owned.Dispose() } catch {
                        $result.passed = $false; $result.closeFailureType = $_.Exception.GetType().FullName
                    }
                }
            }
            Assert-PublicationFixtureTime $caseWatch
            $result.elapsedMilliseconds = $caseWatch.ElapsedMilliseconds
            Save-Json "$directory\case-result.json" $result $caseWatch
            # A late completed-looking original receipt remains unchanged, but cannot
            # admit this case or a later case. No restarted finalization allowance.
            Assert-PublicationFixtureTime $caseWatch
        }
        $results += $result
        if (-not $result.passed) { throw 'Publication fixture failed; the original enclosing launcher owns bounded cleanup' }
    }
    return $results
}

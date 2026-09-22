# Dot-sourced only by the admitted outer controller after its six guard cases.
# Reuse the accepted guard's native declarations; do not compile another helper.
$negativeFlags = [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic
$negativeOpen = [WindowsValidationJob].GetMethod('OpenJobObject', $negativeFlags)
$negativeQueries = @([WindowsValidationJob].GetMethods($negativeFlags) | Where-Object {
    $_.Name -ceq 'QueryInformationJobObject' -and $_.GetParameters()[2].ParameterType -eq [IntPtr]
})
if ($null -eq $negativeOpen -or $negativeQueries.Count -ne 1) { throw 'Missing accepted native query declarations' }
$negativeQuery = $negativeQueries[0]

function Open-NegativeJob([string] $Name) {
    $value = $negativeOpen.Invoke($null, [object[]]@([uint32]4, $false, $Name))
    $handle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]$value, $true)
    if ($handle.IsInvalid) { $handle.Dispose(); throw 'Negative Job query handle unavailable' }
    return $handle
}

function Query-NegativeJob($Handle) {
    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(48)
    try {
        $arguments = [object[]]@($Handle, [int]1, $buffer, [uint32]48, [uint32]0)
        if (-not $negativeQuery.Invoke($null, $arguments)) { throw 'Negative Job accounting query failed' }
        if ($arguments[4] -ne 48) { throw 'Unexpected accounting structure size' }
        return @{
            total = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 36)
            active = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 40)
        }
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
}

function Read-NegativeJournal([string] $Directory) {
    $raw = Read-Bytes "$Directory\launcher.jsonl" 16384
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($raw)
    if (-not $text.EndsWith("`n")) { throw 'Incomplete negative journal line' }
    $records = @($text.TrimEnd([char]10).Split([char]10) | ForEach-Object { $_ | ConvertFrom-Json })
    if ($records.Count -lt 1) { throw 'Empty negative journal' }
    return $records
}

function Assert-NegativeTime($CaseWatch, [int] $Limit = 25000) {
    Assert-Time 300000
    if ($CaseWatch.ElapsedMilliseconds -ge $Limit) { throw 'Negative case deadline' }
}

function Wait-NegativeResumedPrefix($Stream, $Candidate, $CaseWatch, [string] $Name, $Launcher, $RootIdentity) {
    $expected = @('bootstrap', 'job-ready', 'root-suspended', 'resume-requested', 'resumed')
    while ($true) {
        Assert-NegativeTime $CaseWatch 15000
        if ($Candidate.HasExited) { throw 'Journal candidate exited before its resumed prefix' }
        $length = $Stream.Length
        if ($length -gt 16384) { throw 'Live negative journal exceeded its bound' }
        $Stream.Position = 0
        $bytes = [byte[]]::new([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            Assert-NegativeTime $CaseWatch 15000
            $request = $bytes.Length - $offset
            $script:readBytes += $request
            if ($script:readBytes -gt 4194304) { throw 'Live journal input budget' }
            $count = $Stream.Read($bytes, $offset, $request)
            if ($count -eq 0) { throw 'Short live journal prefix' }
            $offset += $count
        }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $end = $text.LastIndexOf([char]10)
        if ($end -ge 0) {
            $records = @($text.Substring(0, $end).Split([char]10) | ForEach-Object { $_ | ConvertFrom-Json })
            if ($records.Count -gt 5) { throw 'Unexpected pre-fault journal records' }
            for ($index = 0; $index -lt $records.Count; $index++) {
                if ($records[$index].event -cne $expected[$index]) { throw 'Unexpected journal startup sequence' }
            }
            if ($records.Count -eq 5 -and $end -eq $text.Length - 1) {
                if ($records[0].jobName -cne $Name -or $records[0].authoritySha256 -cne $AuthoritySha256 -or
                    $records[0].pid -ne $Launcher.pid -or $records[0].creationFileTime -cne $Launcher.creationFileTime -or
                    $records[0].session -ne $Launcher.session -or $records[2].inJob -ne $true -or
                    $records[2].pid -ne $RootIdentity.pid -or
                    $records[2].creationFileTime -cne $RootIdentity.creationFileTime -or
                    $records[2].session -ne $RootIdentity.session) { throw 'Live journal identity mismatch' }
                return (Get-Hash $bytes)
            }
        }
        Start-Sleep -Milliseconds 25
    }
}

function Invoke-LauncherFailureCases {
    $results = @()
    foreach ($name in @('cancel', 'collision', 'overflow', 'journal')) {
        Assert-Time 280000
        $caseWatch = [Diagnostics.Stopwatch]::StartNew()
        $spec = $authority.failureCases.$name
        $directory = [string]$spec.root
        $jobName = 'Local\azureauth-controller-108-' + $directory.Substring($directory.Length - 4) + '-' + $spec.suffix
        $candidate = $null
        $query = $null
        $sentinel = $null
        $locked = $null
        $lockHeld = $false
        $result = [ordered]@{ case = $name; passed = $false; jobName = $jobName }
        try {
            if ($name -eq 'collision') {
                $constructor = [WindowsValidationJob].GetConstructor(
                    ([Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic), $null,
                    [Type[]]@([bool], [Diagnostics.Stopwatch], [long], [string]), $null)
                if ($null -eq $constructor) { throw 'Missing accepted sentinel constructor' }
                $sentinel = $constructor.Invoke([object[]]@($false, $null, [long]0, $jobName))
                $sentinelArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
                    "$directory\Invoke-WindowsNamedGuardFixtures.ps1" + '" -Mode Payload -AuthoritySha256 ' + $AuthoritySha256
                $sentinel.Start($shell, $sentinelArgs, $directory, (New-Environment $directory))
                $sentinelOutput = $sentinel.Output.ReadToEndAsync()
                $sentinelError = $sentinel.Error.ReadToEndAsync()
                while (-not (Test-Path -LiteralPath "$directory\descendant-ready.json")) {
                    Assert-NegativeTime $caseWatch 15000
                    if ($sentinel.Child.HasExited) { throw 'Collision sentinel exited before readiness' }
                    Start-Sleep -Milliseconds 25
                }
                $ready = Read-Json "$directory\descendant-ready.json" 4096
                if ($ready.pid -ne $sentinel.Child.Id -or $ready.authoritySha256 -cne $AuthoritySha256 -or
                    $ready.creationFileTime -cne $sentinel.Child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()) {
                    throw 'Collision sentinel identity mismatch'
                }
                $result.sentinelIdentity = $ready
            }

            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = "$root\WindowsScriptJobLauncher.exe"
            $start.Arguments = '"' + $directory + '" ' + $spec.suffix + ' ' +
                $AuthoritySha256 + ' ' + $authority.failureControllerSha256
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
            Assert-NegativeTime $caseWatch 15000
            if (-not $candidate.Start()) { throw 'Negative candidate startup rejected' }
            [void]$candidate.Handle
            $result.launcherIdentity = @{
                pid = $candidate.Id; creationFileTime = $candidate.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
                session = $candidate.SessionId
            }
            # The pinned launcher writes at most one fixed fallback line to its own
            # console. Workload output goes to its separately bounded capture files.
            $stdout = $candidate.StandardOutput.ReadToEndAsync()
            $stderr = $candidate.StandardError.ReadToEndAsync()

            if ($name -cne 'collision') {
                while (-not (Test-Path -LiteralPath "$directory\root-ready.json")) {
                    Assert-NegativeTime $caseWatch 15000
                    if ($candidate.HasExited) { throw 'Negative candidate exited before readiness' }
                    Start-Sleep -Milliseconds 25
                }
                $ready = Read-Json "$directory\root-ready.json" 4096
                $descendant = Read-Json "$directory\descendant-ready.json" 4096
                if ($ready.authoritySha256 -cne $AuthoritySha256 -or $ready.case -cne $name -or
                    $descendant.authoritySha256 -cne $AuthoritySha256 -or $descendant.case -cne $name -or
                    $ready.descendantPid -ne $descendant.pid -or
                    $ready.descendantCreationFileTime -cne $descendant.creationFileTime) {
                    throw 'Negative workload readiness mismatch'
                }
                $result.rootIdentity = $ready
                $result.descendantIdentity = $descendant
                # Keep an independent handle open through candidate exit. A last-close
                # KILL_ON_JOB_CLOSE fallback cannot supply this case's passing result.
                $query = Open-NegativeJob $jobName
                $result.beforeFault = Query-NegativeJob $query
                if ($result.beforeFault.active -lt 2 -or $result.beforeFault.total -gt 8) {
                    throw 'Negative workload is not live within its bound'
                }
                if ($name -eq 'journal') {
                    $locked = [IO.File]::Open("$directory\launcher.jsonl", 'Open', 'Read', 'ReadWrite')
                    $result.journalPrefixSha256 = Wait-NegativeResumedPrefix $locked $candidate $caseWatch `
                        $jobName $result.launcherIdentity $ready
                    $locked.Lock(0, 16384)
                    $lockHeld = $true
                    $result.journalLockAcquired = $true
                }
                Assert-NegativeTime $caseWatch 15000
                if ($name -eq 'overflow') {
                    Save-Json "$directory\release" @{ release = $true }
                    $result.trigger = 'release'
                } else {
                    Save-Json "$directory\cancel" @{ cancelled = $true }
                    $result.trigger = 'cancel'
                }
                $result.triggerElapsedMilliseconds = $caseWatch.ElapsedMilliseconds
            }

            $completionLimit = 25000
            if ($name -eq 'collision') { $completionLimit = 15000 }
            while (-not $candidate.HasExited -or -not $stdout.IsCompleted -or -not $stderr.IsCompleted) {
                Assert-NegativeTime $caseWatch $completionLimit
                Start-Sleep -Milliseconds 25
            }
            $result.launcherExit = $candidate.ExitCode
            $result.stdout = $stdout.GetAwaiter().GetResult()
            $result.stderr = $stderr.GetAwaiter().GetResult()
            $result.stdoutEof = $true
            $result.stderrEof = $true
            if ($candidate.ExitCode -ne 1 -or $result.stdout.Length -ne 0 -or $result.stderr.Length -gt 1024) {
                throw 'Unexpected negative candidate result'
            }
            if ($name -eq 'collision') {
                if ($sentinel.Child.HasExited -or $sentinel.ActiveProcesses -lt 1) {
                    throw 'Colliding candidate disturbed the original sentinel'
                }
                $result.sentinelSurvived = $true
                Assert-NegativeTime $caseWatch 15000
                Assert-Time 290000
                $result.sentinelStopped = $sentinel.Stop()
                $result.sentinelActiveAfterStop = $sentinel.ActiveAfterStop
                $result.sentinelTotal = $sentinel.TotalAfterStop
                if (-not $result.sentinelStopped -or $result.sentinelActiveAfterStop -ne 0 -or
                    $result.sentinelTotal -lt 1 -or $result.sentinelTotal -gt 8) {
                    throw 'Collision sentinel cleanup failed'
                }
                while (-not $sentinelOutput.IsCompleted -or -not $sentinelError.IsCompleted) {
                    Assert-NegativeTime $caseWatch
                    Start-Sleep -Milliseconds 25
                }
                $result.sentinelStdout = $sentinelOutput.GetAwaiter().GetResult()
                $result.sentinelStderr = $sentinelError.GetAwaiter().GetResult()
                if ($result.sentinelStdout.Length -ne 0 -or $result.sentinelStderr.Length -ne 0) {
                    throw 'Unexpected fixed sentinel output'
                }
                $result.sentinelOutputEof = $true
            } else {
                $result.afterCandidate = Query-NegativeJob $query
                $result.queryHandleHeldThroughExit = $true
                if ($result.afterCandidate.active -ne 0 -or $result.afterCandidate.total -lt 2 -or
                    $result.afterCandidate.total -gt 8) { throw 'Candidate did not empty its live workload Job' }
                if ($name -eq 'journal') {
                    $result.journalLockHeldThroughExitAndEmptyJob = $lockHeld
                    $locked.Unlock(0, 16384)
                    $lockHeld = $false
                    $locked.Dispose()
                    $locked = $null
                }
            }

            if ($name -eq 'journal' -and (Get-Hash (Read-Bytes "$directory\launcher.jsonl" 16384)) -cne
                $result.journalPrefixSha256) { throw 'Journal fault changed its accepted startup prefix' }
            $journal = @(Read-NegativeJournal $directory)
            if ($journal[0].event -cne 'bootstrap' -or $journal[0].jobName -cne $jobName -or
                $journal[0].authoritySha256 -cne $AuthoritySha256 -or
                $journal[0].pid -ne $result.launcherIdentity.pid -or
                $journal[0].creationFileTime -cne $result.launcherIdentity.creationFileTime -or
                $journal[0].session -ne $result.launcherIdentity.session) { throw 'Negative journal launcher mismatch' }
            if ($name -eq 'collision') {
                $failed = @($journal | Where-Object { $_.event -ceq 'failed' })
                if ($failed.Count -ne 1 -or $failed[0].stage -cne 'job-create' -or
                    $failed[0].resumed -ne $false -or $failed[0].failureType -cne 'InvalidOperationException' -or
                    @($journal | Where-Object { $_.event -ceq 'root-suspended' }).Count -ne 0) {
                    throw 'Collision was not rejected before creating a controller'
                }
            } else {
                $suspended = @($journal | Where-Object { $_.event -ceq 'root-suspended' })
                if ($suspended.Count -ne 1 -or $suspended[0].inJob -ne $true -or
                    $suspended[0].pid -ne $ready.pid -or $suspended[0].creationFileTime -cne $ready.creationFileTime -or
                    $suspended[0].session -ne $ready.session) { throw 'Negative root was not contained at creation' }
                if ($name -eq 'journal') {
                    if ($journal.Count -ne 5 -or $journal[-1].event -cne 'resumed') {
                        throw 'Journal fault did not preserve only the pre-fault prefix'
                    }
                } else {
                    $cleanup = @($journal | Where-Object { $_.event -ceq 'cleanup' })
                    if ($cleanup.Count -ne 1 -or $cleanup[0].terminationSucceeded -ne $true -or
                        $cleanup[0].rootExited -ne $true -or $cleanup[0].activeProcesses -ne 0) {
                        throw 'Negative cleanup evidence missing'
                    }
                    if ($name -eq 'cancel') {
                        $failed = @($journal | Where-Object { $_.event -ceq 'failed' })
                        if ($failed.Count -ne 1 -or $failed[0].stage -cne 'running' -or
                            $failed[0].resumed -ne $true -or $failed[0].failureType -cne 'TimeoutException' -or
                            $failed[0].elapsedMilliseconds -ge 330000 -or $result.trigger -cne 'cancel') {
                            throw 'Cancel case did not observe the intended cancellation failure'
                        }
                        $result.cancellationCauseObserved = $true
                    }
                    if ($name -eq 'overflow') {
                        $capture = @($journal | Where-Object { $_.event -ceq 'capture' -and $_.stream -ceq 'stdout' })
                        if ($capture.Count -ne 1 -or $capture[0].overflowDetected -ne $true -or
                            $capture[0].confirmedFlushedBytes -ne 16384) { throw 'Fixed overflow was not observed' }
                    }
                }
            }
            if ($name -cne 'journal' -and ($journal[-1].event -cne 'launcher-exit' -or
                $journal[-1].passed -ne $false)) { throw 'Missing negative launcher terminal record' }
            Assert-NegativeTime $caseWatch
            $result.elapsedMilliseconds = $caseWatch.ElapsedMilliseconds
            $result.passed = $true
            $results += $result
        } catch {
            $result.failureType = $_.Exception.GetType().FullName
            $result.failureDetails = Get-FailureDetails $_
            throw
        } finally {
            # Unexpected results propagate to the outer launcher. Closing these handles
            # is not a passing cleanup observation and never starts another candidate.
            if ($lockHeld) { $locked.Unlock(0, 16384) }
            if ($null -ne $locked) { $locked.Dispose() }
            if ($null -ne $query) { $query.Dispose() }
            if ($null -ne $sentinel) { $sentinel.Dispose() }
            if ($null -ne $candidate) { $candidate.Dispose() }
            Save-Json "$directory\case-result.json" $result
        }
    }
    return $results
}

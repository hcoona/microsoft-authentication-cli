param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]{4}$')][string] $ActionName,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')][string] $ReservationSha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108'
$action = "$root\actions\$ActionName"
$framework = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
$dotnet = 'C:\Program Files\dotnet\dotnet.exe'
$guard = $null
$compiler = $null
$capture = $null
$stage = 'reservation'
$result = [ordered]@{ safetyStop = $true; quiescent = $false; exitCode = -1; captureCompleted = $false }

function Save-Json([string] $Path, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse input' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}

function Assert-Hash([string] $Path, [string] $Expected) {
    Assert-Direct $Path
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected) {
        throw 'Input identity changed'
    }
}

function Read-Output($Process, $Streams, [int] $Seconds, $Watch) {
    $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
    $tasks = @($Streams[0].ReadAsync($buffers[0], 0, 4096), $Streams[1].ReadAsync($buffers[1], 0, 4096))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $done = @($false, $false)
    $disposition = 'read-failure'
    try {
        while (-not ($Process.HasExited -and $done[0] -and $done[1])) {
            if (Test-Path -LiteralPath "$action\cancel") { $disposition = 'cancelled'; throw 'Caller cancellation' }
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

try {
    Assert-Hash "$action\started.json" $ReservationSha256
    $start = Get-Content -LiteralPath "$action\started.json" -Raw | ConvertFrom-Json
    if ($start.action -notin @('bootstrap', 'restore', 'build', 'test')) { throw 'Unallocated action' }
    Save-Json "$action\controller.json" @{
        pid = $PID; started = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('o')
    }
    $result.reservationSha256 = $ReservationSha256
    $stage = 'host-inputs'
    if (-not [Environment]::Is64BitProcess -or [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        throw 'Unexpected Windows execution identity'
    }
    Assert-Direct $root
    if ([IO.DriveInfo]::new('C:\').DriveType -ne [IO.DriveType]::Fixed) { throw 'Nonfixed fixture volume' }
    $owner = (Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw 'Unverified root owner' }
    foreach ($property in $start.toolSha256.PSObject.Properties) { Assert-Hash $property.Name $property.Value }
    foreach ($property in $start.fileSha256.PSObject.Properties) {
        if ($property.Name -notmatch '^[A-Za-z0-9_./,=-]+$' -or $property.Name -match '(^|/)\.\.(/|$)') {
            throw 'Unexpected relative input'
        }
        Assert-Hash (Join-Path $root $property.Name) $property.Value
    }
    Assert-Direct "$root\empty-feed"
    if (@(Get-ChildItem -LiteralPath "$root\empty-feed" -Force).Count -ne 0) { throw 'Nonempty fallback feed' }
    Assert-Direct "$action\empty-program-files"
    if (-not (Get-Item -LiteralPath "$action\empty-program-files" -Force).PSIsContainer -or
        @(Get-ChildItem -LiteralPath "$action\empty-program-files" -Force).Count -ne 0) {
        throw 'Invalid empty program-files directory'
    }
    # Check every active input/output directory before any owned compiler or subject.
    foreach ($base in @("$root\subject", "$root\feed", "$root\packages", $action)) {
        $queue = [Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($base)
        while ($queue.Count -gt 0) {
            $item = Get-Item -LiteralPath $queue.Dequeue() -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse descendant' }
            if ($item.PSIsContainer) {
                foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) { $queue.Enqueue($child.FullName) }
            }
        }
    }
    $environment = @{
        SystemRoot = 'C:\Windows'; WINDIR = 'C:\Windows'; ComSpec = 'C:\Windows\System32\cmd.exe'
        OS = 'Windows_NT'; PROCESSOR_ARCHITECTURE = 'AMD64'
        PROGRAMFILES = "$action\empty-program-files"; 'PROGRAMFILES(X86)' = "$action\empty-program-files"
        PATH = 'C:\Program Files\dotnet;C:\Windows\System32'
        USERPROFILE = "$action\home"; APPDATA = "$action\home\roaming"; LOCALAPPDATA = "$action\home\local"
        TMP = "$action\temp"; TEMP = "$action\temp"; DOTNET_CLI_HOME = "$action\home"
        DOTNET_ROOT = 'C:\Program Files\dotnet'; DOTNET_ROLL_FORWARD = 'Disable'
        NUGET_PACKAGES = "$root\packages"; NUGET_HTTP_CACHE_PATH = "$action\home\http"
        NUGET_PLUGINS_CACHE_PATH = "$action\home\plugins"
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'; TESTINGPLATFORM_TELEMETRY_OPTOUT = '1'
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'; DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
        DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = 'false'; DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = 'true'
        DOTNET_CLI_USE_MSBUILD_SERVER = '0'; MSBUILDDISABLENODEREUSE = '1'
        MSBuildEnableWorkloadResolver = 'false'; DOTNET_NOLOGO = '1'; DOTNET_CLI_UI_LANGUAGE = 'en-US'
    }
    $project = 'Windows.slnx'
    $exe = $dotnet
    $working = "$root\subject"
    $seconds = 120
    if ($start.action -eq 'bootstrap') {
        $seconds = 30
        $exe = "$framework\csc.exe"
        $arguments = '/noconfig /nologo /target:library /out:"' + $action + '\WindowsValidationJob.dll" /reference:"' +
            $framework + '\System.dll" /reference:"' + $framework + '\System.Core.dll" "' +
            $root + '\controller\WindowsValidationJob.cs"'
    } elseif ($start.action -eq 'restore') {
        $seconds = 180
        $arguments = 'restore ' + $project + ' --configfile "' + $root + '\nuget.config" --packages "' +
            $root + '\packages" --disable-parallel --verbosity minimal -p:NuGetAudit=false' +
            ' -p:RestorePackagesWithLockFile=true -p:UseSharedCompilation=false -m:1 -nr:false -noAutoResponse' +
            ' -p:RestoreFallbackFolders= -p:RestoreAdditionalProjectSources= -p:RestoreAdditionalProjectFallbackFolders='
        if (Test-Path -LiteralPath "$working\tests\Authentication.Windows.Scenarios\packages.lock.json") {
            $arguments += ' --locked-mode'
        }
    } elseif ($start.action -eq 'build') {
        $arguments = 'build ' + $project + ' -c Release --no-restore --disable-build-servers --verbosity minimal' +
            ' -p:UseSharedCompilation=false -m:1 -nr:false -noAutoResponse'
    } else {
        $arguments = 'tests\Authentication.Windows.Scenarios\bin\Release\net10.0-windows\Authentication.Windows.Scenarios.dll' +
            ' --report-trx --results-directory "' + $action + '\results"'
    }
    Save-Json "$action\invocation.json" @{
        executable = $exe; arguments = $arguments; workingDirectory = $working
        environment = $environment; seconds = $seconds
    }
    if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancelled before launch' }
    if ($start.action -eq 'bootstrap') {
        # This fixed standalone compiler has no shared compiler, analyzer, or custom task.
        # Retain the process handle; it is the sole bootstrap child before a Job exists.
        $stage = 'bootstrap'
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $exe; $info.Arguments = $arguments; $info.WorkingDirectory = $working
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $info.EnvironmentVariables.Clear()
        foreach ($key in $environment.Keys) { $info.EnvironmentVariables[$key] = $environment[$key] }
        $compiler = [Diagnostics.Process]::new(); $compiler.StartInfo = $info
        $watch = [Diagnostics.Stopwatch]::StartNew()
        if (-not $compiler.Start()) { throw 'Bootstrap start failed' }
        if ($compiler.Handle -eq [IntPtr]::Zero) { throw 'Missing compiler handle' }
        Save-Json "$action\compiler.json" @{
            pid = $compiler.Id; started = $compiler.StartTime.ToUniversalTime().ToString('o')
        }
        $capture = Read-Output $compiler @($compiler.StandardOutput.BaseStream, $compiler.StandardError.BaseStream) $seconds $watch
        $result.exitCode = $compiler.ExitCode
    } else {
        $stage = 'guard-load'
        $helper = Join-Path $root $start.helperPath
        Assert-Hash $helper $start.helperSha256
        Add-Type -Path $helper -ErrorAction Stop -WarningAction Stop
        $guard = [WindowsValidationJob]::new()
        $stage = 'subject'
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $guard.Start($exe, $arguments, $working, $environment)
        Save-Json "$action\subject.json" @{
            pid = $guard.Child.Id; started = $guard.Child.StartTime.ToUniversalTime().ToString('o')
        }
        $capture = Read-Output $guard.Child @($guard.Output.BaseStream, $guard.Error.BaseStream) $seconds $watch
        $result.exitCode = $guard.Child.ExitCode
        while ($guard.ActiveProcesses -ne 0 -and $watch.Elapsed.TotalSeconds -lt $seconds) {
            if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancelled during quiescence' }
            Start-Sleep -Milliseconds 25
        }
        $result.activeProcessesAtNormalExit = $guard.ActiveProcesses
        if ($result.activeProcessesAtNormalExit -ne 0) { throw 'Owned descendants survived' }
    }
    $result.captureCompleted = $true
    $result.seconds = $capture.seconds
    $result.safetyStop = $false
    $stage = 'completed'
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureLine = $_.InvocationInfo.ScriptLineNumber
    $result.safetyStop = $true
} finally {
    $result.stage = $stage
    try {
        $stopped = $true
        if ($compiler -and -not $compiler.HasExited) {
            $result.compilerTerminationRequested = $true
            $compiler.Kill()
            $stopped = $compiler.WaitForExit(10000)
        }
        if ($guard) {
            $stopped = $guard.Stop()
            $result.jobActiveBeforeStop = $guard.ActiveBeforeStop
            $result.jobActiveAfterStop = $guard.ActiveAfterStop
            $result.jobTotalBeforeStop = $guard.TotalBeforeStop
            $result.jobTotalAfterStop = $guard.TotalAfterStop
            $result.jobTerminationRequested = $guard.TerminationRequested
            $result.jobTerminationSucceeded = $guard.TerminationSucceeded
        }
        $result.quiescent = $stopped
    } catch {
        $result.quiescent = $false; $result.safetyStop = $true
        $result.terminationFailureType = $_.Exception.GetType().FullName
    }
    if ($guard) { $guard.Dispose() }
    if ($compiler) { $compiler.Dispose() }
    if (-not $result.quiescent) { $result.safetyStop = $true }
    $result.captureDisposition = 'not-started'
    if ($null -ne $capture) {
        $result.captureDisposition = $capture.disposition
        $result.stdoutBytes = $capture.stdout.Length
        $result.stderrBytes = $capture.stderr.Length
        $result.seconds = $capture.seconds
    }
    # Raw output remains local and is touched only after owned work is quiescent.
    if ($result.quiescent -and $null -ne $capture) {
        [IO.File]::WriteAllBytes("$action\stdout.bin", $capture.stdout)
        [IO.File]::WriteAllBytes("$action\stderr.bin", $capture.stderr)
    }
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    Save-Json "$action\windows-result.json" $result
}
if ($result.safetyStop -or -not $result.quiescent) { exit 1 }
exit 0

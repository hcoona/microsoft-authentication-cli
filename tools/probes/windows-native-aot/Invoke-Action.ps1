param(
    [ValidateSet('positive', 'missing', 'decoy')]
    [string] $Action,
    [ValidatePattern('^[0-9]{2}$')][string] $AttemptName
)
$ErrorActionPreference = 'Stop'
$root = 'C:\Temp\azureauth-native-aot-76'
$attempt = Join-Path "$root\attempts" $AttemptName
$vc = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231'
$sdk = 'C:\Program Files (x86)\Windows Kits\10'
$sdkVersion = '10.0.26100.0'
$result = [ordered]@{ exitCode = -1; quiescent = $false; safetyStop = $true }
$guard = $null
$compiler = $null
$stage = 'controller-start'
$result.compilerTerminationRequested = $false
$framework = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'

function Save-Json($Path, $Value) {
    $Value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-Output($Process, $Streams, $Seconds) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $buffers = @((New-Object char[] 4096), (New-Object char[] 4096))
    $tasks = @($Streams[0].ReadAsync($buffers[0], 0, 4096), $Streams[1].ReadAsync($buffers[1], 0, 4096))
    $texts = @((New-Object Text.StringBuilder), (New-Object Text.StringBuilder))
    $done = @($false, $false)
    while (-not ($Process.HasExited -and $done[0] -and $done[1])) {
        if ($watch.Elapsed.TotalSeconds -gt $Seconds) { throw 'Attempt timeout' }
        for ($index = 0; $index -lt 2; $index++) {
            if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                $count = $tasks[$index].GetAwaiter().GetResult()
                if ($count -eq 0) { $done[$index] = $true } else {
                    if (($texts[0].Length + $texts[1].Length + $count) -gt 8388608) { throw 'Output bound' }
                    [void]$texts[$index].Append($buffers[$index], 0, $count)
                    $tasks[$index] = $Streams[$index].ReadAsync($buffers[$index], 0, 4096)
                }
            }
        }
        Start-Sleep -Milliseconds 50
    }
    $Process.WaitForExit()
    return [pscustomobject]@{ stdout = $texts[0].ToString(); stderr = $texts[1].ToString() }
}


try {
    Save-Json "$attempt\controller.json" @{ pid = $PID; started = (Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o') }
    $stage = 'tool-identity'
    $identities = @{
        "$framework\csc.exe" = '46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00'
    }
    foreach ($path in $identities.Keys) {
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $identities[$path]) {
            throw 'Toolchain identity changed'
        }
    }
    $source = "$root\src"
    $environment = @{
        SystemRoot = 'C:\Windows'; WINDIR = 'C:\Windows'; ComSpec = 'C:\Windows\System32\cmd.exe'
        OS = 'Windows_NT'
        PROGRAMFILES = "$root\empty-program-files"; 'PROGRAMFILES(X86)' = "$root\empty-program-files"
        PATH = "$vc\bin\Hostx64\x64;$sdk\bin\$sdkVersion\x64;C:\Windows\System32;C:\Program Files\dotnet"
        LIB = "$vc\lib\x64;$sdk\Lib\$sdkVersion\ucrt\x64;$sdk\Lib\$sdkVersion\um\x64"
        INCLUDE = "$vc\include;$sdk\Include\$sdkVersion\ucrt;$sdk\Include\$sdkVersion\um;$sdk\Include\$sdkVersion\shared"
        TEMP = "$root\temp"; TMP = "$root\temp"; USERPROFILE = "$root\home"
        APPDATA = "$root\home\AppData\Roaming"; LOCALAPPDATA = "$root\home\AppData\Local"
        DOTNET_ROOT = 'C:\Program Files\dotnet'; DOTNET_CLI_HOME = "$root\home"
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'; DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
        DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'; DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = 'false'
        DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = 'true'; DOTNET_MULTILEVEL_LOOKUP = '0'
        DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK = 'true'
        DOTNET_NOLOGO = '1'; DOTNET_CLI_UI_LANGUAGE = 'en-US'; DOTNET_EnableDiagnostics = '0'
        MSBUILDDISABLENODEREUSE = '1'; MSBuildEnableWorkloadResolver = 'false'
        VSCMD_SKIP_SENDTELEMETRY = '1'; NUGET_PACKAGES = "$root\packages"
        NUGET_HTTP_CACHE_PATH = "$root\http"; NUGET_CERT_REVOCATION_MODE = 'offline'
    }
    $stage = 'case-preparation'
    $artifactHashes = @{
        'NativeAotProbe.exe' = 'e7fbef7f06f86236ae38658052e4e46d46e3851048c7ec878e215986214ae495'
        'msalruntime.dll' = '9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79'
    }
    foreach ($name in $artifactHashes.Keys) {
        if ((Get-FileHash -LiteralPath "$root\out\$name" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $artifactHashes[$name]) {
            throw 'Retained artifact identity changed'
        }
    }
    $timeout = 30
    $case = "$attempt\app"
    New-Item -ItemType Directory -Path $case | Out-Null
    Copy-Item -LiteralPath "$root\out\NativeAotProbe.exe" -Destination $case
    if ($Action -eq 'positive') {
        Copy-Item -LiteralPath "$root\out\msalruntime.dll" -Destination $case
    }
    $working = "$attempt\working"
    New-Item -ItemType Directory -Path $working | Out-Null
    if ($Action -eq 'decoy') {
        Copy-Item -LiteralPath "$root\out\msalruntime.dll" -Destination $working
        $environment['PATH'] = "$working;C:\Windows\System32"
    } else {
        $environment['PATH'] = 'C:\Windows\System32'
    }
    foreach ($directory in @($case, $working)) {
        foreach ($file in Get-ChildItem -LiteralPath $directory -File) {
            if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $artifactHashes[$file.Name]) {
                throw 'Copied case artifact identity changed'
            }
        }
    }
    $exe = "$case\NativeAotProbe.exe"
    $arguments = ''
    # The pinned standalone compiler has no shared-compilation/build-server mode here.
    # Its process handle owns this one bootstrap process before the Job guard exists.
    $stage = 'guard-compile'
    $compileInfo = New-Object System.Diagnostics.ProcessStartInfo
    $compileInfo.FileName = "$framework\csc.exe"
    $compileInfo.Arguments = '/noconfig /nologo /target:library /out:"' + $attempt + '\WindowsJob.dll" /reference:"' + $framework + '\System.dll" /reference:"' + $framework + '\System.Core.dll" "' + $source + '\WindowsJob.cs"'
    $compileInfo.WorkingDirectory = $source
    $compileInfo.UseShellExecute = $false
    $compileInfo.CreateNoWindow = $true
    $compileInfo.RedirectStandardOutput = $true
    $compileInfo.RedirectStandardError = $true
    $compileInfo.EnvironmentVariables.Clear()
    foreach ($key in $environment.Keys) { $compileInfo.EnvironmentVariables[$key] = $environment[$key] }
    $compiler = New-Object System.Diagnostics.Process
    $compiler.StartInfo = $compileInfo
    if (-not $compiler.Start()) { throw 'Guard compiler failed to start' }
    Save-Json "$attempt\compiler.json" @{ pid = $compiler.Id; started = $compiler.StartTime.ToUniversalTime().ToString('o') }
    $compileOutput = Read-Output $compiler @($compiler.StandardOutput, $compiler.StandardError) 60
    $result.guardCompilerExitCode = $compiler.ExitCode
    if ($compiler.ExitCode -ne 0) { throw 'Guard compilation failed' }
    $stage = 'guard-load'
    Add-Type -Path "$attempt\WindowsJob.dll" -ErrorAction Stop -WarningAction Stop
    $guard = New-Object NativeAotJob
    $stage = 'subject-start'
    $guard.Start($exe, $arguments, $working, $environment)
    $child = $guard.Child
    Save-Json "$attempt\subject.json" @{ pid = $child.Id; started = $child.StartTime.ToUniversalTime().ToString('o') }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $stage = 'subject-capture'
    $capture = Read-Output $child @($guard.Output, $guard.Error) $timeout
    $result.captureCompleted = $true
    $texts = @([string]$capture.stdout, [string]$capture.stderr)
    $result.exitCode = $child.ExitCode
    $result.seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
    $stage = 'normal-quiescence'
    $result.activeProcessesAtNormalExit = $guard.ActiveProcesses
    if ($result.activeProcessesAtNormalExit -ne 0) { throw 'Owned descendant survived normal exit' }
    $result.quiescent = $true
    $stage = 'observation-validation'
    if ($texts[1].Length -ne 0) { throw 'Unexpected subject stderr; contents suppressed' }
    # Exact emitter order also rejects duplicate fields before JSON parsing.
    $pattern = '\A\{"nativeAot":(true|false),"restrictedSearch":(true|false),"unexpectedPreload":(true|false),"builderCreated":(true|false),"operation":"(not_started|configuration_created|exception)","exceptionType":"(|System\.(DllNotFoundException|BadImageFormatException|TypeInitializationException|EntryPointNotFoundException|InvalidOperationException|ComponentModel\.Win32Exception)|Microsoft\.Identity\.Client\.(MsalClientException|NativeInterop\.MsalRuntimeException))"(,"nativeStatus":-?(0|[1-9][0-9]{0,9}))?,"nativeModuleLoaded":(true|false),"moduleInApplicationDirectory":(true|false)\}\z'
    if ($texts[0].Length -gt 2048 -or $texts[0] -cnotmatch $pattern) { throw 'Unexpected subject shape' }
    $data = $texts[0] | ConvertFrom-Json
    if ($data.PSObject.Properties.Name -contains 'nativeStatus') {
        [void][int]$data.nativeStatus
        if ($data.operation -ne 'exception') { throw 'Unexpected native status' }
    }
    if (($data.operation -eq 'exception') -ne ($data.exceptionType -ne '')) { throw 'Inconsistent exception' }
    if ($data.operation -eq 'configuration_created' -and -not $data.builderCreated) { throw 'Inconsistent construction' }
    if ($data.moduleInApplicationDirectory -and -not $data.nativeModuleLoaded) { throw 'Inconsistent module state' }
    $success = $data.nativeAot -and $data.restrictedSearch -and -not $data.unexpectedPreload -and $data.builderCreated -and $data.operation -eq 'configuration_created' -and $data.moduleInApplicationDirectory
    $expectedExit = 1
    if ($success) { $expectedExit = 0 }
    if ($result.exitCode -ne $expectedExit) { throw 'Inconsistent subject exit' }
    if ($data.unexpectedPreload -or -not $data.restrictedSearch -or
        ($Action -ne 'positive' -and $data.nativeModuleLoaded)) {
        throw 'Unexpected native search result'
    }
    $result.observation = $data
    $result.safetyStop = $false
    $stage = 'completed'
} catch {
    $result.safetyStop = $true
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureStage = $stage
    $result.failureLine = $_.InvocationInfo.ScriptLineNumber
    # Never emit exception messages, raw native output, or provider diagnostics.
} finally {
    try {
        $compilerStopped = $true
        if ($compiler -and -not $compiler.HasExited) {
            $result.compilerTerminationRequested = $true
            $compiler.Kill()
            $compilerStopped = $compiler.WaitForExit(10000)
        }
        $subjectStopped = $true
        if ($guard) { $subjectStopped = $guard.Stop() }
        $result.quiescent = $compilerStopped -and $subjectStopped
    } catch {
        $result.quiescent = $false; $result.safetyStop = $true
        $result.terminationFailureType = $_.Exception.GetType().FullName
    }
    if ($guard) {
        $result.jobActiveBeforeStop = $guard.ActiveBeforeStop
        $result.jobTerminationRequested = $guard.TerminationRequested
        $result.jobTerminationSucceeded = $guard.TerminationSucceeded
    }
    if (-not $result.quiescent) { $result.safetyStop = $true }
    $result.stage = $stage
    if ($guard) { $guard.Dispose() }
    if ($compiler) { $compiler.Dispose() }
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    Save-Json "$attempt\result.json" $result
}

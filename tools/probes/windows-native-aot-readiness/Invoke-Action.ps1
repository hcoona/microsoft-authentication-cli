param(
    [ValidateSet('restore', 'publish', 'cleanup', 'wrong-architecture')]
    [string] $Action,
    [ValidatePattern('^[0-9]{2}$')][string] $AttemptName,
    [ValidatePattern('^[0-9a-f]{40}$')][string] $Accepted
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-native-aot-diagnostics\round-03'
$attempt = Join-Path "$root\attempts" $AttemptName
$vc = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231'
$sdk = 'C:\Program Files (x86)\Windows Kits\10'
$sdkVersion = '10.0.26100.0'
$dotnet = 'C:\Program Files\dotnet\dotnet.exe'
$result = [ordered]@{ exitCode = -1; quiescent = $false; safetyStop = $true }
$guard = $null
$compiler = $null
$texts = $null
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


function Convert-BuildDiagnostic([string] $Text) {
    # This exception to the strict probe emitter covers ordinary build output only.
    $data = [ordered]@{ text = ''; truncated = $false; redacted = $false; suppressedLines = 0; sensitiveOutput = $false }
    $sensitivePattern = '(?i)\b(access_token|refresh_token|id_token|client_secret|password|authorization|cookie)\s*[:=]|\bBearer\s+\S+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|\bMSALRUNTIME_.*\b(log|trace)\b'
    $clean = $Text -replace '\x1b\[[0-?]*[ -/]*[@-~]', ''
    $clean = $clean -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ''
    if ($Text -match $sensitivePattern -or $clean -match $sensitivePattern) {
        $data.sensitiveOutput = $true
        return $data
    }
    $paths = [ordered]@{
        $root = '<experiment-root>'; $vc = '<vc-tools>'
        $sdk = '<windows-sdk>'; 'C:\Program Files\dotnet' = '<dotnet>'
        'C:\Windows' = '<windows>'
    }
    foreach ($path in $paths.Keys) {
        $clean = [regex]::Replace($clean, [regex]::Escape($path), $paths[$path], 'IgnoreCase')
    }
    $clean = [regex]::Replace($clean, '(?i)https?://[^\s<>"'']+', {
        param($match)
        $uri = $null
        if ([Uri]::TryCreate($match.Value, [UriKind]::Absolute, [ref]$uri) -and
            $uri.Host -in @('api.nuget.org', 'www.nuget.org', 'learn.microsoft.com', 'aka.ms')) {
            return $uri.Scheme + '://' + $uri.Host + '/<url-detail-redacted>'
        }
        return '<url>'
    })
    $clean = $clean -replace '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '<email>'
    $clean = $clean -replace '(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b', '<identifier>'
    $data.redacted = $clean -cne $Text
    $lines = New-Object 'Collections.Generic.List[string]'
    foreach ($line in ($clean -split '\r?\n')) {
        # Unknown host paths and environment assignments are not public evidence.
        if ($line -match '(?i)(?<![a-z0-9])[a-z]:[\\/]|\\\\[^\s\\]+\\|/(home|Users)/' -or
            $line -cmatch '^\s*[A-Z][A-Z0-9_]{1,}\s*=') {
            $lines.Add('<suppressed: unexpected host path or environment assignment>')
            $data.suppressedLines++
        } else { $lines.Add($line) }
    }
    $kept = @($lines | Select-Object -First 8192)
    $textValue = [string]::Join("`n", $kept)
    if ($lines.Count -gt 8192 -or $textValue.Length -gt 1048576) { $data.truncated = $true }
    if ($textValue.Length -gt 1048576) { $textValue = $textValue.Substring(0, 1048576) }
    $data.text = $textValue
    return $data
}

try {
    # Windows reparse points include junctions that WSL leaf-symlink checks may miss.
    foreach ($base in @('C:\Temp', 'C:\Temp\azureauth-native-aot-diagnostics', $root, "$root\source", "$root\attempts", "$root\feed")) {
        if ((Get-Item -LiteralPath $base -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Linked input directory'
        }
    }
    foreach ($item in Get-ChildItem -LiteralPath $root -Force -Recurse) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked experiment input' }
    }
    Save-Json "$attempt\controller.json" @{ pid = $PID; started = (Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o') }
    $result.reservationSha256 = (Get-FileHash -LiteralPath "$attempt\started.json" -Algorithm SHA256).Hash.ToLowerInvariant()
    $stage = 'tool-identity'
    $identities = @{
        "$framework\csc.exe" = '46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00'
        $dotnet = '21a46f1e5235cf4e844b9de5429f0e198b9c97a41f0503a66442f1d639ca3ee6'
        "$vc\bin\Hostx64\x64\link.exe" = '610aae3d74a66fa5ef54cac5df8ea8bcbb1fdd2a3db9087eb92088bd395eaf34'
        "$vc\bin\Hostx64\x64\cl.exe" = '315a654ea116864516a1674858e587e535e3bc3045ff32ed2f2739a2c1ec5640'
        "$sdk\Lib\$sdkVersion\um\x64\kernel32.lib" = '341c7d56125a03b458e4d5093e4c79b33123ccfdfd610fe236937b8e6f3134bb'
        "$sdk\Lib\$sdkVersion\ucrt\x64\ucrt.lib" = '7ef4eac926bf597d2f243f16cdfed7e0db22cb3ca34a1d7e088a84c994a03d66'
    }
    foreach ($path in $identities.Keys) {
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $identities[$path]) {
            throw 'Toolchain identity changed'
        }
    }
    $source = "$root\source\$Accepted"
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
    $stage = 'input-verification'
    $start = Get-Content -LiteralPath "$attempt\started.json" -Raw | ConvertFrom-Json
    if ($start.action -ne $Action -or $start.accepted -ne $Accepted) { throw 'Reservation mismatch' }
    foreach ($property in $start.sourceSha256.PSObject.Properties) {
        $path = Join-Path $source $property.Name
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $property.Value) {
            throw 'Copied source identity changed'
        }
    }
    if ((Get-ChildItem -LiteralPath "$root\empty-program-files" -Force | Measure-Object).Count -ne 0) {
        throw 'Owned program-files root is not empty'
    }
    $working = $source
    $exe = $dotnet
    if ($Action -eq 'restore') {
        $timeout = 180
        $arguments = 'restore NativeAotReadinessProbe.csproj --configfile nuget.config --disable-parallel --verbosity minimal --no-http-cache -p:NuGetAudit=false -p:UseSharedCompilation=false -m:1 -nr:false'
    } elseif ($Action -eq 'publish') {
        $timeout = 600
        $arguments = 'publish NativeAotReadinessProbe.csproj -c Release --no-restore --disable-build-servers --verbosity minimal -o "' + $attempt + '\out" -p:IlcUseEnvironmentalTools=true -p:CppLinker="' + $vc + '\bin\Hostx64\x64\link.exe" -m:1 -nr:false'
    } else {
        $timeout = 30
        $case = "$attempt\app"
        $working = "$attempt\working"
        New-Item -ItemType Directory -Path $case, $working | Out-Null
        foreach ($property in $start.caseInputs.PSObject.Properties) {
            $inputPath = Join-Path $root $property.Value.path
            if ((Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $property.Value.sha256) {
                throw 'Case input identity changed'
            }
            Copy-Item -LiteralPath $inputPath -Destination (Join-Path $case $property.Name)
            if ((Get-FileHash -LiteralPath (Join-Path $case $property.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $property.Value.sha256) {
                throw 'Case copy identity changed'
            }
        }
        $exe = "$case\NativeAotReadinessProbe.exe"
        $arguments = ''
        $environment['PATH'] = 'C:\Windows\System32'
    }
    if ($Action -in @('restore', 'publish')) {
        $arguments += ' -noAutoResponse -p:ImportDirectoryBuildProps=false -p:ImportDirectoryBuildTargets=false -p:ImportDirectoryPackagesProps=false'
    }
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
    $compileOutput = Read-Output $compiler @($compiler.StandardOutput, $compiler.StandardError) 30
    $result.guardCompilerExitCode = $compiler.ExitCode
    if ($compiler.ExitCode -ne 0) { throw 'Guard compilation failed' }
    $stage = 'guard-load'
    Add-Type -Path "$attempt\WindowsJob.dll" -ErrorAction Stop -WarningAction Stop
    $guard = New-Object NativeAotJob
    if ($Action -eq 'publish') { $guard.PrepareMetadata() }
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
    $stage = 'normal-quiescence'
    $result.activeProcessesAfterCapture = $guard.ActiveProcesses
    $drain = [Diagnostics.Stopwatch]::StartNew()
    $drainLimit = [Math]::Min(2000, [Math]::Max(0, $timeout * 1000 - $watch.ElapsedMilliseconds))
    if ($Action -eq 'publish') { $guard.RequestMetadata($drain, $drainLimit) }
    while ($guard.ActiveProcesses -ne 0 -and $drain.ElapsedMilliseconds -lt $drainLimit) {
        Start-Sleep -Milliseconds 25
    }
    $result.normalDrainSeconds = [Math]::Round($drain.Elapsed.TotalSeconds, 3)
    $result.seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
    $result.activeProcessesAtNormalExit = $guard.ActiveProcesses
    if ($result.activeProcessesAtNormalExit -ne 0) { throw 'Owned descendants survived normal exit' }
    $stage = 'observation-validation'
    if ($Action -notin @('restore', 'publish')) {
        if ($texts[1].Length -ne 0) { throw 'Unexpected subject stderr; contents suppressed' }
        $exception = '(|System\.(DllNotFoundException|BadImageFormatException|TypeInitializationException|EntryPointNotFoundException|InvalidOperationException)|Microsoft\.Identity\.Client\.(MsalClientException|NativeInterop\.MsalRuntimeException))'
        $pattern = '\A\{"nativeAot":(true|false),"restrictedSearch":(true|false),"unexpectedPreload":(true|false),"firstChanceSelfCheck":(true|false),"builderCreated":(true|false),"allocated":(true|false),"cleanupExportsPresent":(true|false),"disposeReturned":(true|false),"secondDisposeReturned":(true|false),"cleanupFirstChanceExceptions":(-1|0|[1-9][0-9]{0,8}),"exceptionType":"' + $exception + '","innerExceptionType":"' + $exception + '","nativeModuleLoaded":(true|false),"moduleInApplicationDirectory":(true|false)\}\z'
        if ($texts[0].Length -gt 4096 -or $texts[0] -cnotmatch $pattern) { throw 'Unexpected subject shape' }
        $data = $texts[0] | ConvertFrom-Json
        $success = $data.nativeAot -and $data.restrictedSearch -and -not $data.unexpectedPreload -and $data.firstChanceSelfCheck -and $data.builderCreated -and $data.allocated -and $data.cleanupExportsPresent -and $data.disposeReturned -and $data.secondDisposeReturned -and $data.cleanupFirstChanceExceptions -eq 0 -and $data.exceptionType -eq '' -and $data.moduleInApplicationDirectory
        $expectedExit = 1
        if ($success) { $expectedExit = 0 }
        if ($result.exitCode -ne $expectedExit) { throw 'Inconsistent subject exit' }
        if ($data.unexpectedPreload -or -not $data.restrictedSearch -or
            ($Action -eq 'wrong-architecture' -and $data.nativeModuleLoaded)) { throw 'Unexpected native search result' }
        $result.observation = $data
    }
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
        if ($guard) {
            $subjectStopped = $guard.Stop()
        }
        $result.quiescent = $compilerStopped -and $subjectStopped
    } catch {
        $result.quiescent = $false; $result.safetyStop = $true
        $result.terminationFailureType = $_.Exception.GetType().FullName
    }
    if ($guard) {
        if ($Action -eq 'publish') { $result.jobMetadata = $guard.FinishMetadata() }
        $result.jobActiveBeforeStop = $guard.ActiveBeforeStop
        $result.jobTerminationRequested = $guard.TerminationRequested
        $result.jobTerminationSucceeded = $guard.TerminationSucceeded
    }
    if (-not $result.quiescent) { $result.safetyStop = $true }
    $result.stage = $stage
    if ($guard) { $guard.Dispose() }
    if ($compiler) { $compiler.Dispose() }
    # Terminate and dispose owned work before any diagnostic screening, including failure.
    if ($Action -in @('restore', 'publish') -and $result.captureCompleted -and $null -ne $texts) {
        try {
            $result.stdoutCharacters = $texts[0].Length
            $result.stderrCharacters = $texts[1].Length
            $result.stdoutDiagnostic = Convert-BuildDiagnostic $texts[0]
            $result.stderrDiagnostic = Convert-BuildDiagnostic $texts[1]
            $safeText = $result.stdoutDiagnostic.text + $result.stderrDiagnostic.text
            $result.diagnosticCodes = @([regex]::Matches($safeText, '\b(?:IL|CS|NU|NETSDK|MSB|LNK)[0-9]{4,5}\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)
            $result.diagnosticsComplete = -not ($result.stdoutDiagnostic.sensitiveOutput -or $result.stderrDiagnostic.sensitiveOutput -or
                $result.stdoutDiagnostic.truncated -or $result.stderrDiagnostic.truncated -or
                $result.stdoutDiagnostic.suppressedLines -or $result.stderrDiagnostic.suppressedLines)
            if (-not $result.diagnosticsComplete) {
                $result.safetyStop = $true
                if (-not $result.Contains('failureStage')) { $result.failureStage = 'diagnostic-screening' }
            }
        } catch {
            $result.safetyStop = $true
            $result.diagnosticsComplete = $false
            $result.diagnosticFailureType = $_.Exception.GetType().FullName
            if (-not $result.Contains('failureStage')) { $result.failureStage = 'diagnostic-screening' }
        }
    }
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    Save-Json "$attempt\result.json" $result
}

param(
    [ValidateSet('restore', 'publish', 'positive', 'missing', 'decoy')]
    [string] $Action,
    [ValidatePattern('^[0-9]{2}$')][string] $AttemptName
)
$ErrorActionPreference = 'Stop'
$root = 'C:\Temp\azureauth-native-aot-76'
$attempt = Join-Path "$root\attempts" $AttemptName
$vc = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231'
$sdk = 'C:\Program Files (x86)\Windows Kits\10'
$sdkVersion = '10.0.26100.0'
$dotnet = 'C:\Program Files\dotnet\dotnet.exe'
$result = [ordered]@{ exitCode = -1; quiescent = $false; safetyStop = $true }
$guard = $null
$compiler = $null
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
    return @($texts[0].ToString(), $texts[1].ToString())
}

try {
    Save-Json "$attempt\controller.json" @{ pid = $PID; started = (Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o') }
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
    $source = "$root\src"
    $environment = @{
        SystemRoot = 'C:\Windows'; WINDIR = 'C:\Windows'; ComSpec = 'C:\Windows\System32\cmd.exe'
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
    $working = $source
    $exe = $dotnet
    $timeout = 600
    if ($Action -eq 'restore') {
        $arguments = 'restore NativeAotProbe.csproj --configfile nuget.config --disable-parallel --verbosity minimal --no-http-cache -p:NuGetAudit=false -p:UseSharedCompilation=false -m:1 -nr:false'
    } elseif ($Action -eq 'publish') {
        $timeout = 900
        $arguments = 'publish NativeAotProbe.csproj -c Release --no-restore --disable-build-servers --verbosity minimal -o "' + $root + '\out" -p:IlcUseEnvironmentalTools=true -p:CppLinker="' + $vc + '\bin\Hostx64\x64\link.exe" -m:1 -nr:false'
    } else {
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
        $exe = "$case\NativeAotProbe.exe"
        $arguments = ''
    }
    if ($Action -in @('restore', 'publish')) {
        $arguments += ' -noAutoResponse -p:ImportDirectoryBuildProps=false -p:ImportDirectoryBuildTargets=false -p:ImportDirectoryPackagesProps=false'
    }
    # The pinned standalone compiler has no shared-compilation/build-server mode here.
    # Its process handle owns this one bootstrap process before the Job guard exists.
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
    $compileOutput = @(Read-Output $compiler @($compiler.StandardOutput, $compiler.StandardError) 60)
    $result.guardCompilerExitCode = $compiler.ExitCode
    if ($compiler.ExitCode -ne 0) { throw 'Guard compilation failed' }
    Add-Type -Path "$attempt\WindowsJob.dll" -ErrorAction Stop -WarningAction Stop
    $guard = New-Object NativeAotJob
    $guard.Start($exe, $arguments, $working, $environment)
    $child = $guard.Child
    Save-Json "$attempt\subject.json" @{ pid = $child.Id; started = $child.StartTime.ToUniversalTime().ToString('o') }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $texts = @(Read-Output $child @($guard.Output, $guard.Error) $timeout)
    $result.exitCode = $child.ExitCode
    $result.seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
    $result.safetyStop = $false
    if ($guard.ActiveProcesses -ne 0) { throw 'Owned descendant survived normal exit' }
    $result.quiescent = $true
    if ($Action -in @('restore', 'publish')) {
        # Keep diagnostic codes only; public source/tool inspection explains them later.
        $all = $texts[0].ToString() + $texts[1].ToString()
        $result.diagnosticCodes = @([regex]::Matches($all, '\b(?:IL|CS|NU|NETSDK|MSB|LNK)[0-9]{4,5}\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        $result.stdoutCharacters = $texts[0].Length
        $result.stderrCharacters = $texts[1].Length
        $result.sdkExceptionTypes = @(@(
            'System.ArgumentException', 'System.ArgumentNullException',
            'System.NullReferenceException', 'System.TypeInitializationException',
            'System.IO.DirectoryNotFoundException', 'System.IO.FileNotFoundException',
            'System.IO.IOException', 'System.UnauthorizedAccessException',
            'System.ComponentModel.Win32Exception'
        ) | Where-Object { $all.Contains($_) })
        $result.commandParseFailure = $all.Contains('Unrecognized command or argument')
    } else {
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

    }
} catch {
    $result.safetyStop = $true
    $result.failureType = $_.Exception.GetType().FullName
    # Never emit exception messages, raw native output, or provider diagnostics.
} finally {
    try {
        $compilerStopped = $true
        if ($compiler -and -not $compiler.HasExited) {
            $compiler.Kill()
            $compilerStopped = $compiler.WaitForExit(10000)
        }
        $subjectStopped = $true
        if ($guard) { $subjectStopped = $guard.Stop() }
        $result.quiescent = $compilerStopped -and $subjectStopped
    } catch { $result.quiescent = $false; $result.safetyStop = $true }
    if ($guard) { $guard.Dispose() }
    if ($compiler) { $compiler.Dispose() }
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    Save-Json "$attempt\result.json" $result
}

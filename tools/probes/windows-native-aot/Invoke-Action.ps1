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
$owned = @{}
$child = $null

function Save-Json($Path, $Value) {
    $Value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Record-Children {
    # PID, creation time, and parent links only; never retain names or command lines.
    $snapshot = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, CreationDate)
    do {
        $added = $false
        foreach ($item in $snapshot) {
            $key = [string]$item.ProcessId
            if ($owned.ContainsKey([string]$item.ParentProcessId) -and -not $owned.ContainsKey($key)) {
                $process = Get-Process -Id $key -ErrorAction SilentlyContinue
                if ($process) {
                    $owned[$key] = $process.StartTime.ToUniversalTime().ToString('o')
                    $added = $true
                }
            }
        }
    } while ($added)
    Save-Json "$attempt\owned-processes.json" $owned
}

function Live-Owned {
    foreach ($key in @($owned.Keys)) {
        $process = Get-Process -Id $key -ErrorAction SilentlyContinue
        if ($process -and $process.StartTime.ToUniversalTime().ToString('o') -eq $owned[$key]) {
            $process
        }
    }
}

try {
    Save-Json "$attempt\controller.json" @{ pid = $PID; started = (Get-Date).ToUniversalTime().ToString('o') }
    $identities = @{
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
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $exe
    $startInfo.Arguments = $arguments
    $startInfo.WorkingDirectory = $working
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables.Clear()
    foreach ($key in $environment.Keys) { $startInfo.EnvironmentVariables[$key] = $environment[$key] }
    $child = New-Object System.Diagnostics.Process
    $child.StartInfo = $startInfo
    if (-not $child.Start()) { throw 'Child failed to start' }
    $owned[[string]$child.Id] = $child.StartTime.ToUniversalTime().ToString('o')
    Save-Json "$attempt\owned-processes.json" $owned
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $buffers = @((New-Object char[] 4096), (New-Object char[] 4096))
    $streams = @($child.StandardOutput, $child.StandardError)
    $tasks = @($streams[0].ReadAsync($buffers[0], 0, 4096), $streams[1].ReadAsync($buffers[1], 0, 4096))
    $texts = @((New-Object Text.StringBuilder), (New-Object Text.StringBuilder))
    $done = @($false, $false)
    while (-not ($child.HasExited -and $done[0] -and $done[1])) {
        if ($watch.Elapsed.TotalSeconds -gt $timeout) { throw 'Attempt timeout' }
        for ($index = 0; $index -lt 2; $index++) {
            if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                $count = $tasks[$index].GetAwaiter().GetResult()
                if ($count -eq 0) { $done[$index] = $true } else {
                    if (($texts[0].Length + $texts[1].Length + $count) -gt 8388608) { throw 'Output bound' }
                    [void]$texts[$index].Append($buffers[$index], 0, $count)
                    $tasks[$index] = $streams[$index].ReadAsync($buffers[$index], 0, 4096)
                }
            }
        }
        Record-Children
        if ($owned.Count -gt 32) { throw 'Owned process bound' }
        Start-Sleep -Milliseconds 200
    }
    $child.WaitForExit()
    Record-Children
    $result.exitCode = $child.ExitCode
    $result.seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
    $result.safetyStop = $false
    if (@(Live-Owned).Count -ne 0) { throw 'Owned descendant survived normal exit' }
    $result.quiescent = $true
    if ($Action -in @('restore', 'publish')) {
        # Keep diagnostic codes only; public source/tool inspection explains them later.
        $all = $texts[0].ToString() + $texts[1].ToString()
        $result.diagnosticCodes = @([regex]::Matches($all, '\b(?:IL|CS|NU|NETSDK|MSB|LNK)[0-9]{4,5}\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    } else {
        if ($texts[1].Length -ne 0) { throw 'Unexpected subject stderr; contents suppressed' }
        $data = $texts[0].ToString() | ConvertFrom-Json
        $allowed = @('nativeAot', 'restrictedSearch', 'unexpectedPreload', 'builderCreated', 'operation', 'exceptionType', 'nativeStatus', 'nativeModuleLoaded', 'moduleInApplicationDirectory')
        if (@($data.PSObject.Properties.Name | Where-Object { $_ -notin $allowed }).Count -ne 0) { throw 'Unexpected subject field' }
        $result.observation = $data
        if ($data.unexpectedPreload -or -not $data.restrictedSearch -or
            ($Action -ne 'positive' -and $data.nativeModuleLoaded)) {
            throw 'Unexpected native search result'
        }
    }
} catch {
    $result.safetyStop = $true
    $result.failureType = $_.Exception.GetType().FullName
    # Never emit exception messages, raw native output, or provider diagnostics.
} finally {
    try {
        Record-Children
        foreach ($process in @(Live-Owned)) {
            # Identity is checked above. Only this experiment's still-live process tree.
            $killer = Start-Process -FilePath 'C:\Windows\System32\taskkill.exe' -ArgumentList @('/PID', $process.Id, '/T', '/F') -NoNewWindow -PassThru -RedirectStandardOutput "$attempt\termination.out" -RedirectStandardError "$attempt\termination.err"
            if (-not $killer.WaitForExit(10000)) { $killer.Kill(); throw 'Termination timeout' }
        }
        $result.quiescent = (@(Live-Owned).Count -eq 0)
    } catch { $result.quiescent = $false; $result.safetyStop = $true }
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    Save-Json "$attempt\result.json" $result
}

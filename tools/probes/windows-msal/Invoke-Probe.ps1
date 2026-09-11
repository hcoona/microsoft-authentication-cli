param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('prepare', 'inspect', 'silent', 'interactive')][string]$Action,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')][string]$AcceptedRevision
)
$ErrorActionPreference = 'Stop'
# Run only after the operator verifies the accepted protocol and cumulative history.
$root = Join-Path $env:LOCALAPPDATA 'AzureAuthResearch\windows-msal'
$subject = Join-Path $root ('source-' + $AcceptedRevision)
if ($PSScriptRoot -ne $subject) { throw 'Use the accepted source copy at the protocol location.' }
$lock = [IO.File]::Open((Join-Path $root 'active.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $journal = Join-Path $root 'attempts.jsonl'
    $events = @(if (Test-Path $journal) { Get-Content $journal | ForEach-Object { $_ | ConvertFrom-Json } })
    $starts = @($events | Where-Object Event -eq 'start')
    $ends = @($events | Where-Object Event -eq 'end')
    if ($starts.Count -ne $ends.Count) { throw 'Prior attempt is unresolved; reconcile its outcome before continuing.' }
    $limit = @{ prepare = 6; inspect = 1; silent = 2; interactive = 3 }
    if (@($starts | Where-Object Action -eq $Action).Count -ge $limit[$Action]) { throw 'Attempt limit exhausted.' }
    $attempt = $starts.Count + 1
    $directory = Join-Path $root ('attempt-' + $attempt)
    if (Test-Path $directory) { throw 'Attempt directory already exists; preserve it and reconcile history.' }
    New-Item $directory -ItemType Directory | Out-Null
    function Write-Event([string]$kind, [string]$outcome) {
        @{ Attempt = $attempt; Event = $kind; Action = $Action; Revision = $AcceptedRevision;
           Utc = [DateTime]::UtcNow.ToString('o'); Outcome = $outcome } |
            ConvertTo-Json -Compress | Add-Content $journal -Encoding UTF8
    }
    Write-Event 'start' 'started'
    $outcome = 'step-failed'
    $script:terminationUncertain = $false
    try {
        $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
        $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
        $env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = 'false'
        $env:DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = 'true'
        $env:MSBUILDDISABLENODEREUSE = '1'
        $env:DOTNET_CLI_USE_MSBUILD_SERVER = '0'
        $env:DOTNET_CLI_HOME = Join-Path $root 'cli-home'
        $env:NUGET_PACKAGES = Join-Path $root 'packages'
        $env:NUGET_HTTP_CACHE_PATH = Join-Path $root 'http-cache'
        $env:NUGET_CREDENTIALPROVIDER_SESSIONTOKENCACHE_ENABLED = 'false'
        foreach ($name in @('VSS_NUGET_EXTERNAL_FEED_ENDPOINTS', 'ARTIFACTS_CREDENTIALPROVIDER_FEED_ENDPOINTS',
                            'NUGET_PLUGIN_PATHS', 'NUGET_CREDENTIALPROVIDERS_PATH')) {
            Remove-Item ('Env:' + $name) -ErrorAction SilentlyContinue
        }
        Get-ChildItem Env: | Where-Object Name -like 'NuGetPackageSourceCredentials_*' |
            ForEach-Object { Remove-Item ('Env:' + $_.Name) }
        $dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
        $exe = Join-Path $subject 'bin\Release\net8.0-windows\WindowsMsalProbe.exe'
        $result = Join-Path $directory 'result.json'
        function Run-Bounded([string]$file, [string[]]$arguments, [int]$seconds, [bool]$build) {
            # All arguments are fixed protocol values or local artifact paths, never account selectors.
            $quoted = @($arguments | ForEach-Object { if ($_ -match '"') { throw 'Unsupported quote in path.' }; '"' + $_ + '"' })
            $options = @{ FilePath = $file; ArgumentList = $quoted; WorkingDirectory = $subject; PassThru = $true }
            if ($build) {
                $options.RedirectStandardOutput = Join-Path $directory ('build-' + $arguments[0] + '.stdout')
                $options.RedirectStandardError = Join-Path $directory ('build-' + $arguments[0] + '.stderr')
            }
            $process = $null
            $script:terminationUncertain = $true
            try {
                $process = Start-Process @options
                # Cache the handle before waiting so Windows PowerShell retains the exit code.
                $ownedHandle = $process.Handle
                if (!$process.WaitForExit($seconds * 1000)) {
                    throw 'Process exceeded the protocol limit; stop.'
                }
                $script:terminationUncertain = $false
                $process.Refresh()
                if ($null -eq $process.ExitCode) { throw 'Process exited, but its exit code is unavailable; stop.' }
                if ($process.ExitCode -ne 0) { throw 'Step returned failure; inspect only the permitted evidence.' }
            } finally {
                if ($script:terminationUncertain -and $null -ne $process) {
                    try {
                        if (!$process.HasExited) {
                            if ($build) { & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F | Out-Null }
                            else { $process.Kill() }
                        }
                        if ($process.WaitForExit(10000)) { $script:terminationUncertain = $false }
                    } catch {
                        # Keep the started entry unresolved when owned-process exit is unconfirmed.
                    }
                }
            }
        }
        if ($Action -eq 'prepare') {
            Run-Bounded $dotnet @('restore', 'WindowsMsalProbe.csproj', '--configfile', 'nuget.config', '--force-evaluate', '--disable-parallel', '--nologo') 120 $true
            Run-Bounded $dotnet @('build', 'WindowsMsalProbe.csproj', '--no-restore', '-c', 'Release', '--nologo', '-nodeReuse:false') 120 $true
            Run-Bounded $exe @('self-check', $result) 15 $false
            $outcome = 'prepared-and-self-checked'
        } else {
            if (!(Test-Path $exe)) { throw 'Prepare and verify the build before authentication.' }
            $seconds = if ($Action -eq 'interactive') { 375 } else { 135 }
            Run-Bounded $exe @($Action, $result) $seconds $false
            $outcome = 'completed'
        }
    } finally {
        if (!$script:terminationUncertain) { Write-Event 'end' $outcome }
    }
} finally {
    $lock.Dispose()
}

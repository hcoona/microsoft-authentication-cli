# Fixed synthetic bootstrap for the separately admitted publication-mode fixtures.
param(
    [string] $ActionName, [string] $ReservationSha256, [string] $InvocationSha256,
    [string] $AuthoritySha256,
    [ValidateSet('Root', 'Descendant')][string] $FixtureRole = 'Root'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2
$watch = [Diagnostics.Stopwatch]::StartNew()
$root = [IO.Path]::GetDirectoryName($PSScriptRoot)
$shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if ($root -cnotmatch '^C:\\Temp\\azureauth-windows-slice-108\\publication-fixtures-0106$' -or
    $root.Substring($root.Length - 4) -cne $ActionName -or $env:PSModuleAnalysisCachePath -cne 'NUL') {
    throw 'Unbound publication fixture workload'
}

function Read-Fixed([string] $Path, [int] $Limit) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked workload input' }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        elseif ($item -is [IO.FileInfo]) { $item = $item.Directory }
        else { throw 'Nonfilesystem workload input' }
    }
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -gt $Limit) { throw 'Oversized workload input' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'Incomplete workload input' }
            $offset += $count
        }
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Hash-Fixed([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Save-Ready([string] $Name, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 8 -Compress) + "`n")
    if ($bytes.Length -gt 4096) { throw 'Workload readiness bound' }
    $stream = [IO.File]::Open("$root\$Name.pending", 'CreateNew', 'Write', 'Read')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    [IO.File]::Move("$root\$Name.pending", "$root\$Name")
}

foreach ($hash in @($AuthoritySha256, $ReservationSha256, $InvocationSha256)) {
    if ($hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound workload hash' }
}
$authorityBytes = Read-Fixed "$root\authority.json" 65536
if ((Hash-Fixed $authorityBytes) -cne $AuthoritySha256 -or
    (Hash-Fixed (Read-Fixed "$root\started.json" 4096)) -cne $ReservationSha256 -or
    (Hash-Fixed (Read-Fixed "$root\invocation.json" 4096)) -cne $InvocationSha256) {
    throw 'Changed workload authority or fixture inputs'
}
$authority = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes) | ConvertFrom-Json
$caseName = switch ($ActionName) {
    '0106' { 'journal-cancel' }
}
$spec = $authority.failureCases.$caseName
if ($authority.schema -cne 'named-guard-fixtures-0105-v1' -or $authority.action -cne '0105' -or
    $spec.root -cne $root -or $spec.reservationSha256 -cne $ReservationSha256 -or
    $spec.invocationSha256 -cne $InvocationSha256 -or
    (Hash-Fixed (Read-Fixed $PSCommandPath 65536)) -cne $authority.failureControllerSha256 -or
    (Hash-Fixed (Read-Fixed $shell 1048576)) -cne
        '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e') {
    throw 'Unaccepted publication fixture workload'
}
if ($caseName -ceq 'pre-resume') { throw 'The never-resumed fixture must not execute' }
$self = [Diagnostics.Process]::GetCurrentProcess()
try {
    $identity = @{
        pid = $self.Id; creationFileTime = $self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        session = $self.SessionId; case = $caseName; authoritySha256 = $AuthoritySha256
    }
} finally { $self.Dispose() }

if ($FixtureRole -ceq 'Descendant') {
    Save-Ready 'descendant-ready.json' $identity
    while ($watch.ElapsedMilliseconds -lt 30000) {
        if ($caseName -ceq 'normal' -and (Test-Path -LiteralPath "$root\release")) { exit 0 }
        Start-Sleep -Milliseconds 25
    }
    exit 0
}

$child = $null
try {
    if ($caseName -cne 'resume-unknown') {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $shell
        $start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath +
            '" -ActionName ' + $ActionName + ' -ReservationSha256 ' + $ReservationSha256 +
            ' -InvocationSha256 ' + $InvocationSha256 + ' -AuthoritySha256 ' + $AuthoritySha256 + ' -FixtureRole Descendant'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.WorkingDirectory = $root
        $start.EnvironmentVariables.Clear()
        foreach ($entry in @{
            SystemRoot = 'C:\Windows'; windir = 'C:\Windows'; SystemDrive = 'C:'
            TEMP = $root; TMP = $root; USERPROFILE = $root
            PATH = 'C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0'
            PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
            PSModuleAnalysisCachePath = 'NUL'
            POWERSHELL_TELEMETRY_OPTOUT = '1'; DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        }.GetEnumerator()) { $start.EnvironmentVariables.Add($entry.Key, $entry.Value) }
        $child = [Diagnostics.Process]::new()
        $child.StartInfo = $start
        if (-not $child.Start()) { throw 'Synthetic descendant creation rejected' }
        [void]$child.Handle
        while (-not (Test-Path -LiteralPath "$root\descendant-ready.json")) {
            if ($watch.ElapsedMilliseconds -ge 15000 -or $child.HasExited) { throw 'Descendant readiness failed' }
            Start-Sleep -Milliseconds 25
        }
        $ready = [Text.UTF8Encoding]::new($false, $true).GetString(
            (Read-Fixed "$root\descendant-ready.json" 4096)) | ConvertFrom-Json
        if ($ready.pid -ne $child.Id -or $ready.authoritySha256 -cne $AuthoritySha256 -or
            $ready.creationFileTime -cne $child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()) {
            throw 'Descendant incarnation changed'
        }
        $identity.descendantPid = $child.Id
        $identity.descendantCreationFileTime = $ready.creationFileTime
    }
    Save-Ready 'root-ready.json' $identity
    $wroteOverflow = $false
    while ($watch.ElapsedMilliseconds -lt 30000) {
        if (Test-Path -LiteralPath "$root\release") {
            if ($caseName -ceq 'normal') { exit 0 }
            if ($caseName -ceq 'overflow' -and -not $wroteOverflow) {
                # Exactly one bounded write; a closed reader never causes a retry.
                $wroteOverflow = $true
                try {
                    [Console]::Out.Write([string]::new([char]'X', 20480))
                    [Console]::Out.Flush()
                } catch [IO.IOException] {
                    # The candidate may close its reader after retaining the prefix.
                    # Stay alive for the original survival observation; never retry.
                }
            }
        }
        Start-Sleep -Milliseconds 25
    }
    exit 0
} finally { if ($null -ne $child) { $child.Dispose() } }

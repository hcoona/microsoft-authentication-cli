# Fixed credential-free workloads for the separately admitted 0072 batch.
param(
    [ValidateSet('Controller', 'Payload')][string] $Mode = 'Controller',
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string] $AuthoritySha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2
$watch = [Diagnostics.Stopwatch]::StartNew()
$root = $PSScriptRoot
$shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if ($root -cnotmatch '^C:\\Temp\\azureauth-windows-slice-108\\named-fixtures-007[3-6]$' -or
    $env:PSModuleAnalysisCachePath -cne 'NUL') { throw 'Unbound negative workload' }

function Read-Fixed([string] $Path, [int] $Limit) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked negative workload input' }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        elseif ($item -is [IO.FileInfo]) { $item = $item.Directory }
        else { throw 'Nonfilesystem workload input' }
    }
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -gt $Limit) { throw 'Oversized negative workload input' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'Incomplete negative workload input' }
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
    if ($bytes.Length -gt 4096) { throw 'Negative workload readiness bound' }
    $stream = [IO.File]::Open("$root\$Name.pending", 'CreateNew', 'Write', 'Read')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    [IO.File]::Move("$root\$Name.pending", "$root\$Name")
}

$authorityBytes = Read-Fixed "$root\authority.json" 65536
if ((Hash-Fixed $authorityBytes) -cne $AuthoritySha256) { throw 'Changed negative workload authority' }
$authority = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes) | ConvertFrom-Json
if ($authority.schema -cne 'named-guard-fixtures-0072-v1' -or $authority.action -cne '0072' -or
    (Hash-Fixed (Read-Fixed $PSCommandPath 65536)) -cne $authority.failureControllerSha256 -or
    (Hash-Fixed (Read-Fixed $shell 1048576)) -cne
        '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e') {
    throw 'Unaccepted negative workload source'
}
$caseName = switch ($root.Substring($root.Length - 4)) {
    '0073' { 'cancel' }
    '0074' { 'collision' }
    '0075' { 'overflow' }
    '0076' { 'journal' }
}
if ($authority.failureCases.$caseName.root -cne $root) { throw 'Negative workload root mismatch' }
$self = [Diagnostics.Process]::GetCurrentProcess()
try {
    $identity = @{
        pid = $self.Id; creationFileTime = $self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        session = $self.SessionId; case = $caseName; authoritySha256 = $AuthoritySha256
    }
} finally { $self.Dispose() }

if ($Mode -eq 'Payload') {
    Save-Ready 'descendant-ready.json' $identity
    # The candidate must terminate this live descendant before its natural exit.
    while ($watch.ElapsedMilliseconds -lt 30000) { Start-Sleep -Milliseconds 25 }
    exit 0
}
if ($caseName -eq 'collision') { throw 'A colliding candidate must not create its controller' }

$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $shell
$start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    $PSCommandPath + '" -Mode Payload -AuthoritySha256 ' + $AuthoritySha256
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
try {
    if (-not $child.Start()) { throw 'Descendant startup rejected' }
    [void]$child.Handle
    while (-not (Test-Path -LiteralPath "$root\descendant-ready.json")) {
        if ($watch.ElapsedMilliseconds -ge 15000 -or $child.HasExited) { throw 'Descendant readiness failed' }
        Start-Sleep -Milliseconds 25
    }
    $ready = [Text.UTF8Encoding]::new($false, $true).GetString(
        (Read-Fixed "$root\descendant-ready.json" 4096)) | ConvertFrom-Json
    if ($ready.pid -ne $child.Id -or $ready.authoritySha256 -cne $AuthoritySha256 -or
        $ready.creationFileTime -cne $child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()) {
        throw 'Descendant identity mismatch'
    }
    $identity.descendantPid = $child.Id
    $identity.descendantCreationFileTime = $ready.creationFileTime
    Save-Ready 'root-ready.json' $identity
    while ($watch.ElapsedMilliseconds -lt 25000) {
        if ($caseName -eq 'overflow' -and (Test-Path -LiteralPath "$root\release")) {
            [Console]::Out.Write([string]::new([char]'X', 20480))
            [Console]::Out.Flush()
            # One fixed write, then remain live until the candidate terminates the Job.
            while ($watch.ElapsedMilliseconds -lt 25000) { Start-Sleep -Milliseconds 25 }
            break
        }
        Start-Sleep -Milliseconds 25
    }
    exit 2
} finally { $child.Dispose() }

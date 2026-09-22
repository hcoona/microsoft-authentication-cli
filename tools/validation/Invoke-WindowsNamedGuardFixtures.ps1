# Prospective singleton fixtures. Source, protocol and exact call admission are required.
param(
    [ValidateSet('Controller')][string] $Mode = 'Controller',
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string] $AuthoritySha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2
if ($env:PSModuleAnalysisCachePath -cne 'NUL') { throw 'Fixture startup cache control is absent' }
$watch = [Diagnostics.Stopwatch]::StartNew()
$root = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0080'
$shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$script:writtenBytes = 0
$script:readBytes = 0

function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked fixture path' }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        elseif ($item -is [IO.FileInfo]) { $item = $item.Directory }
        else { throw 'Fixture path is not a filesystem entry' }
    }
}

function Get-Hash([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Read-Bytes([string] $Path, [int] $Maximum) {
    Assert-Direct $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -gt $Maximum) { throw 'Fixture input too large' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $request = $bytes.Length - $offset
            $script:readBytes += $request
            if ($script:readBytes -gt 4194304) { throw 'Fixture input budget' }
            $count = $stream.Read($bytes, $offset, $request)
            if ($count -eq 0) { throw 'Incomplete fixture input' }
            $offset += $count
        }
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Read-Json([string] $Path, [int] $Maximum = 65536) {
    $bytes = Read-Bytes $Path $Maximum
    return ([Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json)
}

function Save-Json([string] $Path, $Value) {
    Assert-Direct ([IO.Path]::GetDirectoryName($Path))
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress) + "`n")
    $script:writtenBytes += $bytes.Length
    if ($bytes.Length -gt 65536 -or $script:writtenBytes -gt 262144) { throw 'Fixture output budget' }
    $stream = [IO.File]::Open(($Path + '.pending'), 'CreateNew', 'Write', 'Read')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    [IO.File]::Move(($Path + '.pending'), $Path)
}

function Assert-Time([long] $Milliseconds) {
    if ($watch.ElapsedMilliseconds -ge $Milliseconds -or (Test-Path -LiteralPath "$root\cancel")) {
        throw 'Fixture deadline or cancellation'
    }
}

function Get-FailureDetails($Record) {
    $text = $Record.ToString() + "`n" + $Record.ScriptStackTrace
    return $text.Substring(0, [Math]::Min(4096, $text.Length))
}

function New-Environment([string] $Working) {
    return @{
        SystemRoot = 'C:\Windows'; windir = 'C:\Windows'; SystemDrive = 'C:'
        TEMP = $Working; TMP = $Working; USERPROFILE = $Working
        PATH = 'C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0'
        PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
        PSModuleAnalysisCachePath = 'NUL'
        POWERSHELL_TELEMETRY_OPTOUT = '1'; DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    }
}

$authorityBytes = Read-Bytes "$root\authority.json" 65536
if ((Get-Hash $authorityBytes) -cne $AuthoritySha256) { throw 'Fixture authority changed' }
$authorityText = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes)
$authority = $authorityText | ConvertFrom-Json
if ($authorityText -cne (($authority | ConvertTo-Json -Depth 20 -Compress) + "`n") -or
    $authority.schema -cne 'named-guard-fixtures-0080-v1' -or
    $authority.accepted -ne $true -or $authority.action -cne '0080' -or
    $authority.countsBefore.preparation -ne 19 -or $authority.countsBefore.buildTest -ne 101 -or
    $authority.countsBefore.publication -ne 2 -or $authority.countsBefore.synthetic -ne 118 -or
    $authority.failedFixtureDispositionSha256 -cne '1ecb4ef1ec1c0eea1afeaa71c6e705dd3962e6998a582bc118780d983e812dcf' -or
    $authority.buildTestCharge -ne 1 -or $authority.syntheticCharge -ne 12) {
    throw 'Unaccepted fixture allocation'
}
if ((Get-Hash (Read-Bytes $PSCommandPath 65536)) -cne $authority.controllerSha256) {
    throw 'Fixture source changed'
}
if ((Get-Hash (Read-Bytes $shell 1048576)) -cne
    '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e') {
    throw 'Pinned fixture PowerShell changed'
}
if (@($authority.cases.PSObject.Properties).Count -ne 0 -or
    $authority.guards0079AcceptanceSha256 -cne '86ea310102425d52e906abd870687c1a0a15d43a090f59751218806c2a7e716c') {
    throw 'Unaccepted prior guards or allocated guard rerun'
}
$negativeRoots = [ordered]@{ cancel = '0081'; collision = '0082'; overflow = '0083'; journal = '0084' }
if (@($authority.failureCases.PSObject.Properties.Name).Count -ne 4 -or
    $authority.failure0071DispositionSha256 -cne
        '7e70e12e52e2eecd0d4fd823763cef52334da5f197fadef91950218b7b511664') {
    throw 'Missing accepted original failure disposition or negative cases'
}
foreach ($entry in $negativeRoots.GetEnumerator()) {
    $spec = $authority.failureCases.($entry.Key)
    if ($spec.root -cne ('C:\Temp\azureauth-windows-slice-108\named-fixtures-' + $entry.Value) -or
        $spec.suffix -cnotmatch '^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$') {
        throw 'Unbound negative case root or Job suffix'
    }
}
Assert-Time 10000

$dll = Read-Bytes "$root\WindowsFinalPublishGuard.dll" 24576
if ($dll.Length -ne 24576 -or (Get-Hash $dll) -cne
    'a18302e4658afc08b564be23c9b52995fba85c1a3345fba19662008efe30ae58') {
    throw 'Accepted actual guard changed'
}
[void][Reflection.Assembly]::Load($dll)

$result = [ordered]@{ schema = 'named-guard-fixtures-result-v1'; passed = $false; quiescent = $false
    launcherFailureCases = @(); authoritySha256 = $AuthoritySha256; failureType = $null; cases = @() }
try {
    $controller = [Diagnostics.Process]::GetCurrentProcess()
    try {
        Save-Json "$root\windows-started.json" @{
            schema = 'named-guard-fixtures-started-v1'; authoritySha256 = $AuthoritySha256
            buildTestCharge = 1; syntheticCharge = 12; controllerPid = $PID
            controllerCreationFileTime = $controller.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
            controllerSession = $controller.SessionId
        }
    } finally { $controller.Dispose() }
    Assert-Time 180000
    if ((Get-Hash (Read-Bytes "$root\WindowsLauncherFailureFixtures.ps1" 65536)) -cne
        $authority.failureDriverSha256) { throw 'Changed launcher failure driver' }
    . "$root\WindowsLauncherFailureFixtures.ps1"
    $result.launcherFailureCases = @(Invoke-LauncherFailureCases)
    if ($result.launcherFailureCases.Count -ne 4) { throw 'Incomplete launcher failure batch' }
    Assert-Time 300000
    $result.quiescent = $true
    $result.passed = $true
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureDetails = Get-FailureDetails $_
}
finally { Save-Json "$root\windows-result.json" $result }
# Four negative slots use at most 100 seconds; no guard case is rerun.
# The original 300-second controller clock also bounds setup and persistence.
Assert-Time 310000
if (-not $result.passed) { exit 1 }
exit 0

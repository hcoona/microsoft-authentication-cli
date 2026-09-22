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
$root = 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0103'
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

function Save-Json([string] $Path, $Value, $CaseWatch = $null) {
    if ($null -ne $CaseWatch) { Assert-PublicationFixtureTime $CaseWatch }
    Assert-Direct ([IO.Path]::GetDirectoryName($Path))
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress) + "`n")
    $script:writtenBytes += $bytes.Length
    if ($bytes.Length -gt 65536 -or $script:writtenBytes -gt 262144) { throw 'Fixture output budget' }
    if ($null -ne $CaseWatch) { Assert-PublicationFixtureTime $CaseWatch }
    $stream = [IO.File]::Open(($Path + '.pending'), 'CreateNew', 'Write', 'Read')
    try {
        if ($null -ne $CaseWatch) { Assert-PublicationFixtureTime $CaseWatch }
        $stream.Write($bytes, 0, $bytes.Length)
        if ($null -ne $CaseWatch) { Assert-PublicationFixtureTime $CaseWatch }
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    if ($null -ne $CaseWatch) { Assert-PublicationFixtureTime $CaseWatch }
    [IO.File]::Move(($Path + '.pending'), $Path)
    if ($null -ne $CaseWatch) { Assert-PublicationFixtureTime $CaseWatch }
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
    $authority.schema -cne 'named-guard-fixtures-0103-v1' -or
    $authority.accepted -ne $true -or $authority.action -cne '0103' -or
    $authority.countsBefore.preparation -ne 20 -or $authority.countsBefore.buildTest -ne 103 -or
    $authority.countsBefore.publication -ne 2 -or $authority.countsBefore.synthetic -ne 147 -or
    $authority.fixture0094DispositionSha256 -cne '62bd9da67fc9f5f887909ed8c10496c052974f006f0d9e7573ab5dac9a7cecf1' -or
    $authority.materialization0101DispositionSha256 -cne '2fdaf1e209bc26bac591ff9b54aae4561054a4252e7595182c441f1b71de9a7b' -or
    $authority.failedFixtureDispositionSha256 -cne '1ecb4ef1ec1c0eea1afeaa71c6e705dd3962e6998a582bc118780d983e812dcf' -or
    $authority.buildTestCharge -ne 1 -or $authority.syntheticCharge -ne 4) {
    throw 'Unaccepted fixture allocation'
}
if ((Get-Hash (Read-Bytes $PSCommandPath 65536)) -cne $authority.controllerSha256) {
    throw 'Fixture source changed'
}
if ((Get-Hash (Read-Bytes $shell 1048576)) -cne
    '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e') {
    throw 'Pinned fixture PowerShell changed'
}
if ($authority.negatives0080AcceptanceSha256 -cne
    'ee9e2ca7b5635add3a231930acc8ef2c3d2851056d3f8689b239ce038c1de791') {
    throw 'Original 0080 acceptance changed'
}
$negativeRoots = [ordered]@{ 'journal-cancel' = '0104' }
if (@($authority.failureCases.PSObject.Properties.Name).Count -ne 1) {
    throw 'Incomplete publication fixture allocation'
}
foreach ($entry in $negativeRoots.GetEnumerator()) {
    $spec = $authority.failureCases.($entry.Key)
    if ($spec.root -cne ('C:\Temp\azureauth-windows-slice-108\publication-fixtures-' + $entry.Value) -or
        $spec.suffix -cnotmatch '^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$' -or
        $spec.reservationSha256 -cnotmatch '^[0-9a-f]{64}$' -or $spec.invocationSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Unbound publication fixture root or inputs'
    }
}
$candidate = Read-Bytes "$root\WindowsPublicationJobLauncher.exe" 65536
if ($candidate.Length -ne $authority.publicationLauncherBytes -or
    (Get-Hash $candidate) -cne $authority.publicationLauncherSha256 -or
    $authority.publicationLauncherAcceptanceSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'Changed admitted publication launcher artifact'
}
Assert-Time 10000

$dll = Read-Bytes "$root\WindowsFinalPublishGuard.dll" 24576
if ($dll.Length -ne 24576 -or (Get-Hash $dll) -cne
    'a18302e4658afc08b564be23c9b52995fba85c1a3345fba19662008efe30ae58') {
    throw 'Accepted actual guard changed'
}
[void][Reflection.Assembly]::Load($dll)

$result = [ordered]@{ schema = 'named-guard-fixtures-result-v1'; passed = $false; quiescent = $false
    launcherFailureCases = @(); authoritySha256 = $AuthoritySha256; failureType = $null }
try {
    $controller = [Diagnostics.Process]::GetCurrentProcess()
    try {
        Save-Json "$root\windows-started.json" @{
            schema = 'named-guard-fixtures-started-v1'; authoritySha256 = $AuthoritySha256
            buildTestCharge = 1; syntheticCharge = 4; controllerPid = $PID
            controllerCreationFileTime = $controller.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
            controllerSession = $controller.SessionId
        }
    } finally { $controller.Dispose() }
    Assert-Time 180000
    if ((Get-Hash (Read-Bytes "$root\WindowsLauncherFailureFixtures.ps1" 65536)) -cne
        $authority.failureDriverSha256) { throw 'Changed launcher failure driver' }
    . "$root\WindowsLauncherFailureFixtures.ps1"
    $result.launcherFailureCases = @(Invoke-LauncherFailureCases)
    if ($result.launcherFailureCases.Count -ne 1) { throw 'Incomplete launcher failure batch' }
    Assert-Time 300000
    $result.quiescent = $true
    $result.passed = $true
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureDetails = Get-FailureDetails $_
}
finally { Save-Json "$root\windows-result.json" $result }
# One fresh journal-cancel slot uses at most 40 seconds.
# The original 300-second controller clock also bounds setup and persistence.
Assert-Time 310000
if (-not $result.passed) { exit 1 }
exit 0

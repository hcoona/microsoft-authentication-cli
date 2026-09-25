# Fixed synthetic clock harness; not a publication entry point.
param(
    [ValidateSet('Controller', 'Success', 'Diagnostic', 'Persistence')][string] $Mode,
    [string] $AuthoritySha256
)
$ClockFixtureDraftOnly = $true
if ($ClockFixtureDraftOnly) { throw 'DRAFT_ONLY: clock fixture has no execution admission' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 2
$fixtureWatch = [Diagnostics.Stopwatch]::StartNew()
$root = $PSScriptRoot
$shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if ($root -cne 'C:\Temp\azureauth-windows-slice-108\named-fixtures-0108' -or
    $AuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or $env:PSModuleAnalysisCachePath -cne 'NUL') {
    throw 'Unbound clock fixture'
}

function Assert-FixtureBudget {
    if ($fixtureWatch.ElapsedMilliseconds -ge 180000 -or (Test-Path -LiteralPath "$root\cancel")) {
        throw 'Clock fixture expired or cancelled'
    }
}

function Read-Fixture([string] $Path, [int] $Limit) {
    Assert-FixtureBudget
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked fixture input' }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        elseif ($item -is [IO.FileInfo]) { $item = $item.Directory }
        else { throw 'Nonfilesystem fixture input' }
    }
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -gt $Limit) { throw 'Fixture input bound' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            Assert-FixtureBudget
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'Incomplete fixture input' }
            $offset += $count
        }
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Hash-Fixture([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Save-Fixture([string] $Path, $Value) {
    Assert-FixtureBudget
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12 -Compress) + "`n")
    if ($bytes.Length -gt 8192) { throw 'Fixture output bound' }
    $stream = [IO.File]::Open(($Path + '.pending'), 'CreateNew', 'Write', 'Read')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Assert-FixtureBudget
    [IO.File]::Move(($Path + '.pending'), $Path)
}

function Wait-FixtureFile([string] $Path, [long] $End) {
    while (-not (Test-Path -LiteralPath $Path)) {
        Assert-FixtureBudget
        if ($fixtureWatch.ElapsedMilliseconds -ge $End) { throw 'Fixture acknowledgment expired' }
        Start-Sleep -Milliseconds 25
    }
}

$authorityBytes = Read-Fixture "$root\authority.json" 65536
if ((Hash-Fixture $authorityBytes) -cne $AuthoritySha256) { throw 'Changed fixture authority' }
$authority = [Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes) | ConvertFrom-Json
if ($authority.schema -cne 'clock-handoff-0108-v1' -or $authority.action -cne '0108' -or
    $authority.accepted -ne $true -or $authority.buildTestCharge -ne 1 -or $authority.syntheticCharge -ne 4 -or
    (Hash-Fixture (Read-Fixture $PSCommandPath 65536)) -cne $authority.harnessSha256 -or
    (Hash-Fixture (Read-Fixture $shell 1048576)) -cne
        '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e') {
    throw 'Unaccepted fixture inputs'
}

# Only reviewed fixed spans are evaluated. Neither complete source is dot-sourced.
$sourceText = @{}
foreach ($role in @('bootstrap', 'controller')) {
    $pin = $authority.extraction.$role
    $raw = Read-Fixture "$root\$role.source.txt" 131072
    if ($raw.Length -ne $pin.bytes -or (Hash-Fixture $raw) -cne $pin.sha256) { throw 'Changed extraction source' }
    foreach ($value in $raw) { if ($value -gt 127) { throw 'Non-ASCII source offsets' } }
    $sourceText[$role] = [Text.Encoding]::ASCII.GetString($raw)
}
$segments = @{}
$expectedFunctions = @{
    bootstrap = @('Get-BootstrapFailure', 'Assert-BootstrapBudget', 'Assert-BootstrapDirect',
        'Get-BootstrapHash', 'Read-BootstrapBytes', 'Save-BootstrapJson')
    controller = @('Get-FinalStartupFailure', 'Get-FinalHash', 'Read-FinalBytes', 'Assert-FinalBudget',
        'Receive-FinalOriginalClock', 'Save-Json', 'Save-CompleteJson', 'Save-Bytes', 'Assert-GuardDirect')
}
foreach ($role in @('bootstrap', 'controller')) {
    $extra = if ($role -ceq 'bootstrap') { 'handoff' } else { 'startup' }
    $names = @($expectedFunctions[$role]) + @($extra)
    $actual = @($authority.extraction.$role.spans.PSObject.Properties.Name)
    if ($actual.Count -ne $names.Count) { throw 'Extraction shape changed' }
    foreach ($name in $names) {
        if ($actual -cnotcontains $name) { throw 'Missing extraction span' }
        $pin = $authority.extraction.$role.spans.$name
        if ($pin.offset -lt 0 -or $pin.bytes -lt 1 -or $pin.offset + $pin.bytes -gt $sourceText[$role].Length) {
            throw 'Extraction offset bound'
        }
        $text = $sourceText[$role].Substring($pin.offset, $pin.bytes)
        if ((Hash-Fixture ([Text.Encoding]::ASCII.GetBytes($text))) -cne $pin.sha256) { throw 'Changed extraction span' }
        $tokens = $null; $errors = $null
        $parsed = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        if ($errors.Count -ne 0) { throw 'Extraction syntax error' }
        if ($name -cne $extra) {
            $statements = @($parsed.EndBlock.Statements)
            if ($statements.Count -ne 1 -or $statements[0] -isnot [Management.Automation.Language.FunctionDefinitionAst] -or
                $statements[0].Name -cne $name) { throw 'Extraction is not one expected function' }
            . ([scriptblock]::Create($text))
        } else { $segments[$name] = [scriptblock]::Create($text) }
    }
}

$ActionName = '0108'
$ReservationSha256 = $authority.reservationSha256
$InvocationSha256 = $authority.invocationSha256
foreach ($hash in @($ReservationSha256, $InvocationSha256)) {
    if ($hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound synthetic clock identities' }
}
$script:FinalControllerWatch = $fixtureWatch
$script:FinalActionWatch = $null
$script:FinalCancelPath = "$root\cancel"
$script:FinalClock = $null
$script:FinalStartupPhase = 'binding'
$originalControllerWatch = $fixtureWatch
$bootstrapWatch = $fixtureWatch
$deadlineCounter = $null

if ($Mode -cne 'Controller') {
    $case = switch ($Mode) { 'Success' { 'success' }; 'Diagnostic' { 'diagnostic' }; 'Persistence' { 'persistence' } }
    $script:caseBinding = [pscustomobject]@{ actionPath = "$root\$case"; endpoint = $authority.endpoint }
    # The real binding implementation and publication candidate are outside this test.
    # This one fixed synthetic binding substitutes only their fixture boundary.
    function Initialize-FinalBinding($ControllerWatch) { return $script:caseBinding }
    function Invoke-FinalPublishCandidate($Binding, $ControllerWatch) { throw 'Fixture must never enter publication candidate' }
    if ($Mode -cne 'Success') {
        . $segments.startup
        throw 'Negative startup unexpectedly returned'
    }
    Receive-FinalOriginalClock $script:caseBinding $fixtureWatch
    Save-Fixture "$root\success\reader.json" $script:FinalClock
    Wait-FixtureFile "$root\success\release.json" ([Math]::Min(170000L, $fixtureWatch.ElapsedMilliseconds + 30000L))
    Assert-FinalBudget
    exit 0
}

function Start-FixtureChild([string] $Role) {
    Assert-FixtureBudget
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $shell
    $info.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath +
        '" -Mode ' + $Role + ' -AuthoritySha256 ' + $AuthoritySha256
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = $root
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables.Clear()
    foreach ($entry in @{
        SystemRoot = 'C:\Windows'; windir = 'C:\Windows'; SystemDrive = 'C:'
        TEMP = $root; TMP = $root; USERPROFILE = $root
        PATH = 'C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0'
        PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
        PSModuleAnalysisCachePath = 'NUL'
        POWERSHELL_TELEMETRY_OPTOUT = '1'; DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    }.GetEnumerator()) { $info.EnvironmentVariables.Add($entry.Key, $entry.Value) }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $info
    if (-not $child.Start()) { throw 'Fixture child creation failed' }
    [void]$child.Handle
    return $child
}

function Receive-FixtureChild($Child, [string] $Case, [int] $Expected) {
    $streams = @($Child.StandardOutput.BaseStream, $Child.StandardError.BaseStream)
    $buffers = @([byte[]]::new(1024), [byte[]]::new(1024))
    $tasks = @($streams[0].ReadAsync($buffers[0], 0, 1024), $streams[1].ReadAsync($buffers[1], 0, 1024))
    $captured = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $done = @($false, $false)
    $end = [Math]::Min(175000L, $fixtureWatch.ElapsedMilliseconds + 30000L)
    try {
        while (-not ($Child.HasExited -and $done[0] -and $done[1])) {
            Assert-FixtureBudget
            if ($fixtureWatch.ElapsedMilliseconds -ge $end) { throw 'Child transport expired' }
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true }
                    else {
                        if ($captured[0].Length + $captured[1].Length + $count -gt 4096) { throw 'Child capture overflow' }
                        $captured[$index].Write($buffers[$index], 0, $count)
                        $tasks[$index] = $streams[$index].ReadAsync($buffers[$index], 0, 1024)
                    }
                }
            }
            Start-Sleep -Milliseconds 25
        }
        $stderr = $captured[1].ToArray()
        Save-Fixture "$root\$Case\transport.json" ([ordered]@{
            pid = $Child.Id; creationFileTime = $Child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
            exitCode = $Child.ExitCode; stdoutEof = $done[0]; stderrEof = $done[1]
            stdoutBase64 = [Convert]::ToBase64String($captured[0].ToArray()); stderrBase64 = [Convert]::ToBase64String($stderr)
        })
        if ($Child.ExitCode -ne $Expected -or $captured[0].Length -ne 0) { throw 'Unexpected child outcome' }
        if ($Expected -eq 0) {
            if ($stderr.Length -ne 0) { throw 'Unexpected success diagnostic' }
        } else {
            if ($stderr.Length -lt 1 -or $stderr.Length -gt 2050) { throw 'Missing bounded startup diagnostic' }
            $failure = [Text.UTF8Encoding]::new($false, $true).GetString($stderr) | ConvertFrom-Json
            if ($failure.phase -cne 'clock-reply-validation' -or $failure.exceptions.Count -lt 1 -or
                $failure.exceptions.Count -gt 4 -or $failure.incomplete -ne $false) { throw 'Unexpected first-cause diagnostic' }
        }
    } finally { foreach ($buffer in $captured) { $buffer.Dispose() } }
}

$controller = $null
$summary = [ordered]@{ schema = 'clock-handoff-windows-result-v1'; authoritySha256 = $AuthoritySha256
    passed = $false; failureDiagnostic = $null; completedCases = @() }
try {
    $self = [Diagnostics.Process]::GetCurrentProcess()
    try {
        Save-Fixture "$root\windows-started.json" ([ordered]@{ authoritySha256 = $AuthoritySha256
            pid = $self.Id; creationFileTime = $self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(); session = $self.SessionId })
    } finally { $self.Dispose() }
    $action = "$root\success"
    $start = [pscustomobject]@{ endpoint = $authority.endpoint }
    $result = [ordered]@{ controllerStartUtc = $null; deadlineCounter = $null; readySha256 = $null; replySha256 = $null }
    $controller = Start-FixtureChild 'Success'
    $result.controllerStartUtc = $controller.StartTime.ToUniversalTime().ToString('o')
    . $segments.handoff
    Wait-FixtureFile "$action\reader.json" ([Math]::Min(170000L, $fixtureWatch.ElapsedMilliseconds + 10000L))
    $reader = [Text.UTF8Encoding]::new($false, $true).GetString((Read-Fixture "$action\reader.json" 8192)) | ConvertFrom-Json
    if ($reader.readySha256 -cne $result.readySha256 -or $reader.replySha256 -cne $result.replySha256 -or
        $reader.deadlineCounter -ne $result.deadlineCounter) { throw 'Independent readers disagree' }
    Save-Fixture "$action\bootstrap-reader.json" $result
    Save-Fixture "$action\release.json" @{ accepted = $true }
    Receive-FixtureChild $controller 'success' 0
    $controller.Dispose(); $controller = $null
    $summary.completedCases += 'success'
    # Subsequent cases have their own real controller clock; no earlier deadline is reused.
    $deadlineCounter = $null
    foreach ($pair in @(@('Diagnostic', 'diagnostic'), @('Persistence', 'persistence'))) {
        $controller = Start-FixtureChild $pair[0]
        Receive-FixtureChild $controller $pair[1] 1
        $controller.Dispose(); $controller = $null
        $summary.completedCases += $pair[1]
    }
    $summary.passed = $true
} catch { $summary.failureDiagnostic = Get-BootstrapFailure $_ 'fixture-controller' }
finally {
    if ($null -ne $controller) { $controller.Dispose() }
    Save-Fixture "$root\windows-result.json" $summary
}
if ($summary.passed) { exit 0 }
exit 1

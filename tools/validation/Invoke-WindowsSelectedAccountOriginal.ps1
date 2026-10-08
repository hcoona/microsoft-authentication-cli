# Invoke once from the admitted retained Windows PowerShell process/runspace.
# Public helper compilation/loading and exact type/assembly admission precede use.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PlanPath,
    [Parameter(Mandatory)][string] $PlanSha256,
    [Parameter(Mandatory)][ValidateRange(1, 14)][int] $Attempt,
    [ValidateSet('Personal', 'Work')][string] $AccountRole = 'Personal',
    [Parameter(Mandatory)][string] $ControllerSha256,
    [Parameter(Mandatory)][Type] $CutoffType,
    [Parameter(Mandatory)][int] $ExpectedPid,
    [Parameter(Mandatory)][int] $ExpectedSession,
    [Parameter(Mandatory)][long] $ExpectedCreationFileTime,
    [Parameter(Mandatory)][object] $ExpectedRunspace
)

$ExecutionAdmitted = $false
if (-not $ExecutionAdmitted) { exit 125 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v5'
$accountPrefix = if ($AccountRole -ceq 'Work') { 'work-account' } else { 'selected-account' }
$primaryGroup = if ($AccountRole -ceq 'Work') { 'R7' } else { 'R1' }
$reuseGroup = if ($AccountRole -ceq 'Work') { 'R8' } else { 'R6' }
$frequency = [Diagnostics.Stopwatch]::Frequency
$lease = $null
$self = $null
$invoked = $false
$returned = $false
$originalExitCode = 125
$originalReturnTicks = 0L
$e0 = 0L
$receipt = $null
$pins = [Collections.Generic.List[IDisposable]]::new()
$passed = $false
$privateInputPins = $null
$privateInputWatch = [Diagnostics.Stopwatch]::StartNew()
$privateConfigReadBytes = 0L
$privatePublicReadBytes = 0L
$privateContentMatched = $false
$privateInputHandlesClosed = $true
$privateBuffers = [Collections.Generic.List[byte[]]]::new()

function Need([bool] $Condition) {
    if (-not $Condition) { throw 'Selected-account original refused.' }
}

function Before-PrivateInput {
    Need ($privateInputWatch.Elapsed.TotalSeconds -lt 20)
    $helperBytes = if ($null -ne $script:privateInputPins) { $script:privateInputPins.requestedReadBytes } else { 0L }
    Need ($helperBytes + $script:privateConfigReadBytes + $script:privatePublicReadBytes -le 1048576)
}

function Local-Value([object] $Value, [int] $Maximum) {
    Need ($Value -is [string] -and $Value.Length -le $Maximum)
    foreach ($character in $Value.ToCharArray()) {
        Need (-not [char]::IsControl($character) -and -not [char]::IsWhiteSpace($character))
    }
    return $Value
}
function Hold-ValidatedPrivateInput([object] $PublicPlan, [string] $Group) {
    Before-PrivateInput
    $type = $global:AzureAuth108PrivatePinsType
    Need ($type -is [Type] -and $type.FullName -ceq 'SelectedAccountPrivateInputPins' -and
        -not $type.Assembly.IsDynamic -and $null -eq $script:privateInputPins)
    $script:privateInputPins = [Activator]::CreateInstance($type, [object[]] @([Action] { Before-PrivateInput }))
    $privateRoot = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v6'
    $configPath = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v5\private\test-accounts.psd1'
    $configFile = $null; $config = $null; $configHash = $null; $configText = $null
    $configAst = $null; $configTokens = $null; $configErrors = $null; $configTable = $null
    $doc = $null; $email = $null; $tenant = $null; $payloadHash = $null
    try {
        # Read only the explicit Windows-local test configuration; never choose an ambient account.
        Need ($configPath -cmatch '\A[A-Z]:\\' -and
            [IO.Path]::GetFullPath($configPath) -ceq $configPath -and
            [IO.Path]::GetExtension($configPath) -ceq '.psd1')
        for ($current = $configPath; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
            Before-PrivateInput
            Need (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
        }
        $configFile = [IO.File]::Open($configPath, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::Read)
        Need ($configFile.Length -gt 0 -and $configFile.Length -le 4096)
        $configBytes = [byte[]]::new([int]$configFile.Length); $script:privateBuffers.Add($configBytes)
        $offset = 0
        while ($offset -lt $configBytes.Length) {
            Before-PrivateInput
            $script:privateConfigReadBytes += $configBytes.Length - $offset
            Before-PrivateInput
            $count = $configFile.Read($configBytes, $offset, $configBytes.Length - $offset)
            Need ($count -gt 0); $offset += $count
        }
        $script:privateConfigReadBytes++; Before-PrivateInput
        Need ($configFile.ReadByte() -eq -1)
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $configHash = [BitConverter]::ToString($hash.ComputeHash($configBytes)).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        # The hash and selected contents remain in Windows memory. Native Pin retains exact input correspondence.
        $null = $script:privateInputPins.Pin($configPath, $configBytes.Length, $configHash)
        # Parse the already charged buffer; no second pathname read or expression execution.
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $configText = $utf8.GetString($configBytes)
        if ($configText.Length -gt 0 -and $configText[0] -eq [char]0xfeff) {
            $configText = $configText.Substring(1)
        }
        Before-PrivateInput
        $configAst = [System.Management.Automation.Language.Parser]::ParseInput(
            $configText, [ref]$configTokens, [ref]$configErrors)
        Need ($configErrors.Count -eq 0 -and $null -eq $configAst.ParamBlock -and
            $null -eq $configAst.DynamicParamBlock -and $null -eq $configAst.BeginBlock -and
            $null -eq $configAst.ProcessBlock -and $null -ne $configAst.EndBlock -and
            ($null -eq $configAst.EndBlock.Traps -or $configAst.EndBlock.Traps.Count -eq 0) -and $configAst.EndBlock.Statements.Count -eq 1)
        $statement = $configAst.EndBlock.Statements[0]
        Need ($statement -is [System.Management.Automation.Language.PipelineAst] -and
            $statement.PipelineElements.Count -eq 1)
        $expression = $statement.PipelineElements[0]
        Need ($expression -is [System.Management.Automation.Language.CommandExpressionAst] -and
            $expression.Redirections.Count -eq 0)
        $configTable = $expression.Expression
        Need ($configTable -is [System.Management.Automation.Language.HashtableAst] -and
            $configTable.KeyValuePairs.Count -ge 1 -and $configTable.KeyValuePairs.Count -le 3)
        foreach ($pair in $configTable.KeyValuePairs) {
            # HashtableAst stores each value as a statement, not a statement block.
            Need ($pair.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $pair.Item2 -is [System.Management.Automation.Language.PipelineAst])
            $statement = $pair.Item2
            Need ($statement -is [System.Management.Automation.Language.PipelineAst] -and
                $statement.PipelineElements.Count -eq 1)
            $expression = $statement.PipelineElements[0]
            Need ($expression -is [System.Management.Automation.Language.CommandExpressionAst] -and
                $expression.Redirections.Count -eq 0 -and
                $expression.Expression -is [System.Management.Automation.Language.StringConstantExpressionAst])
        }
        $config = $configTable.SafeGetValue()
        Before-PrivateInput
        Need ($config -is [Collections.Hashtable] -and $config.Count -ge 1 -and $config.Count -le 3)
        foreach ($key in $config.Keys) {
            Need ($key -cin @('PersonalAccountEmail', 'WorkAccountEmail', 'WorkTenant'))
        }
        $hashes = @{
            R1 = '182e30d9141184b163ab119906c60eddd13582b4b3e8d217b6cd4c1b8d3d14a5'
            R6 = '95f8a1a27590caf11d74ef4d14ca5b46aa37c82835f969c682f6b9a67101b7ed'
            R7 = 'e2f564e3ded4a9d8ac988439e0108822d759379551e8c36b84029161670b3a11'
            R8 = '29258dbaba129c7819299edaa994685ed708b064a1dceecbe60d55482edbd61f'
        }
        Need ($Group -cin @('R1', 'R6', 'R7', 'R8') -and
            $PublicPlan.privateInput.relative -ceq ('private\' + $Group + '.json'))
        $length = if ($Group -cin @('R1', 'R7')) { 746L } else { 751L }
        $template = $script:privateInputPins.Pin(($privateRoot + '\control\' + $Group + '.template.json'), $length, $hashes[$Group])
        $bytes = $script:privateInputPins.ReadControl($template, 1024); $script:privateBuffers.Add($bytes)
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $doc = $utf8.GetString($bytes) | ConvertFrom-Json
        Need ($doc.schema -ceq 'confidential-native-private-requests-v1' -and
            $doc.group -ceq $Group -and $doc.requests.Count -eq 1 -and
            $null -eq $doc.requests[0].accountEmail -and
            $doc.requests[0].profilePath -ceq ($privateRoot + '\product\selected-account-profile.json'))
        $emailKey = if ($AccountRole -ceq 'Personal') { 'PersonalAccountEmail' } else { 'WorkAccountEmail' }
        Need ($config.ContainsKey($emailKey))
        $email = Local-Value $config[$emailKey] 320
        Need ($email.Length -ge 3 -and $email.IndexOf('@') -gt 0 -and
            $email.IndexOf('@') -eq $email.LastIndexOf('@') -and -not $email.EndsWith('@'))
        $tenant = 'common'
        if ($AccountRole -ceq 'Work') {
            $choice = if ($config.ContainsKey('WorkTenant')) { Local-Value $config.WorkTenant 36 } else { '' }
            if ($choice -ceq 'common') { $choice = '' }
            if ($choice.Length -gt 0) {
                Need ($choice -cmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' -and
                    [Guid]::ParseExact($choice, 'D') -ne [Guid]::Empty)
                $tenant = $choice
            }
            $choice = $null
        }
        $doc.requests[0].accountEmail = $email
        $doc.requests[0].tenantArgument = $tenant
        $doc.requests[0].exactResultTenant = if ($tenant -ceq 'common') { $null } else { $tenant }
        Need ($doc.requests[0].interactionAllowed -eq ($Group -cin @('R1', 'R7')))
        if ($Group -cin @('R1', 'R7')) { Need ($null -eq $doc.requests[0].requiredInteraction) }
        else { Need ($doc.requests[0].requiredInteraction -ceq 'silent') }
        $payload = $utf8.GetBytes(($doc | ConvertTo-Json -Depth 5 -Compress) + "`n"); $script:privateBuffers.Add($payload)
        Need ($payload.Length -gt 0 -and $payload.Length -le 16384 -and $payload.Length -eq $PublicPlan.privateInput.bytes)
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $payloadHash = [BitConverter]::ToString($hash.ComputeHash($payload)).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        # Pin performs exact expected-content hash/length/EOF and current-eight checks.
        # Its read-only stream denies write/delete sharing until this original returns.
        $held = $script:privateInputPins.Pin(($privateRoot + '\private\' + $Group + '.json'), $payload.Length, $payloadHash)
        foreach ($field in @('volume', 'index', 'attributes', 'created', 'modified', 'links')) {
            Need ([decimal]$held.identity.$field -eq [decimal]$PublicPlan.privateInput.identity.$field)
        }
        Need ([decimal]$held.identity.length -eq [decimal]$PublicPlan.privateInput.bytes)
        $script:privateInputPins.CheckAll(); Before-PrivateInput
        Need ($script:privateInputPins.opens -le 64 -and $script:privateInputPins.metadata -le 512 -and
            $script:privateInputPins.writtenBytes -eq 0)
        $script:privateContentMatched = $true
    } finally {
        if ($null -ne $configFile) { $configFile.Dispose() }
        $config = $null; $configHash = $null; $configText = $null; $configAst = $null
        $configTokens = $null; $configErrors = $null; $configTable = $null
        $doc = $null; $email = $null; $tenant = $null; $payloadHash = $null
        foreach ($buffer in $script:privateBuffers) { [Array]::Clear($buffer, 0, $buffer.Length) }
        $script:privateBuffers.Clear()
    }
}

function Read-PinnedPublic([string] $Path, [int] $Maximum, [string] $ExpectedHash) {
    Need ($ExpectedHash -cmatch '\A[0-9a-f]{64}\z')
    $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $pins.Add($file)
    Need ($file.Length -gt 0 -and $file.Length -le $Maximum)
    $bytes = [byte[]]::new([int] $file.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $script:privatePublicReadBytes += $bytes.Length - $offset; Before-PrivateInput
        $count = $file.Read($bytes, $offset, $bytes.Length - $offset)
        Need ($count -gt 0)
        $offset += $count
    }
    $script:privatePublicReadBytes++; Before-PrivateInput
    Need ($file.ReadByte() -eq -1)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    Need ($actual -ceq $ExpectedHash)
    return ,$bytes
}

try {
    # Exact-call admission pins this original source, the loaded helper artifact,
    # its single retained Type, current host/user/environment and private input.
    # Reuse both admitted helper types; selectors and hashes remain Windows-local.
    Need (($AccountRole -ceq 'Personal' -or ($AccountRole -ceq 'Work' -and $Attempt -le 4)) -and
        [Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -eq 'Desktop' -and
        $CutoffType.FullName -ceq 'SelectedAccountControllerCutoff' -and
        -not $CutoffType.Assembly.IsDynamic -and $frequency -gt 0)
    Need ([Environment]::UserInteractive -and $Host.Name -ceq 'ConsoleHost' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1 -and
        [Threading.Thread]::CurrentThread.GetApartmentState() -eq [Threading.ApartmentState]::STA -and
        $PID -eq $ExpectedPid -and [object]::ReferenceEquals($ExpectedRunspace,
            [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace) -and
        [object]::ReferenceEquals($global:AzureAuth108CutoffType, $CutoffType))
    $self = [Diagnostics.Process]::GetCurrentProcess()
    Need ($self.Id -eq $ExpectedPid -and $self.SessionId -eq $ExpectedSession -and
        $self.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $ExpectedCreationFileTime)
    Need ($PSCommandPath -ceq ($root + '\control\Invoke-WindowsSelectedAccountOriginalRetainedSlots.ps1') -and
        $PlanPath -ceq ($root + '\control\' + $accountPrefix + '-plan-' + $Attempt + '.json'))
    $controller = $root + '\control\Invoke-WindowsSelectedAccountCutoffSlots.ps1'
    $null = Read-PinnedPublic $controller 65536 $ControllerSha256
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $plan = $encoding.GetString((Read-PinnedPublic $PlanPath 262144 $PlanSha256)) | ConvertFrom-Json
    $group = if ($Attempt % 2 -eq 1) { $primaryGroup } else { $reuseGroup }
    Need ($plan.schema -ceq 'confidential-native-account-admission-v1' -and $plan.group -ceq $group -and
        $plan.admitted -eq $true -and $plan.accountEffectsAccepted -eq $true -and
        $plan.nonce -cmatch '\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z')
    $receipt = $root + '\records\' + $group + '-' + $plan.nonce + '\original-terminal.json'
    Need (-not [IO.File]::Exists($receipt))
    # Match the admitted construction and hold the exact unchanged private file.
    # No new request, baseline, account selection or cache state is written.
    Hold-ValidatedPrivateInput $plan $group
    # One original epoch precedes lease arming and the sole controller-script call.
    # Capture its original return and exit code before any cleanup or receipt I/O.
    $e0 = [Diagnostics.Stopwatch]::GetTimestamp()
    $lease = [Activator]::CreateInstance($CutoffType, [object[]] @([long] $e0))
    Need ($null -ne $lease -and $lease.Armed -and -not $lease.Failed)
    $global:LASTEXITCODE = 125
    $invoked = $true
    & $controller -PlanPath $PlanPath -PlanSha256 $PlanSha256 -Attempt $Attempt `
        -ControllerSha256 $ControllerSha256 -AccountRole $AccountRole -InvocationStartTicks $e0 -CutoffLease $lease
    $originalExitCode = $LASTEXITCODE
    $originalReturnTicks = [Diagnostics.Stopwatch]::GetTimestamp()
    $returned = $true
    Need ($originalExitCode -eq 0 -and $originalReturnTicks -ge $e0 -and
        ($originalReturnTicks - $e0) / $frequency -lt 180 -and
        $lease.Bound -and $lease.ExitObserved -and $lease.CleanupComplete -and
        -not $lease.Failed -and -not $lease.StopClaimed -and
        -not $lease.TerminationAttempted -and -not $lease.FallbackFired)
    $passed = $true
} catch {
    # Never export raw exceptions, provider text, environment or private inputs.
} finally {
    if ($null -ne $lease -and -not $lease.CleanupComplete) {
        try { $null = $lease.Finish($false) } catch { }
        $passed = $false
    }
    if ($null -ne $privateInputPins) {
        try { $privateInputPins.Dispose() } catch { $privateInputHandlesClosed = $false; $passed = $false }
        $privateInputPins = $null
    }
    if ($null -ne $self) { try { $self.Dispose() } catch { $passed = $false } }
    foreach ($pin in $pins) { $pin.Dispose() }
    if ($e0 -gt 0 -and $receipt) {
        try {
            Need (([Diagnostics.Stopwatch]::GetTimestamp() - $e0) / $frequency -lt 180)
            $safe = [ordered]@{
                schema = 'selected-account-original-v2'; attempt = $Attempt
                invocationStartTicks = $e0; stopwatchFrequency = $frequency
                invoked = $invoked; returned = $returned; originalExitCode = $originalExitCode
                privateContentMatched = $privateContentMatched; privateInputHandlesClosed = $privateInputHandlesClosed
                originalReturnTicks = $originalReturnTicks; passed = $passed
                cutoffCleanupComplete = ($null -ne $lease -and $lease.CleanupComplete)
                cutoffFailed = ($null -eq $lease -or $lease.Failed)
                noExperimentLive = $false
            }
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($safe | ConvertTo-Json -Compress) + "`n")
            Need ($bytes.Length -le 4096)
            $file = [IO.File]::Open($receipt, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
            finally { $file.Dispose() }
            Need (([Diagnostics.Stopwatch]::GetTimestamp() - $e0) / $frequency -lt 180)
        } catch { $passed = $false }
    }
}
if ($passed) { exit 0 }
exit 1

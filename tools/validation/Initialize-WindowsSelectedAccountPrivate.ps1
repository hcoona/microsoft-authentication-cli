# One admitted local creation per role; no account/provider API or product start.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Personal', 'Work')][string] $AccountRole,
    [Parameter(Mandatory)][Type] $PrivatePinsType,
    [Parameter(Mandatory)][object] $ExpectedPrimaryTemplateIdentity,
    [Parameter(Mandatory)][object] $ExpectedReuseTemplateIdentity,
    [Parameter(Mandatory)][bool] $CurrentOperatingBasisAccepted,
    [Parameter(Mandatory)][bool] $ExperimentalProfileExplicitlySelected,
    [Parameter(Mandatory)][int] $ExpectedPid,
    [Parameter(Mandatory)][int] $ExpectedSession,
    [Parameter(Mandatory)][long] $ExpectedCreationFileTime,
    [Parameter(Mandatory)][object] $ExpectedRunspace,
    [ValidateRange(1, 3)][int] $CreationAttempt = 1,
    [switch] $ContinueAfterObservedAbsence,
    [string] $PrivateConfigPath = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v5\private\test-accounts.psd1'
)
$PrivateCreationAdmitted = $false
if (-not $PrivateCreationAdmitted) { return }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$watch = [Diagnostics.Stopwatch]::StartNew()
$root = 'C:\Temp\azureauth-windows-slice-108\confidential-native-account-v5'
$primary = if ($AccountRole -ceq 'Personal') { 'R1' } else { 'R7' }
$reuse = if ($AccountRole -ceq 'Personal') { 'R6' } else { 'R8' }
$hashes = @{
    R1 = 'cf98559a6b639882048094365bf714e01e585e6f381a20bda79e8115043831f8'
    R6 = 'e1d0bc7d7f3a3d7bf4782a182843d03fdf58e927bdcd74f9f187a2e1da162072'
    R7 = 'c40c7d775cbf29fc800aff232bda74b079b84333c7d15bf3842b68d2f3c5f18c'
    R8 = '07d03b9987297875e4cdfc7b7b11d0a70503259faf31624f30232c6815d876d0'
}
$pins = $null
$self = $null
$configFile = $null
$config = $null
$configHash = $null
$configText = $null
$configAst = $null
$configTokens = $null
$configErrors = $null
$configTable = $null
$configReadBytes = 0L
$buffers = [Collections.Generic.List[byte[]]]::new()
$documents = @()
$email = $null
$tenant = $null
$passed = $false
$closed = $true
$equal = $false
$validated = $false
$rows = @()
$templateRows = @()
function Need([bool] $Value) { if (-not $Value) { throw 'Private creation refused.' } }
function Before {
    Need ($watch.Elapsed.TotalSeconds -lt 115)
    if ($null -ne $script:pins) {
        Need ($script:pins.requestedReadBytes + $script:pins.writtenBytes + $script:configReadBytes -le 1048576)
    }
}
function Local-Value([object] $Value, [int] $Maximum) {
    Need ($Value -is [string] -and $Value.Length -le $Maximum)
    foreach ($character in $Value.ToCharArray()) {
        Need (-not [char]::IsControl($character) -and -not [char]::IsWhiteSpace($character))
    }
    return $Value
}
function Match-TemplateIdentity([string] $Group, [object] $Expected, [object] $Actual) {
    $fields = @('volume', 'index', 'attributes', 'created', 'modified', 'links', 'length', 'changed')
    Need (@($Expected.PSObject.Properties).Count -eq 8)
    $historical = [ordered]@{}; $current = [ordered]@{}; $mismatches = @()
    foreach ($name in $fields) {
        $a = $Expected.$name; $b = $Actual.$name
        Need (($a -is [int] -or $a -is [long] -or $a -is [uint] -or
            $a -is [ulong] -or $a -is [decimal]) -and
            [decimal]$a -eq [decimal]::Truncate([decimal]$a))
        $historical[$name] = ([decimal]$a).ToString([Globalization.CultureInfo]::InvariantCulture)
        $current[$name] = $b.ToString([Globalization.CultureInfo]::InvariantCulture)
        if ([decimal]$a -ne [decimal]$b) { $mismatches += $name }
    }
    # Only this public-template historical comparison qualifies ChangeTime.
    # Native Pin, ReadControl and CheckAll keep strict current eight-field checks.
    $script:templateRows += [pscustomobject]@{ group = $Group; historicalIdentity = $historical;
        currentIdentity = $current; mismatchFields = @($mismatches); historicalChangeTimeQualified = $true }
    Need (@($mismatches | Where-Object { $_ -cne 'changed' }).Count -eq 0)
}

try {
    Before
    Need ($CurrentOperatingBasisAccepted -and $ExperimentalProfileExplicitlySelected -and
        $PrivatePinsType.FullName -ceq 'SelectedAccountPrivateInputPins' -and
        [object]::ReferenceEquals($global:AzureAuth108PrivatePinsType, $PrivatePinsType) -and
        -not $PrivatePinsType.Assembly.IsDynamic -and [Environment]::UserInteractive -and
        [Environment]::Is64BitProcess -and $Host.Name -ceq 'ConsoleHost' -and
        $PSVersionTable.PSEdition -ceq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)
    Need ([Threading.Thread]::CurrentThread.GetApartmentState() -eq [Threading.ApartmentState]::STA -and
        $PID -eq $ExpectedPid -and [object]::ReferenceEquals($ExpectedRunspace,
            [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace))
    $self = [Diagnostics.Process]::GetCurrentProcess()
    Need ($self.Id -eq $ExpectedPid -and $self.SessionId -eq $ExpectedSession -and
        $self.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $ExpectedCreationFileTime)
    $marker = 'AzureAuth108PrivateCreation' + $AccountRole + 'Attempted'
    Need (-not $ContinueAfterObservedAbsence -or ($AccountRole -ceq 'Personal' -and $CreationAttempt -eq 3))
    if ($CreationAttempt -eq 2) {
        # A corrected call preserves the original constant marker and gets one distinct slot.
        Need ($null -ne (Get-Variable -Name $marker -Scope Global -ErrorAction SilentlyContinue))
        $marker += 'Correction1'
    } elseif ($CreationAttempt -eq 3) {
        Need ($AccountRole -ceq 'Personal')
        if ($ContinueAfterObservedAbsence) {
            # The reviewed call preserves spent attempts in retained evidence, not reconstructed variables.
            Need ($null -eq (Get-Variable -Name $marker -Scope Global -ErrorAction SilentlyContinue) -and
                $null -eq (Get-Variable -Name ($marker + 'Correction1') -Scope Global -ErrorAction SilentlyContinue))
            $marker += 'Correction2AfterObservedAbsence'
        } else {
            # One Personal template-history correction preserves both spent markers in this runspace.
            Need ($null -ne (Get-Variable -Name $marker -Scope Global -ErrorAction SilentlyContinue) -and
                $null -ne (Get-Variable -Name ($marker + 'Correction1') -Scope Global -ErrorAction SilentlyContinue))
            $marker += 'Correction2'
        }
    }
    Need ($null -eq (Get-Variable -Name $marker -Scope Global -ErrorAction SilentlyContinue))
    New-Variable -Name $marker -Scope Global -Option Constant -Value $true
    $pins = [Activator]::CreateInstance($PrivatePinsType, [object[]] @([Action] { Before }))
    $pins.HoldDirectory($root + '\private')
    # Read only the explicit Windows-local test configuration; never choose an ambient account.
    Need ($PrivateConfigPath -cmatch '\A[A-Z]:\\' -and
        [IO.Path]::GetFullPath($PrivateConfigPath) -ceq $PrivateConfigPath -and
        [IO.Path]::GetExtension($PrivateConfigPath) -ceq '.psd1')
    for ($current = $PrivateConfigPath; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
        Before
        Need (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    }
    $configFile = [IO.File]::Open($PrivateConfigPath, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    Need ($configFile.Length -gt 0 -and $configFile.Length -le 4096)
    $configBytes = [byte[]]::new([int]$configFile.Length); $buffers.Add($configBytes)
    $offset = 0
    while ($offset -lt $configBytes.Length) {
        Before
        $configReadBytes += $configBytes.Length - $offset
        Before
        $count = $configFile.Read($configBytes, $offset, $configBytes.Length - $offset)
        Need ($count -gt 0); $offset += $count
    }
    $configReadBytes++; Before
    Need ($configFile.ReadByte() -eq -1)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $configHash = [BitConverter]::ToString($hash.ComputeHash($configBytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    # The hash and selected contents remain in Windows memory. Native Pin retains exact input correspondence.
    $null = $pins.Pin($PrivateConfigPath, $configBytes.Length, $configHash)
    # Parse the already charged buffer; no second pathname read or expression execution.
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $configText = $utf8.GetString($configBytes)
    if ($configText.Length -gt 0 -and $configText[0] -eq [char]0xfeff) {
        $configText = $configText.Substring(1)
    }
    Before
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
    Before
    Need ($config -is [Collections.Hashtable] -and $config.Count -ge 1 -and $config.Count -le 3)
    foreach ($key in $config.Keys) {
        Need ($key -cin @('PersonalAccountEmail', 'WorkAccountEmail', 'WorkTenant'))
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $expected = @($ExpectedPrimaryTemplateIdentity, $ExpectedReuseTemplateIdentity)
    $groups = @($primary, $reuse)
    for ($i = 0; $i -lt 2; $i++) {
        $group = $groups[$i]
        $length = if ($i -eq 0) { 746 } else { 751 }
        $held = $pins.Pin($root + '\control\' + $group + '.template.json', $length, $hashes[$group])
        Match-TemplateIdentity $group $expected[$i] $held.identity
        $bytes = $pins.ReadControl($held, 1024); $buffers.Add($bytes)
        $doc = $utf8.GetString($bytes) | ConvertFrom-Json
        Need ($doc.schema -ceq 'confidential-native-private-requests-v1' -and
            $doc.group -ceq $group -and $doc.requests.Count -eq 1 -and
            $null -eq $doc.requests[0].accountEmail -and
            $doc.requests[0].profilePath -ceq ($root + '\product\selected-account-profile.json'))
        $documents += $doc
    }
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
    foreach ($doc in $documents) {
        $doc.requests[0].accountEmail = $email
        $doc.requests[0].tenantArgument = $tenant
        $doc.requests[0].exactResultTenant = if ($tenant -ceq 'common') { $null } else { $tenant }
    }
    foreach ($field in $documents[0].requests[0].PSObject.Properties.Name) {
        if ($field -cin @('interactionAllowed', 'requiredInteraction')) { continue }
        Need (($documents[0].requests[0].$field | ConvertTo-Json -Compress) -ceq
            ($documents[1].requests[0].$field | ConvertTo-Json -Compress))
    }
    Need ($documents[0].requests[0].interactionAllowed -eq $true -and
        $null -eq $documents[0].requests[0].requiredInteraction -and
        $documents[1].requests[0].interactionAllowed -eq $false -and
        $documents[1].requests[0].requiredInteraction -ceq 'silent')
    $equal = $true
    $validated = $true
    for ($i = 0; $i -lt 2; $i++) {
        Before
        $payload = $utf8.GetBytes(($documents[$i] | ConvertTo-Json -Depth 5 -Compress) + "`n")
        $buffers.Add($payload); Need ($payload.Length -le 16384)
        $identity = $pins.WritePrivate($root + '\private\' + $groups[$i] + '.json', $payload)
        $rows += [pscustomobject]@{ group = $groups[$i]; bytes = $payload.Length; identity = $identity }
    }
    $pins.CheckAll(); Before
    $passed = $true
} catch {
    # Suppress contents, hashes, selectors, tenant IDs, provider text and exception details.
} finally {
    if ($null -ne $pins) { try { $pins.Dispose() } catch { $closed = $false } }
    if ($null -ne $configFile) { try { $configFile.Dispose() } catch { $closed = $false } }
    if ($null -ne $self) { try { $self.Dispose() } catch { $closed = $false } }
    $config = $null; $configHash = $null; $configText = $null
    $configAst = $null; $configTokens = $null; $configErrors = $null; $configTable = $null
    $statement = $null; $expression = $null; $pair = $null
    foreach ($buffer in $buffers) { [Array]::Clear($buffer, 0, $buffer.Length) }
    $documents = @(); $email = $null; $tenant = $null
    $passed = $passed -and $closed -and $watch.Elapsed.TotalSeconds -lt 120
}
# Only complete timely natural return and independent outcome acceptance admit these identities.
[pscustomobject]@{
    schema = 'selected-account-private-creation-v2'; role = $AccountRole; passed = $passed
    privateRowsValidated = $validated; sharedSelectionEqual = $equal; allHandlesClosed = $closed
    rows = $rows; templateRows = $templateRows; accountAccess = $false; productStarted = $false
    elapsedMilliseconds = $watch.ElapsedMilliseconds
} | ConvertTo-Json -Depth 5 -Compress

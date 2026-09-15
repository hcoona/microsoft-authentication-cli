# PRIVATE SOURCE CANDIDATE: not a controller admitted by any accepted protocol.
param([string] $ActionName, [string] $ReservationSha256, [string] $InvocationSha256, [string] $AuthoritySha256)
$script:FinalPublishDraftOnly = $true
if ($script:FinalPublishDraftOnly) { throw 'DRAFT_ONLY: final-publish integration and guard build are unadmitted' }
$originalControllerWatch = [Diagnostics.Stopwatch]::StartNew()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Source fragment inserted before the unchanged guard loader. No dynamic import.
$script:FinalAuthority = $null
$script:FinalInvocation = $null
$script:FinalGraph = $null
$script:FinalRecipe = $null
$script:FinalClock = $null
$script:FinalCallerAuthorization = $null
$script:FinalOriginalLoaderHash = 'ef16811f0f8cf481ee6a54b9b7f0552c14bbd6eeeca32bb391c255e52d35628e'
$script:FinalControllerWatch = $null
$script:FinalRecipeHash = '2fcf2e7e265b91e1103b0c91e240079e04d87dfd505d633c281a4abe53e900c2'

function Get-FinalHash([byte[]] $Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Assert-FinalKeys($Value, [string[]] $Expected) {
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { throw 'Unknown or missing final fields' }
    foreach ($name in $Expected) {
        if (-not ($actual -ccontains $name)) { throw 'Unknown or missing final field' }
    }
}

function Read-FinalBytes([string] $Path, [int] $Maximum) {
    Assert-GuardDirect $Path
    $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($file.Length -gt $Maximum) { throw 'Final input size limit' }
        $bytes = [byte[]]::new([int]$file.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $file.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'Incomplete final input' }
            $offset += $count
        }
        return ,$bytes
    } finally { $file.Dispose() }
}

function Read-FinalJson([string] $Path, [string] $ExpectedHash, [int] $Maximum = 8388608) {
    if ($ExpectedHash -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound exact final JSON hash' }
    $bytes = Read-FinalBytes $Path $Maximum
    if ((Get-FinalHash $bytes) -cne $ExpectedHash) { throw 'Final JSON identity changed' }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $value = $text | ConvertFrom-Json
    # Python emits sorted compact ASCII. Round trip also rejects duplicate keys,
    # noncanonical JSON, multiple frames and partial-file prefixes.
    if ($text -cne (($value | ConvertTo-Json -Depth 40 -Compress) + "`n")) {
        throw 'Noncanonical final JSON input'
    }
    return $value
}

function Assert-FinalCallerValue($Value) {
    if ($null -eq $Value) { throw 'Unbound prospective caller value' }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long]) { return }
    if ($Value -isnot [pscustomobject]) { throw 'Unknown prospective caller value type' }
    foreach ($property in $Value.PSObject.Properties) { Assert-FinalCallerValue $property.Value }
}

function Assert-FinalProvenanceDescriptor($Value, [string] $ExpectedPath = '') {
    Assert-FinalKeys $Value @('path', 'bytes', 'sha256')
    if ($Value.path -isnot [string] -or $Value.path -cnotmatch '^/[ -~]{1,4095}$' -or
        $Value.path.Contains('\') -or $Value.path.Contains('//') -or
        $Value.path -cmatch '/(?:\.|\.\.)(?:/|$)' -or $Value.path.EndsWith('/') -or
        ($ExpectedPath.Length -gt 0 -and $Value.path -cne $ExpectedPath) -or
        ($Value.bytes -isnot [int] -and $Value.bytes -isnot [long]) -or
        $Value.bytes -lt 1 -or $Value.bytes -gt 1048576 -or
        $Value.sha256 -isnot [string] -or $Value.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Original caller provenance descriptor changed'
    }
}

function Assert-FinalCallerAuthorization {
    Assert-FinalBudget
    if ($null -eq $script:FinalAuthority -or $null -eq $script:FinalInvocation) {
        throw 'Missing prospective caller authority'
    }
    $authority = $script:FinalAuthority
    $invocation = $script:FinalInvocation
    Assert-FinalKeys $authority.callerAuthorization @('bytes', 'sha256')
    if (($authority.callerAuthorization.bytes -isnot [int] -and $authority.callerAuthorization.bytes -isnot [long]) -or
        $authority.callerAuthorization.bytes -lt 1 -or $authority.callerAuthorization.bytes -gt 1048576) {
        throw 'Unbound prospective caller authorization length'
    }
    $path = $invocation.actionPath + '\caller-authorization.json'
    $caller = Read-FinalJson $path $authority.callerAuthorization.sha256 1048576
    if ((Get-Item -LiteralPath $path -Force).Length -ne $authority.callerAuthorization.bytes) {
        throw 'Prospective caller authorization length changed'
    }
    Assert-FinalKeys $caller @('schema', 'accepted', 'scope', 'product', 'integration', 'protocol',
        'components', 'recipe', 'sourceReview', 'guardAcceptance', 'acceptedGuard',
        'originalGuardEvidence', 'callerPolicy', 'noExecutionGrant')
    Assert-FinalCallerValue $caller
    if ($caller.schema -cne 'final-publish-caller-authorization-v1' -or
        $caller.accepted -isnot [bool] -or $caller.accepted -ne $true -or
        $caller.scope -cne 'one-final-publish-use-of-original-accepted-guard' -or
        $caller.callerPolicy -cne 'fixed-final-only-callers-no-generic-helper-use' -or
        $caller.noExecutionGrant -isnot [bool] -or $caller.noExecutionGrant -ne $true) {
        throw 'Prospective caller authorization is absent or out of scope'
    }
    foreach ($name in @('product', 'integration', 'protocol', 'components', 'recipe',
                        'sourceReview', 'guardAcceptance', 'acceptedGuard')) {
        if (($caller.$name | ConvertTo-Json -Depth 40 -Compress) -cne
            ($authority.$name | ConvertTo-Json -Depth 40 -Compress)) {
            throw 'Prospective caller authorization names different inputs'
        }
    }
    Assert-FinalKeys $caller.originalGuardEvidence @('binding', 'bindingReview', 'readerLauncher', 'readerLauncherAcceptance')
    Assert-FinalProvenanceDescriptor $caller.originalGuardEvidence.binding '/tmp/windows-final-guard-0055-history-binding.json'
    Assert-FinalProvenanceDescriptor $caller.originalGuardEvidence.bindingReview '/tmp/windows-final-guard-0055-authority-inputs/history-binding-review.json'
    Assert-FinalProvenanceDescriptor $caller.originalGuardEvidence.readerLauncher
    Assert-FinalProvenanceDescriptor $caller.originalGuardEvidence.readerLauncherAcceptance
    $guardFields = @('actionNumber', 'sourceSha256', 'dllSha256', 'guardBuildSha256',
        'preparationWindowsResultSha256', 'preparationWslResultSha256', 'preparationReservationSha256',
        'invocationSha256', 'compilerReceiptSha256', 'artifactAcceptancePath', 'artifactAcceptanceSha256',
        'expectedAssemblyFullName', 'acceptedLoaderSourceSha256')
    Assert-FinalKeys $caller.acceptedGuard $guardFields
    Assert-FinalKeys $invocation.acceptedGuard $guardFields
    foreach ($name in $guardFields) {
        if ($caller.acceptedGuard.$name -isnot [string] -or
            $caller.acceptedGuard.$name -cne $invocation.acceptedGuard.$name -or
            $caller.acceptedGuard.$name -cne $script:AcceptedFinalGuard[$name]) {
            throw 'Original thirteen-field guard projection changed'
        }
    }
    if ($caller.acceptedGuard.actionNumber -cne '0055' -or
        $caller.acceptedGuard.acceptedLoaderSourceSha256 -cne $script:FinalOriginalLoaderHash) {
        throw 'Original disabled-loader provenance changed'
    }
    # The historical loader remains in G. The new controller is independently
    # authorized through K and the exact current final authority component.
    Assert-GuardHash $PSCommandPath $caller.components.controller.sha256
    Assert-FinalBudget
    return $caller
}

function Assert-OriginalFinalGuardArtifact {
    Assert-FinalBudget
    $guard = $script:AcceptedFinalGuard
    $native = 'C:\Temp\azureauth-windows-slice-108\actions\' + $guard.actionNumber
    if ($guard.artifactAcceptancePath -cne $native + '\final-guard\artifact-acceptance.json') {
        throw 'Original artifact-acceptance destination changed'
    }
    $raw = Read-FinalBytes $guard.artifactAcceptancePath 1048576
    if ($raw.Length -lt 1 -or (Get-FinalHash $raw) -cne $guard.artifactAcceptanceSha256) {
        throw 'Original artifact-acceptance bytes changed'
    }
    # Original raw bytes were checked by WSL's original-compatible JSON decoder.
    # Do not impose final compact-JSON formatting on the preserved acceptance.
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($raw)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff) { $text = $text.Substring(1) }
    $artifact = $text | ConvertFrom-Json
    Assert-FinalKeys $artifact @('schema', 'disposition', 'scope', 'acceptedFinalGuard', 'artifact',
        'completionAcceptance', 'managedPeAndIlReviewed', 'sourceAndCompilerBindingReviewed',
        'noLoadOrSelfTestPerformed', 'reviewer', 'reviewedUtc')
    if ($artifact.schema -cne 'final-guard-managed-artifact-acceptance-v1' -or
        $artifact.disposition -cne 'accepted' -or
        $artifact.scope -cne 'exact-managed-final-guard-source-pe-il-and-final-loader-binding') {
        throw 'Original artifact acceptance scope changed'
    }
    foreach ($name in @('managedPeAndIlReviewed', 'sourceAndCompilerBindingReviewed', 'noLoadOrSelfTestPerformed')) {
        if ($artifact.$name -isnot [bool] -or $artifact.$name -ne $true) { throw 'Original artifact acceptance flag changed' }
    }
    if ($artifact.reviewer -isnot [string] -or $artifact.reviewer -cnotmatch '^[A-Za-z0-9_./-]{1,160}$' -or
        $artifact.reviewedUtc -isnot [string] -or
        $artifact.reviewedUtc -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|\+00:00)$') {
        throw 'Original artifact reviewer metadata changed'
    }
    $originalFields = @('actionNumber', 'sourceSha256', 'dllSha256', 'guardBuildSha256',
        'preparationWindowsResultSha256', 'preparationWslResultSha256', 'preparationReservationSha256',
        'invocationSha256', 'compilerReceiptSha256', 'expectedAssemblyFullName', 'acceptedLoaderSourceSha256')
    Assert-FinalKeys $artifact.acceptedFinalGuard $originalFields
    foreach ($name in $originalFields) {
        if ($artifact.acceptedFinalGuard.$name -isnot [string] -or $artifact.acceptedFinalGuard.$name -cne $guard[$name]) {
            throw 'Original artifact guard projection changed'
        }
    }
    Assert-FinalKeys $artifact.artifact @('path', 'bytes', 'sha256')
    $projected = '/mnt/c/Temp/azureauth-windows-slice-108/actions/' + $guard.actionNumber
    if ($artifact.artifact.path -cne $projected + '/final-guard/WindowsFinalPublishGuard.dll' -or
        $artifact.artifact.sha256 -cne $guard.dllSha256 -or
        ($artifact.artifact.bytes -isnot [int] -and $artifact.artifact.bytes -isnot [long]) -or
        $artifact.artifact.bytes -lt 1 -or $artifact.artifact.bytes -gt 8388608 -or
        (Get-Item -LiteralPath ($native + '\final-guard\WindowsFinalPublishGuard.dll') -Force).Length -ne $artifact.artifact.bytes) {
        throw 'Original artifact DLL descriptor changed'
    }
    Assert-FinalProvenanceDescriptor $artifact.completionAcceptance '/tmp/windows-final-guard-0055-authority-inputs/original-completion-acceptance.json'
    Assert-FinalBudget
}


function Resolve-FinalText([string] $Text, $Slots) {
    foreach ($key in $Slots.Keys) { $Text = $Text.Replace(('${' + $key + '}'), [string]$Slots[$key]) }
    if ($Text.Contains('${') -or $Text.IndexOf([char]0) -ge 0 -or $Text.Contains("`r") -or $Text.Contains("`n")) {
        throw 'Unbound or multiline final substitution'
    }
    return $Text
}

function Assert-FinalBudget {
    if ($null -eq $script:FinalControllerWatch -or -not $script:FinalControllerWatch.IsRunning -or
        $script:FinalControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Original Windows controller expired' }
    if (Test-Path -LiteralPath ($script:FinalInvocation.actionPath + '\cancel')) { throw 'Caller retention cancellation' }
    if ($null -ne $script:FinalClock -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $script:FinalClock.deadlineCounter) {
        throw 'Original cross-host outer deadline expired'
    }
}

function Assert-FinalOutputAncestor([string] $Path) {
    $current = $Path
    while (-not (Test-Path -LiteralPath $current)) {
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $current) { throw 'Missing final output ancestor' }
        $current = $parent
    }
    Assert-GuardDirect $current
}

function Assert-FinalProtectedInputs {
    foreach ($path in $script:FinalGraph.absentInputs) {
        Assert-FinalBudget
        Assert-FinalOutputAncestor $path
        if (Test-Path -LiteralPath $path) { throw 'Unexpected ambient source/import input' }
    }
    foreach ($item in $script:FinalGraph.protectedInputs) {
        Assert-FinalBudget
        Assert-FinalKeys $item @('path', 'bytes', 'sha256', 'role')
        Assert-GuardDirect $item.path
        $file = [IO.File]::Open($item.path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            if ($file.Length -ne $item.bytes -or $file.Length -gt 536870912) { throw 'Protected input length changed' }
            $buffer = [byte[]]::new(1048576)
            while (($count = $file.Read($buffer, 0, $buffer.Length)) -gt 0) {
                Assert-FinalBudget
                [void]$hasher.TransformBlock($buffer, 0, $count, $buffer, 0)
            }
            [void]$hasher.TransformFinalBlock([byte[]]::new(0), 0, 0)
            if (([BitConverter]::ToString($hasher.Hash)).Replace('-', '').ToLowerInvariant() -cne $item.sha256) {
                throw 'Protected input content changed'
            }
        } finally { $hasher.Dispose(); $file.Dispose() }
        Assert-FinalBudget
    }
}

function Quote-FinalArgument([string] $Value) {
    if ($Value.Contains('"') -or $Value.IndexOf([char]0) -ge 0) { throw 'Unexpected quote in fixed argument' }
    if ($Value.Length -eq 0 -or $Value -match '[ \t]') {
        return '"' + [regex]::Replace($Value, '(\\+)$', '$1$1') + '"'
    }
    return $Value
}

# Closed source-bound Csc and Windows Exec adapters. Actual plans are external inputs.
function Get-FinalToolMap($Value) {
    $map = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    if ($Value -is [Collections.IDictionary]) {
        foreach ($name in $Value.Keys) { $map.Add([string]$name, $Value[$name]) }
    } elseif ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) { $map.Add($property.Name, $property.Value) }
    } else { throw 'Expected a closed tool object' }
    return ,$map
}

function Assert-FinalToolEqual($Left, $Right) {
    if ($null -eq $Right) {
        if ($null -ne $Left) { throw 'Expected null tool field' }
        return
    }
    if ($null -eq $Left) { throw 'Missing tool field value' }
    if ($Right -is [Collections.IDictionary] -or $Right -is [pscustomobject]) {
        $a = Get-FinalToolMap $Left
        $b = Get-FinalToolMap $Right
        if ($a.Count -ne $b.Count) { throw 'Tool object key mismatch' }
        foreach ($key in $b.Keys) {
            if (-not $a.ContainsKey($key)) { throw 'Unknown or missing tool key' }
            Assert-FinalToolEqual $a[$key] $b[$key]
        }
    } elseif ($Right -is [Array]) {
        if ($Left -isnot [Array] -or $Left.Count -ne $Right.Count) { throw 'Tool array mismatch' }
        for ($i = 0; $i -lt $Right.Count; $i++) { Assert-FinalToolEqual $Left[$i] $Right[$i] }
    } elseif ($Right -is [bool]) {
        if ($Left -isnot [bool] -or $Left -ne $Right) { throw 'Tool Boolean mismatch' }
    } elseif ($Right -is [string]) {
        if ($Left -isnot [string] -or $Left -cne $Right) { throw 'Tool string mismatch' }
    } else {
        if (($Left -isnot [int] -and $Left -isnot [long]) -or $Left -ne $Right) { throw 'Tool integer mismatch' }
    }
}

function Assert-FinalToolInteger($Value, [long] $Minimum, [long] $Maximum) {
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Minimum -or $Value -gt $Maximum) {
        throw 'Invalid bounded tool integer'
    }
}

function Assert-FinalToolString($Value, [string] $Pattern) {
    if ($Value -isnot [string] -or -not [regex]::IsMatch($Value, '\A(?:' + $Pattern + ')\z')) {
        throw 'Invalid exact tool string'
    }
}

function Assert-FinalToolPath($Value) {
    if ($Value -isnot [string] -or -not $Value.StartsWith('C:\', [StringComparison]::Ordinal) -or
        $Value -match '[\x00\r\n*?"|<>]' -or $Value.Substring(2).Contains(':') -or
        @($Value.Split('\') | Where-Object { $_ -ceq '.' -or $_ -ceq '..' }).Count -ne 0) {
        throw 'Invalid exact tool Windows path'
    }
}

function Test-FinalToolSamePath([string] $Left, [string] $Right) {
    return [string]::Equals([IO.Path]::GetFullPath($Left), [IO.Path]::GetFullPath($Right), [StringComparison]::OrdinalIgnoreCase)
}

function Get-FinalToolText($Value, $Slots) {
    if ($Value -isnot [string]) { throw 'Tool template is not text' }
    $value = Resolve-FinalText $Value $Slots
    if ($value.Length -eq 0 -or $value.Length -gt 1048576 -or $value -match '[\x00-\x1f\x7f]') {
        throw 'Unbounded or control-bearing tool text'
    }
    [void][Text.UTF8Encoding]::new($false, $true).GetBytes($value)
    return $value
}

function Get-FinalCscTokens([string] $Text) {
    $tokens = [Collections.Generic.List[string]]::new()
    $i = 0
    while ($i -lt $Text.Length) {
        Assert-FinalBudget
        while ($i -lt $Text.Length -and [char]::IsWhiteSpace($Text[$i])) { $i++ }
        if ($i -eq $Text.Length) { break }
        if ($Text[$i] -ceq '#') { throw 'Response hash comment is inadmissible' }
        $quotes = 0
        $token = [Text.StringBuilder]::new()
        while ($i -lt $Text.Length -and (-not [char]::IsWhiteSpace($Text[$i]) -or $quotes % 2 -ne 0)) {
            if ($i % 1024 -eq 0) { Assert-FinalBudget }
            $c = $Text[$i]
            if ($c -ceq '\') {
                $start = $i
                while ($i -lt $Text.Length -and $Text[$i] -ceq '\') { [void]$token.Append($Text[$i]); $i++ }
                if ($i -lt $Text.Length -and $Text[$i] -ceq '"') {
                    if (($i - $start) % 2 -eq 0) { $quotes++ }
                    [void]$token.Append('"'); $i++
                }
            } elseif ($c -ceq '"') {
                [void]$token.Append($c); $quotes++; $i++
            } else {
                if ([int]$c -lt 32 -or $c -ceq '|') { throw 'Illegal response character' }
                [void]$token.Append($c); $i++
            }
        }
        if ($quotes % 2 -ne 0) { throw 'Unbalanced response quoting' }
        $value = $token.ToString()
        if ($quotes -eq 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($value.Length -ne 0) {
            if ($value.StartsWith('@')) { throw 'Nested Csc response token' }
            $tokens.Add($value)
        }
    }
    return ,$tokens.ToArray()
}

function Assert-FinalToolPin($Pin, $Graph) {
    Assert-FinalKeys $Pin @('path', 'sha256')
    Assert-FinalToolPath $Pin.path
    Assert-FinalToolString $Pin.sha256 '[0-9a-f]{64}'
    $matches = @($Graph.protectedInputs | Where-Object { $_.path -ceq $Pin.path -and $_.sha256 -ceq $Pin.sha256 })
    if ($matches.Count -ne 1) { throw 'Tool source/runtime/task/consumer pin is not protected' }
}

function Get-FinalToolEnvironment($Graph, $Plan, $Recipe, $Slots) {
    $environment = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($property in $Recipe.invocation.replacementEnvironmentTemplate.PSObject.Properties) {
        $environment.Add($property.Name, (Resolve-FinalText $property.Value $Slots))
    }
    $stages = @($Graph.toolResponseContract.sdkEnvironmentOverrides, $Plan.taskEnvironmentOverrides)
    for ($stage = 0; $stage -lt $stages.Count; $stage++) {
        $changes = $stages[$stage]
        if ($changes -isnot [Array] -or $changes.Count -gt 128) { throw 'Unbounded ordered environment overrides' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($item in $changes) {
            Assert-FinalBudget
            Assert-FinalKeys $item @('name', 'value')
            Assert-FinalToolString $item.name '[A-Za-z_][A-Za-z0-9_()]{0,127}'
            if (-not $seen.Add($item.name) -and -not ($stage -eq 1 -and $Plan.kind -ceq 'Csc' -and $item.name -ceq 'DOTNET_ROOT')) {
                throw 'Duplicate descendant override outside the Csc clear/set pair'
            }
            if (@('_MSPDBSRV_ENDPOINT_', '_MSPDBSRV_', 'LINK', '_LINK_', 'CL', '_CL_',
                    'TEMP', 'TMP', 'MSBUILDPRESERVETOOLTEMPFILES') -icontains $item.name) {
                throw 'Duplicate or forbidden descendant override'
            }
            if ($item.value -isnot [string]) { throw 'Nontext descendant environment value' }
            $value = Resolve-FinalText $item.value $Slots
            foreach ($name in @($environment.Keys)) {
                if ([string]::Equals($name, $item.name, [StringComparison]::OrdinalIgnoreCase)) { [void]$environment.Remove($name) }
            }
            $environment.Add($item.name, $value)
        }
        if ($stage -eq 1 -and $Plan.kind -ceq 'Csc') {
            $rootChanges = @($changes | Where-Object { $_.name -ieq 'DOTNET_ROOT' })
            $expectedRoot = [IO.Path]::GetDirectoryName($Graph.toolResponseContract.hostBindings.sdkHost.path)
            Assert-FinalToolEqual $rootChanges @(@{ name = 'DOTNET_ROOT'; value = '' }, @{ name = 'DOTNET_ROOT'; value = $expectedRoot })
        }
    }
    $declared = Get-FinalToolMap $Plan.childEnvironmentTemplate
    if ($declared.Count -lt 35 -or $declared.Count -gt 256 -or $declared.Count -ne $environment.Count) {
        throw 'Missing complete task child environment'
    }
    foreach ($key in $declared.Keys) {
        Assert-FinalToolString $key '[A-Za-z_][A-Za-z0-9_()]{0,127}'
        if ($declared[$key] -isnot [string] -or -not $environment.ContainsKey($key)) { throw 'Child environment key mismatch' }
        $value = Resolve-FinalText $declared[$key] $Slots
        if ($value.Length -gt 32767 -or $environment[$key] -cne $value) { throw 'Child environment derivation mismatch' }
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $environment.Keys) { if (-not $seen.Add($key)) { throw 'Case-alias child environment' } }
    return ,$environment
}

function Get-FinalToolEnvironmentHash($Environment) {
    $names = [string[]]@($Environment.Keys)
    [Array]::Sort($names, [StringComparer]::OrdinalIgnoreCase)
    $entries = @($names | ForEach-Object { $_ + '=' + $Environment[$_] })
    $block = ($entries -join [char]0) + [char]0 + [char]0
    return Get-FinalHash ([Text.UnicodeEncoding]::new($false, $false, $true).GetBytes($block))
}

function Get-FinalRenderedToolPlan($Graph, $Plan, $Recipe, $Slots) {
    Assert-FinalBudget
    $environment = Get-FinalToolEnvironment $Graph $Plan $Recipe $Slots
    $working = Resolve-FinalText $Plan.workingDirectoryTemplate $Slots
    Assert-FinalToolPath $working
    if ($working -cne [IO.Path]::GetDirectoryName($Plan.projectPath)) { throw 'Task working directory differs from project' }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    if ($Plan.kind -ceq 'Csc') {
        $direct = Get-FinalToolText $Plan.directCommandTextTemplate $Slots
        $responseText = Get-FinalToolText $Plan.responseCommandTextTemplate $Slots
        $directTokens = Get-FinalCscTokens $direct
        $tokens = Get-FinalCscTokens $responseText
        if (@($directTokens | Where-Object { $_ -ceq '/noconfig' }).Count -ne 1) { throw 'Csc no-config command not established' }
        $expectedDirect = '/noconfig'
        if (-not $Plan.executionMode.appHost) { $expectedDirect = 'exec "' + $Plan.consumer.path + '" /noconfig' }
        if ($direct -cne $expectedDirect) { throw 'Csc direct command differs from selected host/consumer' }
        $output = Resolve-FinalText $Plan.outputPathTemplate $Slots
        Assert-FinalToolPath $output
        $outputs = @($tokens | Where-Object { $_.StartsWith('/out:', [StringComparison]::OrdinalIgnoreCase) })
        if ($outputs.Count -ne 1) { throw 'Csc output identity missing or duplicated' }
        $renderedOutput = $outputs[0].Substring(5)
        if ($renderedOutput.StartsWith('"') -and $renderedOutput.EndsWith('"')) {
            $renderedOutput = $renderedOutput.Substring(1, $renderedOutput.Length - 2)
        }
        if (-not (Test-FinalToolSamePath ([IO.Path]::Combine($working, $renderedOutput)) $output)) {
            throw 'Csc output differs from planned artifact'
        }
        $command = $Plan.tool.path + ' ' + $direct + ' ' + $responseText
        $data = [byte[]](@(239, 187, 191) + $utf8.GetBytes($responseText))
    } else {
        $command = Get-FinalToolText $Plan.commandTextTemplate $Slots
        $match = [regex]::Match($command, '\A"([^"]+)" @"([^"]+)"\z')
        if (-not $match.Success -or $command -match '[%!^&|<>]') { throw 'Unreviewed native Exec invocation' }
        $consumer = $match.Groups[1].Value
        if ([IO.Path]::GetExtension($consumer).Length -eq 0) { $consumer += '.exe' }
        $response = @($Graph.generatedResponses | Where-Object { $_.id -ceq $Plan.responseId })
        if ($response.Count -ne 1 -or -not (Test-FinalToolSamePath $consumer $Plan.consumer.path) -or
            -not (Test-FinalToolSamePath ([IO.Path]::Combine($working, $match.Groups[2].Value)) (Resolve-FinalText $response[0].pathTemplate $Slots))) {
            throw 'Exec consumer/response does not join its static plan'
        }
        $encoding = $Plan.batchEncoding
        $oem = [int]$encoding.oemCodePage
        $codec = [Text.Encoding]::GetEncoding($oem, [Text.EncoderFallback]::ExceptionFallback, [Text.DecoderFallback]::ExceptionFallback)
        $representable = $true
        try { [void]$codec.GetBytes($command + $working) }
        catch [Text.EncoderFallbackException] { $representable = $false }
        $specification = $encoding.useUtf8Encoding.ToUpperInvariant()
        $selected = $oem
        if (@('ALWAYS', 'TRUE') -ccontains $specification -or
            (@('', 'DETECT') -ccontains $specification -and -not $representable)) { $selected = 65001 }
        if ($encoding.codePage -ne $selected) { throw 'Exec encoding differs from source selection' }
        $lines = @('setlocal', 'set errorlevel=dummy', 'set errorlevel=')
        if ($selected -ne $oem) { $lines += '%SystemRoot%\System32\chcp.com ' + $selected + '>nul' }
        $lines += @($command, 'exit %errorlevel%')
        $crlf = [string][char]13 + [char]10
        $text = ($lines -join $crlf) + $crlf
        if ($selected -eq 65001) { $data = $utf8.GetBytes($text) }
        else { $data = $codec.GetBytes($text) }
    }
    if ($data.Length -gt 8388608) { throw 'Tool response exceeds per-input bound' }
    return [pscustomobject]@{ command = $command; bytes = $data; environmentHash = (Get-FinalToolEnvironmentHash $environment) }
}

function Assert-FinalToolContract($Graph, $Recipe, $Slots) {
    Assert-FinalKeys $Graph @('schema', 'source', 'sourceRoot', 'packageRoot', 'protectedInputs',
        'generatedResponses', 'preexistingResponses', 'generatedPaths', 'effectiveProperties',
        'sourceInventory', 'absentInputs', 'toolResponseContract', 'toolResponses')
    if ($Graph.schema -cne 'final-publish-exact-graph-v2') { throw 'Unexpected tool graph schema' }
    $contract = $Graph.toolResponseContract
    Assert-FinalKeys $contract @('schema', 'sources', 'hostBindings', 'console', 'sdkEnvironmentOverrides',
        'directoryRoles', 'singleLoggingService', 'outOfProcessTaskHosts')
    Assert-FinalToolEqual $contract.schema 'final-publish-tool-response-contract-v1'
    Assert-FinalToolEqual $contract.sources @{
        msbuild = 'b44cdcec4c79c50c67560876707d57d4f635fa3b'; roslyn = 'f7797ed513e3035983346552ac2d9ca2281bc2ec'
        sdk = '32593ca81f8aae7b0d41c1a7198529c3365106b8'; runtime = '4271d88e0aebf3d04f188f1334c2220d80555ef6'
    }
    Assert-FinalToolEqual $contract.singleLoggingService $true
    Assert-FinalToolEqual $contract.outOfProcessTaskHosts $false
    Assert-FinalToolEqual $contract.console @{
        stream = 'stdout'; encoding = 'utf-8'; locale = 'en-US'; verbosity = 'detailed'
        showEventId = $true; forceNoAlign = $true; disableConsoleColor = $true; terminalLogger = $false
    }
    Assert-FinalKeys $contract.hostBindings @('sdkHost', 'sdkForwarder', 'msbuild', 'corelib', 'taskHost',
        'logger', 'utilities', 'cscTask', 'execTask')
    foreach ($property in $contract.hostBindings.PSObject.Properties) { Assert-FinalToolPin $property.Value $Graph }
    if ($contract.hostBindings.sdkHost.path -cne $Recipe.invocation.executable) { throw 'SDK host pin differs from root invocation' }
    $plans = $Graph.toolResponses
    if ($plans -isnot [Array] -or $plans.Count -lt 3 -or $plans.Count + $Graph.generatedResponses.Count -gt 32) {
        throw 'Missing or excessive finite Csc/Exec plans'
    }
    $roles = $contract.directoryRoles
    if ($roles -isnot [Array] -or $roles.Count -lt 1 -or $roles.Count -gt $plans.Count) { throw 'Missing finite directory roles' }
    $roleSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($role in $roles) {
        Assert-FinalToolString $role '[a-z][a-z0-9-]{0,63}'
        if (-not $roleSet.Add($role)) { throw 'Duplicate directory role' }
    }
    if ($Graph.generatedPaths.Count + $roles.Count + $plans.Count -gt 10000) { throw 'Generated-input ceiling exceeded' }
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($response in $Graph.generatedResponses) { if (-not $identities.Add($response.id)) { throw 'Duplicate static response identity' } }
    $occurrences = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $usedRoles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $execResponses = [Collections.Generic.List[string]]::new()
    $common = @('id', 'kind', 'projectPath', 'targetName', 'taskOccurrence', 'producer', 'tool', 'consumer',
        'directoryRole', 'workingDirectoryTemplate', 'taskEnvironmentOverrides', 'childEnvironmentTemplate', 'expectedOutcome')
    foreach ($plan in $plans) {
        Assert-FinalBudget
        $extra = @('commandTextTemplate', 'responseId', 'batchEncoding', 'echoOff', 'ignoreExitCode', 'workingDirectoryIsUnc')
        if ($plan.kind -ceq 'Csc') { $extra = @('directCommandTextTemplate', 'responseCommandTextTemplate', 'outputPathTemplate', 'executionMode') }
        Assert-FinalKeys $plan ($common + $extra)
        Assert-FinalToolString $plan.id '[a-z][a-z0-9-]{0,63}'
        if (-not $identities.Add($plan.id) -or @('Csc', 'Exec') -cnotcontains $plan.kind -or
            $plan.expectedOutcome -cne 'executed-success') { throw 'Unknown, duplicate or skipped tool plan' }
        Assert-FinalToolPath $plan.projectPath
        if (@($Graph.protectedInputs | Where-Object { $_.path -ceq $plan.projectPath }).Count -ne 1) { throw 'Unprotected tool project' }
        Assert-FinalToolString $plan.targetName '[A-Za-z_][A-Za-z0-9_]{0,127}'
        Assert-FinalToolInteger $plan.taskOccurrence 1 10000
        $identity = @($plan.projectPath, $plan.targetName, $plan.kind, [string]$plan.taskOccurrence) -join [char]0
        if (-not $occurrences.Add($identity) -or -not $roleSet.Contains($plan.directoryRole)) { throw 'Duplicate occurrence or unknown role' }
        [void]$usedRoles.Add($plan.directoryRole)
        Assert-FinalKeys $plan.producer @('import', 'task')
        foreach ($pin in @($plan.producer.import, $plan.producer.task, $plan.tool, $plan.consumer)) { Assert-FinalToolPin $pin $Graph }
        $taskRole = 'execTask'
        if ($plan.kind -ceq 'Csc') { $taskRole = 'cscTask' }
        Assert-FinalToolEqual $plan.producer.task $contract.hostBindings.$taskRole
        if ($plan.kind -ceq 'Csc') {
            if ($plan.executionMode.appHost -isnot [bool]) { throw 'Unselected Csc apphost branch' }
            Assert-FinalToolEqual $plan.executionMode @{
                builtinNetTask = $true; frameworkBridge = $false; hostCompiler = $false; skipCompiler = $false
                useSharedCompilation = $false; useCommandProcessor = $false; responseFiles = @(); appHost = $plan.executionMode.appHost
            }
            $directory = [IO.Path]::GetDirectoryName($plan.producer.task.path) + '\bincore'
            if ($plan.consumer.path -cne ($directory + '\csc.dll')) { throw 'Built-in Csc consumer differs from task location' }
            if ($plan.executionMode.appHost) {
                if ($plan.tool.path -cne ($directory + '\csc.exe')) { throw 'Built-in Csc apphost not pinned' }
            } else {
                Assert-FinalToolEqual $plan.tool $contract.hostBindings.sdkHost
                if ($Graph.absentInputs -cnotcontains ($directory + '\csc.exe')) { throw 'Missing absent-apphost proof' }
            }
            if ($Graph.generatedPaths -cnotcontains $plan.outputPathTemplate) { throw 'Csc output outside finite graph' }
        } else {
            Assert-FinalToolEqual $plan.echoOff $false
            Assert-FinalToolEqual $plan.ignoreExitCode $false
            Assert-FinalToolEqual $plan.workingDirectoryIsUnc $false
            if ($plan.tool.path -cne 'C:\Windows\System32\cmd.exe' -or @('ilc', 'link') -cnotcontains $plan.responseId) {
                throw 'Unreviewed Exec tool or companion role'
            }
            $response = @($Graph.generatedResponses | Where-Object { $_.id -ceq $plan.responseId })
            if ($response.Count -ne 1 -or $plan.consumer.path -cne $response[0].consumer.path -or
                $plan.consumer.sha256 -cne $response[0].consumer.sha256 -or
                $plan.targetName -cne $response[0].consumer.target -or
                $plan.producer.import.sha256 -cne $response[0].producer.sha256) { throw 'Exec/native response producer mismatch' }
            $execResponses.Add($plan.responseId)
            Assert-FinalKeys $plan.batchEncoding @('oemCodePage', 'codePage', 'useUtf8Encoding', 'codePageTool')
            Assert-FinalToolInteger $plan.batchEncoding.oemCodePage 1 65535
            Assert-FinalToolInteger $plan.batchEncoding.codePage 1 65535
            if (@('', 'Detect', 'Always', 'True', 'Never', 'System') -cnotcontains $plan.batchEncoding.useUtf8Encoding) {
                throw 'Unreviewed Exec encoding branch'
            }
            if ($plan.batchEncoding.codePage -ne $plan.batchEncoding.oemCodePage) {
                Assert-FinalToolPin $plan.batchEncoding.codePageTool $Graph
                if ($plan.batchEncoding.codePageTool.path -cne 'C:\Windows\System32\chcp.com') { throw 'Wrong Exec codepage tool' }
            } elseif ($null -ne $plan.batchEncoding.codePageTool) { throw 'Unused codepage tool' }
        }
        [void](Get-FinalRenderedToolPlan $Graph $plan $Recipe $Slots)
    }
    if (-not $usedRoles.SetEquals($roleSet) -or $execResponses.Count -ne 2 -or
        @($execResponses | Where-Object { $_ -ceq 'ilc' }).Count -ne 1 -or
        @($execResponses | Where-Object { $_ -ceq 'link' }).Count -ne 1) { throw 'Incomplete native companions or unused directory roles' }
}

function Get-FinalToolMessageReceipt([byte[]] $Raw, [long] $Offset) {
    return @{ offset = $Offset; bytes = $Raw.Length; sha256 = (Get-FinalHash $Raw) }
}

function Join-FinalToolMessages($Graph, $Recipe, $Slots, [byte[]] $Stdout, [byte[]] $Stderr) {
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $errorText = $utf8.GetString($Stderr)
    if ($errorText -match '(?:TaskId:|TargetId:|Preserving temporary file)') { throw 'Tool event in wrong stream' }
    if ($Stdout.Length -lt 2 -or $Stdout[$Stdout.Length - 2] -ne 13 -or $Stdout[$Stdout.Length - 1] -ne 10) {
        throw 'Original ordinary console stream is incomplete'
    }
    $plans = $Graph.toolResponses
    $rendered = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($plan in $plans) { $rendered.Add($plan.id, (Get-FinalRenderedToolPlan $Graph $plan $Recipe $Slots)) }
    $targets = [Collections.Generic.List[object]]::new()
    $tasks = [Collections.Generic.Dictionary[int,object]]::new()
    $done = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $seenTargets = [Collections.Generic.HashSet[int]]::new()
    $counts = [Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $directories = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $seenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $previousTask = 0
    $offset = 0
    while ($offset -lt $Stdout.Length) {
        Assert-FinalBudget
        $end = $offset
        while ($end -lt $Stdout.Length -and $Stdout[$end] -ne 10) { $end++ }
        $length = $end - $offset + 1
        if ($end -ge $Stdout.Length -or $length -lt 2 -or $Stdout[$end - 1] -ne 13 -or $length -gt 2097152) {
            throw 'Unexpected console framing or size'
        }
        $raw = [byte[]]::new($length)
        [Array]::Copy($Stdout, $offset, $raw, 0, $length)
        $text = $utf8.GetString($raw, 0, $length - 2)
        $receipt = Get-FinalToolMessageReceipt $raw $offset
        $offset += $length
        if ($text -match '[\x00\r\n\x1b]') { throw 'Uninterpretable console event' }
        $match = [regex]::Match($text, '\ATarget "([^"]+): \(TargetId:([1-9][0-9]*)\)" (?:in file "([^"]+)" from project|in project) "([^"]+)" \((?:entry point|target "[^"]+" depends on it)\):\z')
        if ($match.Success) {
            $number = [long]::Parse($match.Groups[2].Value, [Globalization.CultureInfo]::InvariantCulture)
            Assert-FinalToolInteger $number 1 2147483647
            if (-not $seenTargets.Add([int]$number)) { throw 'Reused target context' }
            $project = $match.Groups[4].Value
            $imported = $match.Groups[3].Value
            if ($imported.Length -eq 0) { $imported = $project }
            $targets.Add(@{ id = [int]$number; name = $match.Groups[1].Value; project = $project; import = $imported; start = $receipt })
            continue
        }
        $match = [regex]::Match($text, '\ADone building target "([^"]+)" in project "([^"]+)"\.: \(TargetId:([1-9][0-9]*)\)\z')
        if ($match.Success) {
            if ($targets.Count -eq 0) { throw 'Unmatched target finish' }
            $target = $targets[$targets.Count - 1]
            $targets.RemoveAt($targets.Count - 1)
            if ($target.id -ne [long]$match.Groups[3].Value -or $target.name -cne $match.Groups[1].Value -or
                [IO.Path]::GetFileName($target.project) -cne $match.Groups[2].Value -or
                @($tasks.Values | Where-Object { $_.target.id -eq $target.id }).Count -ne 0) { throw 'Ambiguous target/project nesting' }
            continue
        }
        $match = [regex]::Match($text, '\ATask "([^"]+)" \(TaskId:([1-9][0-9]*)\)\z')
        if ($match.Success) {
            $name = $match.Groups[1].Value
            $number = [long]::Parse($match.Groups[2].Value, [Globalization.CultureInfo]::InvariantCulture)
            Assert-FinalToolInteger $number 1 2147483647
            if ($number -le $previousTask -or $tasks.ContainsKey([int]$number) -or $targets.Count -eq 0) {
                throw 'Missing/reused/nonmonotonic same-service task context'
            }
            $previousTask = [int]$number
            $target = $targets[$targets.Count - 1]
            $identity = @($target.project, $target.name, $name) -join [char]0
            if (-not $counts.ContainsKey($identity)) { $counts.Add($identity, 0) }
            $counts[$identity]++
            $state = @{ name = $name; target = $target; start = $receipt; plan = $null
                command = $null; preservation = $null; environment = [Collections.Generic.List[object]]::new() }
            if (@('Csc', 'Exec') -ccontains $name) {
                $selected = @($plans | Where-Object {
                    $_.projectPath -ceq $target.project -and $_.targetName -ceq $target.name -and
                    $_.kind -ceq $name -and $_.taskOccurrence -eq $counts[$identity]
                })
                if ($selected.Count -ne 1 -or $selected[0].producer.import.path -cne $target.import) {
                    throw 'Unexpected or ambiguous executed Csc/Exec occurrence'
                }
                $state.plan = $selected[0]
            }
            $tasks.Add([int]$number, $state)
            continue
        }
        $match = [regex]::Match($text, '\ADone executing task "([^"]+)"\. \(TaskId:([1-9][0-9]*)\)\z')
        if ($match.Success) {
            $name = $match.Groups[1].Value
            $number = [int]::Parse($match.Groups[2].Value, [Globalization.CultureInfo]::InvariantCulture)
            if (-not $tasks.ContainsKey($number)) { throw 'Unmatched successful task finish' }
            $state = $tasks[$number]
            [void]$tasks.Remove($number)
            if ($state.name -cne $name -or $targets.Count -eq 0 -or $state.target.id -ne $targets[$targets.Count - 1].id) {
                throw 'Mismatched successful task finish'
            }
            $plan = $state.plan
            if ($null -ne $plan) {
                $expectedEnvironment = @($plan.taskEnvironmentOverrides | ForEach-Object {
                    '  ' + $_.name + '=' + (Resolve-FinalText $_.value $Slots)
                })
                $observedEnvironment = @($state.environment | ForEach-Object { $_.text })
                Assert-FinalToolEqual $observedEnvironment $expectedEnvironment
                if ($null -eq $state.command -or $null -eq $state.preservation -or
                    $state.command.offset -ge $state.preservation.offset -or $done.ContainsKey($plan.id)) {
                    throw 'Incomplete, duplicate or out-of-order tool evidence'
                }
                $done.Add($plan.id, @{
                    id = $plan.id; kind = $plan.kind; taskId = $number; projectPath = $plan.projectPath
                    targetName = $plan.targetName; taskOccurrence = $plan.taskOccurrence; targetId = $state.target.id
                    targetStart = $state.target.start; taskStart = $state.start; command = $state.command
                    preservation = $state.preservation; taskFinish = $receipt
                    environmentMessages = @($state.environment | ForEach-Object { $_.receipt })
                    path = $state.path; directoryRole = $plan.directoryRole
                })
            }
            continue
        }
        $match = [regex]::Match($text, '\A  (.*) \(TaskId:([1-9][0-9]*)\)\z')
        if ($match.Success) {
            $message = $match.Groups[1].Value
            $number = [int]::Parse($match.Groups[2].Value, [Globalization.CultureInfo]::InvariantCulture)
            if (-not $tasks.ContainsKey($number)) { throw 'Message outside its original task boundaries' }
            $state = $tasks[$number]
            $plan = $state.plan
            $preserving = [regex]::Match($message, "\APreserving temporary file '([^']+)'\z")
            if ($preserving.Success -and $null -eq $plan) { throw 'Undeclared retained ToolTask producer' }
            if ($null -ne $plan) {
                if ($message -ceq $rendered[$plan.id].command) {
                    if ($null -ne $state.command) { throw 'Duplicate exact expanded command' }
                    $state.command = $receipt
                } elseif ($preserving.Success) {
                    if ($null -ne $state.preservation) { throw 'Multiple temporary files for one planned role' }
                    $path = $preserving.Groups[1].Value
                    Assert-FinalToolPath $path
                    $parent = [IO.Path]::GetDirectoryName($path)
                    $leaf = [IO.Path]::GetFileName($path)
                    $extension = '\.exec\.cmd'
                    if ($plan.kind -ceq 'Csc') { $extension = '\.rsp' }
                    if ([IO.Path]::GetDirectoryName($parent) -cne ($Slots.ACTION_ROOT + '\temp') -or
                        [IO.Path]::GetFileName($parent) -cnotmatch '\AMSBuildTemp[a-z0-5]{8}\.[a-z0-5]{3}\z' -or
                        -not [regex]::IsMatch($leaf, '\Atmp[0-9a-f]{32}' + $extension + '\z') -or -not $seenPaths.Add($path)) {
                        throw 'Temporary input violates finite directory/leaf role'
                    }
                    $role = $plan.directoryRole
                    if (($directories.ContainsKey($role) -and $directories[$role] -cne $parent) -or
                        (-not $directories.ContainsKey($role) -and $directories.ContainsValue($parent))) {
                        throw 'Temporary-directory role aliases or changes'
                    }
                    $directories[$role] = $parent
                    $state.path = $path
                    $state.preservation = $receipt
                } elseif ($message -cmatch '\A  [A-Za-z_][A-Za-z0-9_()]*=.*\z') {
                    if ($null -ne $state.command) { throw 'Late environment override message' }
                    $state.environment.Add(@{ text = $message; receipt = $receipt })
                }
            }
            continue
        }
        if ($text.Contains('(TaskId:') -or $text.Contains('(TargetId:') -or $text.Contains('Preserving temporary file') -or
            $text.StartsWith('Done executing task "') -or $text.StartsWith('Done building target "')) {
            throw 'Unknown, failed or ambiguous source event'
        }
    }
    $roleSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($role in $Graph.toolResponseContract.directoryRoles) { [void]$roleSet.Add($role) }
    if ($targets.Count -ne 0 -or $tasks.Count -ne 0 -or $done.Count -ne $plans.Count -or -not $roleSet.SetEquals($directories.Keys)) {
        throw 'Incomplete original graph event closure'
    }
    return [pscustomobject]@{ observations = @($plans | ForEach-Object { $done[$_.id] }); directories = $directories }
}

function Assert-FinalToolInventory($Graph, $Slots, $ExpectedPaths, $ExpectedDirectories, [bool] $Before = $false) {
    $root = $Slots.ACTION_ROOT + '\temp'
    Assert-GuardDirect $root
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $count = 0
    $prefix = $root + '\'
    $static = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($template in $Graph.generatedPaths) {
        $path = Resolve-FinalText $template $Slots
        if ($path.StartsWith($prefix, [StringComparison]::Ordinal)) {
            if ($path.Substring($prefix.Length).Split('\')[0].StartsWith('MSBuildTemp', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Static generated path overlaps a dynamic temporary role'
            }
            [void]$static.Add($path)
            $parent = [IO.Path]::GetDirectoryName($path)
            while ($parent.StartsWith($prefix, [StringComparison]::Ordinal)) {
                [void]$static.Add($parent)
                $parent = [IO.Path]::GetDirectoryName($parent)
            }
        }
    }
    $pending = [Collections.Generic.Stack[string]]::new()
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($root)) {
        Assert-FinalBudget
        $count++
        if ($count + $Graph.generatedPaths.Count -gt 10000) { throw 'Temporary inventory bound exceeded' }
        $name = [IO.Path]::GetFileName($entry)
        if (-not $name.StartsWith('MSBuildTemp', [StringComparison]::OrdinalIgnoreCase)) { $pending.Push($entry); continue }
        $attributes = [IO.File]::GetAttributes($entry)
        if ($Before -or $name -cnotmatch '\AMSBuildTemp[a-z0-5]{8}\.[a-z0-5]{3}\z' -or
            ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw 'Stale or invalid MSBuild temporary directory' }
        Assert-GuardDirect $entry
        [void]$directories.Add($entry)
        foreach ($member in [IO.Directory]::EnumerateFileSystemEntries($entry)) {
            Assert-FinalBudget
            $count++
            if ($count + $Graph.generatedPaths.Count -gt 10000) { throw 'Temporary inventory bound exceeded' }
            $attributes = [IO.File]::GetAttributes($member)
            if (($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Device)) -ne 0) {
                throw 'Nonregular or nested retained temporary input'
            }
            Assert-GuardDirect $member
            [void]$paths.Add($member)
        }
    }
    while ($pending.Count -ne 0) {
        Assert-FinalBudget
        $path = $pending.Pop()
        if ($Before -or -not $static.Contains($path)) { throw 'Undeclared or stale temporary input outside a tool role' }
        Assert-GuardDirect $path
        $attributes = [IO.File]::GetAttributes($path)
        if (($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Device)) -ne 0) {
            throw 'Nonregular static temporary input'
        }
        if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            foreach ($member in [IO.Directory]::EnumerateFileSystemEntries($path)) {
                Assert-FinalBudget
                $count++
                if ($count + $Graph.generatedPaths.Count -gt 10000) { throw 'Temporary inventory bound exceeded' }
                $pending.Push($member)
            }
        }
    }
    if (-not $Before -and (-not $paths.SetEquals([string[]]$ExpectedPaths) -or -not $directories.SetEquals([string[]]$ExpectedDirectories))) {
        throw 'Unmatched or missing retained temporary member'
    }
}

function Get-FinalToolObservations($Graph, $Recipe, $Slots, [byte[]] $Stdout, [byte[]] $Stderr,
    [string] $Reservation, [string] $GraphHash, [string] $ResponseRoot) {
    $joined = Join-FinalToolMessages $Graph $Recipe $Slots $Stdout $Stderr
    Assert-FinalToolInventory $Graph $Slots @($joined.observations | ForEach-Object { $_.path }) @($joined.directories.Values)
    $observations = [Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Graph.toolResponses.Count; $i++) {
        Assert-FinalBudget
        $plan = $Graph.toolResponses[$i]
        $observed = $joined.observations[$i]
        $rendered = Get-FinalRenderedToolPlan $Graph $plan $Recipe $Slots
        $actual = Read-FinalBytes $observed.path 8388608
        $actualHash = Get-FinalHash $actual
        if ($actual.Length -ne $rendered.bytes.Length -or $actualHash -cne (Get-FinalHash $rendered.bytes)) {
            throw 'Original preserved tool input differs from exact producer bytes'
        }
        Save-Bytes ($ResponseRoot + '\' + $plan.id + '.bin') $actual
        $observed.bytes = $actual.Length
        $observed.sha256 = $actualHash
        $observed.producerImportSha256 = $plan.producer.import.sha256
        $observed.taskAssemblySha256 = $plan.producer.task.sha256
        $observed.consumerSha256 = $plan.consumer.sha256
        $observed.toolSha256 = $plan.tool.sha256
        $observed.childEnvironmentBlockSha256 = $rendered.environmentHash
        $observed.stream = 'stdout'
        $observed.streamSha256 = Get-FinalHash $Stdout
        $observed.reservationSha256 = $Reservation
        $observed.graphSha256 = $GraphHash
        $observed.snapshot = 'response-inputs/' + $plan.id + '.bin'
        $observed.snapshotSha256 = $actualHash
        $observations.Add($observed)
    }
    return ,$observations.ToArray()
}


function Initialize-FinalBinding($ControllerWatch) {
    if ($script:FinalPublishDraftOnly) { throw 'DRAFT_ONLY: final admission disabled' }
    if ($ActionName -cnotmatch '^(?!0000)[0-9]{4}$') { throw 'Invalid original action number' }
    $action = 'C:\Temp\azureauth-windows-slice-108\actions\' + $ActionName
    $script:FinalControllerWatch = $ControllerWatch
    $authority = Read-FinalJson "$action\authority.json" $AuthoritySha256
    $invocation = Read-FinalJson "$action\invocation.json" $InvocationSha256
    $start = Read-FinalJson "$action\started.json" $ReservationSha256 16384
    Assert-FinalKeys $authority @('schema', 'repository', 'target', 'protocol', 'wave', 'product', 'integration',
        'components', 'recipe', 'acceptedGuard', 'rootMarkers', 'limits', 'sourceReview', 'handoff',
        'handoffAcceptance', 'graph', 'graphAcceptance', 'guardAcceptance', 'callerAuthorization', 'executionReview', 'publication')
    Assert-FinalKeys $invocation @('schema', 'action', 'reservationSha256', 'authoritySha256', 'actionPath',
        'workingDirectory', 'executable', 'argumentVector', 'nativeArguments', 'nativeArgumentsSha256',
        'nativeCommandLine', 'nativeCommandLineSha256', 'environment', 'environmentBlockSha256',
        'endpoint', 'acceptedGuard', 'graphSha256', 'limits')
    Assert-FinalKeys $start @('schema', 'action', 'number', 'utc', 'source', 'sourceTree', 'protocol', 'waveBlob',
        'authoritySha256', 'handoffSha256', 'guardAcceptanceSha256', 'priorCounters', 'preparationCharge',
        'buildTestCharge', 'publishCharge', 'reservedProcessScenarios', 'endpoint', 'originalOuterLimitMilliseconds')
    if ($authority.schema -cne 'final-publish-external-authority-v2' -or
        $authority.repository -cne 'hcoona/microsoft-authentication-cli' -or
        $authority.product.commit -cne '503360753accd0829801953823b1b57a4f852440' -or
        $authority.product.tree -cne '8506cdd9781c8a331ea12ea8fe27a55292eec073' -or
        $start.schema -cne 'final-publish-reservation-v1' -or $start.action -cne 'final-publish' -or
        $start.number -cne $ActionName -or $start.source -cne $authority.product.commit -or
        $start.sourceTree -cne $authority.product.tree -or $start.protocol -cne $authority.protocol.commit -or
        $start.waveBlob -cne $authority.wave.gitBlob -or $start.authoritySha256 -cne $AuthoritySha256 -or
        $start.handoffSha256 -cne $authority.handoff.sha256 -or
        $start.guardAcceptanceSha256 -cne $authority.guardAcceptance.sha256 -or
        $start.preparationCharge -ne 0 -or $start.buildTestCharge -ne 0 -or $start.publishCharge -ne 1 -or
        $start.reservedProcessScenarios -ne 0 -or $start.originalOuterLimitMilliseconds -ne 700000 -or
        $invocation.schema -cne 'final-publish-invocation-v1' -or $invocation.action -cne $ActionName -or
        $invocation.actionPath -cne $action -or $invocation.reservationSha256 -cne $ReservationSha256 -or
        $invocation.authoritySha256 -cne $AuthoritySha256 -or
        $invocation.endpoint -cnotmatch '^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$' -or
        $start.endpoint -cne $invocation.endpoint -or $invocation.graphSha256 -cne $authority.graph.sha256) {
        throw 'Original final publication reservation or authority join changed'
    }
    Assert-GuardHash $PSCommandPath $authority.components.controller.sha256
    $graph = Read-FinalJson "$action\graph.json" $authority.graph.sha256
    if ($authority.recipe.sha256 -cne $script:FinalRecipeHash) { throw 'Fixed env35 recipe changed' }
    $recipe = Read-FinalJson "$action\recipe.json" $script:FinalRecipeHash
    if ($invocation.workingDirectory -cne $graph.sourceRoot -or $invocation.executable -cne $recipe.invocation.executable) {
        throw 'Final subject path changed'
    }
    $slots = @{ ACTION_ROOT = $action; SOURCE_ROOT = $graph.sourceRoot; PACKAGE_ROOT = $graph.packageRoot; ENDPOINT = $start.endpoint }
    $argsExpected = @($recipe.invocation.argumentVectorTemplate | ForEach-Object { Resolve-FinalText $_ $slots })
    if (($argsExpected | ConvertTo-Json -Compress) -cne ($invocation.argumentVector | ConvertTo-Json -Compress)) {
        throw 'Final ordered argument vector changed'
    }
    $nativeExpected = (@($argsExpected | ForEach-Object { Quote-FinalArgument $_ }) -join ' ')
    $commandExpected = '"' + $invocation.executable + '" ' + $nativeExpected
    if ($invocation.nativeArguments -cne $nativeExpected -or $invocation.nativeCommandLine -cne $commandExpected -or
        (Get-FinalHash ([Text.Encoding]::Unicode.GetBytes($commandExpected))) -cne $invocation.nativeCommandLineSha256 -or
        (Get-FinalHash ([Text.Encoding]::Unicode.GetBytes($invocation.nativeArguments))) -cne $invocation.nativeArgumentsSha256) {
        throw 'Final native argument bytes changed'
    }
    $environment = @{}
    foreach ($property in $recipe.invocation.replacementEnvironmentTemplate.PSObject.Properties) {
        $environment.Add($property.Name, (Resolve-FinalText $property.Value $slots))
    }
    if ($environment.Count -ne 35 -or @($invocation.environment.PSObject.Properties).Count -ne 35) {
        throw 'Final environment entry count changed'
    }
    foreach ($property in $invocation.environment.PSObject.Properties) {
        if (-not $environment.ContainsKey($property.Name) -or $environment[$property.Name] -cne $property.Value) {
            throw 'Final replacement environment changed'
        }
    }
    foreach ($name in $recipe.invocation.mustBeAbsentCaseInsensitive) {
        if ($environment.ContainsKey($name)) { throw 'Native override must be absent' }
    }
    $orderedNames = [string[]]@($environment.Keys)
    [Array]::Sort($orderedNames, [StringComparer]::OrdinalIgnoreCase)
    $entries = @($orderedNames | ForEach-Object { $_ + '=' + $environment[$_] })
    $block = [Text.Encoding]::Unicode.GetBytes(($entries -join [char]0) + [char]0 + [char]0)
    if ((Get-FinalHash $block) -cne $invocation.environmentBlockSha256) { throw 'Final native environment block changed' }
    $guardFields = @('actionNumber', 'sourceSha256', 'dllSha256', 'guardBuildSha256',
        'preparationWindowsResultSha256', 'preparationWslResultSha256', 'preparationReservationSha256',
        'invocationSha256', 'compilerReceiptSha256', 'artifactAcceptancePath', 'artifactAcceptanceSha256',
        'expectedAssemblyFullName', 'acceptedLoaderSourceSha256')
    Assert-FinalKeys $authority.acceptedGuard $guardFields
    Assert-FinalKeys $invocation.acceptedGuard $guardFields
    foreach ($name in $guardFields) {
        $value = $authority.acceptedGuard.$name
        if ($null -eq $value -or $value -cne $invocation.acceptedGuard.$name) { throw 'Unbound guard projection' }
        $script:AcceptedFinalGuard[$name] = $value
    }
    if ($script:AcceptedFinalGuard.sourceSha256 -cne 'd38846b080d5ee092fae9e21c9031712b56289093b50ca048d50589cca50ff4b') {
        throw 'Final guard source changed'
    }
    $script:FinalAuthority = $authority
    $script:FinalInvocation = $invocation
    $script:FinalGraph = $graph
    $script:FinalRecipe = $recipe
    $script:FinalCallerAuthorization = Assert-FinalCallerAuthorization
    Assert-FinalBudget
    $invocation | Add-Member -NotePropertyName guardPreparationWslResultSha256 -NotePropertyValue $script:AcceptedFinalGuard.preparationWslResultSha256
    $invocation | Add-Member -NotePropertyName guardArtifactAcceptanceSha256 -NotePropertyValue $script:AcceptedFinalGuard.artifactAcceptanceSha256
    $invocation | Add-Member -NotePropertyName resolvedSlots -NotePropertyValue $slots
    $invocation.environment = $environment
    return $invocation
}

function Receive-FinalOriginalClock($Binding, $ControllerWatch) {
    if (-not [Diagnostics.Stopwatch]::IsHighResolution -or -not $ControllerWatch.IsRunning) { throw 'Original monotonic clock unavailable' }
    $action = $Binding.actionPath
    foreach ($name in @('clock-ready.json', 'clock-ready.json.pending', 'clock-remaining.json')) {
        if (Test-Path -LiteralPath "$action\$name") { throw 'Original clock handoff already exists' }
    }
    $self = [Diagnostics.Process]::GetCurrentProcess()
    try { $started = $self.StartTime.ToUniversalTime().ToString('o'); $pidValue = $self.Id }
    finally { $self.Dispose() }
    $readyCounter = [Diagnostics.Stopwatch]::GetTimestamp()
    $frequency = [Diagnostics.Stopwatch]::Frequency
    Save-CompleteJson "$action\clock-ready.json" ([ordered]@{
        schema = 'final-publish-clock-ready-v1'; action = $ActionName
        reservationSha256 = $ReservationSha256; invocationSha256 = $InvocationSha256
        endpoint = $Binding.endpoint; windowsReadyCounter = $readyCounter; windowsClockFrequency = $frequency
        controllerPid = $pidValue; controllerStartUtc = $started
    })
    $readyHash = (Get-FileHash -LiteralPath "$action\clock-ready.json" -Algorithm SHA256).Hash.ToLowerInvariant()
    $end = [Math]::Min(700000L, $ControllerWatch.ElapsedMilliseconds + 20000L)
    $replyBytes = $null
    while ($true) {
        Assert-FinalBudget
        if ($ControllerWatch.ElapsedMilliseconds -ge $end) { throw 'Clock handshake expired' }
        if (Test-Path -LiteralPath "$action\clock-remaining.json") {
            $replyBytes = Read-FinalBytes "$action\clock-remaining.json" 4096
            if ($replyBytes.Length -gt 0 -and $replyBytes[$replyBytes.Length - 1] -eq 10) { break }
        }
        Start-Sleep -Milliseconds 25
    }
    $replyText = [Text.UTF8Encoding]::new($false, $true).GetString($replyBytes)
    $reply = $replyText | ConvertFrom-Json
    $left = $reply.remainingMilliseconds
    if (($left -isnot [int] -and $left -isnot [long]) -or $left -le 0 -or $left -gt 700000) { throw 'Invalid original remaining time' }
    $expected = [ordered]@{ action = $ActionName; endpoint = $Binding.endpoint; invocationSha256 = $InvocationSha256
        readySha256 = $readyHash; remainingMilliseconds = $left; reservationSha256 = $ReservationSha256
        schema = 'final-publish-clock-remaining-v1' }
    if ($replyText -cne (($expected | ConvertTo-Json -Compress) + "`n")) { throw 'Clock reply changed' }
    # QPC is the common Windows counter. Anchor before WSL samples remaining
    # time; subtract one tick for cross-thread ordering uncertainty, never add it.
    $deadline = [decimal]$readyCounter + [Math]::Floor(([decimal]$left * [decimal]$frequency) / 1000) - 1
    if ($deadline -gt [long]::MaxValue) { throw 'Original clock deadline overflow' }
    $script:FinalClock = [pscustomobject]@{ deadlineCounter = [long]$deadline; frequency = $frequency
        readySha256 = $readyHash; replySha256 = (Get-FinalHash $replyBytes) }
    Assert-FinalBudget
}

function Assert-ExactFinalPublishAdmission($Binding) {
    if ($null -eq $script:FinalClock -or $null -eq $script:FinalAuthority) { throw 'Missing original final admission' }
    [void](Assert-FinalCallerAuthorization)
    Assert-FinalBudget
    Assert-FinalProtectedInputs
    Assert-FinalToolContract $script:FinalGraph $script:FinalRecipe $Binding.resolvedSlots
    Assert-FinalToolInventory $script:FinalGraph $Binding.resolvedSlots @() @() $true
    foreach ($template in $script:FinalGraph.generatedPaths) {
        $path = Resolve-FinalText $template $Binding.resolvedSlots
        Assert-FinalOutputAncestor $path
        if (Test-Path -LiteralPath $path) { throw 'Stale generated response or output' }
    }
    foreach ($property in $script:FinalAuthority.components.PSObject.Properties) {
        if ($property.Name -ceq 'controller') { Assert-GuardHash $PSCommandPath $property.Value.sha256 }
    }
    Assert-FinalBudget
}

function Assert-ExactFinalPublishPostconditions($Binding, $Result) {
    [void](Assert-FinalCallerAuthorization)
    Assert-FinalBudget
    if ($script:capture.disposition -cne 'complete' -or $Result.exitCode -ne 0 -or $Result.activeProcessesAtNormalExit -ne 0) {
        throw 'Original root, capture or natural drain is incomplete'
    }
    Assert-FinalProtectedInputs
    $total = $script:capture.stdout.Length + $script:capture.stderr.Length
    if ($total -gt 8388608) { throw 'Combined original diagnostic limit exceeded' }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $outText = $utf8.GetString($script:capture.stdout)
    $errText = $utf8.GetString($script:capture.stderr)
    $diagnostics = $outText + "`n" + $errText
    if ($diagnostics.IndexOf([char]0) -ge 0 -or $diagnostics.Contains([string][char]27)) { throw 'Uninterpretable original diagnostics' }
    $warningPattern = '(?im)(?:^|[\s:])(?:fatal\s+)?warning(?:\s+[A-Z][A-Z0-9]*\d+)?\s*:'
    $errorPattern = '(?im)(?:^|[\s:])(?:fatal\s+)?error(?:\s+[A-Z][A-Z0-9]*\d+)?\s*:'
    $warnings = [regex]::Matches($diagnostics, $warningPattern).Count
    $errors = [regex]::Matches($diagnostics, $errorPattern).Count
    if ($warnings -ne 0 -or $errors -ne 0) { throw 'Original compiler diagnostics include warnings or errors' }
    $observations = @()
    $responseRoot = $Binding.actionPath + '\response-inputs'
    if (Test-Path -LiteralPath $responseRoot) { throw 'Response collection already exists' }
    [void][IO.Directory]::CreateDirectory($responseRoot)
    foreach ($response in $script:FinalGraph.generatedResponses) {
        Assert-FinalBudget
        $slots = @{}
        foreach ($key in $Binding.resolvedSlots.Keys) { $slots.Add($key, $Binding.resolvedSlots[$key]) }
        foreach ($property in $response.substitutions.PSObject.Properties) {
            $slots.Add($property.Name, (Resolve-FinalText $property.Value $Binding.resolvedSlots))
        }
        $path = Resolve-FinalText $response.pathTemplate $slots
        $lines = @($response.lines | ForEach-Object { Resolve-FinalText $_ $slots })
        $text = ($lines -join "`r`n") + "`r`n"
        $expected = $utf8.GetBytes($text)
        if ($response.encoding -ceq 'utf-8-bom') { $expected = [byte[]](@(239, 187, 191) + $expected) }
        elseif ($response.encoding -cne 'utf-8') { throw 'Unknown response encoding' }
        $actual = Read-FinalBytes $path 8388608
        if ($actual.Length -ne $expected.Length -or (Get-FinalHash $actual) -cne (Get-FinalHash $expected)) {
            throw 'Generated consumed response differs from the reviewed exact template'
        }
        Save-Bytes ($responseRoot + '\' + $response.id + '.rsp') $actual
        $observations += [ordered]@{ id = $response.id; path = $path; bytes = $actual.Length; sha256 = (Get-FinalHash $actual)
            producerSha256 = $response.producer.sha256; consumerSha256 = $response.consumer.sha256 }
    }
    Assert-FinalBudget
    $toolObservations = Get-FinalToolObservations $script:FinalGraph $script:FinalRecipe $Binding.resolvedSlots $script:capture.stdout $script:capture.stderr $ReservationSha256 $Binding.graphSha256 $responseRoot
    Assert-FinalBudget
    Save-CompleteJson ($Binding.actionPath + '\postconditions.json') ([ordered]@{
        schema = 'final-publish-postconditions-v2'; reservationSha256 = $ReservationSha256
        graphSha256 = $Binding.graphSha256; protectedInputsUnchanged = $true; generatedResponses = $observations; toolResponses = $toolObservations
        stdoutSha256 = (Get-FinalHash $script:capture.stdout); stderrSha256 = (Get-FinalHash $script:capture.stderr)
        warningCount = $warnings; errorCount = $errors; bothStreamsEof = $true; diagnosticsComplete = $true
    })
    Assert-FinalBudget
    $Result.protectedInputsUnchanged = $true
    $Result.diagnosticsComplete = $true
    $Result.generatedResponsesMatched = $true
    $Result.bothStreamsEof = $true
    $Result.warningCount = 0
    $Result.errorCount = 0
    $Result.postconditionsSha256 = (Get-FileHash -LiteralPath ($Binding.actionPath + '\postconditions.json') -Algorithm SHA256).Hash.ToLowerInvariant()
}


function Save-Json([string] $Path, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Save-CompleteJson([string] $Path, $Value) {
    Save-Json ($Path + '.pending') $Value
    [IO.File]::Move(($Path + '.pending'), $Path)
}

function Save-Bytes([string] $Path, [byte[]] $Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-FinalPublishOutput($Process, $Streams, [int] $Seconds, $Watch, $ControllerWatch) {
    $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
    $tasks = @($Streams[0].ReadAsync($buffers[0], 0, 4096), $Streams[1].ReadAsync($buffers[1], 0, 4096))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $done = @($false, $false)
    $disposition = 'read-failure'
    try {
        while (-not ($Process.HasExited -and $done[0] -and $done[1])) {
            Assert-FinalBudget
            if (Test-Path -LiteralPath "$action\cancel") { $disposition = 'cancelled'; throw 'Caller cancellation' }
            if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { $disposition = 'controller-timeout'; throw 'Controller expired' }
            if ($Watch.Elapsed.TotalSeconds -ge $Seconds) { $disposition = 'timeout'; throw 'Execution timeout' }
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true } else {
                        if ($data[0].Length + $data[1].Length + $count -gt 8388608) {
                            $disposition = 'output-limit'; throw 'Output limit'
                        }
                        $data[$index].Write($buffers[$index], 0, $count)
                        $tasks[$index] = $Streams[$index].ReadAsync($buffers[$index], 0, 4096)
                    }
                }
            }
            Start-Sleep -Milliseconds 25
        }
        $disposition = 'complete'
    } finally {
        # Preserve the bounded prefix through a thrown timeout/cancellation/read failure.
        $script:capture = [pscustomobject]@{
            stdout = $data[0].ToArray(); stderr = $data[1].ToArray()
            seconds = [Math]::Round($Watch.Elapsed.TotalSeconds, 3); disposition = $disposition
        }
        $data[0].Dispose(); $data[1].Dispose()
    }
    return $script:capture
}

# Inserted in the already disabled final-publish controller before its invocation.
# All actual preparation and artifact acceptance identities remain unbound.
# They are outputs of the still-rejecting final admission authority loader, not
# self-referential source hash literals to insert into this same file.
$script:AcceptedFinalGuard = @{
    actionNumber = $null; sourceSha256 = $null; dllSha256 = $null
    guardBuildSha256 = $null; preparationWindowsResultSha256 = $null
    preparationWslResultSha256 = $null; preparationReservationSha256 = $null
    invocationSha256 = $null; compilerReceiptSha256 = $null
    artifactAcceptancePath = $null; artifactAcceptanceSha256 = $null
    expectedAssemblyFullName = $null; acceptedLoaderSourceSha256 = $null
}

function Assert-GuardDirect([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse guard input' }
        if ($item.PSIsContainer) { $item = $item.Parent } else { $item = $item.Directory }
    }
}

function Assert-GuardHash([string] $Path, [string] $Expected) {
    if ($Expected -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound final guard hash' }
    Assert-GuardDirect $Path
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected) {
        throw 'Final guard identity changed'
    }
}

function Import-ExactFinalGuard($Binding, $ControllerWatch) {
    if ($script:FinalPublishDraftOnly) { throw 'DRAFT_ONLY: final guard load is not admitted' }
    foreach ($value in $script:AcceptedFinalGuard.Values) {
        if ($null -eq $value) { throw 'UNBOUND: original preparation and artifact acceptance' }
    }
    if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired before loader' }
    if ($script:AcceptedFinalGuard.actionNumber -cnotmatch '^[0-9]{4}$' -or
        $script:AcceptedFinalGuard.actionNumber -ceq '0000') { throw 'Invalid guard preparation action' }
    $root = 'C:\Temp\azureauth-windows-slice-108\actions\' + $script:AcceptedFinalGuard.actionNumber
    $source = "$root\final-guard\source\WindowsValidationJob.cs"
    $dll = "$root\final-guard\WindowsFinalPublishGuard.dll"
    # Full final admission verifies the original WSL result and its linked original
    # Windows reservation. This loader never treats the WSL proxy's exit as proof.
    if ($Binding.guardPreparationWslResultSha256 -cne $script:AcceptedFinalGuard.preparationWslResultSha256 -or
        $Binding.guardArtifactAcceptanceSha256 -cne $script:AcceptedFinalGuard.artifactAcceptanceSha256) {
        throw 'Final admission does not bind accepted preparation'
    }
    if ($null -eq $script:FinalCallerAuthorization) { throw 'UNBOUND: prospective caller authorization' }
    Assert-GuardHash $PSCommandPath $script:FinalCallerAuthorization.components.controller.sha256
    Assert-GuardHash "$root\started.json" $script:AcceptedFinalGuard.preparationReservationSha256
    Assert-GuardHash "$root\invocation.json" $script:AcceptedFinalGuard.invocationSha256
    Assert-GuardHash "$root\compiler.json" $script:AcceptedFinalGuard.compilerReceiptSha256
    Assert-GuardHash "$root\windows-result.json" $script:AcceptedFinalGuard.preparationWindowsResultSha256
    Assert-GuardHash "$root\guard-build.json" $script:AcceptedFinalGuard.guardBuildSha256
    Assert-GuardHash $script:AcceptedFinalGuard.artifactAcceptancePath $script:AcceptedFinalGuard.artifactAcceptanceSha256
    Assert-GuardHash $source $script:AcceptedFinalGuard.sourceSha256
    Assert-GuardHash $dll $script:AcceptedFinalGuard.dllSha256
    $build = [IO.File]::ReadAllText("$root\guard-build.json") | ConvertFrom-Json
    if ($build.schema -cne 'final-guard-build-v1' -or
        $build.reservationSha256 -cne $script:AcceptedFinalGuard.preparationReservationSha256 -or
        $build.windowsResultSha256 -cne $script:AcceptedFinalGuard.preparationWindowsResultSha256 -or
        $build.invocationSha256 -cne $script:AcceptedFinalGuard.invocationSha256 -or
        $build.sourceSha256 -cne $script:AcceptedFinalGuard.sourceSha256 -or
        $build.dllSha256 -cne $script:AcceptedFinalGuard.dllSha256 -or $build.dllPath -cne $dll) {
        throw 'Compiled guard binding changed'
    }
    Assert-OriginalFinalGuardArtifact
    # Original guard-build stays artifactAccepted=false. A later independent review
    # binds it without rewriting that original compiler/collector evidence.
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        if ($null -ne $assembly.GetType('WindowsValidationJob', $false)) { throw 'A guard type is already loaded' }
    }
    if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired before assembly load' }
    $caller = Assert-FinalCallerAuthorization
    if (($caller | ConvertTo-Json -Depth 40 -Compress) -cne
        ($script:FinalCallerAuthorization | ConvertTo-Json -Depth 40 -Compress)) {
        throw 'Prospective caller authorization changed before load'
    }
    Assert-GuardHash $PSCommandPath $caller.components.controller.sha256
    Assert-FinalBudget
    Add-Type -Path $dll -ErrorAction Stop -WarningAction Stop
    $found = @()
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $type = $assembly.GetType('WindowsValidationJob', $false)
        if ($null -ne $type) { $found += $type }
    }
    if ($found.Count -ne 1) { throw 'Missing or ambiguous loaded guard type' }
    $loaded = $found[0].Assembly
    if (-not [string]::Equals($loaded.Location, $dll, [StringComparison]::OrdinalIgnoreCase) -or
        $loaded.FullName -cne $script:AcceptedFinalGuard.expectedAssemblyFullName) { throw 'Loaded guard identity changed' }
    Assert-GuardHash $dll $script:AcceptedFinalGuard.dllSha256
    if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired after assembly load' }
    return @{ path = $loaded.Location; fullName = $loaded.FullName
              dllSha256 = $script:AcceptedFinalGuard.dllSha256
              guardBuildSha256 = $script:AcceptedFinalGuard.guardBuildSha256 }
}

function Invoke-FinalPublishCandidate($Binding, $ControllerWatch) {
    if ($script:FinalPublishDraftOnly) { throw 'DRAFT_ONLY: no final-publish execution' }
    # The exact admission supplies the v4 recipe and original running clock.
    $action = $Binding.actionPath
    $guard = $null
    $script:capture = $null
    $watch = $null
    $normal = $false
    $result = [ordered]@{
        schema = 'final-publish-windows-result-v1'
        bothStreamsEof = $false; protectedInputsUnchanged = $false; diagnosticsComplete = $false
        generatedResponsesMatched = $false; warningCount = $null; errorCount = $null
        safetyStop = $true; quiescent = $false; normalCompletion = $false
        artifactEligible = $false; continuation_allowed = $false
        exitCode = -1; captureCompleted = $false; captureDisposition = 'not-started'
        jobTerminationRequested = $false; jobTerminationSucceeded = $false
        rootTerminationRequested = $false; rootTerminationSucceeded = $false
        neverResumedRootExitConfirmed = $false; executionMayHaveBegun = $false
        retainedLiveWorkOrUnknown = $true; stage = 'admission'
        reservationSha256 = $Binding.reservationSha256
    }
    try {
        Assert-ExactFinalPublishAdmission $Binding
        $loadedGuard = Import-ExactFinalGuard $Binding $ControllerWatch
        Save-CompleteJson ($Binding.actionPath + '\guard-load.json') $loadedGuard
        Assert-FinalBudget
        # Reserve the complete 600-second action plus the existing ten-second
        # never-resumed-root allowance within the original cross-host clock.
        $leftTicks = $script:FinalClock.deadlineCounter - [Diagnostics.Stopwatch]::GetTimestamp()
        if ([decimal]$leftTicks * 1000 -lt [decimal]610000 * $script:FinalClock.frequency) {
            throw 'Insufficient original time for final publication; no action launch'
        }
        if ($ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Controller expired before guard' }
        if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation before guard' }
        $guard = [WindowsValidationJob]::CreateFinalPublishDraft($ControllerWatch, [long]$script:FinalClock.deadlineCounter)
        $result.stage = 'subject'
        if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation before subject' }
        # This clock starts immediately before root creation and never restarts.
        Assert-FinalBudget
        $leftTicks = $script:FinalClock.deadlineCounter - [Diagnostics.Stopwatch]::GetTimestamp()
        if ([decimal]$leftTicks * 1000 -lt [decimal]610000 * $script:FinalClock.frequency) {
            throw 'Original action allowance expired before root creation'
        }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $guard.StartFinalPublishDraft($Binding.executable, $Binding.nativeArguments, $Binding.workingDirectory, $Binding.environment, $watch)
        Save-Json "$action\subject.json" @{
            pid = $guard.Child.Id; started = $guard.Child.StartTime.ToUniversalTime().ToString('o')
        }
        $script:capture = Read-FinalPublishOutput $guard.Child @($guard.Output.BaseStream, $guard.Error.BaseStream) 600 $watch $ControllerWatch
        $result.exitCode = $guard.Child.ExitCode
        if ($result.exitCode -ne 0) { throw 'Final publish root failed' }
        $result.stage = 'normal-drain'
        $result.normalDrainStartedMilliseconds = $watch.ElapsedMilliseconds
        $drainEnd = [Math]::Min(600000L, $result.normalDrainStartedMilliseconds + 2000L)
        $result.normalDrainDeadlineMilliseconds = $drainEnd
        while (-not $guard.ObserveFinalPublishQuiescence()) {
            Assert-FinalBudget
            if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation during final drain' }
            if ($watch.ElapsedMilliseconds -ge $drainEnd -or $ControllerWatch.ElapsedMilliseconds -ge 700000) {
                throw 'Final publish normal drain expired'
            }
            Start-Sleep -Milliseconds 25
        }
        $result.normalDrainObservedMilliseconds = $watch.ElapsedMilliseconds
        if ($watch.ElapsedMilliseconds -gt ($drainEnd + 100) -or $watch.ElapsedMilliseconds -ge 600000 -or
            $ControllerWatch.ElapsedMilliseconds -ge 700000) { throw 'Final publish observation exceeded original bound' }
        if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancellation at final observation' }
        if ($guard.TerminationRequested -or $guard.NeverResumedRootTerminationRequested) { throw 'Termination cannot establish success' }
        $result.activeProcessesAtNormalExit = $guard.FinalPublishObservedActive
        $result.captureCompleted = $true
        $result.captureDisposition = $script:capture.disposition
        # Validate the complete original capture and fixed protected inputs only
        # after natural Job quiescence; artifact eligibility remains separate.
        Assert-ExactFinalPublishPostconditions $Binding $result
        $normal = $true
        $result.stage = 'normal-observed'
    } catch {
        $result.failureType = $_.Exception.GetType().FullName
        $result.failureLine = $_.InvocationInfo.ScriptLineNumber
        $normal = $false
    } finally {
        try { Assert-FinalBudget } catch { $normal = $false; $result.clockFailureType = $_.Exception.GetType().FullName }
        # Never call Stop, Kill, TerminateJobObject or the old emergency script.
        # The guard itself handles only a proven-never-resumed root during Start.
        if ($null -ne $guard) {
            $result.executionMayHaveBegun = $guard.FinalPublishExecutionMayHaveBegun
            $result.rootTerminationRequested = $guard.NeverResumedRootTerminationRequested
            $result.rootTerminationSucceeded = $guard.NeverResumedRootTerminationSucceeded
            $result.neverResumedRootExitConfirmed = $guard.NeverResumedRootExitConfirmed
            try {
                $result.quiescent = $guard.ObserveFinalPublishQuiescence()
                if ($ControllerWatch.ElapsedMilliseconds -ge 700000 -or
                    ($null -ne $watch -and $watch.ElapsedMilliseconds -ge 600000)) { $normal = $false }
            } catch {
                $result.quiescent = $false
                $result.accountingFailureType = $_.Exception.GetType().FullName
                $normal = $false
            }
            $result.lastJobActive = $guard.FinalPublishObservedActive
            $result.lastJobTotal = $guard.FinalPublishObservedTotal
            try { $guard.Dispose() } catch {
                $normal = $false
                $result.closeFailureType = $_.Exception.GetType().FullName
            }
        }
        # Zero after any earlier failure never erases that failure.
        $result.retainedLiveWorkOrUnknown = -not $result.quiescent
        $result.normalCompletion = $normal -and $result.quiescent -and -not $result.rootTerminationRequested
        $result.safetyStop = -not $result.normalCompletion
        # Eligibility and continuation also need the original outer completion and
        # independent actual-artifact acceptance. This candidate never grants either.
        $result.artifactEligible = $false
        $result.continuation_allowed = $false
        if ($null -ne $watch) { $result.seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3) }
        if ($null -ne $script:capture) {
            $result.captureDisposition = $script:capture.disposition
            $result.stdoutBytes = $script:capture.stdout.Length
            $result.stderrBytes = $script:capture.stderr.Length
            $result.stdoutSha256 = Get-FinalHash $script:capture.stdout
            $result.stderrSha256 = Get-FinalHash $script:capture.stderr
            # Controller-owned bounded byte snapshots only; no subject-file survey
            # or reading mutable compiler outputs while retained work may be live.
            Save-Bytes "$action\stdout.bin" $script:capture.stdout
            Save-Bytes "$action\stderr.bin" $script:capture.stderr
        }
        $result.controllerSeconds = [Math]::Round($ControllerWatch.Elapsed.TotalSeconds, 3)
        $result.ended = (Get-Date).ToUniversalTime().ToString('o')
        Save-CompleteJson "$action\windows-result.json" $result
    }
    return $result
}

# Only this fixed bootstrap route can reach the disabled candidate. The original
# controller watch starts before all JSON/source/admission work and never resets.
try {
    $binding = Initialize-FinalBinding $originalControllerWatch
    Receive-FinalOriginalClock $binding $originalControllerWatch
    $result = Invoke-FinalPublishCandidate $binding $originalControllerWatch
    Assert-FinalBudget
    if ($result.normalCompletion -and $result.quiescent -and -not $result.safetyStop) { exit 0 }
    exit 1
} catch {
    # A pre-admission failure has no subject. The bootstrap still observes this
    # original nonzero exit, and WSL retains the already charged reservation.
    exit 1
}

# INACTIVE source proposal. No runtime, SDK evaluation, or assembly load is admitted.
param([string] $AuthorityPath, [string] $AuthoritySha256,
      [string] $InvocationPath, [string] $InvocationSha256)
$script:ExecutionAdmitted = $false
$script:MaterializationAdmitted = $false
$script:GuardLoadAdmitted = $false
if (-not $script:ExecutionAdmitted) {
    # Original transport only: no admission-dependent path is touched.
    [Console]::Out.WriteLine('{"schema":"compiler-native-inputs-bootstrap-v1","stage":"entry-gate","outcome":"failure","exceptionType":"ExecutionNotAdmitted"}')
    exit 1
}
# The exact authority SHA is supplied by the separately reviewed literal admission.
# The source and authority never embed each other's content hashes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
$script:Leases = [Collections.Generic.List[IDisposable]]::new()
$script:ReadBytes = [long]0
$script:ReadFiles = 0
$script:StartAttempted = $false
$script:AbsenceChecks = 0
$script:AbsenceMetadataProbes = 0
$script:MembershipChecks = 0
$script:MembershipMetadataProbes = 0
$script:MembershipEntries = 0
$script:LastDirectoryCount = 0
$script:PreseededInputs = @{}
$script:MaterializationSha256 = $null
$script:Scans = 0
$script:Capture = $null
$script:ProposalSha256 = $null
$script:ManifestSha256 = $null
$script:SourceBytes = $null
$script:ActiveTargetSha256 = $null
$script:ActiveTargetBytes = $null
$script:BootstrapStage = 'bootstrap-initialization'
$script:BootstrapFailureStage = $null
$script:BootstrapFailureType = $null
$script:DiagnosticRoot = 'C:\Temp\azureauth-windows-slice-108\compiler-native-inputs-5033607-v5'
$script:SourceRoot = $script:DiagnosticRoot + '\source'
$script:CaptureRoot = $script:DiagnosticRoot + '\capture'
$script:Marker = $script:DiagnosticRoot + '\compiler-sequence.claim'
$script:Binlog = $script:DiagnosticRoot + '\compiler-native-inputs.binlog'
$script:ClaimBytes = [Text.Encoding]::ASCII.GetBytes("core-begin`r`ncore-complete`r`nwindows-begin`r`nwindows-complete`r`ncli-begin`r`ncli-complete`r`nnative-inputs-captured`r`n")

# A single bounded original bootstrap frame carries only a closed stage and
# exception-type vocabulary. Never serialize Message, ErrorRecord, stack, paths,
# invocation text, or arbitrary exception properties to this transport.
function Get-SanitizedExceptionType($Exception) {
    $name=$Exception.GetType().FullName
    if ($name -cin @(
        'System.Management.Automation.RuntimeException',
        'System.Management.Automation.MethodInvocationException',
        'System.Management.Automation.PropertyNotFoundException',
        'System.Management.Automation.ParameterBindingException',
        'System.Management.Automation.ItemNotFoundException',
        'System.Management.Automation.CommandNotFoundException',
        'System.Management.Automation.PSArgumentException',
        'System.Management.Automation.PSInvalidOperationException',
        'System.IO.IOException','System.IO.FileNotFoundException',
        'System.IO.DirectoryNotFoundException','System.IO.PathTooLongException',
        'System.IO.EndOfStreamException','System.UnauthorizedAccessException',
        'System.InvalidOperationException','System.ArgumentException',
        'System.ArgumentNullException','System.ArgumentOutOfRangeException',
        'System.NotSupportedException',
        'System.TimeoutException','System.Security.SecurityException',
        'System.OutOfMemoryException','System.FormatException',
        'System.ObjectDisposedException','System.InvalidCastException')) { return $name }
    return 'OtherException'
}
function Remember-BootstrapFailure($Exception) {
    if ($null -eq $script:BootstrapFailureType) {
        $script:BootstrapFailureStage=$script:BootstrapStage
        $script:BootstrapFailureType=Get-SanitizedExceptionType $Exception
    }
}
function Write-BootstrapFrame([int] $ExitCode) {
    $stage=$script:BootstrapFailureStage; $type=$script:BootstrapFailureType
    $outcome='failure'
    if ($ExitCode -eq 0) { $stage='controller-exit'; $type=$null; $outcome='candidate' }
    elseif ($null -eq $type) { $stage=$script:BootstrapStage; $type='IncompleteOriginalObservation' }
    if ($stage -cnotin @('bootstrap-initialization','source-bindings','authority-shape',
        'authority-read','invocation-read','source-admission','clock-handoff',
        'materialization','guard-load','preflight','subject-start',
        'subject-observation','claim-validation','subject-cleanup',
        'receipt-finalization','lease-release','controller-exit')) {
        $stage='bootstrap-initialization'; $type='OtherException'; $outcome='failure'
    }
    $frame=[ordered]@{schema='compiler-native-inputs-bootstrap-v1';stage=$stage
        outcome=$outcome;exceptionType=$type} | ConvertTo-Json -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($frame+"`n") -gt 1024) { throw 'Bootstrap frame bound' }
    [Console]::Out.Write($frame+"`n")
    [Console]::Out.Flush()
}
function Assert-NewSourceBindings {
    foreach ($value in @($script:ProposalSha256,$script:ManifestSha256,
        $script:MaterializationSha256,$script:ActiveTargetSha256)) {
        if ($null -eq $value -or $value -isnot [string] -or $value -cnotmatch '^[0-9a-f]{64}$') {
            throw 'New diagnostic source binding is not admitted'
        }
    }
    if (($script:SourceBytes -isnot [int] -and $script:SourceBytes -isnot [long]) -or
        $script:SourceBytes -le 0 -or
        ($script:ActiveTargetBytes -isnot [int] -and $script:ActiveTargetBytes -isnot [long]) -or
        $script:ActiveTargetBytes -le 0 -or $script:ActiveTargetBytes -gt 65536 -or
        $script:ClaimBytes.Length -ne 109) { throw 'New diagnostic source sizes are not admitted' }
}

# Origin: reviewed final caller Assert-GuardDirect / Assert-GuardHash.
# Adapter retains read leases; selectors run only after the literal entry gate.
function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse input' }
        # Parent and Directory return CLR objects without provider note properties.
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        elseif ($item -is [IO.FileInfo]) { $item = $item.Directory }
        else { throw 'Unsupported filesystem input' }
    }
}
function Get-BytesSha256([byte[]] $Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
function Charge-Read([long] $Bytes) {
    if ($Bytes -lt 0) { throw 'Negative read charge' }
    $script:ReadFiles++; $script:ReadBytes += $Bytes
    if ($script:ReadFiles -gt 256 -or $script:ReadBytes -gt 268435456) { throw 'Input read allowance' }
}
function Read-Bound($Descriptor, [switch] $Bytes) {
    if ($null -eq $Descriptor -or $Descriptor.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Descriptor.bytes -lt 0 -or $Descriptor.bytes -gt 67108864) { throw 'Unbound input' }
    if ($Bytes -and $Descriptor.bytes -gt 16777216) { throw 'Buffered input bound' }
    Charge-Read ([long]$Descriptor.bytes)
    Assert-Direct $Descriptor.path
    $item=Get-Item -LiteralPath $Descriptor.path -Force
    if ($item.PSIsContainer) { throw 'Input is a directory' }
    $stream=[IO.File]::Open($Descriptor.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $script:Leases.Add($stream)
    if ($stream.Length -ne $Descriptor.bytes) { throw 'Input length changed' }
    $hash=[Security.Cryptography.SHA256]::Create()
    try {
        if ($Bytes) {
            # One bounded read pass; hashing the captured array performs no file I/O.
            $data=[byte[]]::new([int]$Descriptor.bytes); $offset=0
            while ($offset -lt $data.Length) {
                $n=$stream.Read($data,$offset,$data.Length-$offset)
                if ($n -le 0) { throw 'Short input' }
                $offset += $n
            }
            $actual=[BitConverter]::ToString($hash.ComputeHash($data)).Replace('-','').ToLowerInvariant()
        } else {
            $actual=[BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()
        }
    } finally { $hash.Dispose() }
    if ($actual -cne $Descriptor.sha256) { throw 'Input hash changed' }
    if ($Bytes) { return ,$data }
}
function Read-SmallFile([string] $Path, [int] $Limit) {
    if ($Limit -lt 0 -or $Limit -gt 1048576) { throw 'Small-read limit' }
    # Charge the complete possible read, including the one-byte overflow probe.
    Charge-Read ([long]$Limit+1)
    Assert-Direct $Path
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) { throw 'Small input is a directory' }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $data=[byte[]]::new($Limit+1); $offset=0; $eof=$false
        while ($offset -lt $data.Length) {
            $n=$stream.Read($data,$offset,$data.Length-$offset)
            if ($n -eq 0) { $eof=$true; break }
            $offset += $n
        }
        $result=[byte[]]::new($offset); [Array]::Copy($data,$result,$offset)
        return @{ bytes=$result; eof=$eof }
    } finally { $stream.Dispose() }
}

# Origin: reviewed final caller exclusive, durable receipt helpers.
function Save-Bytes([string] $Path, [byte[]] $Bytes) {
    Assert-Direct ([IO.Path]::GetDirectoryName($Path))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}
function Save-CompleteJson([string] $Path, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 30 -Compress))
    if ($bytes.Length -gt 1048576) { throw 'Receipt bound' }
    Save-Bytes ($Path + '.pending') $bytes
    [IO.File]::Move(($Path + '.pending'), $Path)
}
function In-Root([string] $Path, [string] $Root) {
    return $Path.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Assert-OwnedPath([string] $Path, $Binding) {
    if ([IO.Path]::GetFullPath($Path) -cne $Path -or
        -not ((In-Root $Path $Binding.actionPath) -or (In-Root $Path $script:DiagnosticRoot) -or
              $Path -ceq $script:DiagnosticRoot)) { throw 'Outside declared new roots' }
}
function Quote-WindowsArgument([string] $Value) {
    if ($Value.IndexOf([char]0) -ge 0 -or $Value.Contains("`r") -or $Value.Contains("`n")) { throw 'Argument control character' }
    $s = [Text.StringBuilder]::new(); [void]$s.Append('"'); $slashes = 0
    foreach ($c in $Value.ToCharArray()) {
        if ($c -eq '\') { $slashes++; continue }
        if ($c -eq '"') { [void]$s.Append(('\' * (2 * $slashes + 1))) }
        else { [void]$s.Append(('\' * $slashes)) }
        [void]$s.Append($c); $slashes = 0
    }
    [void]$s.Append(('\' * (2 * $slashes))); [void]$s.Append('"')
    return $s.ToString()
}
function Resolve-Template([string] $Value, $Binding) {
    $v = $Value.Replace('${ACTION_ROOT}', $Binding.actionPath).Replace('${PACKAGE_ROOT}', $Binding.packageRoot).Replace('${ENDPOINT}', $Binding.endpoint)
    if ($v.Contains('${')) { throw 'Unresolved template' }
    return $v
}
function Assert-ExactCompilerNativeInputsAdmission($Authority, $Binding) {
    if (-not $script:ExecutionAdmitted -or $AuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Binding.authoritySha256 -cne $AuthoritySha256) { throw 'Unaccepted literal authority binding' }
    foreach ($name in @('wave','protocol','callerReview','runtimeReview','loaderReview','physicalPreflightReview',
                        'materializationReview','helperEffectsReview','activeTargetReview','historyReview','executionReview')) {
        if ($null -eq $Authority.reviews.$name) { throw ('Missing review: ' + $name) }
        Read-Bound $Authority.reviews.$name
    }
    if ($Binding.actionNumber -cne '0061' -or
        $Binding.actionPath -cne ('C:\Temp\azureauth-windows-slice-108\actions\' + $Binding.actionNumber) -or
        $Binding.actionKind -cne 'compiler-native-inputs' -or $Binding.originalOuterLimitMilliseconds -ne 900000 -or
        $Binding.clockHandshakeLimitMilliseconds -ne 20000 -or $Binding.clockNonce -cnotmatch '^[0-9a-f]{64}$' -or
        $Binding.reservationSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Observer reservation shape' }
    Read-Bound $Authority.controller
    if ($Authority.controller.path -cne $PSCommandPath) { throw 'Controller source selector changed' }
    # Dynamic started bytes are derived from the canonical action directory,
    # never embedded into the separately accepted static authority.
    $startedRead=Read-SmallFile ($Binding.actionPath+'\started.json') 1048576
    if (-not $startedRead.eof -or (Get-BytesSha256 $startedRead.bytes) -cne $Binding.reservationSha256) { throw 'Reservation bytes' }
    $started=[Text.UTF8Encoding]::new($false,$true).GetString($startedRead.bytes) | ConvertFrom-Json
    if ($started.clockNonce -cne $Binding.clockNonce -or
        $started.originalClockStartNanoseconds -ne $Binding.originalClockStartNanoseconds -or
        $started.originalClockDeadlineNanoseconds -ne $Binding.originalClockDeadlineNanoseconds -or
        [decimal]$started.originalClockDeadlineNanoseconds-[decimal]$started.originalClockStartNanoseconds -ne 900000000000) { throw 'Dynamic reservation clock join' }
    if ($Authority.proposal.sha256 -cne $script:ProposalSha256 -or $Authority.sourceManifest.sha256 -cne $script:ManifestSha256) { throw 'Proposal identity' }
    $proposal = [Text.Encoding]::UTF8.GetString((Read-Bound $Authority.proposal -Bytes)) | ConvertFrom-Json
    $manifest = [Text.Encoding]::UTF8.GetString((Read-Bound $Authority.sourceManifest -Bytes)) | ConvertFrom-Json
    if ($manifest.files.Count -ne 34 -or $manifest.diagnosticRoot -cne $script:SourceRoot) { throw 'Source manifest' }
    if ($Binding.workingDirectory -cne $script:SourceRoot -or $Binding.executable -cne 'C:\Program Files\dotnet\dotnet.exe') { throw 'Root command' }
    $args = @($proposal.argumentVectorTemplate | ForEach-Object { Resolve-Template $_ $Binding })
    $native = (@($args | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    if ($native -cne $Binding.nativeArguments) { throw 'Native argument encoding' }
    $env = @{}
    foreach ($p in $proposal.replacementEnvironmentTemplate.PSObject.Properties) { $env.Add($p.Name, (Resolve-Template $p.Value $Binding)) }
    if ($env.Count -ne 35 -or @($Binding.environment.PSObject.Properties).Count -ne 35) { throw 'Environment count' }
    foreach ($key in $env.Keys) { if ($Binding.environment.$key -cne $env[$key]) { throw 'Replacement environment changed' } }
    if ($null -eq $Authority.materialization -or $null -eq $Authority.activeTarget -or
        $Authority.activeTarget.sha256 -cne $script:ActiveTargetSha256 -or $Authority.activeTarget.bytes -ne $script:ActiveTargetBytes -or
        $null -eq $Authority.physicalInputs -or $null -eq $Authority.guard -or
        $Authority.physicalInputs.Count -gt 128) { throw 'Unbound physical/materialization/guard inputs' }
    foreach ($input in $Authority.physicalInputs) { Read-Bound $input }
    if ($Authority.materialization.sha256 -cne $script:MaterializationSha256) { throw 'Materialization proposal identity' }
    $plan=[Text.Encoding]::UTF8.GetString((Read-Bound $Authority.materialization -Bytes)) | ConvertFrom-Json
    if ($plan.sourceFileCount -ne 34 -or $plan.sourceBytes -ne $script:SourceBytes -or $plan.restoreFileCount -ne 12 -or
        $plan.restoreBytes -ne 233709 -or $Binding.packageRoot -cne $plan.packageRoot) { throw 'Materialization totals/root' }
    return @{ proposal=$proposal; manifest=$manifest; environment=$env; materialization=$plan }
}
# Origin: 0055 preparation clock. Same ready-time anchor and floor conversion.
function Get-RemainingMilliseconds($OuterWatch, $Clock) {
    if ($null -eq $Clock -or -not $OuterWatch.IsRunning) { return [long]0 }
    $now = $OuterWatch.ElapsedTicks
    if ($now -lt $Clock.windowsReadyElapsedTicks) { throw 'Windows clock moved backward' }
    $ticks = [decimal]$Clock.windowsDeadlineElapsedTicks - [decimal]$now
    if ($ticks -le 0) { return [long]0 }
    return [long][Math]::Floor(($ticks * [decimal]1000) / [decimal]$Clock.windowsClockFrequency)
}
function Assert-Remaining($OuterWatch, $Clock, [string] $Cancel, [long] $Reserve = 0) {
    if ((Get-RemainingMilliseconds $OuterWatch $Clock) -le $Reserve) { throw 'Original observer allowance expired' }
    if (Test-Path -LiteralPath $Cancel) { throw 'Observer cancelled' }
}
function Assert-ExactOriginalClockHandoff($Binding, $OuterWatch) {
    if (-not [Diagnostics.Stopwatch]::IsHighResolution -or -not $OuterWatch.IsRunning) { throw 'Monotonic clock unavailable' }
    $action = $Binding.actionPath; $cancel = $action + '\cancel'
    $frequency = [Diagnostics.Stopwatch]::Frequency
    if ($frequency -le 0) { throw 'Invalid clock frequency' }
    foreach ($name in @('clock-ready.json','clock-ready.json.pending','clock-remaining.json')) {
        if (Test-Path -LiteralPath "$action\$name") { throw 'Clock handoff already exists' }
    }
    if ($OuterWatch.ElapsedMilliseconds -ge 20000 -or (Test-Path -LiteralPath $cancel)) { throw 'Late ready' }
    $readyTicks = $OuterWatch.ElapsedTicks
    # Same clock record shape; action identity binds this use to the observer.
    $ready = [ordered]@{ schema = 'final-guard-clock-ready-v1'; action = $Binding.actionNumber
        nonce = $Binding.clockNonce; reservationSha256 = $Binding.reservationSha256
        invocationSha256 = $InvocationSha256; originalOuterLimitMilliseconds = 900000
        windowsReadyElapsedTicks = $readyTicks; windowsClockFrequency = $frequency }
    Save-CompleteJson "$action\clock-ready.json" $ready
    $readyRead=Read-SmallFile "$action\clock-ready.json" 2048
    if (-not $readyRead.eof) { throw 'Ready size' }
    $readyHash=Get-BytesSha256 $readyRead.bytes
    $replyBytes = $null
    while ($true) {
        if ($OuterWatch.ElapsedMilliseconds -ge 20000 -or (Test-Path -LiteralPath $cancel)) { throw 'Clock handshake expired' }
        if (Test-Path -LiteralPath "$action\clock-remaining.json") {
            Assert-Direct "$action\clock-remaining.json"
            $file = Get-Item -LiteralPath "$action\clock-remaining.json" -Force
            if ($file.PSIsContainer -or $file.Length -gt 2048) { throw 'Clock frame bound' }
            $replyRead=Read-SmallFile $file.FullName 2048
            $replyBytes=$replyRead.bytes
            if ($replyBytes.Length -gt 2048) { throw 'Clock frame growth' }
            if ($replyBytes.Length -gt 0 -and $replyBytes[$replyBytes.Length - 1] -eq 10) { break }
        }
        Start-Sleep -Milliseconds 25
    }
    $replyText = [Text.UTF8Encoding]::new($false,$true).GetString($replyBytes)
    $reply = $replyText | ConvertFrom-Json; $left = $reply.remainingMilliseconds
    if (($left -isnot [long] -and $left -isnot [int]) -or $left -le 0 -or $left -gt 900000) { throw 'Remaining allowance' }
    $expected = [ordered]@{ action = $Binding.actionNumber; invocationSha256 = $InvocationSha256
        nonce = $Binding.clockNonce; originalOuterLimitMilliseconds = 900000; readySha256 = $readyHash
        remainingMilliseconds = $left; reservationSha256 = $Binding.reservationSha256; schema = 'final-guard-clock-remaining-v1' }
    if ($replyText -cne (($expected | ConvertTo-Json -Compress) + "`n")) { throw 'Clock frame identity' }
    $deadlineTicks = [decimal]$readyTicks + [Math]::Floor(([decimal]$left * [decimal]$frequency) / [decimal]1000)
    if ($deadlineTicks -gt [long]::MaxValue) { throw 'Clock overflow' }
    $clock = [pscustomobject]@{ windowsReadyElapsedTicks = $readyTicks; windowsClockFrequency = $frequency
        windowsDeadlineElapsedTicks = [long]$deadlineTicks; readySha256 = $readyHash
        replySha256 = (Get-BytesSha256 $replyBytes); remainingMilliseconds = $left }
    Assert-Remaining $OuterWatch $clock $cancel
    return $clock
}
function Assert-EmptyServicing($Binding, $Environment) {
    $path=$Binding.actionPath+'\empty-program-files'
    if ($Environment['PROGRAMFILES'] -cne $path -or $Environment['PROGRAMFILES(X86)'] -cne $path) { throw 'Servicing environment' }
    Assert-Direct $path
    if (-not (Get-Item -LiteralPath $path -Force).PSIsContainer) { throw 'Servicing parent is not a directory' }
    $enumerator=[IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator()
    try { if ($enumerator.MoveNext()) { throw 'Owned servicing directory is not empty' } }
    finally { $enumerator.Dispose() }
    if (Test-Path -LiteralPath ($path+'\coreservicing')) { throw 'Unexpected servicing child' }
}
function Get-ActiveTargetDescriptor($Authority, $Binding) {
    if ($null -eq $Authority.activeTarget) { throw 'Unbound active target' }
    return [pscustomobject]@{path=(Resolve-Template $Authority.activeTarget.path $Binding);bytes=$Authority.activeTarget.bytes;sha256=$Authority.activeTarget.sha256}
}
function Assert-EmptyUserExtensions($Binding) {
    $path=$Binding.actionPath+'\home\msbuild-user'
    Assert-Direct $path
    if (-not (Get-Item -LiteralPath $path -Force).PSIsContainer) { throw 'User extensions root is not a directory' }
    $enumerator=[IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator()
    try { if ($enumerator.MoveNext()) { throw 'Owned user extensions directory is not empty' } }
    finally { $enumerator.Dispose() }
}
function Assert-CompilerNativeInputsAbsences($Authority, $Binding, $Watch, $Clock) {
    # The exact independently admitted authority supplies fixed literal leaves.
    # Never enumerate an ancestor or follow a path discovered in file contents.
    $script:AbsenceChecks++
    if ($script:AbsenceChecks -gt 2 -or $null -eq $Authority.physicalAbsences -or
        $Authority.physicalAbsences.Count -lt 1 -or $Authority.physicalAbsences.Count -gt 256) { throw 'Absence checkpoint bound' }
    $seen=@{}
    foreach ($template in $Authority.physicalAbsences) {
        $path=Resolve-Template $template $Binding
        if ($path.Length -gt 1024 -or $path -cnotmatch '^C:\\' -or
            $path -cne [IO.Path]::GetFullPath($path) -or $seen.ContainsKey($path)) { throw 'Noncanonical or duplicate absence selector' }
        $seen.Add($path,$true)
        $parts=$path.Substring(3).Split([char]'\')
        if ($parts.Count -lt 1 -or $parts.Count -gt 17) { throw 'Absence path depth bound' }
        foreach ($part in $parts) {
            if ($part.Length -eq 0 -or $part -in @('.','..') -or $part.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw 'Invalid absence component' }
        }
        $prefix='C:\'; $missing=$false
        for ($index=-1;$index -lt $parts.Count;$index++) {
            Assert-Remaining $Watch $Clock ($Binding.actionPath+'\cancel') 20000
            if ($index -ge 0) { $prefix=[IO.Path]::Combine($prefix,$parts[$index]) }
            $script:AbsenceMetadataProbes++
            if ($script:AbsenceMetadataProbes -gt 9216) { throw 'Absence metadata allowance' }
            try { $attributes=[IO.File]::GetAttributes($prefix) }
            catch [IO.FileNotFoundException] { if ($index -lt 0) { throw }; $missing=$true; break }
            catch [IO.DirectoryNotFoundException] { if ($index -lt 0) { throw }; $missing=$true; break }
            if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse absence ancestor or leaf' }
            if ($index -eq $parts.Count-1) { throw 'Required absent input is present' }
            if (-not ($attributes -band [IO.FileAttributes]::Directory)) { throw 'Nondirectory absence ancestor' }
        }
        if (-not $missing) { throw 'Absence was not established' }
    }
}
function Assert-CompilerNativeInputsMembership($Authority, $Binding, $Watch, $Clock) {
    # Inspect only the independently admitted top-level wildcard domains. Names
    # found here never select another directory or an unbound content read.
    $script:MembershipChecks++
    if ($script:MembershipChecks -gt 2 -or $null -eq $Authority.physicalMembership -or
        $Authority.physicalMembership.Count -lt 1 -or $Authority.physicalMembership.Count -gt 32) { throw 'Membership checkpoint bound' }
    $seen=@{}; $checkpointEntries=0; $hostfxrDomains=0
    $fixedHostfxrPath='C:\Program Files\dotnet\host\fxr'
    foreach ($domain in $Authority.physicalMembership) {
        $path=Resolve-Template $domain.path $Binding
        if ($path.Length -gt 1024 -or $path -cnotmatch '^C:\\' -or
            $path -cne [IO.Path]::GetFullPath($path)) { throw 'Noncanonical membership selector' }
        if ($domain.pattern -cnotmatch '^(\*|Microsoft\.VisualStudioVersion\.v\*\.Common\.props|Authentication\.(Cli|Core|Windows)\.csproj\.\*\.(props|targets))$' -or
            $null -eq $domain.members -or $domain.members.Count -gt 32) { throw 'Unbound membership pattern or members' }
        $isHostfxrDomain=$path -ieq $fixedHostfxrPath
        if ($isHostfxrDomain) {
            $hostfxrDomains++
            if ($hostfxrDomains -ne 1 -or $path -cne $fixedHostfxrPath -or
                $domain.pattern -cne '*' -or $domain.members.Count -ne 3) { throw 'Unbound fixed hostfxr membership domain' }
        }
        $key=$path+'|'+$domain.pattern
        if ($seen.ContainsKey($key)) { throw 'Duplicate membership domain' }
        $seen.Add($key,$true)
        $expected=@{}
        foreach ($member in $domain.members) {
            if ($member -isnot [string] -or $member.Length -eq 0 -or $member -in @('.','..') -or
                $member.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
                $member -inotlike $domain.pattern -or $expected.ContainsKey($member)) { throw 'Invalid expected member' }
            if ($isHostfxrDomain -and $member -cnotin @('10.0.12','6.0.36','8.0.31')) { throw 'Unexpected fixed hostfxr version name' }
            $expected.Add($member,$true)
            # Only this fixed domain contains directory names rather than leased files.
            if (-not $isHostfxrDomain) {
                $memberPath=[IO.Path]::Combine($path,$member)
                if (-not $script:PreseededInputs.ContainsKey($memberPath) -and
                    @($Authority.physicalInputs | Where-Object { $_.path -ieq $memberPath }).Count -ne 1) { throw 'Member has no leased input identity' }
            }
        }
        $parts=$path.Substring(3).Split([char]'\')
        if ($parts.Count -lt 1 -or $parts.Count -gt 17) { throw 'Membership path depth bound' }
        foreach ($part in $parts) {
            if ($part.Length -eq 0 -or $part -in @('.','..') -or $part.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw 'Invalid membership component' }
        }
        $prefix='C:\'; $missing=$false
        for ($index=-1;$index -lt $parts.Count;$index++) {
            Assert-Remaining $Watch $Clock ($Binding.actionPath+'\cancel') 20000
            if ($index -ge 0) { $prefix=[IO.Path]::Combine($prefix,$parts[$index]) }
            $script:MembershipMetadataProbes++
            if ($script:MembershipMetadataProbes -gt 2176) { throw 'Membership metadata allowance' }
            try { $attributes=[IO.File]::GetAttributes($prefix) }
            catch [IO.FileNotFoundException] { if ($index -lt 0) { throw }; $missing=$true; break }
            catch [IO.DirectoryNotFoundException] { if ($index -lt 0) { throw }; $missing=$true; break }
            if ($attributes -band [IO.FileAttributes]::ReparsePoint -or
                -not ($attributes -band [IO.FileAttributes]::Directory)) { throw 'Membership ancestor is not an ordinary directory' }
        }
        if ($missing) {
            if ($expected.Count -ne 0) { throw 'Expected membership directory is missing' }
            continue
        }
        $actual=@{}
        $enumerator=[IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator()
        try {
            while ($true) {
                Assert-Remaining $Watch $Clock ($Binding.actionPath+'\cancel') 20000
                if (-not $enumerator.MoveNext()) { break }
                $checkpointEntries++; $script:MembershipEntries++
                # One overflow entry is observed solely to reject it.
                if ($checkpointEntries -gt 512 -or $script:MembershipEntries -gt 1024) { throw 'Membership entry allowance' }
                $leaf=[IO.Path]::GetFileName($enumerator.Current)
                if ($leaf -inotlike $domain.pattern) { continue }
                if (-not $expected.ContainsKey($leaf) -or $actual.ContainsKey($leaf)) { throw 'Unexpected or duplicate wildcard member' }
                Assert-Remaining $Watch $Clock ($Binding.actionPath+'\cancel') 20000
                $script:MembershipMetadataProbes++
                if ($script:MembershipMetadataProbes -gt 2176) { throw 'Membership metadata allowance' }
                $attributes=[IO.File]::GetAttributes($enumerator.Current)
                if ($isHostfxrDomain) {
                    if ($attributes -band [IO.FileAttributes]::ReparsePoint -or
                        -not ($attributes -band [IO.FileAttributes]::Directory)) { throw 'Hostfxr member is not an ordinary directory' }
                } elseif ($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) { throw 'Wildcard member is not an ordinary file' }
                $actual.Add($leaf,$true)
            }
        } finally { $enumerator.Dispose() }
        if ($actual.Count -ne $expected.Count) { throw 'Expected wildcard member is missing' }
    }
    if ($hostfxrDomains -ne 1) { throw 'Required fixed hostfxr membership domain is missing' }
}
function Assert-EmptyDiagnosticCapture {
    Assert-Direct $script:CaptureRoot
    if (-not (Get-Item -LiteralPath $script:CaptureRoot -Force).PSIsContainer) { throw 'Capture root is not a directory' }
    $enumerator=[IO.Directory]::EnumerateFileSystemEntries($script:CaptureRoot).GetEnumerator()
    try { if ($enumerator.MoveNext()) { throw 'Diagnostic capture root is not empty' } }
    finally { $enumerator.Dispose() }
}
function New-CompilerNativeInputsMaterialization($Authority, $Binding, $Inputs, $Watch, $Clock) {
    if (-not $script:MaterializationAdmitted) { throw 'INACTIVE: materialization' }
    $plan=$Inputs.materialization; $manifest=$Inputs.manifest
    if ($plan.sourcePayloads.Count -ne 34 -or $plan.restorePayloads.Count -ne 12) { throw 'Exact materialization counts' }
    # The WSL dispatcher exclusively stages compiler-inputs-payloads and compiler-inputs-support.
    # Every other new directory is created here, in the fixed proposal order.
    $staging=$Binding.actionPath+'\compiler-inputs-payloads'; Assert-Direct $staging
    if (-not (Get-Item -LiteralPath $staging).PSIsContainer) { throw 'Staging directory' }
    $directories=@($plan.actionDirectoriesData)+@($plan.newDirectoriesData)
    foreach ($template in $directories) {
        $path=Resolve-Template $template $Binding
        if ($path -ceq $staging) { continue }
        Assert-Remaining $Watch $Clock ($Binding.actionPath+'\cancel') 20000
        Assert-OwnedPath $path $Binding; Assert-Direct ([IO.Path]::GetDirectoryName($path))
        if (Test-Path -LiteralPath $path) { throw 'New directory already exists' }
        [void](New-Item -ItemType Directory -Path $path -ErrorAction Stop)
    }
    Assert-EmptyDiagnosticCapture
    $seen=@{}; $sourceTotal=[long]0; $restoreTotal=[long]0
    foreach ($entry in $plan.sourcePayloads) {
        $matches=@($manifest.files | Where-Object { $_.gitPath -ceq $entry.gitPath })
        if ($matches.Count -ne 1 -or $seen.ContainsKey($entry.gitPath)) { throw 'Source mapping' }
        $expected=$matches[0]; $seen.Add($entry.gitPath,$true)
        if ($entry.diagnosticPath -cne $expected.diagnosticPath -or $entry.bytes -ne $expected.diagnosticBytes -or
            $entry.sha256 -cne $expected.diagnosticSha256) { throw 'Source proposal join' }
        Assert-Remaining $Watch $Clock ($Binding.actionPath+'\cancel') 20000
        $payload=[pscustomobject]@{path=(Resolve-Template $entry.stagedPayloadPathTemplate $Binding);bytes=$entry.bytes;sha256=$entry.sha256}
        $bytes=Read-Bound $payload -Bytes; $sourceTotal+=$bytes.Length
        Save-Bytes $entry.diagnosticPath $bytes
        Read-Bound ([pscustomobject]@{path=$entry.diagnosticPath;bytes=$entry.bytes;sha256=$entry.sha256})
        $script:PreseededInputs.Add($entry.diagnosticPath,$true)
    }
    foreach ($entry in $plan.restorePayloads) {
        Assert-Remaining $Watch $Clock ($Binding.actionPath+'\cancel') 20000
        $payload=[pscustomobject]@{path=(Resolve-Template $entry.stagedPayloadPathTemplate $Binding);bytes=$entry.bytes;sha256=$entry.sha256}
        $bytes=Read-Bound $payload -Bytes; $restoreTotal+=$bytes.Length
        Save-Bytes $entry.diagnosticPath $bytes
        Read-Bound ([pscustomobject]@{path=$entry.diagnosticPath;bytes=$entry.bytes;sha256=$entry.sha256})
        $script:PreseededInputs.Add($entry.diagnosticPath,$true)
    }
    if ($sourceTotal -ne $script:SourceBytes -or $restoreTotal -ne 233709) { throw 'Materialized byte totals' }
    $target=Get-ActiveTargetDescriptor $Authority $Binding
    Save-Bytes $plan.activeCompilerNativeInputsTargetDestination (Read-Bound $target -Bytes)
    Read-Bound ([pscustomobject]@{path=$plan.activeCompilerNativeInputsTargetDestination;bytes=$target.bytes;sha256=$target.sha256})
    $script:PreseededInputs.Add($plan.activeCompilerNativeInputsTargetDestination,$true)
    foreach ($marker in $plan.markers) {
        if ($marker.initialBytes -ne 0 -or -not $marker.retained) { throw 'Marker contract' }
        Save-Bytes (Resolve-Template $marker.path $Binding) ([byte[]]::new(0))
    }
    if ((Get-Item -LiteralPath $script:Marker).Length -ne 0) { throw 'Initial claim changed' }
    $sentinel=$Binding.actionPath+'\home\.dotnet\10.0.401.dotnetFirstUseSentinel'
    if ((Get-Item -LiteralPath $sentinel).Length -ne 0) { throw 'Initial sentinel changed' }
    Assert-EmptyServicing $Binding $Inputs.environment
}

# Origin: reviewed Import-ExactFinalGuard. No final factory/start call is copied.
function Import-ExactCompilerNativeInputsGuard($Authority, $Binding, $Watch, $Clock) {
    if (-not $script:GuardLoadAdmitted) { throw 'INACTIVE: guard load' }
    $g = $Authority.guard
    if ($g.dll.sha256 -cne 'f67ea23171e4ceeae50a201c8300dbd3113555c83fb7d4e1f5c93ce9c242d375' -or
        $g.dll.bytes -ne 16384 -or $g.source.sha256 -cne 'd38846b080d5ee092fae9e21c9031712b56289093b50ca048d50589cca50ff4b' -or
        $g.expectedAssemblyFullName -cne 'WindowsFinalPublishGuard, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null') { throw 'Guard identity' }
    foreach ($name in @('dll','source','started','invocation','compiler','windowsResult','wslResult','guardBuild','artifactAcceptance','completionAcceptance')) { Read-Bound $g.$name }
    $build = [Text.Encoding]::UTF8.GetString((Read-Bound $g.guardBuild -Bytes)) | ConvertFrom-Json
    if ($build.schema -cne 'final-guard-build-v1' -or $build.reservationSha256 -cne $g.started.sha256 -or
        $build.windowsResultSha256 -cne $g.windowsResult.sha256 -or $build.invocationSha256 -cne $g.invocation.sha256 -or
        $build.sourceSha256 -cne $g.source.sha256 -or $build.dllSha256 -cne $g.dll.sha256 -or $build.dllPath -cne $g.dll.path) { throw 'Guard compilation binding' }
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        if ($null -ne $assembly.GetType('WindowsValidationJob',$false)) { throw 'Guard type already loaded' }
    }
    Assert-Remaining $Watch $Clock ($Binding.actionPath + '\cancel') 20000
    Add-Type -Path $g.dll.path -ErrorAction Stop -WarningAction Stop
    $found = @()
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $type = $assembly.GetType('WindowsValidationJob',$false)
        if ($null -ne $type) { $found += $type }
    }
    if ($found.Count -ne 1) { throw 'Ambiguous loaded guard' }
    $loaded = $found[0].Assembly
    if (-not [string]::Equals($loaded.Location,$g.dll.path,[StringComparison]::OrdinalIgnoreCase) -or
        $loaded.FullName -cne $g.expectedAssemblyFullName) { throw 'Loaded guard changed' }
    Read-Bound $g.dll
    Assert-Remaining $Watch $Clock ($Binding.actionPath + '\cancel') 20000
    return @{ path=$loaded.Location; fullName=$loaded.FullName; dllSha256=$g.dll.sha256; guardBuildSha256=$g.guardBuild.sha256 }
}
# Metadata monitoring is bounded and detects thresholds. It is not a write sandbox,
# an instantaneous quota, or a count of transient files between samples.
function Get-CompilerNativeInputsFileSample($Binding, $Watch, $Clock) {
    $script:Scans++; if ($script:Scans -gt 3600) { throw 'Metadata sample count' }
    $stack = [Collections.Generic.Stack[string]]::new()
    $stack.Push($Binding.actionPath); $stack.Push($script:DiagnosticRoot)
    # Both scan roots are newly owned directories and count toward the limit.
    # Keep progress outside the returned sample so a rejecting sample retains 129.
    $script:LastDirectoryCount = 2
    $items = [Collections.Generic.List[object]]::new(); $bytes=[long]0; $entries=0
    $textBytes=[long]0; $textFiles=0; $logBytes=[long]0
    while ($stack.Count -gt 0) {
        Assert-Remaining $Watch $Clock ($Binding.actionPath + '\cancel') 5000
        $directory=$stack.Pop(); Assert-Direct $directory
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $entries++; if ($entries -gt 512) { throw 'Metadata entry bound' }
            $item=Get-Item -LiteralPath $path -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse output' }
            if ($item.PSIsContainer) {
                $script:LastDirectoryCount++
                if ($script:LastDirectoryCount -gt 128) { throw 'New-directory stop threshold' }
                $stack.Push($path); continue
            }
            $bytes += $item.Length
            $items.Add([pscustomobject]@{path=$path;bytes=$item.Length})
            if ($items.Count -gt 512 -or $bytes -gt 268435456) { throw 'New-file stop threshold' }
            if ($path -ceq $script:Binlog) { $logBytes=$item.Length; if ($logBytes -gt 67108864) { throw 'Binlog stop threshold' } }
            # The 60 named .items companions share the same 96-file/32-MiB text
            # allowance with newly generated managed sources/configuration. The
            # binlog and preserved original RSPs stay separate. Exact membership,
            # item boundaries, and bytes still require independent acceptance.
            if (-not $script:PreseededInputs.ContainsKey($path) -and
                (($path -match '\\obj\\' -and $path -match '\.(cs|editorconfig|json|txt)$') -or
                 ((In-Root $path $script:CaptureRoot) -and $path -match '\.items$'))) {
                $textFiles++; $textBytes += $item.Length
                if ($textFiles -gt 96 -or $item.Length -gt 1048576 -or $textBytes -gt 33554432) { throw 'Intermediate text acceptance bound' }
            }
        }
    }
    return @{ files=@($items.ToArray()); bytes=$bytes; binlogBytes=$logBytes; textFiles=$textFiles; textBytes=$textBytes; scans=$script:Scans; directoryCount=$script:LastDirectoryCount }
}
# Origin: Read-FinalPublishOutput. Read only BaseStream, never StreamReader text.
function Start-Capture($Guard) {
    $streams=@($Guard.Output.BaseStream,$Guard.Error.BaseStream)
    $buffers=@([byte[]]::new(4096),[byte[]]::new(4096))
    return @{ streams=$streams; buffers=$buffers
        tasks=@($streams[0].ReadAsync($buffers[0],0,4096),$streams[1].ReadAsync($buffers[1],0,4096))
        pending=@($true,$true); data=@([IO.MemoryStream]::new(),[IO.MemoryStream]::new()); done=@($false,$false)
        truncated=$false; readFailure=$false; afterStopProcessedBytes=0
        afterStopOverflowObservedBytes=0; afterStopRejected=$false }
}
function Pump-Capture($Capture, [switch] $AfterStop) {
    if ($Capture.afterStopRejected) { throw 'Emergency drain already rejected; no new read' }
    for ($i=0;$i -lt 2;$i++) {
        if (-not $Capture.done[$i] -and $null -ne $Capture.tasks[$i] -and $Capture.tasks[$i].IsCompleted) {
            try { $n=$Capture.tasks[$i].GetAwaiter().GetResult() }
            catch { $Capture.readFailure=$true; throw }
            # A completed read with a returned count is observed. A faulted or
            # still-pending read retains its conservative 4096-byte allowance.
            $Capture.pending[$i]=$false
            if ($n -eq 0) { $Capture.done[$i]=$true; continue }
            if ($AfterStop) {
                $available=65536-$Capture.afterStopProcessedBytes
                $within=[int][Math]::Min($available,$n)
                $Capture.afterStopProcessedBytes+=$within
                if ($n -gt $within) {
                    $Capture.afterStopOverflowObservedBytes+=($n-$within)
                    $Capture.afterStopRejected=$true
                    # No new read is issued after this rejection. The observed
                    # overflow plus other issued/in-flight bytes totals <=8192.
                    throw 'Emergency drain processed threshold exceeded'
                }
            }
            $remaining=8388608-$Capture.data[0].Length-$Capture.data[1].Length
            $retain=[int][Math]::Min($remaining,$n)
            if ($retain -gt 0) { $Capture.data[$i].Write($Capture.buffers[$i],0,$retain) }
            if ($retain -lt $n) { $Capture.truncated=$true }
            # At most one 4096-byte operation per stream. This issued allowance
            # is separate from the 65536-byte processed rejection threshold.
            $Capture.tasks[$i]=$null; $Capture.pending[$i]=$true
            $Capture.tasks[$i]=$Capture.streams[$i].ReadAsync($Capture.buffers[$i],0,4096)
            if ($Capture.truncated -and -not $AfterStop) { throw 'Retained raw capture limit' }
        }
    }
}
function Get-CaptureReadAccounting($Capture) {
    $possible=0
    for ($i=0;$i -lt 2;$i++) { if ($Capture.pending[$i]) { $possible+=4096 } }
    return [ordered]@{
        processedRejectionThresholdBytes=65536; processedBytes=$Capture.afterStopProcessedBytes
        observedOverflowBytes=$Capture.afterStopOverflowObservedBytes
        possibleUnobservedInFlightBytes=$possible; possibleBytesAreObserved=$false
        issuedOverflowAllowanceBytes=8192; maximumReadEnvelopeBytes=73728
        observedPlusPossibleBytes=($Capture.afterStopProcessedBytes+$Capture.afterStopOverflowObservedBytes+$possible)
        overflowRejected=$Capture.afterStopRejected
    }
}
function Invoke-CompilerNativeInputsCandidate($Authority, $Binding, $OuterWatch, $Clock, $Inputs) {
    if (-not $script:ExecutionAdmitted) { throw 'INACTIVE: observer entry' }
    $guard=$null; $sample=$null; $natural=$false; $stopCalled=$false
    $r=[ordered]@{ actionKind='compiler-native-inputs'; action=$Binding.actionNumber; reservationSha256=$Binding.reservationSha256
        invocationSha256=$InvocationSha256; graphAccepted=$false; artifactAccepted=$false; continuation_allowed=$false
        normalCompletion=$false; quiescent=$false; safetyStop=$true; independentObservationAccepted=$false
        startAttempted=$false; startReturned=$false; captureCompleted=$false; subjectExitCode=$null
        outcome='incomplete'; jobTerminationRequested=$null; jobTerminationSucceeded=$null; clock=$Clock
        disposeAttempted=$false; disposeCompleted=$false; disposeKillOnClose=$true; disposeConfirmsQuiescence=$false; stopReturned=$false }
    try {
        $script:BootstrapStage='materialization'
        New-CompilerNativeInputsMaterialization $Authority $Binding $Inputs $OuterWatch $Clock
        $script:BootstrapStage='guard-load'
        $loaded=Import-ExactCompilerNativeInputsGuard $Authority $Binding $OuterWatch $Clock
        Save-CompleteJson ($Binding.actionPath+'\guard-load.json') $loaded
        $script:BootstrapStage='preflight'
        $sample=Get-CompilerNativeInputsFileSample $Binding $OuterWatch $Clock
        Assert-Remaining $OuterWatch $Clock ($Binding.actionPath+'\cancel') 20000
        Assert-EmptyServicing $Binding $Inputs.environment
        Assert-EmptyUserExtensions $Binding
        Assert-CompilerNativeInputsAbsences $Authority $Binding $OuterWatch $Clock
        Assert-CompilerNativeInputsMembership $Authority $Binding $OuterWatch $Clock
        $guard=[WindowsValidationJob]::new()
        if ($script:StartAttempted) { throw 'Repeated Start' }
        $script:BootstrapStage='subject-start'
        $script:StartAttempted=$true; $r.startAttempted=$true
        Save-CompleteJson ($Binding.actionPath+'\subject-start-attempt.json') @{ reservationSha256=$Binding.reservationSha256; attempted=$true }
        # Persistence may return late. Preserve the charged attempt but refuse a
        # newly entered Start after cancellation/expiry; keep the cleanup reserve.
        Assert-Remaining $OuterWatch $Clock ($Binding.actionPath+'\cancel') 20000
        if ((Get-RemainingMilliseconds $OuterWatch $Clock) -le 20000) { throw 'Start reserve expired after cancellation check' }
        $guard.Start($Binding.executable,$Binding.nativeArguments,$Binding.workingDirectory,$Inputs.environment)
        $r.startReturned=$true
        # The already-entered ordinary Start may finish Assign/Handle/Resume after
        # a delayed native return. This is not a new caller start allowance.
        if ((Get-RemainingMilliseconds $OuterWatch $Clock) -le 0) { throw 'Late ordinary Start return' }
        $script:BootstrapStage='subject-observation'
        $script:Capture=Start-Capture $guard
        $nextSample=$OuterWatch.ElapsedMilliseconds+250
        while ($true) {
            Assert-Remaining $OuterWatch $Clock ($Binding.actionPath+'\cancel') 20000
            Pump-Capture $script:Capture
            if ($OuterWatch.ElapsedMilliseconds -ge $nextSample) {
                $sample=Get-CompilerNativeInputsFileSample $Binding $OuterWatch $Clock
                $nextSample=$OuterWatch.ElapsedMilliseconds+250
            }
            if ($guard.Child.HasExited -and $script:Capture.done[0] -and $script:Capture.done[1] -and $guard.ActiveProcesses -eq 0) { break }
            Start-Sleep -Milliseconds 25
        }
        $r.subjectExitCode=$guard.Child.ExitCode; $natural=$true
        $r.captureCompleted=-not ($script:Capture.truncated -or $script:Capture.readFailure)
        $sample=Get-CompilerNativeInputsFileSample $Binding $OuterWatch $Clock
        $script:BootstrapStage='claim-validation'
        $claimRead=Read-SmallFile $script:Marker 109
        $claim=$claimRead.bytes
        if (-not $claimRead.eof -or $claim.Length -ne 109 -or (Get-BytesSha256 $claim) -cne (Get-BytesSha256 $script:ClaimBytes)) { throw 'Claim not exact' }
        if ((Get-Item -LiteralPath ($Binding.actionPath+'\home\.dotnet\10.0.401.dotnetFirstUseSentinel')).Length -ne 0) { throw 'Sentinel changed' }
        Assert-EmptyServicing $Binding $Inputs.environment
        Assert-EmptyUserExtensions $Binding
        Assert-CompilerNativeInputsAbsences $Authority $Binding $OuterWatch $Clock
        Assert-CompilerNativeInputsMembership $Authority $Binding $OuterWatch $Clock
        $text=[Text.Encoding]::UTF8.GetString($script:Capture.data[0].ToArray()) + [Text.Encoding]::UTF8.GetString($script:Capture.data[1].ToArray())
        $r.expectedDiagnosticSeen=$text.Contains('AUTH108NATIVEINPUTSTOP')
        if ($r.subjectExitCode -eq 0 -or -not $r.expectedDiagnosticSeen -or $sample.binlogBytes -le 0) { throw 'Expected diagnostic absent or wrong exit' }
        $r.terminalMarkerBytes=$claim.Length
        $r.terminalMarkerSha256=Get-BytesSha256 $claim
        $r.expectedCompilerContexts=3; $r.expectedNativeInputCutoffs=1
        # These are expected counts, not observed Csc task acceptance. The marker
        # and text cannot prove three successful compilers, zero native Exec, exact
        # ordered item boundaries, original RSP joins, or complete binlog EOF.
        $r.outcome='expected-stop-candidate-awaiting-independent-acceptance'
    } catch {
        Remember-BootstrapFailure $_.Exception
        $r.failureType=Get-SanitizedExceptionType $_.Exception; $r.failureStage=$script:BootstrapStage
        $r.outcome='incomplete'
    } finally {
        if ($null -ne $guard) {
            $script:BootstrapStage='subject-cleanup'
            try {
                # Enter no new Stop after the original deadline. Once entered,
                # the unchanged guard owns its source-fixed 10-second accounting
                # loop after TerminateJobObject returns; native delay and the last
                # 50-ms poll can overshoot. Late return never qualifies as success.
                if ((Get-RemainingMilliseconds $OuterWatch $Clock) -gt 15000) {
                    $stopCalled=$true
                    try { $r.quiescent=$guard.Stop(); $r.stopReturned=$true }
                    finally {
                        $r.jobTerminationRequested=$guard.TerminationRequested
                        $r.jobTerminationSucceeded=$guard.TerminationSucceeded
                        $r.jobActive=$guard.ActiveAfterStop; $r.jobTotal=$guard.TotalAfterStop
                    }
                }
                if ($null -ne $script:Capture -and $r.stopReturned) {
                    while (-not ($script:Capture.done[0] -and $script:Capture.done[1])) {
                        if ((Get-RemainingMilliseconds $OuterWatch $Clock) -le 5000) { throw 'Drain reserve exhausted' }
                        Pump-Capture $script:Capture -AfterStop
                        Start-Sleep -Milliseconds 25
                    }
                }
            } catch { Remember-BootstrapFailure $_.Exception; $r.cleanupFailureType=(Get-SanitizedExceptionType $_.Exception); $r.outcome='incomplete' }
            finally {
                # Capture flags even if Stop or accounting threw or was skipped.
                try {
                    $r.jobTerminationRequested=$guard.TerminationRequested
                    $r.jobTerminationSucceeded=$guard.TerminationSucceeded
                } catch { Remember-BootstrapFailure $_.Exception; $r.stopFlagFailureType=(Get-SanitizedExceptionType $_.Exception); $r.outcome='incomplete' }
                $r.disposeAttempted=$true
                try { $guard.Dispose(); $r.disposeCompleted=$true }
                catch { Remember-BootstrapFailure $_.Exception; $r.disposeFailureType=(Get-SanitizedExceptionType $_.Exception); $r.outcome='incomplete' }
                # Closing this Job has kill-on-close semantics. A successful
                # Dispose does not establish a zero count or an unassigned exit.
            }
        }

        $r.naturalJobCompletion=$natural
        if (-not $r.quiescent -or $r.jobTerminationRequested -or -not $r.captureCompleted -or
            (Get-RemainingMilliseconds $OuterWatch $Clock) -le 0) { $r.outcome='incomplete' }
        $r.normalCompletion=$natural -and $r.quiescent -and $r.captureCompleted -and $r.stopReturned -and
            $r.disposeCompleted -and $r.jobTerminationRequested -ceq $false -and $r.outcome -ceq 'expected-stop-candidate-awaiting-independent-acceptance'
        $r.safetyStop=-not $r.normalCompletion
        # No post-failure source/output survey; retain partial state and marker.
        $r.lastFileSample=$sample; $r.stopCalled=$stopCalled
        $r.lastDirectoryCount=$script:LastDirectoryCount
        $script:BootstrapStage='receipt-finalization'
        if ($null -ne $script:Capture) {
            $r.stdoutBytes=$script:Capture.data[0].Length; $r.stderrBytes=$script:Capture.data[1].Length
            $r.captureTruncated=$script:Capture.truncated
            $r.emergencyDrainReadAccounting=Get-CaptureReadAccounting $script:Capture
            Save-Bytes ($Binding.actionPath+'\stdout.bin') $script:Capture.data[0].ToArray()
            Save-Bytes ($Binding.actionPath+'\stderr.bin') $script:Capture.data[1].ToArray()
            $script:Capture.data[0].Dispose(); $script:Capture.data[1].Dispose()
        }
        $r.windowsElapsedMilliseconds=$OuterWatch.ElapsedMilliseconds
        $r.absenceChecks=$script:AbsenceChecks; $r.absenceMetadataProbes=$script:AbsenceMetadataProbes
        $r.membershipChecks=$script:MembershipChecks; $r.membershipMetadataProbes=$script:MembershipMetadataProbes
        $r.membershipEntries=$script:MembershipEntries
        $r.remainingMilliseconds=Get-RemainingMilliseconds $OuterWatch $Clock
        Save-CompleteJson ($Binding.actionPath+'\windows-result.json') $r
    }
    return $r
}
# The reviewed literal admission supplies AuthorityPath/SHA and the exact source
# bootstrap. No source-embedded authority hash or runtime authority rewrite exists.
$watch=[Diagnostics.Stopwatch]::StartNew(); $result=$null; $clock=$null; $binding=$null
$finalizationFailed=$false; $exitCode=1
try {
    $script:BootstrapStage='source-bindings'
    Assert-NewSourceBindings
    $script:BootstrapStage='authority-shape'
    if ($AuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or $InvocationSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound literal hash' }
    $script:BootstrapStage='authority-read'
    $a=Get-Item -LiteralPath $AuthorityPath
    $authority=[Text.Encoding]::UTF8.GetString((Read-Bound ([pscustomobject]@{path=$AuthorityPath;bytes=$a.Length;sha256=$AuthoritySha256}) -Bytes)) | ConvertFrom-Json
    $script:BootstrapStage='invocation-read'
    $i=Get-Item -LiteralPath $InvocationPath
    $binding=[Text.Encoding]::UTF8.GetString((Read-Bound ([pscustomobject]@{path=$InvocationPath;bytes=$i.Length;sha256=$InvocationSha256}) -Bytes)) | ConvertFrom-Json
    $script:BootstrapStage='source-admission'
    $inputs=Assert-ExactCompilerNativeInputsAdmission $authority $binding
    $script:BootstrapStage='clock-handoff'
    $clock=Assert-ExactOriginalClockHandoff $binding $watch
    $result=Invoke-CompilerNativeInputsCandidate $authority $binding $watch $clock $inputs
} catch { Remember-BootstrapFailure $_.Exception; $finalizationFailed=$true }
finally {
    # Attempt every retained lease release even when an earlier release throws.
    $script:BootstrapStage='lease-release'
    foreach ($lease in $script:Leases) {
        try { $lease.Dispose() } catch { Remember-BootstrapFailure $_.Exception; $finalizationFailed=$true }
    }
}
# The persisted receipt is provisional. Original late/nonzero controller exit
# rejects it; it is never rewritten to hide late receipt or lease finalization.
if (-not $finalizationFailed -and $null -ne $result -and $result.normalCompletion -and
    $null -ne $binding -and -not (Test-Path -LiteralPath ($binding.actionPath+'\cancel')) -and
    (Get-RemainingMilliseconds $watch $clock) -gt 0) { $exitCode=0 }
$script:BootstrapStage='controller-exit'
try { Write-BootstrapFrame $exitCode } catch { $exitCode=1 }
exit $exitCode

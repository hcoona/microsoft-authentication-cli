param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]{4}$')][string] $ActionName,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')][string] $ReservationSha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Temp\azureauth-windows-slice-108'
$action = "$root\actions\$ActionName"
$framework = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
$dotnet = 'C:\Program Files\dotnet\dotnet.exe'
$guard = $null
$compiler = $null
$capture = $null
$attendanceWatch = $null
$controllerWatch = [Diagnostics.Stopwatch]::StartNew()
$stage = 'reservation'
$result = [ordered]@{ safetyStop = $true; quiescent = $false; exitCode = -1; captureCompleted = $false }

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

function Assert-AttendanceOpen {
    if (Test-Path -LiteralPath "$action\cancel") { throw 'Attendance cancelled' }
    if ($attendanceWatch.Elapsed.TotalSeconds -ge 1800) { throw 'Attendance expired' }
}

function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse input' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}

function Assert-Hash([string] $Path, [string] $Expected) {
    Assert-Direct $Path
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected) {
        throw 'Input identity changed'
    }
}

function Read-Output($Process, $Streams, [int] $Seconds, $Watch) {
    $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
    $tasks = @($Streams[0].ReadAsync($buffers[0], 0, 4096), $Streams[1].ReadAsync($buffers[1], 0, 4096))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $done = @($false, $false)
    $disposition = 'read-failure'
    try {
        while (-not ($Process.HasExited -and $done[0] -and $done[1])) {
            if (Test-Path -LiteralPath "$action\cancel") { $disposition = 'cancelled'; throw 'Caller cancellation' }
            if (Test-Path -LiteralPath "$action\temp\owned-host-safety-stop.json") {
                $disposition = 'fixture-safety-stop'; throw 'Owned-host fixture safety stop'
            }
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

try {
    Assert-Hash "$action\started.json" $ReservationSha256
    $start = Get-Content -LiteralPath "$action\started.json" -Raw | ConvertFrom-Json
    if ($start.action -cnotin @('bootstrap', 'restore', 'build', 'test')) { throw 'Unallocated action' }
    if (-not ($start.PSObject.Properties.Name -ccontains 'testSuite')) { throw 'Missing finite selection' }
    if ($start.expected -cnotin @('red', 'green') -or
        ($start.action -cne 'test' -and $start.expected -cne 'green')) { throw 'Invalid result expectation' }
    $filter = $null
    if ($start.action -ceq 'test') {
        if ($start.testSuite -ceq 'cli') {
            $filter = 'FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.ExplicitFilePreservesSelectedProfileAndRequest|FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.FileSizeLimitAppliesBeforeAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.ReplacingFileAfterAdmissionCannotChangeTheInFlightProfile|FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.UnreadableOrInvalidFileStopsBeforeProviderConstruction|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.RootHelpCompletesWithoutAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.MalformedAuthenticationReturnsTheBootstrapFailure|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.SelectedRequestReturnsOneSuccessDespiteBrokenDiagnostics|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.FlaggedRegularFileStopsBeforeProfileAndProvider|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.AlreadyClosedLifetimePipeCancelsBeforeAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.WriterClosureRejectsLateSuccessAndEndsTheProcess|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.ClosedStdinWithoutTheFlagDoesNotCancel|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.LifetimePipePayloadIsIgnoredAndClosureStillCancels|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.DeadlineEndsUncooperativeWorkWithinTheProcessBound|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.BrokenResultReaderEndsWithTransportFailure|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.UndrainedResultPipeCannotKeepTheProcessAlive|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.BlockedDiagnosticsDoNotChangeTheAuthenticationResultOrKeepTheProcessAlive'
            $reserved = 12
        } elseif ($start.testSuite -ceq 'adapter') {
            $filter = 'FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ConsentRequirementHonorsInteractionPermission|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.SilentClaimsReachOneContinuationAndSecondChallengeStops|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.AccessDeniedWinsOverUiRequiredAndRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.Structured65004WinsOverRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.DenialTextAndNativeCodeDoNotImplyEntraDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.DuplicateErrorCodesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.NonNumericErrorCodesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.MalformedOrOverBudgetBodiesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ProviderUserCancellationRemainsCancelled|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalCancellationWinsOverDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalDeadlineWinsLateProviderCancellation|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.HttpTimeoutDoesNotConsumeRequestDeadline|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RetryableProviderStopsWithoutApplicationRetry|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RecognizedNetworkErrorStopsWithoutRetry|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UnknownProviderConfigurationStaysInternal|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UnexplainedCancellationStaysInternal|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UserMismatchWinsOverRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ResultProjectionPreservesObservedMetadata|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.MissingAccountAndInvalidTenantRemainMissing|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RejectedCustomUiCannotReturnAuthorizationUri|FullyQualifiedName=Authentication.Windows.Scenarios.ManagedTransportScenarios.ManagedUserAgentIsSingleStableAndForwardsCancellation'
            $reserved = 0
        } elseif ($start.testSuite -ceq 'ui-admission') {
            if ([int]$ActionName -le 32) { throw 'UI-admission selection predates its admission' }
            $filter = 'FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ForbiddenInteractionDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.MissingPresentationPreventsInteraction|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ReadyParentCarriesAdmittedBranding|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CreationFailurePreventsInteractiveAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.OriginalCancellationBeforeCreationWins|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringCreationRejectsLateParent|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CloseDuringCreationCannotReopenHost|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ClosedHostCannotReopen|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.InternalCloseDoesNotCancelCaller|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CompletionWaitsForActualUiThreadExit|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancelButtonStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CaptionCloseStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.EscapeStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.PostReadinessCallbackFaultIsContained|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.UiRejectionBeforeCreationPreventsParentAndAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.UiRejectionBeforeShowingWithholdsParentAndAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.UiRechecksUseOriginalTokenOnTheOwnedStaThread|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringUiRecheckPreventsAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotInspectTheOwnedUiThread'
            $reserved = 0
        } elseif ($start.testSuite -ceq 'host-admission') {
            if ([int]$ActionName -le 28) { throw 'Host-admission selection predates its admission' }
            $filter = 'FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ConstructionDoesNotObserveLocalState|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.PrecancelledRequestDoesNotObserveLocalState|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.OrdinaryInteractiveLogonKindsPermitSelectedAccountAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.UnsupportedPlatformStopsBeforeWindowsObservations|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ServerOrUnobservableProductPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ImpersonationOrUnknownThreadIdentityPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.MissingOrInvalidOwnLogonPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ServiceIdentitiesPrecludeAccountDiscovery|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.NoninteractiveAndAlternateCredentialLogonKindsAreRejected|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.HiddenWindowStationPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.MissingOrDifferentWindowStationUserPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.InactiveOrUnobservableSessionPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.NoninputOrUnobservableDesktopPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.CancellationAfterAnyObservationStopsFurtherQueriesAndInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.OriginalCancellationWinsWhenAnObservationThrows|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.UnexpectedObservationFaultRemainsSanitizedInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.SessionLossBeforeSilentAcquisitionPreventsItsEffect|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ImpersonationBeforeSilentAcquisitionPreventsItsEffect|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.InputDesktopLossAfterReadinessPreventsInteractionAndClosesParent|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.CancellationDuringVolatileObservationPreventsAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.EachProviderEffectHasFreshVolatileObservations|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ObservationsRunOnTheCallingThreadWithOriginalCancellation'
            $reserved = 0
        } elseif ($start.testSuite -ceq 'local-provider') {
            if ([int]$ActionName -le 24) { throw 'Local-provider selection predates its admission' }
            $filter = 'FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.ConstructionDoesNotObserveHostOrInitializeProvider|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.PrecancelledRequestStopsBeforeHostAdmission|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.RejectedHostPreventsInitializationAndOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.AdmittedHostAllowsOneSelectedAccountSilentResult|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringAdmissionPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.OriginalCancellationWinsOverAdmissionRejection|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringInitializationPreventsDiscovery|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnavailableInitializationPreventsDiscoveryAndOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedInitializationFaultStaysInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedHostObservationFaultStaysInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityBeforeSilentPreventsAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityAfterReadinessPreventsInteractionAndClosesHost|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringVolatileRecheckPreventsNextEffect|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.EligibleInteractiveContinuationUsesOriginalRequestAndOneParent|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.NoninteractivePermissionDoesNotOpenHostAfterSilentChallenge'
            $reserved = 0
        } elseif ($start.testSuite -ceq 'owned-host') {
            if ([int]$ActionName -le 18) { throw 'Owned-host selection predates its admission' }
            $filter = 'FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ForbiddenInteractionDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.MissingPresentationPreventsInteraction|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ReadyParentCarriesAdmittedBranding|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CreationFailurePreventsInteractiveAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.OriginalCancellationBeforeCreationWins|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringCreationRejectsLateParent|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CloseDuringCreationCannotReopenHost|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ClosedHostCannotReopen|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.InternalCloseDoesNotCancelCaller|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CompletionWaitsForActualUiThreadExit|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancelButtonStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CaptionCloseStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.EscapeStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.PostReadinessCallbackFaultIsContained'
            $reserved = 0
        } else { throw 'Unknown finite selection' }
    } else {
        if ($null -ne $start.testSuite) { throw 'Non-test selection' }
        $reserved = 0
    }
    if (($start.reservedProcessScenarios -isnot [int] -and $start.reservedProcessScenarios -isnot [long]) -or
        $start.reservedProcessScenarios -ne $reserved) { throw 'Incorrect process reservation' }
    Save-Json "$action\controller.json" @{
        pid = $PID; started = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('o')
    }
    $result.reservationSha256 = $ReservationSha256
    $stage = 'host-inputs'
    if (-not [Environment]::Is64BitProcess -or [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        throw 'Unexpected Windows execution identity'
    }
    Assert-Direct $root
    if ([IO.DriveInfo]::new('C:\').DriveType -ne [IO.DriveType]::Fixed) { throw 'Nonfixed fixture volume' }
    $owner = (Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw 'Unverified root owner' }
    foreach ($property in $start.toolSha256.PSObject.Properties) { Assert-Hash $property.Name $property.Value }
    foreach ($property in $start.fileSha256.PSObject.Properties) {
        if ($property.Name -notmatch '^[A-Za-z0-9_./,=-]+$' -or $property.Name -match '(^|/)\.\.(/|$)') {
            throw 'Unexpected relative input'
        }
        Assert-Hash (Join-Path $root $property.Name) $property.Value
    }
    Assert-Direct "$root\empty-feed"
    if (@(Get-ChildItem -LiteralPath "$root\empty-feed" -Force).Count -ne 0) { throw 'Nonempty fallback feed' }
    Assert-Direct "$action\empty-program-files"
    if (-not (Get-Item -LiteralPath "$action\empty-program-files" -Force).PSIsContainer -or
        @(Get-ChildItem -LiteralPath "$action\empty-program-files" -Force).Count -ne 0) {
        throw 'Invalid empty program-files directory'
    }
    # Check every active input/output directory before any owned compiler or subject.
    foreach ($base in @("$root\subject", "$root\feed", "$root\packages", $action)) {
        $queue = [Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($base)
        while ($queue.Count -gt 0) {
            $item = Get-Item -LiteralPath $queue.Dequeue() -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse descendant' }
            if ($item.PSIsContainer) {
                foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) { $queue.Enqueue($child.FullName) }
            }
        }
    }
    $environment = @{
        SystemRoot = 'C:\Windows'; WINDIR = 'C:\Windows'; ComSpec = 'C:\Windows\System32\cmd.exe'
        OS = 'Windows_NT'; PROCESSOR_ARCHITECTURE = 'AMD64'
        PROGRAMFILES = "$action\empty-program-files"; 'PROGRAMFILES(X86)' = "$action\empty-program-files"
        PATH = 'C:\Program Files\dotnet;C:\Windows\System32'
        USERPROFILE = "$action\home"; APPDATA = "$action\home\roaming"; LOCALAPPDATA = "$action\home\local"
        TMP = "$action\temp"; TEMP = "$action\temp"; DOTNET_CLI_HOME = "$action\home"
        DOTNET_ROOT = 'C:\Program Files\dotnet'; DOTNET_ROLL_FORWARD = 'Disable'
        NUGET_PACKAGES = "$root\packages"; NUGET_HTTP_CACHE_PATH = "$action\home\http"
        NUGET_PLUGINS_CACHE_PATH = "$action\home\plugins"
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'; TESTINGPLATFORM_TELEMETRY_OPTOUT = '1'
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'; DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
        DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = 'false'; DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = 'true'
        DOTNET_CLI_USE_MSBUILD_SERVER = '0'; MSBUILDDISABLENODEREUSE = '1'
        MSBuildEnableWorkloadResolver = 'false'; DOTNET_NOLOGO = '1'; DOTNET_CLI_UI_LANGUAGE = 'en-US'
    }
    $project = 'Windows.slnx'
    $exe = $dotnet
    $working = "$root\subject"
    $seconds = 120
    if ($start.action -eq 'bootstrap') {
        $seconds = 30
        $exe = "$framework\csc.exe"
        $arguments = '/noconfig /nologo /target:library /out:"' + $action + '\WindowsValidationJob.dll" /reference:"' +
            $framework + '\System.dll" /reference:"' + $framework + '\System.Core.dll" "' +
            $root + '\controller\WindowsValidationJob.cs"'
    } elseif ($start.action -eq 'restore') {
        $seconds = 180
        $arguments = 'restore ' + $project + ' --configfile "' + $root + '\nuget.config" --packages "' +
            $root + '\packages" --disable-parallel --verbosity minimal -p:NuGetAudit=false' +
            ' -p:RestorePackagesWithLockFile=true -p:UseSharedCompilation=false -m:1 -nr:false -noAutoResponse' +
            ' -p:RestoreFallbackFolders= -p:RestoreAdditionalProjectSources= -p:RestoreAdditionalProjectFallbackFolders='
        if (Test-Path -LiteralPath "$working\tests\Authentication.Windows.Scenarios\packages.lock.json") {
            $arguments += ' --locked-mode'
        }
    } elseif ($start.action -eq 'build') {
        $arguments = 'build ' + $project + ' -c Release --no-restore --disable-build-servers --verbosity minimal' +
            ' -p:UseSharedCompilation=false -m:1 -nr:false -noAutoResponse'
    } else {
        $arguments = 'tests\Authentication.Windows.Scenarios\bin\Release\net10.0-windows\Authentication.Windows.Scenarios.dll' +
            ' --report-trx --results-directory "' + $action + '\results"' + ' --filter "' + $filter + '"'
    }
    Save-Json "$action\invocation.json" @{
        executable = $exe; arguments = $arguments; workingDirectory = $working
        environment = $environment; seconds = $seconds
    }
    if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancelled before launch' }
    if ($start.action -eq 'bootstrap') {
        # This fixed standalone compiler has no shared compiler, analyzer, or custom task.
        # Retain the process handle; it is the sole bootstrap child before a Job exists.
        $stage = 'bootstrap'
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $exe; $info.Arguments = $arguments; $info.WorkingDirectory = $working
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $info.EnvironmentVariables.Clear()
        foreach ($key in $environment.Keys) { $info.EnvironmentVariables[$key] = $environment[$key] }
        $compiler = [Diagnostics.Process]::new(); $compiler.StartInfo = $info
        $watch = [Diagnostics.Stopwatch]::StartNew()
        if (-not $compiler.Start()) { throw 'Bootstrap start failed' }
        if ($compiler.Handle -eq [IntPtr]::Zero) { throw 'Missing compiler handle' }
        Save-Json "$action\compiler.json" @{
            pid = $compiler.Id; started = $compiler.StartTime.ToUniversalTime().ToString('o')
        }
        $capture = Read-Output $compiler @($compiler.StandardOutput.BaseStream, $compiler.StandardError.BaseStream) $seconds $watch
        $result.exitCode = $compiler.ExitCode
    } else {
        $stage = 'guard-load'
        $helper = Join-Path $root $start.helperPath
        Assert-Hash $helper $start.helperSha256
        Add-Type -Path $helper -ErrorAction Stop -WarningAction Stop
        $guard = [WindowsValidationJob]::new()
        if ($start.action -ceq 'test' -and ($start.testSuite -ceq 'ui-admission' -or
            ($start.testSuite -ceq 'owned-host' -and $start.expected -ceq 'green'))) {
            $stage = 'attendance'
            if ($controllerWatch.Elapsed.TotalSeconds -ge 230) { throw 'Preparation expired' }
            if (@(Get-ChildItem -LiteralPath $action -Filter 'attendance-*' -Force).Count -ne 0) {
                throw 'Preexisting attendance evidence'
            }
            $attendanceWatch = [Diagnostics.Stopwatch]::StartNew()
            Save-CompleteJson "$action\attendance-ready.json" @{
                action = $ActionName; reservationSha256 = $ReservationSha256; waitSeconds = 1800
                invocationSha256 = (Get-FileHash -LiteralPath "$action\invocation.json").Hash.ToLowerInvariant()
                controllerSha256 = (Get-FileHash -LiteralPath "$action\controller.json").Hash.ToLowerInvariant()
                preparedUtc = (Get-Date).ToUniversalTime().ToString('o')
            }
            $readyHash = (Get-FileHash -LiteralPath "$action\attendance-ready.json").Hash.ToLowerInvariant()
            $releaseName = 'attendance-release-' + $readyHash
            while ($true) {
                Assert-AttendanceOpen
                $releases = @(Get-ChildItem -LiteralPath $action -Filter 'attendance-release-*' -Force)
                if ($releases.Count -gt 0) {
                    if ($releases.Count -ne 1 -or $releases[0].Name -cne $releaseName) { throw 'Invalid attendance release' }
                    Assert-Direct $releases[0].FullName
                    if ($releases[0].PSIsContainer -or $releases[0].Length -ne 0) { throw 'Invalid release marker' }
                    break
                }
                Start-Sleep -Milliseconds 50
            }
            Assert-AttendanceOpen
            $waitMilliseconds = [long]$attendanceWatch.Elapsed.TotalMilliseconds
            Save-CompleteJson "$action\attendance-released.json" @{
                readySha256 = $readyHash; releaseName = $releaseName; waitMilliseconds = $waitMilliseconds
            }
            $result.attendanceReadySha256 = $readyHash
            $result.attendanceReleasedSha256 = (Get-FileHash -LiteralPath "$action\attendance-released.json").Hash.ToLowerInvariant()
            if ($controllerWatch.Elapsed.TotalSeconds - ($waitMilliseconds / 1000.0) -ge 230) {
                throw 'Controller work allowance expired'
            }
            # Withdrawal or expiry wins even when the release was observed concurrently.
            Assert-AttendanceOpen
        }
        $stage = 'subject'
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $guard.Start($exe, $arguments, $working, $environment)
        Save-Json "$action\subject.json" @{
            pid = $guard.Child.Id; started = $guard.Child.StartTime.ToUniversalTime().ToString('o')
        }
        $capture = Read-Output $guard.Child @($guard.Output.BaseStream, $guard.Error.BaseStream) $seconds $watch
        $result.exitCode = $guard.Child.ExitCode
        while ($guard.ActiveProcesses -ne 0 -and $watch.Elapsed.TotalSeconds -lt $seconds) {
            if (Test-Path -LiteralPath "$action\cancel") { throw 'Cancelled during quiescence' }
            Start-Sleep -Milliseconds 25
        }
        $result.activeProcessesAtNormalExit = $guard.ActiveProcesses
        if ($result.activeProcessesAtNormalExit -ne 0) { throw 'Owned descendants survived' }
    }
    if (Test-Path -LiteralPath "$action\temp\owned-host-safety-stop.json") {
        throw 'Owned-host fixture safety stop'
    }
    $result.captureCompleted = $true
    $result.seconds = $capture.seconds
    $result.safetyStop = $false
    $stage = 'completed'
} catch {
    $result.failureType = $_.Exception.GetType().FullName
    $result.failureLine = $_.InvocationInfo.ScriptLineNumber
    $result.safetyStop = $true
} finally {
    $result.stage = $stage
    try {
        $stopped = $true
        if ($compiler -and -not $compiler.HasExited) {
            $result.compilerTerminationRequested = $true
            $compiler.Kill()
            $stopped = $compiler.WaitForExit(10000)
        }
        if ($guard) {
            $stopped = $guard.Stop()
            $result.jobActiveBeforeStop = $guard.ActiveBeforeStop
            $result.jobActiveAfterStop = $guard.ActiveAfterStop
            $result.jobTotalBeforeStop = $guard.TotalBeforeStop
            $result.jobTotalAfterStop = $guard.TotalAfterStop
            $result.jobTerminationRequested = $guard.TerminationRequested
            $result.jobTerminationSucceeded = $guard.TerminationSucceeded
        }
        $result.quiescent = $stopped
    } catch {
        $result.quiescent = $false; $result.safetyStop = $true
        $result.terminationFailureType = $_.Exception.GetType().FullName
    }
    if ($guard) { $guard.Dispose() }
    if ($compiler) { $compiler.Dispose() }
    if (-not $result.quiescent) { $result.safetyStop = $true }
    $result.captureDisposition = 'not-started'
    if ($null -ne $capture) {
        $result.captureDisposition = $capture.disposition
        $result.stdoutBytes = $capture.stdout.Length
        $result.stderrBytes = $capture.stderr.Length
        $result.seconds = $capture.seconds
    }
    # Raw output remains local and is touched only after owned work is quiescent.
    if ($result.quiescent -and $null -ne $capture) {
        [IO.File]::WriteAllBytes("$action\stdout.bin", $capture.stdout)
        [IO.File]::WriteAllBytes("$action\stderr.bin", $capture.stderr)
    }
    $result.ended = (Get-Date).ToUniversalTime().ToString('o')
    Save-Json "$action\windows-result.json" $result
}
if ($result.safetyStop -or -not $result.quiescent) { exit 1 }
exit 0

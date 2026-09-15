# PRIVATE SOURCE CANDIDATE. No accepted invocation or compilation is admitted.
param([string] $ActionName, [string] $ReservationSha256, [string] $InvocationSha256, [string] $AuthoritySha256)
$script:DraftOnly = $false
if ($script:DraftOnly) { throw 'DRAFT_ONLY: final guard preparation is not admitted' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Verified projection outputs start unbound. The original WSL verifier supplies
# their immutable evidence; Windows checks the exact copied envelope and original
# reservation/invocation join before ready publication.
$script:AcceptedProtocolCommit = $null
$script:AcceptedSourceCommit = $null
$script:AcceptedControllerSha256 = $null
$script:AcceptedDispatcherSha256 = $null
$script:AcceptedSourceReviewSha256 = $null
$script:AcceptedAdmissionSha256 = $null
$script:ExpectedSourceSha256 = 'd38846b080d5ee092fae9e21c9031712b56289093b50ca048d50589cca50ff4b'
$script:RecipeJson = @'
{
  "compilerInvocation": {
    "analyzers": [],
    "argumentVectorTemplate": [
      "/noconfig",
      "/nologo",
      "/target:library",
      "/out:C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll",
      "/reference:C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll",
      "/reference:C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll",
      "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs"
    ],
    "callerArgumentOrEnvironmentOverridesAllowed": false,
    "clearInheritedEnvironment": true,
    "compilerConfiguration": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config",
    "customTasks": [],
    "executable": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
    "explicitReferences": [
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll"
    ],
    "generators": [],
    "implicitMscorlibReference": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll",
    "nativeAotLinkerOrPdbServiceSelected": false,
    "nativeArgumentsTemplate": "/noconfig /nologo /target:library /out:\"C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll\" /reference:\"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll\" /reference:\"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll\" \"C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs\"",
    "packageRestoreOrCopy": false,
    "preservesOriginalBootstrapEnvironmentRecipe": true,
    "productSymbolPolicyChanged": false,
    "replacementEnvironmentEntryCount": 30,
    "replacementEnvironmentTemplate": {
      "APPDATA": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\roaming",
      "ComSpec": "C:\\Windows\\System32\\cmd.exe",
      "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "false",
      "DOTNET_CLI_HOME": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home",
      "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
      "DOTNET_CLI_UI_LANGUAGE": "en-US",
      "DOTNET_CLI_USE_MSBUILD_SERVER": "0",
      "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true",
      "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
      "DOTNET_NOLOGO": "1",
      "DOTNET_ROLL_FORWARD": "Disable",
      "DOTNET_ROOT": "C:\\Program Files\\dotnet",
      "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
      "LOCALAPPDATA": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\local",
      "MSBUILDDISABLENODEREUSE": "1",
      "MSBuildEnableWorkloadResolver": "false",
      "NUGET_HTTP_CACHE_PATH": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\http",
      "NUGET_PACKAGES": "C:\\Temp\\azureauth-windows-slice-108\\packages",
      "NUGET_PLUGINS_CACHE_PATH": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\plugins",
      "OS": "Windows_NT",
      "PATH": "C:\\Program Files\\dotnet;C:\\Windows\\System32",
      "PROCESSOR_ARCHITECTURE": "AMD64",
      "PROGRAMFILES": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\empty-program-files",
      "PROGRAMFILES(X86)": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\empty-program-files",
      "SystemRoot": "C:\\Windows",
      "TEMP": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\temp",
      "TESTINGPLATFORM_TELEMETRY_OPTOUT": "1",
      "TMP": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\temp",
      "USERPROFILE": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home",
      "WINDIR": "C:\\Windows"
    },
    "resolvedArgumentStringBytesAndHash": null,
    "resolvedEnvironmentBytesAndHash": null,
    "responseFiles": [],
    "sharedCompiler": false,
    "sourceFiles": [
      "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs"
    ],
    "workingDirectoryTemplate": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source"
  },
  "paths": {
    "compiledArtifactReceiptTemplate": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\guard-build.json",
    "compiledArtifactTemplate": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll",
    "compilerWorkingDirectoryTemplate": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source",
    "copiedSourceTemplate": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs",
    "guardActionFourDigits": null,
    "onlyDynamicPathSubstitution": "GUARD_ACTION4; derive once from the fresh contiguous durable Windows reservation, not from this proposal.",
    "preparationControllerDirectoryTemplate": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\controller",
    "sharedActionLock": "/var/tmp/azureauth-windows-slice-108/action.lock",
    "windowsActionTemplate": "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}",
    "windowsRoot": "C:\\Temp\\azureauth-windows-slice-108",
    "wslActionTemplate": "/var/tmp/azureauth-windows-slice-108/windows-actions/${GUARD_ACTION4}",
    "wslHistoryRoot": "/var/tmp/azureauth-windows-slice-108/windows-actions",
    "wslWindowsProjectionTemplate": "/mnt/c/Temp/azureauth-windows-slice-108/actions/${GUARD_ACTION4}"
  },
  "tools": {
    "installedToolReadPerformed": false,
    "newToolInstallationOrRepairAllowed": false,
    "sha256": {
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll": "fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll": "2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe": "46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config": "2d4610ade011e530d817dd3ba4fc787e5dc0c2297cc520c30a643b8fb13f9093",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll": "5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb",
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe": "8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e"
    },
    "source": "Accepted immutable tools/validation/run_windows.py TOOLS entries"
  }
}
'@

$script:AuthorityShapeJson = @'
{
  "branch": "main-v2",
  "components": {
    "controller": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/Invoke-WindowsFinalGuardPrepare.ps1",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "dispatcher": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/run_windows_final_guard_prepare.py",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "finalPublishController": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/Invoke-WindowsFinalPublish.ps1",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "finalPublishDispatcher": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/run_windows_final_publish.py",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "guard": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/WindowsFinalPublishGuard.cs",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "guardHistory": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/final_guard_history.py",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "linuxHistoryReader": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/run_managed.py",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "preflight": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/WindowsFinalGuardPreflight.body.txt",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "windowsHistoryController": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/Invoke-WindowsValidation.ps1",
      "sha256": "@hash",
      "tree": "@rev"
    },
    "windowsHistoryReader": {
      "bytes": "@size",
      "commit": "@rev",
      "gitBlob": "@rev",
      "repositoryPath": "tools/validation/run_windows.py",
      "sha256": "@hash",
      "tree": "@rev"
    }
  },
  "executionAdmission": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-0055-authority-inputs/execution-admission-v2.json",
    "sha256": "@hash"
  },
  "failedGuardDisposition": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-0054-failed-history-disposition-v1.json",
    "sha256": "@hash"
  },
  "fixtureDisposition": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-0055-authority-inputs/fixture-disposition.json",
    "sha256": "@hash"
  },
  "handoffAcceptance": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-authority-inputs/post0053-handoff-acceptance.json",
    "sha256": "@hash"
  },
  "handoffManifest": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-authority-inputs/post0053-handoff.json",
    "sha256": "@hash"
  },
  "handoffProtocol": {
    "commit": "@rev",
    "sha256": "@hash"
  },
  "handoffSource": {
    "commit": "@rev",
    "tree": "@rev"
  },
  "limits": {
    "accountEffects": false,
    "buildTestCharge": 0,
    "cleanupMillisecondsWithinOriginal": 10000,
    "combinedBuildTestCeiling": 120,
    "combinedPreparationCeiling": 16,
    "compilerMilliseconds": 30000,
    "externalCallMilliseconds": 30000,
    "fixtureBuildTestCharge": 1,
    "guardPreparations": 2,
    "handshakeMilliseconds": 20000,
    "installation": false,
    "linuxPreparationCeiling": 9,
    "outerMilliseconds": 230000,
    "preflightMilliseconds": 20000,
    "preparationCharge": 1,
    "publishCharge": 0,
    "reservedProcessScenarios": 0,
    "retry": false,
    "windowsBuildTestCeiling": 48,
    "windowsPreparationCeiling": 7
  },
  "preflight": {
    "argvSha256": "47a11709b88178a0963d560b866a79d20d9e9310407c8e161365344870897bfb",
    "bodySha256": "11a93b9504b70e2caf1e7e6c2f333f1cda178e0adcf88d5998d3eca83450e8b9"
  },
  "protocol": {
    "blob": "@rev",
    "commit": "@rev",
    "path": "docs/research/experiments/windows-slice-validation.md",
    "sha256": "@hash",
    "tree": "@rev"
  },
  "publication": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-0055-authority-inputs/publication-v2.json",
    "sha256": "@hash"
  },
  "receiptPolicy": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-authority-inputs/receipt-artifact-policy.json",
    "sha256": "@hash"
  },
  "recipeSha256": "ed0fa260a638d3594a18dc51cbc87b588bdfa45f4fd90c7b9ce2fec501e65bcc",
  "repository": "hcoona/microsoft-authentication-cli",
  "rootMarkers": {
    "linuxOwnerSha256": "@hash",
    "semanticMarker": {
      "grant": "a0f741b59e09f1eb95594dbfde7a6e634d962210",
      "issue": 108,
      "protocol_family": "docs/research/experiments/windows-slice-validation.md"
    },
    "windowsOwnerSha256": "@hash"
  },
  "schema": "final-guard-external-authority-v2",
  "scope": "compiler-only-final-guard-prepare",
  "source": {
    "commit": "@rev",
    "tree": "@rev"
  },
  "sourceReview": {
    "bytes": "@size",
    "path": "/tmp/windows-final-guard-0055-authority-inputs/source-review-v2.json",
    "sha256": "@hash"
  },
  "target": {
    "commit": "@rev",
    "tree": "@rev"
  },
  "toolSha256": {
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll": "fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b",
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll": "2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71",
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe": "46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00",
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config": "2d4610ade011e530d817dd3ba4fc787e5dc0c2297cc520c30a643b8fb13f9093",
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll": "5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe": "8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e"
  },
  "wave": {
    "blob": "@rev",
    "path": "docs/delivery-wave.md",
    "sha256": "@hash"
  }
}
'@

function Assert-Direct([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse input or output' }
        if ($item.PSIsContainer) { $item = $item.Parent } else { $item = $item.Directory }
    }
}

function Assert-Hash([string] $Path, [string] $Expected) {
    if ($Expected -cnotmatch '^[0-9a-f]{64}$') { throw 'Unbound input hash' }
    Assert-Direct $Path
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected) {
        throw 'Input identity changed'
    }
}

function Save-Bytes([string] $Path, [byte[]] $Bytes) {
    Assert-Direct ([IO.Path]::GetDirectoryName($Path))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Save-CompleteJson([string] $Path, $Value) {
    $data = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 30))
    Save-Bytes ($Path + '.pending') $data
    [IO.File]::Move(($Path + '.pending'), $Path)
}

function Assert-PreReadyBudget($OuterWatch, [string] $Cancel) {
    if (-not $OuterWatch.IsRunning -or $OuterWatch.ElapsedMilliseconds -ge 20000 -or
        (Test-Path -LiteralPath $Cancel)) { throw 'Authority/clock startup expired or cancelled' }
}

function Read-BoundAuthorityFile([string] $Path, [string] $Expected, [int] $Limit = 1048576) {
    if ($Expected -cnotmatch '^[0-9a-f]{64}$' -or $Limit -le 0 -or $Limit -gt 1048576) {
        throw 'Unbound authority input'
    }
    Assert-Direct $Path
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Length -gt $Limit) { throw 'Invalid authority input size' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $data = [IO.MemoryStream]::new()
    $buffer = [byte[]]::new(4096)
    try {
        while ($true) {
            $left = [Math]::Min(4096, $Limit + 1 - $data.Length)
            $count = $stream.Read($buffer, 0, [int]$left)
            if ($count -eq 0) { break }
            $data.Write($buffer, 0, $count)
            if ($data.Length -gt $Limit) { throw 'Authority input exceeded bound' }
        }
        $bytes = $data.ToArray()
        if ((Get-BytesSha256 $bytes) -cne $Expected) { throw 'Authority input bytes changed' }
        return ,$bytes
    } finally { $stream.Dispose(); $data.Dispose() }
}

function Assert-AuthorityShape($Value, $Shape) {
    if ($Shape -is [pscustomobject]) {
        if ($Value -isnot [pscustomobject]) { throw 'Wrong authority object type' }
        $wanted = @($Shape.PSObject.Properties.Name)
        $actual = @($Value.PSObject.Properties.Name)
        if (($wanted -join "`n") -cne ($actual -join "`n")) { throw 'Unknown, missing or unordered authority fields' }
        foreach ($name in $wanted) { Assert-AuthorityShape $Value.$name $Shape.$name }
        return
    }
    if ($Shape -is [string] -and $Shape -cin @('@hash', '@rev', '@size')) {
        if ($Shape -ceq '@size') {
            if (($Value -isnot [long] -and $Value -isnot [int]) -or $Value -le 0 -or $Value -gt 8388608) {
                throw 'Invalid authority size'
            }
        } else {
            $pattern = if ($Shape -ceq '@hash') { '^[0-9a-f]{64}$' } else { '^[0-9a-f]{40}$' }
            if ($Value -isnot [string] -or $Value -cnotmatch $pattern) { throw 'Invalid authority identity' }
        }
        return
    }
    if ($Shape -is [bool]) {
        if ($Value -isnot [bool] -or $Value -ne $Shape) { throw 'Fixed authority Boolean changed' }
    } elseif ($Shape -is [int] -or $Shape -is [long]) {
        if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -ne $Shape) { throw 'Fixed authority integer changed' }
    } elseif ($Shape -is [string]) {
        if ($Value -isnot [string] -or $Value -cne $Shape) { throw 'Fixed authority string changed' }
    } else { throw 'Unsupported authority schema leaf' }
}

function Assert-BoundSource($OuterWatch, [string] $Action, [string] $Cancel, $Start, $Invocation, $Recipe) {
    if ($script:DraftOnly) { throw 'DRAFT_ONLY: external projection is not admitted' }
    Assert-ExactExternalSourceAdmission $OuterWatch $Action $Cancel $Start $Invocation $Recipe
    if ($null -eq $script:AcceptedProtocolCommit -or $null -eq $script:AcceptedSourceCommit -or
        $null -eq $script:AcceptedControllerSha256 -or $null -eq $script:AcceptedDispatcherSha256 -or
        $null -eq $script:AcceptedSourceReviewSha256 -or $null -eq $script:AcceptedAdmissionSha256) {
        throw 'UNBOUND: verified authority projection outputs'
    }
}

function Assert-ExactExternalSourceAdmission($OuterWatch, [string] $Action, [string] $Cancel, $Start, $Invocation, $Recipe) {
    Assert-PreReadyBudget $OuterWatch $Cancel
    if ($ActionName -cnotmatch '^[0-9]{4}$' -or $ActionName -ceq '0000' -or
        $Action -cne ('C:\Temp\azureauth-windows-slice-108\actions\' + $ActionName)) {
        throw 'Authority path is not the original four-digit action'
    }
    # This is the fixed copied envelope of the original WSL verifier, not a
    # caller-selected path, new network interpreter or independent approval.
    $bytes = Read-BoundAuthorityFile "$Action\authority.json" $AuthoritySha256
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $envelope = $text | ConvertFrom-Json
    $shape = $script:AuthorityShapeJson | ConvertFrom-Json
    Assert-AuthorityShape $envelope $shape
    # Exact compact framing rejects duplicate keys, alternate escapes/numbers,
    # nonfinite values and additional frames lost by ConvertFrom-Json.
    if ($text -cne (($envelope | ConvertTo-Json -Depth 30 -Compress) + "`n")) {
        throw 'Noncanonical copied authority envelope'
    }
    Assert-PreReadyBudget $OuterWatch $Cancel
    if ($Start.authoritySha256 -cne $AuthoritySha256 -or $Invocation.authoritySha256 -cne $AuthoritySha256 -or
        $Start.protocol -cne $envelope.protocol.commit -or $Start.source -cne $envelope.source.commit -or
        $Start.sourceTree -cne $envelope.source.tree -or $Start.waveBlob -cne $envelope.wave.blob -or
        $Start.sourceBlob -cne $envelope.components.guard.gitBlob -or
        $Start.handoffSha256 -cne $envelope.handoffManifest.sha256 -or
        $Start.reviewSha256 -cne $envelope.executionAdmission.sha256 -or
        $Invocation.admissionSha256 -cne $envelope.executionAdmission.sha256 -or
        $Start.sourceReviewSha256 -cne $envelope.sourceReview.sha256 -or
        $Invocation.sourceReviewSha256 -cne $envelope.sourceReview.sha256 -or
        $Start.dispatcherSha256 -cne $envelope.components.dispatcher.sha256 -or
        $Start.preparationControllerSha256 -cne $envelope.components.controller.sha256 -or
        $Start.sourceSha256 -cne $envelope.components.guard.sha256 -or
        $envelope.components.guard.sha256 -cne $script:ExpectedSourceSha256) {
        throw 'Original reservation/invocation/authority join changed'
    }
    foreach ($role in @('dispatcher', 'controller', 'guard', 'preflight', 'finalPublishDispatcher', 'finalPublishController')) {
        if ($envelope.components.$role.commit -cne $envelope.source.commit -or
            $envelope.components.$role.tree -cne $envelope.source.tree) { throw 'Guard source component role changed' }
    }
    foreach ($role in @('linuxHistoryReader', 'windowsHistoryReader', 'windowsHistoryController', 'guardHistory')) {
        if ($envelope.components.$role.commit -cne $envelope.protocol.commit -or
            $envelope.components.$role.tree -cne $envelope.protocol.tree) { throw 'Protocol component role changed' }
    }
    foreach ($field in @('paths', 'compiler', 'toolSha256')) {
        $wanted = switch ($field) {
            'paths' { $Recipe.paths }
            'compiler' { $Recipe.compilerInvocation }
            'toolSha256' { $Recipe.tools.sha256 }
        }
        if (($Invocation.$field | ConvertTo-Json -Depth 30 -Compress) -cne
            ($wanted | ConvertTo-Json -Depth 30 -Compress)) { throw 'Complete compiler recipe projection changed' }
    }
    if (($envelope.toolSha256 | ConvertTo-Json -Compress) -cne ($Recipe.tools.sha256 | ConvertTo-Json -Compress)) {
        throw 'Authority tool definitions changed'
    }
    $controllerPath = "$Action\final-guard\controller\Invoke-WindowsFinalGuardPrepare.ps1"
    if ($PSCommandPath -cne $controllerPath) { throw 'Executing controller is not the original copied source' }
    $controller = Read-BoundAuthorityFile $PSCommandPath $envelope.components.controller.sha256
    $guard = Read-BoundAuthorityFile $Recipe.paths.copiedSourceTemplate $envelope.components.guard.sha256
    $preflight = Read-BoundAuthorityFile "$Action\final-guard\controller\WindowsFinalGuardPreflight.body.txt" $envelope.preflight.bodySha256
    if ($controller.Length -ne $envelope.components.controller.bytes -or $guard.Length -ne $envelope.components.guard.bytes -or
        $preflight.Length -ne $envelope.components.preflight.bytes -or
        $envelope.components.preflight.sha256 -cne $envelope.preflight.bodySha256) {
        throw 'Copied component byte binding changed'
    }
    $body = [Text.UTF8Encoding]::new($false, $true).GetString($preflight)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $argv = @('/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
              '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)
    $argvBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($argv | ConvertTo-Json -Compress))
    if ((Get-BytesSha256 $argvBytes) -cne $envelope.preflight.argvSha256 -or
        $Start.preflightBodySha256 -cne $envelope.preflight.bodySha256 -or
        $Start.preflightArgvSha256 -cne $envelope.preflight.argvSha256 -or
        $Invocation.preflightBodySha256 -cne $envelope.preflight.bodySha256 -or
        $Invocation.preflightArgvSha256 -cne $envelope.preflight.argvSha256) {
        throw 'Fixed preflight body/argv projection changed'
    }
    Assert-PreReadyBudget $OuterWatch $Cancel
    $script:AcceptedProtocolCommit = $envelope.protocol.commit
    $script:AcceptedSourceCommit = $envelope.source.commit
    $script:AcceptedControllerSha256 = $envelope.components.controller.sha256
    $script:AcceptedDispatcherSha256 = $envelope.components.dispatcher.sha256
    $script:AcceptedSourceReviewSha256 = $envelope.sourceReview.sha256
    $script:AcceptedAdmissionSha256 = $envelope.executionAdmission.sha256
    $script:VerifiedAuthoritySha256 = Get-BytesSha256 $bytes
    $script:VerifiedPreflightBodySha256 = $envelope.preflight.bodySha256
    $script:VerifiedPreflightArgvSha256 = $envelope.preflight.argvSha256
}

function Get-BytesSha256([byte[]] $Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}

function Get-RemainingMilliseconds($OuterWatch, $Clock) {
    if ($null -eq $Clock -or -not $OuterWatch.IsRunning) { return [long]0 }
    $now = $OuterWatch.ElapsedTicks
    if ($now -lt $Clock.windowsReadyElapsedTicks) { throw 'Windows clock moved backward' }
    $ticks = [decimal]$Clock.windowsDeadlineElapsedTicks - [decimal]$now
    if ($ticks -le 0) { return [long]0 }
    return [long][Math]::Floor(($ticks * [decimal]1000) / [decimal]$Clock.windowsClockFrequency)
}

function Assert-Remaining($OuterWatch, $Clock, [string] $Cancel) {
    if ((Get-RemainingMilliseconds $OuterWatch $Clock) -le 0) { throw 'Original outer allowance expired' }
    if (Test-Path -LiteralPath $Cancel) { throw 'Preparation cancelled' }
}

function Assert-ExactOriginalClockHandoff($Invocation, $Start, $OuterWatch, [string] $Action, [string] $Cancel) {
    if ($ActionName -cne '0055') { throw 'Only the separately admitted successor0055 is permitted' }
    if ($Invocation.schema -cne 'final-guard-invocation-v1' -or $Invocation.action -cne $ActionName -or
        $Invocation.reservationSha256 -cne $ReservationSha256 -or
        $Invocation.clockNonce -cnotmatch '^[0-9a-f]{64}$' -or $Invocation.clockNonce -cne $Start.clockNonce -or
        $Invocation.originalOuterLimitMilliseconds -ne 230000 -or $Invocation.clockHandshakeLimitMilliseconds -ne 20000) {
        throw 'Original clock invocation changed'
    }
    if (-not [Diagnostics.Stopwatch]::IsHighResolution -or -not $OuterWatch.IsRunning) {
        throw 'Running monotonic Windows clock unavailable'
    }
    $frequency = [Diagnostics.Stopwatch]::Frequency
    if ($frequency -le 0) { throw 'Invalid Windows clock frequency' }
    foreach ($name in @('clock-ready.json', 'clock-ready.json.pending', 'clock-remaining.json')) {
        if (Test-Path -LiteralPath "$Action\$name") { throw 'Clock handoff already exists' }
    }
    if ($OuterWatch.ElapsedMilliseconds -ge 20000 -or (Test-Path -LiteralPath $Cancel)) {
        throw 'Clock handoff expired or cancelled'
    }
    # Capture before publication. This same running watch is never restarted.
    $readyTicks = $OuterWatch.ElapsedTicks
    Save-CompleteJson "$Action\clock-ready.json" ([ordered]@{
        schema = 'final-guard-clock-ready-v1'; action = $ActionName; nonce = $Invocation.clockNonce
        reservationSha256 = $ReservationSha256; invocationSha256 = $InvocationSha256
        originalOuterLimitMilliseconds = 230000
        windowsReadyElapsedTicks = $readyTicks; windowsClockFrequency = $frequency
    })
    $readyHash = (Get-FileHash -LiteralPath "$Action\clock-ready.json" -Algorithm SHA256).Hash.ToLowerInvariant()
    $replyBytes = $null
    while ($true) {
        if ($OuterWatch.ElapsedMilliseconds -ge 20000 -or (Test-Path -LiteralPath $Cancel)) {
            throw 'Clock handoff expired or cancelled'
        }
        if (Test-Path -LiteralPath "$Action\clock-remaining.json") {
            Assert-Direct "$Action\clock-remaining.json"
            $replyFile = Get-Item -LiteralPath "$Action\clock-remaining.json" -Force
            if ($replyFile.PSIsContainer -or $replyFile.Length -gt 2048) { throw 'Invalid remaining reply size' }
            $replyBytes = [IO.File]::ReadAllBytes($replyFile.FullName)
            if ($replyBytes.Length -gt 2048) { throw 'Remaining reply exceeded bound' }
            if ($replyBytes.Length -gt 0 -and $replyBytes[$replyBytes.Length - 1] -eq 10) { break }
        }
        Start-Sleep -Milliseconds 25
    }
    $replyText = [Text.UTF8Encoding]::new($false, $true).GetString($replyBytes)
    $reply = $replyText | ConvertFrom-Json
    $left = $reply.remainingMilliseconds
    if (($left -isnot [long] -and $left -isnot [int]) -or $left -le 0 -or $left -gt 230000) {
        throw 'Invalid original remaining milliseconds'
    }
    # Exact compact ordered bytes reject duplicate/unknown fields, extra frames,
    # alternate nonce/reservation/ready identities and incomplete JSON prefixes.
    $expected = [ordered]@{
        action = $ActionName; invocationSha256 = $InvocationSha256; nonce = $Invocation.clockNonce
        originalOuterLimitMilliseconds = 230000; readySha256 = $readyHash
        remainingMilliseconds = $left; reservationSha256 = $ReservationSha256
        schema = 'final-guard-clock-remaining-v1'
    }
    if ($replyText -cne (($expected | ConvertTo-Json -Compress) + "`n")) { throw 'Remaining reply binding changed' }
    Assert-Hash "$Action\clock-ready.json" $readyHash
    $replyHash = Get-BytesSha256 $replyBytes
    Assert-Hash "$Action\clock-remaining.json" $replyHash
    # FLOOR before conversion: PowerShell integral casts otherwise round.
    # Anchor to readyTicks, which precedes WSL's remaining calculation; receive
    # time must never become a new origin or add the reply transit delay.
    $deadlineTicks = [decimal]$readyTicks + [Math]::Floor(([decimal]$left * [decimal]$frequency) / [decimal]1000)
    if ($deadlineTicks -gt [long]::MaxValue) { throw 'Clock deadline overflow' }
    $clock = [pscustomobject]@{
        readySha256 = $readyHash; replySha256 = $replyHash; nonce = $Invocation.clockNonce
        windowsReadyElapsedTicks = $readyTicks; windowsClockFrequency = $frequency
        remainingMilliseconds = $left; windowsDeadlineElapsedTicks = [long]$deadlineTicks
    }
    Assert-Remaining $OuterWatch $clock $Cancel
    if ($OuterWatch.ElapsedMilliseconds -ge 20000) { throw 'Late clock handoff' }
    return $clock
}

function Get-ResolvedRecipe([string] $Number) {
    if ($Number -cnotmatch '^[0-9]{4}$' -or $Number -ceq '0000') { throw 'Invalid action number' }
    # Only the durable action substitution is permitted. This is JSON data, never code.
    return ($script:RecipeJson.Replace('${GUARD_ACTION4}', $Number) | ConvertFrom-Json)
}

function Assert-ExactInvocation($Invocation, $Recipe, [string] $Action, [string] $StartHash) {
    if ($Invocation.schema -cne 'final-guard-invocation-v1' -or $Invocation.action -cne $ActionName -or
        $Invocation.reservationSha256 -cne $StartHash) { throw 'Invocation binding changed' }
    if ($Invocation.compiler.executable -cne $Recipe.compilerInvocation.executable -or
        $Invocation.compiler.nativeArgumentsTemplate -cne $Recipe.compilerInvocation.nativeArgumentsTemplate -or
        $Invocation.compiler.workingDirectoryTemplate -cne $Recipe.compilerInvocation.workingDirectoryTemplate) {
        throw 'Compiler recipe changed'
    }
    $expectedEnvironment = $Recipe.compilerInvocation.replacementEnvironmentTemplate
    $actualEnvironment = $Invocation.compiler.replacementEnvironmentTemplate
    $expectedNames = @($expectedEnvironment.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $actualNames = @($actualEnvironment.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    if ($expectedNames.Count -ne 30 -or ($expectedNames -join "`n") -cne ($actualNames -join "`n")) {
        throw 'Replacement environment keys changed'
    }
    foreach ($name in $expectedNames) {
        if ($actualEnvironment.$name -cne $expectedEnvironment.$name) { throw 'Replacement environment value changed' }
    }
    $expectedTools = $Recipe.tools.sha256
    $actualTools = $Invocation.toolSha256
    $toolNames = @($expectedTools.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    if ($toolNames.Count -ne 6 -or
        ($toolNames -join "`n") -cne (@($actualTools.PSObject.Properties.Name | Sort-Object -CaseSensitive) -join "`n")) {
        throw 'Installed tool keys changed'
    }
    foreach ($name in $toolNames) {
        if ($actualTools.$name -cne $expectedTools.$name) { throw 'Installed tool binding changed' }
        Assert-Hash $name $expectedTools.$name
    }
    Assert-Hash $Recipe.paths.copiedSourceTemplate $script:ExpectedSourceSha256
    Assert-Hash $PSCommandPath $script:AcceptedControllerSha256
    Assert-Direct $Action
    if (Test-Path -LiteralPath $Recipe.paths.compiledArtifactTemplate) { throw 'Output already exists' }
    # This source has no Add-Type, guard constructor, SDK/MSBuild or old helper load.
}

function Read-CompilerCapture($Process, $Streams, $CompilerWatch, $OuterWatch, $Clock, [string] $Cancel) {
    $buffers = @([byte[]]::new(4096), [byte[]]::new(4096))
    $tasks = @($Streams[0].ReadAsync($buffers[0], 0, 4096), $Streams[1].ReadAsync($buffers[1], 0, 4096))
    $data = @([IO.MemoryStream]::new(), [IO.MemoryStream]::new())
    $done = @($false, $false)
    $disposition = 'read-failure'
    try {
        while (-not ($Process.HasExited -and $done[0] -and $done[1])) {
            Assert-Remaining $OuterWatch $Clock $Cancel
            if ($CompilerWatch.ElapsedMilliseconds -ge 30000) { $disposition = 'timeout'; throw 'Compiler timeout' }
            for ($index = 0; $index -lt 2; $index++) {
                if (-not $done[$index] -and $tasks[$index].IsCompleted) {
                    $count = $tasks[$index].GetAwaiter().GetResult()
                    if ($count -eq 0) { $done[$index] = $true } else {
                        if ($data[0].Length + $data[1].Length + $count -gt 8388608) {
                            $disposition = 'output-limit'; throw 'Compiler output limit'
                        }
                        $data[$index].Write($buffers[$index], 0, $count)
                        $tasks[$index] = $Streams[$index].ReadAsync($buffers[$index], 0, 4096)
                    }
                }
            }
            Start-Sleep -Milliseconds 25
        }
        Assert-Remaining $OuterWatch $Clock $Cancel
        if ($CompilerWatch.ElapsedMilliseconds -ge 30000) { throw 'Late compiler completion' }
        $disposition = 'complete'
    } finally {
        $script:Capture = [pscustomobject]@{
            stdout = $data[0].ToArray(); stderr = $data[1].ToArray()
            bothStreamsEof = ($done[0] -and $done[1]); disposition = $disposition
        }
        $data[0].Dispose(); $data[1].Dispose()
    }
    return $script:Capture
}

function Invoke-GuardPreparationCandidate {
    $outerWatch = [Diagnostics.Stopwatch]::StartNew()
    $recipe = $null
    $action = $null
    $cancel = $null
    $compiler = $null
    $compilerWatch = $null
    $originalHandle = [IntPtr]::Zero
    $started = $false
    $startAttempted = $false
    $normal = $false
    $completionConfirmed = $false
    $script:Capture = $null
    $clock = $null
    $result = [ordered]@{
        schema = 'final-guard-windows-result-v1'; reservationSha256 = $ReservationSha256
        invocationSha256 = $InvocationSha256; normalCompletion = $false; safetyStop = $true
        compilerCompletionConfirmed = $false; compilerTerminationRequested = $false
        compilerExitCode = -1; captureCompleted = $false; bothStreamsEof = $false
        artifactAccepted = $false; continuation_allowed = $false; stage = 'admission'
        authorityVerified = $false; authoritySha256 = $null; sourceReviewSha256 = $null
        admissionSha256 = $null; preflightBodySha256 = $null; preflightArgvSha256 = $null
    }
    try {
        $recipe = Get-ResolvedRecipe $ActionName
        $action = $recipe.paths.windowsActionTemplate
        $cancel = "$action\cancel"
        Assert-PreReadyBudget $outerWatch $cancel
        $startBytes = Read-BoundAuthorityFile "$action\started.json" $ReservationSha256
        $invocationBytes = Read-BoundAuthorityFile "$action\invocation.json" $InvocationSha256
        $start = [Text.UTF8Encoding]::new($false, $true).GetString($startBytes) | ConvertFrom-Json
        $invocation = [Text.UTF8Encoding]::new($false, $true).GetString($invocationBytes) | ConvertFrom-Json
        Assert-BoundSource $outerWatch $action $cancel $start $invocation $recipe
        $result.authorityVerified = $true
        $result.authoritySha256 = $script:VerifiedAuthoritySha256
        $result.sourceReviewSha256 = $script:AcceptedSourceReviewSha256
        $result.admissionSha256 = $script:AcceptedAdmissionSha256
        $result.preflightBodySha256 = $script:VerifiedPreflightBodySha256
        $result.preflightArgvSha256 = $script:VerifiedPreflightArgvSha256
        if ($start.action -cne 'final-guard-prepare' -or $start.protocol -cne $script:AcceptedProtocolCommit -or
            $start.source -cne $script:AcceptedSourceCommit -or $start.reviewSha256 -cne $script:AcceptedAdmissionSha256 -or
            $start.sourceSha256 -cne $script:ExpectedSourceSha256 -or $start.preparationCharge -ne 1 -or
            $start.buildTestCharge -ne 0 -or $start.publishCharge -ne 0 -or $start.reservedProcessScenarios -ne 0) {
            throw 'Unaccepted preparation reservation'
        }
        $clock = Assert-ExactOriginalClockHandoff $invocation $start $outerWatch $action $cancel
        $result.clockHandoff = $clock
        Assert-Remaining $outerWatch $clock $cancel
        Assert-ExactInvocation $invocation $recipe $action $ReservationSha256
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $recipe.compilerInvocation.executable
        $info.Arguments = $recipe.compilerInvocation.nativeArgumentsTemplate
        $info.WorkingDirectory = $recipe.compilerInvocation.workingDirectoryTemplate
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $info.EnvironmentVariables.Clear()
        foreach ($property in $recipe.compilerInvocation.replacementEnvironmentTemplate.PSObject.Properties) {
            $info.EnvironmentVariables[$property.Name] = [string]$property.Value
        }
        $compiler = [Diagnostics.Process]::new(); $compiler.StartInfo = $info
        Assert-Remaining $outerWatch $clock $cancel
        $result.stage = 'compiler-start'
        $compilerWatch = [Diagnostics.Stopwatch]::StartNew()
        $startAttempted = $true
        if (-not $compiler.Start()) { throw 'Compiler start failed' }
        $started = $true
        $originalHandle = $compiler.Handle
        if ($originalHandle -eq [IntPtr]::Zero) { throw 'Original compiler handle unavailable' }
        Save-CompleteJson "$action\compiler.json" @{
            pid = $compiler.Id; started = $compiler.StartTime.ToUniversalTime().ToString('o')
            sourceSha256 = $script:ExpectedSourceSha256; invocationSha256 = $InvocationSha256
        }
        $result.stage = 'compiler-capture'
        $script:Capture = Read-CompilerCapture $compiler @($compiler.StandardOutput.BaseStream, $compiler.StandardError.BaseStream) $compilerWatch $outerWatch $clock $cancel
        $completionConfirmed = $compiler.HasExited
        if (-not $completionConfirmed) { throw 'Original compiler completion unavailable' }
        $result.compilerExitCode = $compiler.ExitCode
        if ($result.compilerExitCode -ne 0 -or $script:Capture.stdout.Length -ne 0 -or $script:Capture.stderr.Length -ne 0) {
            throw 'Compiler exit or diagnostics failed'
        }
        $result.captureCompleted = $true
        $result.bothStreamsEof = $script:Capture.bothStreamsEof
        Assert-Remaining $outerWatch $clock $cancel
        Assert-Hash $recipe.paths.copiedSourceTemplate $script:ExpectedSourceSha256
        foreach ($property in $recipe.tools.sha256.PSObject.Properties) { Assert-Hash $property.Name $property.Value }
        Assert-Hash "$action\started.json" $ReservationSha256
        Assert-Hash "$action\invocation.json" $InvocationSha256
        Assert-Hash "$action\authority.json" $script:VerifiedAuthoritySha256
        Assert-Hash "$action\final-guard\controller\WindowsFinalGuardPreflight.body.txt" $script:VerifiedPreflightBodySha256
        Assert-Hash "$action\clock-ready.json" $clock.readySha256
        Assert-Hash "$action\clock-remaining.json" $clock.replySha256
        Assert-Hash $PSCommandPath $script:AcceptedControllerSha256
        Assert-Direct $recipe.paths.compiledArtifactTemplate
        $dll = Get-Item -LiteralPath $recipe.paths.compiledArtifactTemplate -Force
        if ($dll.PSIsContainer -or $dll.Length -le 0 -or $dll.Length -gt 8388608) { throw 'Invalid guard output size' }
        $result.dllSha256 = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $result.dllBytes = $dll.Length
        # Only the fixed compiler may produce this DLL. PE/IL/managed-type review
        # occurs later without load/self-test; a nonempty file is not that review.
        Assert-Remaining $outerWatch $clock $cancel
        $normal = $true
        $result.stage = 'compiler-normal-awaiting-outer-and-artifact-review'
    } catch {
        $normal = $false
        $result.failureType = $_.Exception.GetType().FullName
        $result.failureLine = $_.InvocationInfo.ScriptLineNumber
    } finally {
        if (-not $normal -and $started -and $originalHandle -ne [IntPtr]::Zero) {
            try {
                $completionConfirmed = $compiler.HasExited
                if (-not $completionConfirmed) {
                    $left = [Math]::Min(10000, (Get-RemainingMilliseconds $outerWatch $clock))
                    if ($left -gt 0) {
                        $result.compilerTerminationRequested = $true
                        $stopWatch = [Diagnostics.Stopwatch]::StartNew()
                        $compiler.Kill()
                        $left = [Math]::Min(10000 - $stopWatch.ElapsedMilliseconds, (Get-RemainingMilliseconds $outerWatch $clock))
                        if ($left -gt 0) { $completionConfirmed = $compiler.WaitForExit([int]$left) }
                        else { $completionConfirmed = $compiler.HasExited }
                    }
                }
            } catch {
                $completionConfirmed = $false
                $result.stopFailureType = $_.Exception.GetType().FullName
            }
        }
        # Start uncertainty or a missing original handle is retained. Never reacquire
        # by PID, scan descendants or call a guard/old emergency controller.
        $result.startAttempted = $startAttempted
        $result.compilerCompletionConfirmed = $completionConfirmed
        $result.normalCompletion = $normal -and $completionConfirmed -and -not $result.compilerTerminationRequested
        $result.safetyStop = -not $result.normalCompletion
        if ($completionConfirmed -and $null -ne $script:Capture) {
            Save-Bytes "$action\stdout.bin" $script:Capture.stdout
            Save-Bytes "$action\stderr.bin" $script:Capture.stderr
            foreach ($name in @('stdout', 'stderr')) {
                $result[$name + 'Bytes'] = $script:Capture.$name.Length
                $result[$name + 'Sha256'] = (Get-FileHash -LiteralPath "$action\$name.bin" -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $result.captureDisposition = $script:Capture.disposition
        }
        if ($null -ne $compiler) { $compiler.Dispose() }
        if ((Get-RemainingMilliseconds $outerWatch $clock) -le 0) { $result.normalCompletion = $false; $result.safetyStop = $true }
        $result.outerMilliseconds = $outerWatch.ElapsedMilliseconds
        $result.ended = (Get-Date).ToUniversalTime().ToString('o')
        if ($null -ne $action) { Save-CompleteJson "$action\windows-result.json" $result }
    }
    if (-not $result.normalCompletion) { return 1 }
    return 0
}

# Exact source/protocol and execution admission must bind this entry point.
$guardPreparationExitCode = Invoke-GuardPreparationCandidate
if ($guardPreparationExitCode -isnot [int] -or $guardPreparationExitCode -notin @(0, 1)) {
    throw 'Invalid guard preparation exit result'
}
exit $guardPreparationExitCode

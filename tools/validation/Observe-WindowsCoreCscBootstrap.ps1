# INACTIVE PROPOSAL: invoke only after a separate accepted protocol amendment and admission.
# Exact 0056 bootstrap observation; selected-subject exclusion is separate source evidence.
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
$timer = [Diagnostics.Stopwatch]::StartNew()
$state = @{ rows = 0; exact = 0; ambiguous = 0; complete = $false; reason = 'query-error' }
$status = 'unknown'
try {
    $image = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $expected = @(
        $image,
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        'C:\Temp\azureauth-windows-slice-108\actions\0056\observer-support\Invoke-WindowsCoreCscObserver.ps1',
        '-AuthorityPath',
        'C:\Temp\azureauth-windows-slice-108\actions\0056\observer-support\authority.json',
        '-AuthoritySha256',
        'af7cac0c88c5284e1970f42b816a70ec4a367de204d544e6c6b9f6f310d04663',
        '-InvocationPath',
        'C:\Temp\azureauth-windows-slice-108\actions\0056\invocation.json',
        '-InvocationSha256',
        '896dcf2a0ccfae09dcecf7dfaec46db7f06dd8faf846b0157ab2cbc64b60d54f'
    )
    # The fixed LIKE body has only literal path characters and escaped backslashes.
    $query = @'
SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE Name='powershell.exe' AND (CommandLine IS NULL OR CommandLine='' OR CommandLine LIKE '%C:\\Temp\\azureauth-windows-slice-108\\actions\\0056\\observer-support\\Invoke-WindowsCoreCscObserver.ps1%')
'@
    if ($timer.ElapsedMilliseconds -gt 15000) {
        $state.reason = 'elapsed-limit'
        throw 'observation-limit'
    }
    CimCmdlets\Get-CimInstance -Namespace 'root/cimv2' -QueryDialect WQL `
        -Query $query -OperationTimeoutSec 5 -ErrorAction Stop |
        Microsoft.PowerShell.Core\ForEach-Object {
            $state.rows++
            if ($state.rows -gt 16) {
                $state.reason = 'row-limit'
                throw 'observation-limit'
            }
            if ($timer.ElapsedMilliseconds -gt 15000) {
                $state.reason = 'elapsed-limit'
                throw 'observation-limit'
            }
            $commandLine = $_.CommandLine
            $executablePath = $_.ExecutablePath
            if (($null -eq $commandLine) -or ($null -eq $executablePath)) {
                $state.ambiguous++
            } elseif (($commandLine -isnot [string]) -or ($executablePath -isnot [string])) {
                $state.ambiguous++
            } elseif (($commandLine.Length -gt 4096) -or ($executablePath.Length -gt 512)) {
                $state.reason = 'data-limit'
                throw 'observation-limit'
            } elseif (($commandLine.Length -eq 0) -or ($executablePath.Length -eq 0)) {
                $state.ambiguous++
            } else {
                [string[]] $tokens = $commandLine.Split(
                    [char[]]@(' ', "`t"), [StringSplitOptions]::RemoveEmptyEntries)
                $matches = [string]::Equals($executablePath, $image, [StringComparison]::OrdinalIgnoreCase)
                $matches = $matches -and ($tokens.Length -eq $expected.Length)
                if ($matches) {
                    for ($index = 0; $index -lt $expected.Length; $index++) {
                        $plain = $expected[$index]
                        $quoted = '"' + $plain + '"'
                        if (($tokens[$index] -cne $plain) -and ($tokens[$index] -cne $quoted)) {
                            $matches = $false
                            break
                        }
                    }
                }
                if ($matches) { $state.exact++ } else { $state.ambiguous++ }
            }
        }
    $state.complete = $true
    $state.reason = 'complete'
} catch {
    # Never print provider errors, exception messages, process rows, or command lines.
}
$elapsedMs = $timer.ElapsedMilliseconds
if ($elapsedMs -gt 15000) { $state.reason = 'elapsed-limit' }
if ($state.complete -and ($state.reason -eq 'complete')) {
    if (($state.ambiguous -gt 0) -or ($state.exact -gt 1)) {
        $state.reason = 'ambiguous'
    } elseif ($state.exact -eq 1) {
        $status = 'present'
    } else {
        $status = 'absent'
    }
}
$completeJson = $state.complete.ToString().ToLowerInvariant()
$line = '{"schema":"exact-0056-bootstrap-observation-v1","status":"' + $status +
    '","reason":"' + $state.reason + '","queryCompleted":' + $completeJson +
    ',"rows":' + $state.rows + ',"exact":' + $state.exact +
    ',"ambiguous":' + $state.ambiguous + ',"elapsedMs":' + $elapsedMs + '}'
[Console]::Out.WriteLine($line)
if ($status -eq 'unknown') { exit 2 }
exit 0

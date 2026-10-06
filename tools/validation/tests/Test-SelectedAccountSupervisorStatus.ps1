# Pure NAS1 consumer checks. Parse functions only; never invoke a controller or native API.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$validationRoot = Split-Path $PSScriptRoot -Parent
$checked = 0
foreach ($leaf in @('Invoke-WindowsSelectedAccount.ps1', 'Invoke-WindowsSelectedAccountCutoff.ps1')) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $validationRoot $leaf), [ref] $tokens, [ref] $errors)
    if ($errors.Count -ne 0) { throw 'Controller syntax failed.' }
    foreach ($name in @('Need', 'Read-SupervisorStatus')) {
        $functions = @($ast.FindAll({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $false))
        if ($functions.Count -ne 1) { throw 'Expected one pure consumer function.' }
        . ([scriptblock]::Create($functions[0].Extent.Text))
    }
    # Golden NAS1 frame shared with ControlledChecks.WireCase(1).
    $golden = [byte[]] @(78, 65, 83, 49, 5, 1, 0, 2, 193, 0, 0, 0, 1, 0, 0, 0)
    $status = Read-SupervisorStatus $golden 16 1
    if ($status.stage -ne 5 -or $status.fault -ne 1 -or $status.flags -ne 512 -or
        $status.publicInputOrdinal -ne 193 -or $status.reportedExitCode -ne 1) { throw 'Golden status mismatch.' }
    $checked++
    # Decode both signed ordinal -1 and a successful return without conflating them with closure.
    $success = [byte[]] @(78, 65, 83, 49, 17, 7, 63, 3, 255, 255, 255, 255, 0, 0, 0, 0)
    $status = Read-SupervisorStatus $success 16 0
    if ($status.publicInputOrdinal -ne -1 -or $status.flags -ne 831) { throw 'Signed status mismatch.' }
    $checked++
    # Rejection cases include short/long frames, unknown codes, reserved flag bits and exit disagreement.
    foreach ($variant in @('short', 'long', 'magic', 'stage0', 'stage18', 'fault', 'flags', 'ordinal', 'exit')) {
        $bytes = $golden.Clone(); $length = 16; $exit = 1
        switch ($variant) {
            short { $length = 15 }
            long { $bytes = [byte[]] ($golden + @(0)); $length = 17 }
            magic { $bytes[0] = 0 }
            stage0 { $bytes[4] = 0 }
            stage18 { $bytes[4] = 18 }
            fault { $bytes[5] = 8 }
            flags { $bytes[7] = 4 }
            ordinal { $bytes[8] = 226 }
            exit { $exit = 0 }
        }
        $rejected = $false
        try { $null = Read-SupervisorStatus $bytes $length $exit } catch { $rejected = $true }
        if (-not $rejected) { throw 'Malformed status accepted.' }
        $checked++
    }
    # Match the production capture's successive short reads and separate overflow probe.
    $buffer = [byte[]]::new(17); $offset = 0
    foreach ($count in @(1, 3, 7, 5)) {
        [Array]::Copy($golden, $offset, $buffer, $offset, $count); $offset += $count
    }
    $null = Read-SupervisorStatus $buffer $offset 1
    $checked++
}
if ($checked -ne 24) { throw 'Incomplete status checks.' }
Write-Output '24 pure supervisor status checks passed; no controller or native invocation.'

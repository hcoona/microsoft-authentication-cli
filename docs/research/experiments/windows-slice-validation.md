# Windows Slice Implementation Validation

This protocol governs execution and evidence for
[Issue #108](https://github.com/hcoona/microsoft-authentication-cli/issues/108).
The accepted [Delivery Wave](../../delivery-wave.md) owns authorization, normal
account effects, shared capacity and standing risk dispositions. The
[experiment policy](../experiment-safety.md) owns safety. The
[validation strategy](../../validation/strategy.md#windows-slice-design-acceptance)
owns the evidence required for acceptance.

## Direct Execution and Observation

Invoke the existing authentication product directly through an ordinary foreground
Windows process call on the designated Windows 11 x64 interactive machine, under
its existing ordinary logged-on user. Use the installed admitted toolchain only
when a necessary source change requires compilation. Reuse unchanged accepted
product artifacts, dependency provenance and controlled scenario results.

Observe request and authentication phases through the product's standard
`ActivitySource`/`Activity` instrumentation and explicitly enabled bounded local
`--telemetry stderr` output. The existing fixed progress logs provide observations
while an operation is pending. Keep local telemetry optional: its absence, failure,
overflow or missing completion cannot alter authentication or cause another attempt.
No network exporter, Collector service or elevated ETW observer is required.

The former retained host, script Job launcher, NativeCaller supervisor/worker,
cutoff controller, custom wire/handshake, input catalog, historical script-name
aliases and chained receipt collectors are retired. Their presence, rebuilding,
loading and receipts are not prerequisites for a new attempt. Do not recreate them
as new wrappers or expand the result validator into a process-control framework.
Use existing shell/process facilities and ordinary review to bind a finite call.

## Source and Artifact Admission

Before a covered execution, independently accept one bounded call or scenario
batch with the exact accepted protocol revision, product source and artifact,
required runtime assets, explicit selected request and interaction permission,
current operating basis, finite command/time/output limits and cumulative charge.
The review may reuse unchanged accepted evidence and cover these matters together;
no separate executable admission generator or review for each source leaf is needed.
A review does not activate an unmerged protocol change.

Use the established Windows x64 product basis: .NET SDK 10.0.401/runtime 10.0.12,
MSAL/Broker 4.83.1 and NativeInterop 0.20.3. Necessary Native AOT compilation retains
the admitted MSVC 14.51.36231 and Windows SDK 10.0.26100.0. Matching executable hashes
alone do not establish dependency, source, native-image or Profile provenance.
Retain stronger content/identity checks and the accepted historical ctime
qualification. Do not copy or recompile inputs already sufficiently accepted.

Keep native-call account values, Profile binding and equality checks Windows-local.
Only the bounded WSL batch below admits confidential caller transport; its
Windows-only validator retains the same exact request and result checks.
Use the existing owner-designated personal and work roles and existing private
configuration; no substitute account, enumeration for unrelated purposes, cache
repair, Profile provisioning or rewriting of private documents is permitted.
Bind the validation expectations to the same actual arguments passed to the product.
The experimental `visual-studio-legacy-wam` Profile and its independently accepted
Azure DevOps default-scope association remain an experimental selection, with no
registration ownership, distribution or general compatibility claim.

The operating-basis review applies the Wave's current-absence dispositions to the
recorded historical uncertainties. Preserve failed outcomes, spent observations,
unknown historical completion/account-effects extent and `noExperimentLive=false`.
No new host survey, exhaustive process search, reboot or renewed owner approval is
required merely because an old process or terminal cannot be found. Positive evidence
of ongoing experiment-owned work invokes the accepted stop procedure. A new material
ownership/interference gap still stops dependent real execution.

## Ordinary Process Execution

One product invocation performs one request. Native account cases use a 120-second
product deadline, with at most 130 seconds for external exit observation and stopping.
The exact call must name its ordinary process owner, external timeout and bounded
stop method before submission. Keep its creation-time process handle or equivalent
unambiguous owned-process identity through exit observation. Never terminate an
unrelated process identified by a name, age or session alone.

Observe the actual process exit and complete transport independently of program
logs. Where a case uses redirected output, require both streams to complete before
claiming a complete result. If the existing launch facility uses a Job or Linux
scope, retain its actual scoped completion evidence; a dedicated launcher, extra
supervisor and Job-count protocol are not mandatory for an otherwise bounded direct
call. Do not infer descendant or global quiescence from a root return. A case needing
owned descendant termination must use an already available adequate mechanism or
remain incomplete; it does not authorize building a new controller.

Reserve at most 1 MiB for a result and 1 MiB for safe local diagnostics per native
request. Stop on timeout, overflow, unproved owned completion, unexpected interaction,
unsafe output or mismatched inputs. Preserve forced termination and incomplete output
as failure. No automatic retry, background/persistent host or deadline reset is allowed.
Use fresh dedicated nonproduction evidence destinations and intentionally retain only
safe evidence and public artifacts. Do not delete or overwrite failed evidence.

## Result Validation and Privacy

For flow-only observation, direct stdout to the Windows null device and read only
allowlisted local telemetry/logs and the actual exit. Such a call cannot satisfy
normal stdout-contract or selected-result-metadata acceptance.

For stdout-contract acceptance, process the full bounded result only on Windows,
in memory, using the extracted `ProtocolResult.Validate` in
`tools/result-validation`. It checks protocol shape, duplicate members, strict
UTF-8, outcome/exit agreement, exact selected email and applicable tenant, authority,
expiration, scopes/default-scope association, WAM route and interaction permission.
Its expected values come from the same Windows-local selected request. Return only
its fixed enum/Boolean conclusions. Malformed output yields a fixed validation
failure, without source exceptions, excerpts, bytes or hashes. Unknown additive data
and syntactically valid unknown reason text are not forwarded.

The validator owns no process, clock, file discovery, account acquisition, retry,
telemetry collection or authentication lifetime. It receives the actual exit and a
receipt timestamp; it cannot prove those observations itself. For native calls, no
real result, token,
account/tenant identifier or identifier hash, authorization code, provider text or
raw diagnostic may enter Linux, agent/chat output, retained captures or Git.
Do not write a token-bearing result to an intermediate file. The ordinary shell call
must route native-call confidential stdout directly to Windows-local in-memory
validation. Only the bounded WSL batch below admits an intermediate caller pipe
and memory buffer before returning the result to this Windows-only validator.
Raw stderr is not a fallback: only the product's fixed safe indications and bounded
allowlisted telemetry may become evidence.

The small `tools/result-validation/cli` .NET 10 entry makes the same validator
callable from the ordinary Windows shell without loading .NET 10 assemblies into
PowerShell 5.1. It accepts, in order, the actual product exit, the receipt time in
round-trip (`O`) format, selected email, tenant (`common` or the exact GUID),
interaction permission, expected `Outcome`, expected `Route`, and scopes. Supply
these arguments from the same Windows-local values used for authentication, and
pipe only the captured result bytes to its stdin; no intermediate result file is
permitted. Its default-scope association is limited to the already accepted Azure
DevOps resource. It emits only fixed check conclusions or a fixed validation
failure. Validator exit 0 means a valid result was checked, including a failed
authentication; scenario acceptance additionally requires the reported checks and
actual product exit. Its caller bounds stdin delivery and validator termination.
It does not start or stop the authentication product, read configuration, collect
telemetry, or retry. Review and precharge any necessary bounded compilation before
using this entry, reusing the accepted pure-parser scenarios.

Optional product token interpretation remains best-effort after committed success.
It does not establish signature validity, account identity, scope satisfaction or
resource-service acceptance. No arbitrary-token analyzer or token-input channel is added.

## Selected-Account Scenarios

Allocate a finite native batch of at most six product starts, six account discoveries,
six selected-account silent calls and two separately permitted interactive calls from
the remaining shared real pool. Each role may use one silent-first primary probe,
one separately admitted interactive primary if needed, and one success-gated reuse
call. Failed/partial starts consume their reserved charge. This allocation cannot
reset the historical ledger or start an interaction automatically.

| Case | Request | Acceptance |
| --- | --- | --- |
| Personal R1 | Existing selected personal role; interaction permission false initially | Validated normal success, actual exit 0 and complete required result/process evidence. |
| Personal R6 | Fresh process; same personal selection/Profile/tenant/scopes; interaction permission false | Accepted same-selection R1 success first; validated success with silent route and actual exit 0. |
| Work R7 | Existing selected work role; interaction permission false initially | Work-role primary evidence independently accepted under its exact applicable tenant/Profile request. |
| Work R8 | Fresh process; same work selection/Profile/tenant/scopes; interaction permission false | Accepted same-selection R7 success first; validated silent success and actual exit 0. |

A validated closed `interaction_required` ends the primary probe and is not success.
Notify the operator explicitly and wait for fresh readiness. Then independently admit
one permission-true primary for that role; preserve silent-first product behavior.
A different failure stops dependent reuse and requires supported diagnosis and a
reviewed correction before any further attempt. No alternative account, tenant,
client registration, browser/device-code provider or PAT fallback is allowed.

Normal WAM discovery for exact selection, selected-account acquisition, operator
sign-in/MFA/ordinary delegated consent and normal protected provider-managed session
updates remain within the accepted Wave. Administrator consent, account addition or
removal, cache clearing/import, registration changes, authenticated service requests
and remote mutation remain excluded. Existing state is not clean first use.

Actual window behavior needs independent Windows-local observation, through an
already available suitable facility or operator observation when needed. Record
unavailable UI evidence as incomplete. A silent API route, no-interaction permission,
telemetry or process exit alone does not prove no visible UI or UI closure. Attendance
is not required merely to watch automated preparation or authentication logs.

## Actual WSL Acceptance

Native R1/R6 and R7/R8 do not establish actual WSL transport, caller-death/lifetime-pipe
behavior or WSL/UI acceptance. Keep unobserved account-role WSL obligations open.
The calls below admit normal result transport and an initially closed lifetime
pipe; the personal continuation additionally admits permission-gated interaction.
Other lifetime scenarios need their own accepted exact recipes within the Wave's
WSL boundary before execution. Do not resurrect the
retired ETW observer, host or controller chain to prepare or observe it.

### Bounded WSL Result-Transport Batch

Use the existing designated WSL2 Linux x64 caller and Windows 11 x64 ordinary user,
the same accepted Native AOT candidate, selected account roles, experimental
Profile and Azure DevOps default scope. Independently accept the native primary
and fresh-process success for a role before its WSL cases. Reuse their unchanged
source, dependency, artifact and validator evidence; do not recompile or recopy
those assets. This is an existing-state experiment, not clean first use or service
authorization. Normal protected provider updates retain the native account boundary.

| Case, once per role | Request and expected observation |
| --- | --- |
| Normal result | Same selected request, noninteractive permission, lifetime-pipe writer kept open. Directly invoke the Windows CLI through WSL interop; require complete normal stdout, validated `Success`/`Silent`, exit 0 and complete transport termination. |
| Initially closed pipe | Same explicit request and noninteractive permission, but close the dedicated writer before starting the CLI. Require a valid `Cancelled`/`None` result, exit 1, no token, and complete transport termination before accepting the case. |

Allocate each finite batch's product starts, discoveries, silent calls and eligible
interactive calls conservatively from the remaining shared real pool. Precharge the
whole batch and its exact bounded file passes before its first covered operation.
There is no automatic retry. Missing configuration, an unexpected result, malformed
output, a timeout or incomplete ownership/completion stops dependent cases for
review. A valid closed `InteractionRequired` ends that role's noninteractive probe;
interaction requires a separately admitted continuation and fresh actual readiness.

Use ordinary foreground shell/process facilities. Before authentication, one
Windows-local read of the existing private account data file, at most 8 KiB and
30 seconds, projects only the selected email and applicable tenant into a private
caller pipe, at most 1 KiB. Preserve a supplied work tenant; only its absence uses
`common` under `V2-REQ-019`. Reject invalid supplied values without fallback or
repair. Supply exactly those values to the product and validator. The Profile path
retains Windows interpretation; no Linux configuration becomes authoritative.

The admitted Linux caller may hold the selected request values and complete result
in bounded private memory. Product stdout must pass through its ordinary interop
pipe before returning, without an intermediate file, to the existing Windows-only
validator. The caller does not parse token claims or expose result fields. Disable
caller core dumps; retain no private payload, selector, identifier hash, raw stderr
or exception text. Return only the validator's explicit safe projection and fixed
phase, exit, timeout and completion facts. Malformed or unexpected output yields a
fixed failure; it is never partially forwarded. Product local telemetry remains
optional and cannot change the authentication result or cause another attempt.

Each call has the same 120-second product deadline, at most 130 seconds for product
completion/transport, 10 seconds for validator delivery/completion and five seconds
of validator stop allowance. Bound the whole foreground call to 180 seconds plus
five final stop seconds; component deadlines cannot renew that outer clock.
Limit product stdout and stderr to 1 MiB each and safe validator output to 4 KiB.
Use the same receipt-time and actual-exit inputs as native validation. Keep exactly
one caller-owned lifetime-pipe writer, prevent its inheritance by other children,
and close unused ends. Stdin remains a lifetime signal, never a credential channel.

Bound necessary public-input and private-configuration checks to at most four
metadata passes, 64 operations and 16 MiB plus 8 KiB per pass, 30 seconds each,
within the unchanged shared passive ceilings. Exact admission must include any
necessary public materialization pass; no new artifact survey is permitted.

Require actual interop exit and both complete streams; source safeguards and
telemetry alone cannot establish Windows process completion. A Linux signal is
not proof of Windows termination. Stop only experiment-owned objects through
ordinary bounded facilities, never shared brokers or unrelated processes. Preserve
the original deadline on failure: close the lifetime writer and allow completion
only through the remaining product deadline and its five-second shutdown allowance.
Ending an owned Linux relay after that limit is not observed Windows closure.
Preserve
any missing Windows completion and consumed charge; do not infer success or admit
another attempt from the configured deadline. Independently accept the actual
safe result, transport and scoped completion before dependent execution.

Record unavailable UI evidence explicitly. Neither these calls nor normal
interop completion proves UI absence, EOF during WAM, Linux-caller-death behavior,
timeout behavior or full WSL acceptance. Those required observations remain open
and need their own smallest admitted calls; this protocol grants no observer project,
retained host, new controller, network listener or confidential file transport.

### Personal WSL Interactive Continuation

After independently accepting a personal-role WSL `InteractionRequired` result,
complete streams, actual exit and scoped completion, admit one sequential
three-call continuation using the same selected account, Profile, authority,
Azure DevOps default scope, candidate and Windows-only validator. Reuse sufficient
native and work-role evidence. Do not repeat the accepted work WSL cases or alter
configuration, scopes, caches or broker state to force a personal prompt.

| Case, at most once | Permission and acceptance |
| --- | --- |
| Interactive permission | Use `interactive-if-needed`, retaining silent-first selection. Require valid `Success`, exit 0 and complete result/metadata/transport; either `Silent` or `Interactive` is eligible. Use the existing validator's unrestricted expected-route option and separately retain its actual fixed route. Obtain fresh actual sign-in readiness after all automated preparation, before this call. |
| Fresh silent reuse | Only after accepting the first call's success and scoped completion, use a fresh process with `non-interactive-only`. Require `Success`/`Silent`, exit 0 and the same complete checks. |
| Initially closed pipe | Only after accepting silent reuse, close the dedicated writer before starting a fresh `non-interactive-only` request. Require valid `Cancelled`/`None`, exit 1, no token and complete transport termination. |

Allocate three starts, discoveries and silent calls plus one eligible interactive
call from the remaining shared real pool. Allocate at most three metadata passes,
64 operations and 16 MiB plus 8 KiB per pass, 30 seconds each; allocate at most
three safe outcome collection passes, eight operations and 1 MiB per pass,
30 seconds each. Precharge the whole continuation and any necessary public
materialization before its first covered operation. There is no automatic retry
or refund for cancellation, failure or an unsubmitted dependent slot.

All ordinary memory, confidential-transport, product/validator/outer deadlines,
pipe ownership and stop limits above apply unchanged, including the 120-second
product deadline and original-clock shutdown allowance. The Windows configuration
read and strict selected values remain authoritative. A valid failure, unexpected
result, incomplete streams, missing exit or new ownership gap stops dependent
cases for review; this continuation admits no account, configuration or cache repair.

When sign-in, selection or delegated user consent appears, wait for the designated
operator's actual action in the ordinary Windows desktop. Administrator consent
and account addition remain excluded. Record actual UI observations only when
available from the operator or another already admitted observation path. A
`Silent` success does not prove visible UI absence; an `Interactive` result alone
does not prove the observed windows or their closure. Do not rerun a sufficient
success to manufacture UI evidence. Preserve missing observations explicitly.

This continuation admits no caller-death, EOF-during-WAM or intentional timeout
experiment. Prepare and independently accept the smallest exact lifetime recipes
within the accepted Wave before those cases execute; reuse standard process/pipe
facilities and the existing validator rather than creating a new observer project.
Accepting this continuation alone does not complete the WSL or whole-Slice claim.

## Console Parent Feasibility

This credential-free comparison answers whether an intermediate, already
installed PowerShell 7 process gives a WSL-launched console child an existing
visible root parent. It does not test authentication or modify the selected
product host. Use the same designated WSL2 caller and ordinary Windows user;
operator sign-in attendance is unnecessary because no WAM/provider, account,
Profile, cache, network, or visible-window operation runs.

Use only the already admitted Windows PowerShell 5.1 x64 executable as the
metadata subject. Compare two ordinary finite foreground calls, at most once
each:

| Case | Exact launch shape |
| --- | --- |
| Direct | WSL invokes `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` with `-NoLogo -NoProfile -NonInteractive -Sta -EncodedCommand` and the fixed script below. |
| Via PowerShell 7 | If the fixed existing `C:\Program Files\PowerShell\7\pwsh.exe` is present and independently admitted, WSL invokes it with `-NoLogo -NoProfile -NonInteractive -EncodedCommand`. Its only command invokes the same Windows PowerShell subject with the same arguments and script, then exits with the actual child's `$LASTEXITCODE`. No other command or child is allowed. |

Before the second call, finitely inspect only that fixed PowerShell 7 executable
as public installed-tool data, at most 32 MiB and 30 seconds, with exact
length/hash/EOF correspondence and an independent input admission. If absent,
record the second case as unavailable, keep its conservative charge, and do not
search other paths, install PowerShell, or substitute another shell. A file's
presence alone does not admit executable use.

The entire batch reserves three synthetic process starts/scenarios conservatively
(one direct process and at most two processes for the second case), zero
preparation/build/publication actions and zero real-account units. Allocate one
metadata pass, at most 16 operations, 32 MiB plus 64 KiB and 30 seconds; one safe
collection pass, at most eight operations, 1 MiB and 30 seconds. Precharge the
whole batch before its first covered file read or process call. Reuse existing
source/artifact/basis reviews; no second accounting system or generic runner is
needed.

Pin the extracted script and both encoded command strings in the independently
accepted exact call. Each foreground original has a 30-second deadline and
five-second external stop allowance, at most 64 KiB stdout and stderr. Require
actual normal root return, complete streams, zero exit and empty stderr before
accepting its safe report. A timeout, malformed output, unexpected child or
missing completion stops the batch; retain the failure and original deadline.
Stopping a Linux relay is not observed Windows closure. Apply existing
current-absence review only through its accepted boundary; no reboot, elevation,
process survey or unrelated cleanup is allowed.

The complete observation script is:

```powershell
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
$report = [ordered]@{
    ObservationFailed = $false
    ConsoleHandlePresent = $false
    ConsoleExists = $false
    ConsoleVisibleStyle = $false
    RootOwnerHandlePresent = $false
    RootOwnerExists = $false
    RootOwnerVisibleStyle = $false
    RootOwnerEqualsConsole = $false
}
try {
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly(
        [Reflection.AssemblyName]::new('ConsoleParentObservation'),
        [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('ConsoleParentObservation')
    $type = $module.DefineType('ConsoleParentNative', [Reflection.TypeAttributes]::Public)
    $attributes = [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl
    $declarations = @(
        @('GetConsoleWindow', 'kernel32.dll', [IntPtr], [Type[]]@()),
        @('GetAncestor', 'user32.dll', [IntPtr], [Type[]]@([IntPtr], [uint32])),
        @('IsWindow', 'user32.dll', [int], [Type[]]@([IntPtr])),
        @('IsWindowVisible', 'user32.dll', [int], [Type[]]@([IntPtr]))
    )
    foreach ($declaration in $declarations) {
        $method = $type.DefinePInvokeMethod($declaration[0],
            ([Environment]::SystemDirectory + '\' + $declaration[1]),
            $attributes, [Reflection.CallingConventions]::Standard,
            $declaration[2], $declaration[3],
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    }
    $native = $type.CreateType()
    $console = $native.GetMethod('GetConsoleWindow').Invoke($null, $null)
    $report.ConsoleHandlePresent = $console -ne [IntPtr]::Zero
    if ($report.ConsoleHandlePresent) {
        $report.ConsoleExists = $native.GetMethod('IsWindow').Invoke(
            $null, [object[]]@($console)) -ne 0
        $report.ConsoleVisibleStyle = $native.GetMethod('IsWindowVisible').Invoke(
            $null, [object[]]@($console)) -ne 0
        $root = $native.GetMethod('GetAncestor').Invoke(
            $null, [object[]]@($console, [uint32]3))
        $report.RootOwnerHandlePresent = $root -ne [IntPtr]::Zero
        if ($report.RootOwnerHandlePresent) {
            $report.RootOwnerExists = $native.GetMethod('IsWindow').Invoke(
                $null, [object[]]@($root)) -ne 0
            $report.RootOwnerVisibleStyle = $native.GetMethod('IsWindowVisible').Invoke(
                $null, [object[]]@($root)) -ne 0
            $report.RootOwnerEqualsConsole = $root -eq $console
        }
    }
} catch {
    $report.ObservationFailed = $true
}
$report | ConvertTo-Json -Compress
if ($report.ObservationFailed) { exit 1 }
exit 0
```

The four P/Invoke declarations query only the subject's console and its root
owner. Emit only the eight fixed booleans above; do not emit HWNDs, process IDs,
window titles, paths, desktop/account identifiers, exception text or diagnostic
data. No compiler, on-disk assembly, message loop, window creation, foreground
window selection, attach/detach, display/focus change, or borrowed-handle
destruction is permitted. Transient Reflection.Emit declarations live only in
the ordinary PowerShell subject; they do not establish Native AOT compatibility.

A zero or nonvisible root is evidence against using that launch shape to obtain
an existing visible parent. A visible root is only an instantaneous prerequisite,
not proof of correct WAM modality, user-visible focus or durable handle ownership.
Windows PowerShell is a surrogate console subject: neither outcome proves the
exact Native AOT product's handle behavior. Retain that limitation, the installed
PowerShell input identity, each launch shape, safe observations, exits, full
charges and scoped completion. Independently accept actual results before
changing the parent design or running any dependent real-account experiment.
No automatic retry or forced shell/window presentation is allowed.

## Outcome-Based Execution and Accounting

Continue the existing sanitized cumulative accounting carrier. Preserve every prior
charge, failed/partial start, pending flag, historical uncertainty and role assignment.
The shared Wave ceilings remain 100 preparation, 400 build/test, 60 Native AOT
publication and 1,200 synthetic scenarios; the real pool remains separate at
96 starts/discoveries/silent calls and 52 interactive calls. This protocol changes
execution mechanics, not those authorizations or historical consumption.

Passive metadata ceilings remain 512 passes / 16 GiB reserved bytes / 30,720 seconds;
collection ceilings remain 512 passes / 1 TiB reserved bytes / 153,600 seconds.
Each necessary pass needs a reviewed fixed selection and stricter finite operation,
byte and time limits. Do not perform passive surveys or read private inputs through
Linux. Ordinary source editing and repository checks are not account experiments.

Precharge the whole selected call before submission. One independent review may
bind the protocol, exact source/input/call, current operating basis and full charge.
Use ordinary recording in the existing carrier; no accounting-only execution,
reservation generator, recursive collector or new accounting system is required.
A fresh bounded attempt is not replay of a spent original or renewal of its deadline.

After execution, independently review the actual safe outcome, relevant source/input
correspondence, actual exit/transport and applicable scoped completion. Reuse unchanged
accepted evidence and accept each primary before its dependent reuse. Do not launch a
new evidence process merely to obtain another receipt for sufficient retained evidence.
A failure remains failed even when some produced artifacts are prospectively accepted.

## Focused Validator Extraction Check

Before compiling or executing the extracted result validator, independently accept
its exact source and focused synthetic scenarios. Allocate at most one offline
preparation action and one build/test action from the remaining common pool. Reuse the
existing Core scenario project, admitted Linux SDK/runtime and retained public offline
feed. No Windows/provider/product process, network download or private input is used.

Restore only if required, with locked existing dependencies, cleared credentials and
network package sources, and audit disabled. Build/run only the focused extraction
scenarios, with one MSBuild node, node reuse/shared compilation disabled and finite
foreground execution. Each invocation has at most 180 seconds, 8 MiB public output,
1 GiB retained artifacts and five seconds of final stop allowance. Exact original calls
and cumulative precharge precede execution. No detached compiler/test process survives
completion. This is parser/source evidence, not Windows, WAM, UI or WSL acceptance.

The Windows-local CLI entry may additionally use one offline preparation action
and one build action under these same installed-toolchain, finite-time, output,
retention and compiler-ownership bounds. It has no package dependencies. Reuse
the accepted parser scenarios instead of rerunning them. Independently admit its
exact source and compilation call, precharge the existing ledger, and accept the
actual compiler outcome before using its output. A Linux managed build establishes
compilation only; exact Windows execution admission remains required.

## Historical Evidence

The prior detailed protocols, source pins, receipts, failed outcomes and bounded
controlled observations remain recoverable in the
[fixed pre-cleanup Git version](https://github.com/hcoona/microsoft-authentication-cli/blob/06ab8855e4fc4c3144852f4cadeb12086531c388/docs/research/experiments/windows-slice-validation.md).
Current validation claims link directly to their fixed historical evidence. Deleted
source and recipes remain recoverable at that same revision; they grant no current
execution authority. Retained experiment/accounting artifacts are not removed by this
source cleanup, and no historical success, closure or evidence level is changed.

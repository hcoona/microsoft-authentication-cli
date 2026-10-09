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

Keep selected account values, Profile binding and equality checks Windows-local.
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
receipt timestamp; it cannot prove those observations itself. No real result, token,
account/tenant identifier or identifier hash, authorization code, provider text or
raw diagnostic may enter Linux, agent/chat output, retained captures or Git.
Do not write a token-bearing result to an intermediate file. The ordinary shell call
must route confidential stdout directly to Windows-local in-memory validation.
Raw stderr is not a fallback: only the product's fixed safe indications and bounded
allowlisted telemetry may become evidence.

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
behavior or WSL/UI acceptance. Keep both account-role WSL obligations open. This
protocol does not admit confidential token transport through WSL. Accept the smallest
explicit Wave/protocol boundary amendment before such execution; do not resurrect the
retired ETW observer, host or controller chain to prepare it.

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

## Historical Evidence

The prior detailed protocols, source pins, receipts, failed outcomes and bounded
controlled observations remain recoverable in the
[fixed pre-cleanup Git version](https://github.com/hcoona/microsoft-authentication-cli/blob/06ab8855e4fc4c3144852f4cadeb12086531c388/docs/research/experiments/windows-slice-validation.md).
Current validation claims link directly to their fixed historical evidence. Deleted
source and recipes remain recoverable at that same revision; they grant no current
execution authority. Retained experiment/accounting artifacts are not removed by this
source cleanup, and no historical success, closure or evidence level is changed.

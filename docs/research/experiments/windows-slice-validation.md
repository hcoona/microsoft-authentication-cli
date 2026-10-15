# Windows Slice Implementation Validation

This protocol governs execution and evidence for
[Issue #108](https://github.com/hcoona/microsoft-authentication-cli/issues/108).
The [Delivery Wave entry](https://github.com/hcoona/microsoft-authentication-cli/blob/e8f74fa759a9d15488242ee338f3a9c87089ed3f/docs/delivery-wave.md#first-windows-authentication-slice-implementation-and-scenario-acceptance) owned authorization, normal account effects,
shared capacity and standing risk dispositions. That entry was completed and
removed; this protocol is a historical record and authorizes nothing. The
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

Use the established Windows x64 product basis: .NET SDK 10.0.402/runtime 10.0.12,
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

### Actual WSL Deadline Assessment

After the accepted native and WSL success evidence, admit one actual noninteractive
personal-account deadline assessment on the unchanged selected Native AOT candidate,
Profile, common authority and Azure DevOps default scope. Reuse the existing
Windows-local selected configuration, bounded confidential WSL transport, fixed
local observations and Windows-only result validator. The hidden-parent experimental
variant is not selected for this assessment. No sign-in or attendance is required.

Set the supported caller timeout to one second; the request's original entry clock
covers all phases. Observe product exit and both complete streams for at most six
seconds from launch, preserving the product's original watchdog allowance. The
unchanged preflight has at most 30 seconds, the validator ten seconds plus five
stop seconds, and the whole foreground call 180 seconds plus five stop seconds.
Keep stdout/stderr at most 1 MiB each, validator output at most 4 KiB, and private
configuration/projection at most 8 KiB/1 KiB. Keep the single noninherited lifetime
writer open during the normal assessment; on failure close it and use only the
remaining original deadline/stop allowance. A stopped Linux relay does not prove
Windows closure and stops dependent work.

Require valid Timeout/None, exit 1, no token, complete result/streams and normal
owned completion for a successful timeout observation. A valid success before
expiry, InteractionRequired or other ordinary failure is retained as an insufficient
observation, without a retry or a timeout claim. Exit 2 or incomplete transport is
a transport failure, not a complete typed timeout. Do not stall the network, alter
account/cache/configuration/provider state, force interaction, refresh or change
scopes to manufacture expiry. Local fixed phase observations locate observed
progress but do not prove a dependency was pending at expiry; retain that limit.

Independently admit the exact source, selected artifact, preflight, request,
current operating basis and cumulative accounting before execution. Reserve one
product start/discovery/silent call and zero interactive calls, one metadata pass
of 64 operations/16 MiB plus 8 KiB/30 seconds, and one safe collection pass of eight
operations/1 MiB/30 seconds. Precharge before the first covered read or invocation;
no automatic retry or refund. Preserve all previous failures, conservative charges
and historical noExperimentLive=false. Independently accept the actual and scoped
completion before any dependent work. This one call does not satisfy caller death,
EOF during WAM, human cancellation, hidden-parent UX or the whole Slice.

If this assessment instead completes with a valid unavailable result whose
existing fixed diagnostics establish a current host/session/input obstruction,
independently accept the failed actual and normal completion, retaining its full
charge. After the required actual ordinary desktop state action, admit at most
one separately charged assessment of the same candidate and exact request. This
is a new reviewed call, not an automatic retry or a renewed original deadline.
Require unchanged source/artifact/current-basis admission and the same full
one-call allocation before its first operation. Any result ends this supplement;
no additional attempt, host restoration, account/cache/configuration repair,
forced prompt or network manipulation follows from it.


### WSL Deadline After Dispatch Correction

After independent acceptance of the corrected request-lifetime source, ordinary
Windows publication and existing process scenarios, admit one new noninteractive
personal-account deadline assessment on that candidate. Reuse the exact selected
request, Windows-local configuration, Profile, validator and confidential memory/pipe
transport from the prior deadline recipe. Keep its one-second original request
clock, six-second product completion limit, preflight/validator/outer limits,
allowlisted observations, byte bounds, stop rules and typed Timeout acceptance.
The candidate and public preflight hashes are the only subject-input changes.

Record caller launch-to-complete-streams elapsed time as a caller interval, not an
exact product-entry clock or proof of a dependency pending at expiry. Reserve one
start/discovery/silent call, zero interactive calls, one existing 64-operation
metadata pass of 16 MiB plus 8 KiB/30 seconds and one eight-operation safe-collection
pass of 1 MiB/30 seconds. Independently accept exact source/artifact/call/current
basis and full charges before execution. No attendance is required for this
noninteractive request. Any outcome ends this recipe without retry or refund;
retain ordinary insufficient outcomes and transport failures. This new assessment
does not reopen the exhausted prior supplement or admit state repair, forced UI,
network manipulation, a new observer, or caller-death/EOF-during-WAM execution.

If this new assessment returns a valid unavailable result with the existing fixed
host/session/input indication and normal scoped completion, independently accept
that failed outcome before one separately charged same-request reassessment.
Finish exact preparation first, then require the owner to freshly connect and keep
the ordinary designated Windows desktop usable. Keep the same corrected candidate,
request, limits, observations, operating-basis admission and full one-call allocation.
Any outcome ends this supplement without another attempt. It grants no host switch,
new launch mechanism, state repair, forced UI or interaction permission.


### WSL Deadline Observation Correction

After independent acceptance of the preceding exit-2 reassessment and its normal
scoped completion, admit one same-candidate/request noninteractive diagnostic call.
Correct only the safe projection of existing standard local telemetry. Preserve
stage event start/completion, stage name, bounded elapsed/duration milliseconds
and fixed status for the request and existing authentication phases, at most
32 events. Also preserve fixed completion/cancellation indications, an allowlisted
request-completion outcome and elapsed time, stdout/stderr byte counts and validator
exit/stderr-presence. Do not export trace/span IDs, provider text, arbitrary fields
or any raw result or diagnostics. Invalid observation fields mark observation
failure; they do not change authentication or manufacture a typed result.

Reuse the accepted dispatch candidate, preflight, selected request, Profile,
Windows-only validator and confidential bounded memory/pipe transport. Retain
one-second product, six-second completion, all original preflight/validator/outer
limits and stop rules. Reserve one start/discovery/silent call, zero interactive
calls, one 64-operation metadata pass of 16 MiB plus 8 KiB/30 seconds and one
eight-operation safe-collection pass of 1 MiB/30 seconds before execution.
Independently accept the exact corrected source/call and current basis; unchanged
artifact and input admission remains reusable. No new desktop action or sign-in
permission is required for this noninteractive observation correction.

Any result ends this recipe without retry or refund. Exit 2 remains a transport
failure, even when fixed telemetry suggests a selected terminal outcome; only the
unchanged Windows validator with matching exit and complete transport can accept
a typed result. Missing optional events do not prove an event did not occur, and
phase-start or caller elapsed alone does not prove a dependency pending at expiry
or identify a watchdog branch. Use the fixed observations to choose supported
source correction or retain the specific unknown. This recipe does not reopen a
spent call or admit caller-death/EOF-during-WAM execution, a new observer/controller,
product host, state repair, forced UI or a larger process allowance.


### Corrected-Candidate Real-Provider Baseline

After accepting the preceding diagnostic failure and scoped completion, admit
one ordinary 120-second noninteractive personal WSL request on the accepted
dispatch candidate. This establishes its current real-provider/result baseline
before planning the remaining lifetime cases; it does not repeat the already
accepted old-candidate personal/work pairs or attempt another one-second timeout.
Reuse the existing preflight, selected request, Profile, confidential memory/pipe
transport, Windows-only validator and fixed observation projection above.

Require validated Success/Silent, exit 0, complete result and streams and normal
created-root completion. Preserve the original 120-second product deadline,
130-second completion limit, 30-second preflight, 10-second validator plus five
stop seconds, and 180-second whole call plus five stop seconds. Keep all current
byte, observation, lifetime-writer ownership and stop limits. Reserve one
start/discovery/silent call, zero interactive calls, one 64-operation metadata
pass of 16 MiB plus 8 KiB/30 seconds and one eight-operation safe-collection pass
of 1 MiB/30 seconds before the first covered operation. Exact source/call/current
basis requires independent admission; reuse unchanged artifact/input admission.

Any result ends this recipe without retry or refund. A valid InteractionRequired
ends the silent probe and needs a separately admitted interactive continuation
and fresh sign-in readiness; do not infer permission from desktop readiness.
No new host, account/cache repair, forced UI, process observer/controller or
lifetime experiment is admitted. Preserve the remaining typed-deadline, caller
death, EOF-during-WAM and human UI gaps separately from baseline success.


### Corrected-Candidate Interactive Cancellation

After accepting the preceding valid InteractionRequired result and scoped
completion, admit one personal WSL `interactive-if-needed` request on the same
corrected candidate, selected request, Profile, validator and transport. Preserve
silent-first behavior. Complete exact source/call/current-basis preparation and
independent admission, then obtain fresh actual operator readiness before the
whole one-call precharge and invocation. Existing desktop readiness is not sign-in
or cancellation attendance for this call.

If ordinary WAM sign-in, selection or delegated-consent UI appears, the operator
cancels that surface using its normal cancel or close action. Do not enter
credentials merely for this cancellation case, force interaction, change state
or launch a different surface. Require validated Cancelled/None, exit 1, no token,
complete result/streams and normal created-root completion for the cancellation
claim. Separately record actual operator observations of the surface, action and
window closure when available. Provider Denied, silent Success or another valid
outcome remains its own observation and does not satisfy user cancellation; do
not repeat a successful or insufficient result to manufacture UI.

Reserve one product start/discovery/silent call and one permitted interactive
call, one 64-operation metadata pass of 16 MiB plus 8 KiB/30 seconds and one
eight-operation safe-collection pass of 1 MiB/30 seconds before the first covered
operation. Keep the preceding ordinary 120-second product, 130-second completion,
preflight/validator/outer limits, fixed projection, privacy, writer ownership and
stop rules. Any outcome ends this recipe without retry or refund. Retain missing
UI evidence as incomplete. No account addition, administrator consent, cache or
configuration repair, new observer/controller/host, deadline or EOF/caller-death
experiment is admitted by this cancellation call.

### Corrected-Candidate Interaction-Pipe EOF

After accepting the preceding alternative typed Timeout and normal scoped
completion, admit one personal WSL `interactive-if-needed` request using the same
corrected candidate, selected request, Profile, validator and bounded transport.
Retain silent-first behavior and the original 120-second product deadline. Complete
exact source/call/current-basis review, then obtain fresh operator readiness to
observe any ordinary WAM surface. Do not sign in or cancel merely for this case.

Use the existing single, noninherited lifetime writer. If the product is still
running, close that writer once, 15 seconds after the caller's product launch;
the existing ordinary pipe loop may perform this action without another process,
observer, host or controller. Record whether closure occurred while the product
was running and its caller-relative elapsed time. An earlier result ends the
case without delayed closure or retry. These caller times do not establish the
exact product entry clock or native UI state.

Require validated Cancelled/None, exit 1, no token, complete streams, normal
created-root completion and actual timed writer closure for the pipe-cancellation
result. A claim of EOF during actual WAM additionally requires the operator's
observation of an ordinary WAM surface before that closure and its later state,
together with the existing standard phase observations. Phase events alone do not
prove visible UI or its shutdown. Preserve missing observations as incomplete;
do not force a prompt or repeat an insufficient outcome to manufacture evidence.

Reserve one start/discovery/silent/interactive call, one 64-operation metadata
pass of 16 MiB plus 8 KiB/30 seconds and one eight-operation safe-collection pass
of 1 MiB/30 seconds before the first covered operation. Preserve the preceding
preflight, validator, memory, original deadlines and owned stop limits; closing
the writer does not renew a clock. Independently accept every actual result and
scoped completion. Any outcome ends this recipe without retry or refund. No
caller-death experiment, forced interaction, account/cache/configuration repair,
new tool or effects boundary is admitted.

### Fixed WSL Observation Method

Use this same observation method for caller death, EOF during WAM and human
cancellation/denial. Correct and accept the observation method before spending
further real-account calls on these goals. Keep the product, existing local
telemetry, selected request, Profile, validator and account state unchanged.
No product instrumentation change, new host, controller, executable project,
network exporter, console input handshake or elevated observer is part of this
correction. Retired recipes remain historical evidence, not extra current gates.

Keep three evidence channels separate:

- Existing local OTEL stage-start/completion events establish observed request
  phases. The ordinary caller reads stderr while the operation runs and exports
  only reconstructed fixed event/stage names and bounded elapsed milliseconds.
  Cap progress output at 32 events; never forward raw lines, tags, exceptions,
  identifiers, provider text or stdout. Missing events remain unavailable.
- Ordinary process handles and actual tool returns establish process completion.
  Normal calls additionally require complete streams and Windows-only result
  validation. For caller death, retain one independent Windows process handle
  because terminating the Linux caller removes its result/exit channel.
- Actual operator reports establish visible WAM and the human action when those
  facts are required. Phase events and process exit do not prove visible UI,
  window attribution, provider-wide closure or an unattended interval.

The separate caller-death stock PowerShell command performs one same-name query,
opens and retains the sole native handle, and verifies the accepted candidate
path and original launch-time association. The zero-match preflight and sole
caller launch remain required. Absence, ambiguity or failed binding ends as
unavailable, without elevation, another query or substitute identity. Emit one
fixed Ready fact, including whether the instance is then live, and immediately
perform finite `Process.WaitForExit(int)` on that same object. Read its exit code
and exit timestamp even if it has already exited. Early completion is a valid
observation, not an observer failure or proof of interruption. Never require
post-marker liveness, read `CallerEnded`, use a PTY or add a stdin handshake.

Keep the original 120-second product deadline, launch-plus-130-second completion
bound and 180+5-second foreground bound. Convert the original Windows UTC expiry
once to a Stopwatch budget with the existing four-second margin and reviewed
no-clock-step operating basis; independently clamp the stock command to the
remaining original Linux 125+5-second interval. Waiting with zero remaining
milliseconds may read an already signaled handle but cannot renew the deadline.
Record a late receipt as late evidence, without claiming timely completion.

Use one sequential tool orchestration for startup/Ready qualification, any
caller-only pidfd signal, actual default SIGTERM termination, finite observer
completion and the final known-relay PID/start-time read. Do not leave a model
turn between these steps. Poll admitted originals only within their remaining
original clocks; a first tool return or presentation delay is not an acceptance
condition. Use ordinary non-PTY output and fixed JSON lines. The final relay
read must occur within its original 130-second window; expiration records
Unavailable without another wait or query. Never signal the relay, native
product, shared broker or unrelated process. Before a caller-death action,
require unambiguous caller PID/start-time identity, bound native identity and
live work evidence. An early result or completion is retained as itself. Do
not infer precise cross-host ordering from unsynchronized wall timestamps.

Completion observation and scenario acceptance are separate decisions. A valid
native exit establishes only scoped native completion. It is not a typed result,
pending-WAM interruption, UI closure, persistence or whole-Slice acceptance.
Retain signal, phase, exit and relay facts independently. If ordering or an
actually pending interaction is needed for a claim, require its own evidence;
do not add a liveness failure to the observer to manufacture that evidence.

### Credential-Free Observation Verification

Before further real-account acceptance, admit one batch of at most three stock
PowerShell calls on the same designated host, using public inputs only. Each
starts one known credential-free child with ordinary `Process.Start`, retains
its handle and executes the identical completion block used above:

| Call, once | Expected observation |
| --- | --- |
| Already exited | Stock `cmd.exe /d /c exit 7`; establish its exit, then read the retained handle. Report exit 7 without observation failure. |
| Still running | Stock PowerShell sleeps two seconds and exits 9. Start waiting while it is live; report exit 9 without observation failure. |
| Deadline exhausted | The same two-second child, with a zero remaining wait budget. Report completion unavailable rather than success; independently observe its natural exit within the original test bound. |

These are observer checks, not product authentication or WAM claims. Use the
installed PowerShell 5.1 x64 only, no product/account/configuration access,
network, private streams, new project or retained host. Each call has a single
30+5-second outer bound and at most 4 KiB safe output. Child startup/observation
has five seconds, natural completion eight seconds, and an owned-child-only
kill plus two-second exit observation is the failure fallback; forced cleanup
fails the check. Keep every process handle through actual exit and dispose it.
Any failed check stops the batch without an automatic retry or added test.

Independently review the exact native completion source, three public test
commands, streaming phase projection, one continuous orchestration and operating
basis together. Precharge three shared synthetic actions, one 64-operation
metadata pass of 4 MiB/30 seconds and one eight-operation collection pass of
1 MiB/120 seconds before the first call. Use no real-account units and preserve
all prior charges, failed observations and historical `noExperimentLive=false`.
Independently accept actual check results and scoped completion. After a passing
batch, freeze these observation mechanics for the remaining three goals. A
necessary correction requires a concrete failure; do not add speculative
infrastructure or repeat successful checks.

Further real cases retain the preceding WSL account, private-memory, result,
pipe-ownership and deadline boundaries. Their exact calls, finite allocation and
required human action must be accepted before execution. This verification does
not itself reopen any exhausted real-account recipe or complete caller death,
actual WAM EOF, human cancellation/denial or applicable hidden-parent UX.

### Remaining WSL Acceptance Batch

After independent acceptance of the credential-free observation batch, admit
one separately charged three-case personal-role batch on the unchanged selected
visible-parent candidate, request, Profile, validator and Windows configuration.
Reuse the fixed observation method above without another observation check or
source change to its native completion block or phase projection. Ordinary WAM
provider session/protected-state effects retain the existing Wave boundary.
The exact call and current-absence/sole-launch basis still need independent
admission before any real invocation. This is existing-state acceptance, not
clean first use, forced interaction or a new support promise.

| Case, at most once | Action and evidence |
| --- | --- |
| Caller death without lifetime pipe | Null stdin, no lifetime option, `interactive-if-needed` with mandatory silent first. Bind the same native handle before caller-only default SIGTERM. Require actual caller exit 143 without a normal final result, observed held-native exit within the original bound, and the known original relay ended. Early completion stays itself; do not require post-action liveness or infer immediate Windows signal delivery. No actual sign-in/choice/consent is needed for this case. |
| EOF during actual WAM | One dedicated noninherited lifetime writer, same interaction permission. Obtain actual operator readiness before launch. Keep the writer open until the operator reports an ordinary WAM surface. Then signal only the owned matching caller with SIGUSR1; its ordinary pipe loop closes its own writer once while the product is running. Require observed phase progress, actual surface before closure, validated Cancelled/None, exit 1, no token, complete streams and normal root completion; separately record subsequent window state. A timed or initially closed pipe result is already sufficient for its own claim and is not repeated. |
| Human cancellation/denial | Keep the sole lifetime writer open. After actual readiness, the operator cancels/closes the ordinary WAM or owned parent surface, or declines ordinary delegated consent if offered. Require the actual reported action, the corresponding valid Cancelled or recognized Denied result, exit 1, no token, complete streams and normal root completion. Distinguish parent cancellation from WAM cancellation/denial and record observed closure. Do not enter credentials merely for this case or automate the action. |

All calls retain the original 120-second product, 130-second completion,
10+5-second validator and 180+5-second foreground bounds. Startup and local phase
facts use at most 16 KiB safe output; private product streams remain at most
1 MiB each, configuration/projection at most 8 KiB/1 KiB and validator output
at most 4 KiB. Only fixed reconstructed stage facts, signal/pipe/process facts
and the existing validator conclusions may be retained. No arbitrary stderr,
result, selector, identifier/hash or exception is exported. Stdin never carries
credentials. The SIGUSR1 action is ordinary Linux signaling of the already owned
caller, not a console marker, extra process or control channel to Windows.
A report of no WAM surface does not trigger EOF merely to reproduce the prior
timed cancellation. An early success, timeout, host rejection, unavailable UI
or another valid outcome is retained as itself, without forced UI or retry.

Use a matching Linux pidfd and saved start-time ticks for either caller signal.
Never signal the product, relay or shared broker. Before caller termination,
record the existing Linux UTC/monotonic pair at observer submission and actual
Ready receipt; require both elapsed-clock comparisons against launch within
100 ms. Require the same Ready timestamp `W >= receiptUTC - 2000 ms`, and
`receiptMono + max(0, 126000 - (W - launchUTC))` inside launch-plus-130 seconds,
using matching units. This qualifies backward clock offset and a conservative
original budget without a symmetric bracket or first-return rule. Missing or
failed qualification withholds the signal and dependent execution; it does not
change frozen sources, renew a deadline or authorize another clock query.
Death removes the result path:
collect only the existing native observer and known relay within their original
clocks, in one continuous orchestration. For the two pipe cases, close the owned
writer on an execution failure and use only the remaining original product
allowance; never renew its clock. Preserve any unavailable exit and stop dependent
execution. Reuse the Wave's independently reviewed standing current-absence
basis without a new owner question or exhaustive survey.

Precharge the whole batch: three starts/discoveries/silent/eligible-interactive
calls, four metadata passes of 64 operations/16 MiB plus 8 KiB/30 seconds each,
and three collection passes of eight operations/1 MiB/180 seconds each. Reserve
all slots before the first covered operation; no refund for failed or unsubmitted
slots. Independently accept each actual and scoped completion before advancing.
A safely completed alternative may leave its claim open while another separately
admitted case progresses. New ownership or safety gaps stop the batch. The
operator may close only an identified test-created surface normally; no foreign
cleanup, account/cache repair, administrator consent, registration change,
main-program modification, new tool/project/controller/host or network exporter
is included. Applicable hidden-parent UX and whole-Slice acceptance remain open.

#### Single Caller-Death Continuation After Desktop Reactivation

After independently accepting the initial batch's normally completed
host_session_inactive alternative and closing only that case, permit one
separately charged fresh CallerDeath request. Before launch, the operator must
actually reconnect and unlock the same ordinary Windows desktop and report
readiness. This state correction does not prove the earlier session state or
cause. Retain the failed case and its exhausted slot; the two unsubmitted human
cases remain in their original precharged batch.

Use exactly the preceding CallerDeath command, source, candidate, account
configuration, native completion and phase projection, clock qualification,
continuous collection and original deadlines. Do not modify or repeat the
observation checks. Independently admit the exact fresh call and operating basis,
then precharge one start/discovery/silent/eligible-interactive unit, two metadata
passes of 64 operations/16 MiB plus 8 KiB/30 seconds each and one collection pass
of eight operations/1 MiB/180 seconds. No refund, automatic retry, new host,
controller, account/cache repair or main-program change is included.

Accept the actual and scoped completion before advancing. Another early
alternative remains itself. If host_session_inactive recurs after the reported
desktop action, stop dependent real calls and diagnose the concrete source or
environment cause before proposing another execution; do not repeat desktop
preparation or change the frozen observer speculatively.

#### Remaining Goals From Observed Entry Conditions

After accepting the normally completed personal Success/Silent alternative,
the two still-unsubmitted human cases may use the already admitted selected
work role. Retain their original whole-batch charges and slots; independently
admit the role-specific call, Windows-local selection, applicable supplied tenant,
unchanged Profile/scope/validator and operating basis before execution. The sole
existing caller may take only a fixed Personal or Work role argument. Its native
completion and live phase projection remain unchanged; product code is unchanged.

Run the work-role WamEof case first, after actual readiness. Its writer stays
open until actual operator WAM confirmation. If it completes silently or otherwise
fails to establish actual WAM EOF, accept that alternative and stop this route;
do not submit the other human slot or probe another account to obtain a prompt.
Only accepted actual WAM appearance and EOF cancellation permit the remaining
work-role continuation: one separately charged CallerDeath and the original
unsubmitted HumanCancellation case. A later early alternative stays itself.
No interaction is forced, and account, cache, scopes and configuration are unchanged.

For that single additional CallerDeath, wait on the same original for its
CallerStarted fact within the existing 30-second preflight bound. An empty
initial tool return is not a completed preflight or permission to skip that wait.
If a final result also arrived, do not signal. Then use the frozen native handle,
clock qualification, caller-only signal and continuous completion/relay sequence.
Precharge the same one-unit real, two-pass metadata and one-pass collection
allocation as the desktop-reactivation continuation before its first covered
operation; no debit is made while that conditional case remains unsubmitted.
Preserve all previous charges, failures, unknowns and separately scoped completions.

#### Independent Caller Death With Existing Silent State

After accepting the work-role WamEof Success/Silent alternative and its scoped
completion, stop that human-case route as specified above. Actual WAM EOF and
HumanCancellation remain open; their missing entry condition does not prevent
the separate caller-death claim, which requires no WAM surface or human action.
Permit one independently admitted, separately charged Work CallerDeath request
on the unchanged selected candidate, request, source and operating basis.

Use the existing no-lifetime-pipe caller-death sequence, retained native handle,
clock qualification, matching caller-only signal and original finite deadlines.
Poll the same original for CallerStarted within its 30-second preflight bound;
request a three-second initial caller yield and one-second observer/poll yields.
Actual tool returns may take longer; the original clocks still govern.
Do not signal after an observed final result or completed native alternative.
An early alternative remains itself, with no automatic retry or forced UI.
The frozen native completion block and phase projection do not change.

Before its first covered operation, charge one fresh real unit in each category,
two metadata passes and one collection pass with the identical limits used by
the desktop-reactivation continuation. Independently accept its actual and scoped
completion. Preserve the exhausted human EOF slot, unsubmitted cancellation slot,
uncharged earlier conditional proposal, all prior charges and historical unknowns.
This separate case does not activate the stopped human route or establish WAM UX.

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

## Hidden Owned-Parent Candidate

This experiment evaluates the hidden owned-parent hypothesis in the
[Windows design](../../designs/windows-ado-authentication.md#parent-selection-decision),
under the existing Windows Slice Wave, designated hosts, selected roles, normal
account effects and shared pools. It does not replace the accepted candidate,
add a desktop application or introduce a runtime mode/public command.

Pin a separate experimental source commit based on accepted `main-v2`. Its
production-code delta is limited to omitting `ShowNativeParent(window)` in
`OwnedRequestHost.RunWindow` and setting `BrokerOptions.Title` to
`Unofficial hcoona/microsoft-authentication-cli`. Preserve the original creation,
controls, gate/readiness ordering, STA pump, rechecks, provider policy and cleanup.
Adapt the existing `ReadyParentCarriesAdmittedBranding` visibility assertion to
require a live owned hidden parent; retain its immutable-Profile and thread checks.
No new project, native observer, controller, launcher, export or dependency is
part of this comparison. Independently admit the exact source and calls before
any build or execution; the experimental branch is not a product acceptance.

Use the same installed SDK/runtime, MSAL/Broker/NativeInterop, MSVC/Windows SDK,
public offline caches and bounded ordinary compilation/artifact recipe already
admitted for the current candidate. Use fresh source/build/artifact destinations.
At most two offline preparations, two build/test actions, one Native AOT publication
and four credential-free native scenarios are permitted by this recipe; reserve
all actual roles before their batch. Each compiler phase has at most 600 seconds,
the combined foreground preparation/build/publication call at most 1,260 seconds
plus five seconds for stopping, and bounded public logs/artifacts under the reused
recipe. A failure stops dependent work; no automatic retry or tool installation.

Run only these existing Windows scenarios, once each, under one finite runner call:
`ReadyParentCarriesAdmittedBranding`, `CancellationDuringCreationRejectsLateParent`,
`InternalCloseDoesNotCancelCaller`, and `CompletionWaitsForActualUiThreadExit`.
Give the call at most 120 seconds plus five seconds for stopping and 1 MiB per
safe output stream. Require actual runner exit, complete results and all four
passing cases. These establish own-HWND/readiness/teardown behavior with synthetic
providers, not WAM, user-visible branding or real user cancellation. Other tests
that require a visible parent remain outside this experimental subset; preserve
their accepted evidence for the unchanged selected implementation.

After independent artifact and synthetic acceptance, admit at most three actual
product calls for the same selected personal request, sequentially: (1) silent-only
assessment; (2) only after an accepted closed `InteractionRequired`, separately
admitted interactive permission with fresh actual readiness and silent-first
acquisition; (3) only after accepted normal success, fresh-process silent reuse.
An accepted success in case 1 skips case 2 without refund and leaves hidden-parent
WAM behavior unvalidated. Do not force interaction, refresh, claims, consent,
account choice or scopes to manufacture UX evidence. Cancellation instead of
success ends this authentication comparison; no success-gated reuse follows it.
All real calls retain the accepted 120-second product, 130-second process,
180+5-second foreground, memory/output limits and Windows-only result validator.
Use the existing bounded WSL private-memory/pipe transport if the exact call does;
no confidential output may enter files, traces, chat or committed evidence.

Before case 2, communicate the public unofficial project and experimental Profile's
registration-owner/external-dependency context, the expected WAM-only visible
surface, the actual sign-in/choice/consent action if needed, and available caller
cancellation. Wait for fresh actual readiness. The operator may cancel on WAM's
own surface; neither a hidden button nor synthetic `WM_CLOSE` is a usable human
Cancel action. Unexpected owned-window display, unusable focus, unrequested
interaction, a private-output leak, mismatched inputs or uncertain completion stops
the batch. Use only the existing owned stop procedure; do not manipulate foreign
windows or terminate the shared broker. Retain provider-managed session updates
under the standing account-effects boundary, including after cancellation.

Observe through existing standard local OTEL stages, fixed diagnostics, normal
stdout validation and actual process return. Record operator observations separately
when WAM actually appears: visible surfaces/title, ability to interact, performed
login/cancellation and disappearance. Do not export screenshots, window handles,
titles containing private data, selectors, tokens or provider text. A title setting,
span completion or caller exit alone does not establish UX or full native lifetime.
No new window collector or observation tool is permitted.

If the initial silent assessment returns a complete valid `MechanismUnavailable`
without a retained fixed reason, independently accept its failure and normal
completion, then close that comparison with all charges retained. Admit at most
one separately charged silent diagnostic call of the same candidate and selected
request. Reuse the existing WSL transport, validator and standard local output;
project only the existing fixed phase names and mechanism indication. A missing,
malformed or unavailable observation cannot change result acceptance, cause a
retry or expose raw diagnostics. This is not an additional host query or observer.

Only an accepted fixed diagnostic that establishes a current host/session/input
obstruction permits one fresh three-case comparison after the required actual
operator state action and independent current-basis/call admission. It uses the
same silent assessment, conditional interaction and success-gated reuse rules
above; state readiness alone is not interaction permission. Allocate that whole
fresh batch before its first operation, without reusing or refunding the original
skipped reservations. No further correction batch, configuration/cache repair,
prompt manufacturing or interaction follows from this supplement. A diagnostic
success does not itself admit interaction or dependent reuse.

Allocate exact finite preparation and real batches from the current accounting;
reserve at most ten metadata and ten safe-collection passes cumulatively for this
recipe, within the shared passive ceilings. Reuse the prior exact per-role bounds:
public materialization at most 16 MiB/30 seconds, one bounded public artifact pass
at most 5 GiB/60 seconds, and each account call's 16 MiB plus 8 KiB/30-second
metadata and 1 MiB/30-second safe collection. Exact calls must include any scenario
build and runner inputs in these allocations. Retain all spent/failed/unused
charges, historical flags and original deadlines. Independently accept each actual
and scoped completion before its dependent step. Preserve the current candidate,
public artifacts and safe evidence; no cache/configuration repair, install, cleanup
of historical unknown objects or general support promise follows from this recipe.

## Windows Request Lifetime Dispatch Validation

After the accepted request-lifetime dispatch correction, build the unchanged visible
owned-parent product from its accepted source. Reuse the prior current-candidate
compiler environment, installed toolchains and public offline package cache. Preserve
the selected candidate until the new source, artifacts and relevant controlled
process outcomes have independent acceptance. No account configuration, Profile,
cache, broker state, hidden-parent behavior or dependency changes are part of this
preparation.

In fresh dedicated roots, admit at most two offline preparations, two build/test
actions, one Native AOT publication and 12 synthetic process scenarios. The compiler
call restores the CLI and existing Windows scenario project, builds the latter and
publishes the CLI. Reuse the existing ordinary creation-time process handles and
owned stop method, with one MSBuild node and no shared compiler, node reuse or build
servers. Restore phases have at most 180 seconds each, build 240 seconds and publish
600 seconds; the whole call has at most 1,260 seconds plus five stop seconds. Bound
each of the four Windows-local compiler logs to 512 KiB, aggregate 2 MiB, and retain
at most 1 GiB and 10,000 entries. Export only the existing fixed code/fact report.

Run these unchanged cases once through the existing scenario runner:

- ProcessScenarios: selected success despite broken diagnostics, initially closed
  lifetime pipe, writer closure rejecting late success, and uncooperative deadline.
- OwnedProcessScenarios: normal closure, local cancellation, local host fault, actual
  UI-thread drain, outgoing callback drain, and closure arming the bound before core
  terminal selection.
- DefaultHttpCompositionScenarios: cancellation through drain, and disposal stall
  retaining the watchdog.

These 12 cases cover result transport, pipe cancellation, original deadline/watchdog,
owned UI/callback drain and HTTP disposal. Controlled providers and synthetic
Profiles remain credential-free. Allow the runner at most 120 seconds plus five
stop seconds, each safe stream/log/TRX at most 1 MiB, and require actual runner exit,
complete fixed results, all expected cases and their required owned-child completion.
No new launcher, controller, observer or executable project is admitted.

Allocate three metadata and three safe-collection passes before the batch. Reuse
the prior fixed public-source materialization, four compiler-log projection, three
public output acquisition and scenario-result qualification recipes, with their
16 MiB/30-second, 2 MiB/30-second, 5 GiB/60-second and bounded scenario limits.
Independently admit exact source/input/calls, operating basis and full charges before
the first Windows read or invocation. A failure stops dependent execution without
retry or refund. Independently accept compiler/artifact outcomes before the runner,
and accept all actual outcomes before executable account use. Reuse the accepted
Core scenarios and unchanged dependency/native API evidence. These controlled cases
do not establish a real WAM cancellation, actual WSL deadline or full Slice acceptance.

## Outcome-Based Execution and Accounting

Continue the existing sanitized cumulative accounting carrier. Preserve every prior
charge, failed/partial start, pending flag, historical uncertainty and role assignment.
The shared Wave ceilings remain 100 preparation, 400 build/test, 60 Native AOT
publication and 1,200 synthetic scenarios; the real pool remains separate at
96 starts/discoveries/silent calls and 52 interactive calls. This protocol changes
execution mechanics, not those authorizations or historical consumption.

Passive metadata ceilings remain 512 passes / 16 GiB reserved bytes / 30,720 seconds;
Collection capacity is 560 passes / 1 TiB reserved bytes / 153,600 seconds, including
the remaining preparation and acceptance buffer under the same Wave outcome and
effects boundary. This revision changes only the pass ceiling; it preserves all
consumption, failed and unused reservations, and original byte/time ceilings.
Capacity is not an instruction to consume the buffer.
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

## Focused Request Lifetime Dispatch Check

Use the existing Core scenario project to check terminal-task availability while a
synthetic dependency blocks synchronously before returning its Task. Cover caller
cancellation and original deadline expiry, each with and without a pending
cancellation callback. Keep the synthetic operation and callback pending until the
test has checked terminal-task availability, cancellation, withholding late success
and incomplete actual drain. Release both gates in `finally`, observe operation and
callback completion, and join the one owned caller thread within finite fixture
limits, including after an assertion failure. No Windows, broker, account, UI or
private input is involved.

Independently admit the exact red and green source trees and calls before execution.
The red selection adds these four cases to the unchanged inline-dispatch source;
expected terminal-task wait failures demonstrate the missing behavior. A compiler
failure, unexpected test result or incomplete owned completion stops the batch.
The green selection applies the reviewed dispatch correction and any required
fixture publication synchronization, then runs RequestLifetimeScenarios,
ApplicationScenarios and TelemetryScenarios in the existing project. Retain the
expected failed red evidence; it is not a passing product observation.

Allocate one offline preparation action and two combined build/test actions from
the remaining common technical pool before the first SDK call. Use the admitted
Linux SDK 10.0.401/runtime 10.0.12, retained public offline feeds, locked dependencies,
cleared credentials and network sources, audit disabled, and fresh dedicated output
roots bound to each admitted source tree. Disable node reuse, shared compilation,
build servers and tool/test telemetry. Each foreground call has at most 180 seconds
plus five stop seconds and 8 MiB public output; the batch retains at most 1 GiB and
10,000 entries. No detached compiler or test process may survive completion.

There is no real-account or passive-collection charge, automatic retry, download,
new executable project or controller. Preserve all historical failures and charges.
Independently accept red/green outcomes and scoped completion before relying on the
correction. This check establishes controlled lifetime behavior, not the cause of a
real exit-2 failure, actual Windows shutdown, WAM cancellation or WSL acceptance.

## Focused Forced-Interaction Implementation Check

Validate the accepted `force-interactive` account-selection intent in the existing
Core and Windows scenario projects on the admitted WSL2 Linux x64 development
environment. This is a separate finite batch; the earlier focused dispatch batch
and real-account routes remain spent or stopped as recorded.

Independently admit the exact implementation, scenario selection and ordinary
foreground calls before execution. Core coverage includes argument admission and
projection, skipping a successful silent path, exact discovery and ambiguity,
selected account or requested hint, one interactive call, final identity rejection,
terminal provider failure, owned-parent cleanup and original cancellation/deadline.
Windows adapter coverage uses the existing controlled MSAL session to check
request-local account-selection intent without constructing or invoking a broker.
Exclude `MsalConstructionScenarios` from Linux execution: their Windows-only
broker-enabled assertions require the designated Windows environment. No private
input, network request, availability check, native load, account/token acquisition,
window or product/child process is admitted. These checks do not establish WAM UI.

Allocate at most two offline preparation and two combined build/test actions from
the shared technical pool. Use installed SDK 10.0.401/runtime 10.0.12, retained
public offline feeds, locked dependencies, cleared credentials/network sources,
audit disabled and fresh dedicated output/cache/temp roots. Disable build servers,
node reuse, shared compilation and tool/test telemetry. Each of the four calls
has at most 180 seconds plus five stop seconds and 8 MiB public output; the batch
retains at most 1 GiB and 10,000 entries. Keep exact finite test filters in the
reviewed call; no Windows-only scenario or unfiltered test run is included.

Precharge before the first SDK call. A failed compilation, unexpected test result,
overflow or incomplete owned-process completion stops dependent execution without
automatic retry. Retain failed evidence and intentionally retain only public source,
dependencies, build output and test reports. Independently accept actual results
and scoped completion before relying on them. No new executable project, runner,
controller, observation check, account effect or real-account charge is included.

## Forced-Interaction Candidate Preparation

After accepting the exact managed implementation and relevant controlled outcomes,
publish its Windows x64 Native AOT candidate on the designated ordinary Windows
host. A failed managed batch remains failed; independently accepted passing cases
may establish their narrower coverage. Reuse sufficient unchanged source, dependency,
host/lifetime and earlier real-account evidence. Preserve the selected candidate
until the new compilation, artifacts and Windows construction checks are accepted.

Reuse the existing ordinary compiler shell, installed SDK/runtime, MSVC and Windows
SDK, public offline feeds/cache, creation-time process handles, fixed diagnostic
projection and owned stop method. In fresh dedicated roots, allocate at most two
offline preparations, two build/test actions and one Native AOT publication from
the shared pool. Restore the CLI and existing Windows scenario project, build the
latter and publish the CLI with one MSBuild node and no build servers, node reuse
or shared compilation. Restore phases have 180 seconds each, build 240 seconds,
publish 600 seconds and the whole compiler call 1,260 seconds plus five stop seconds.
Each compiler log is at most 512 KiB, aggregate 2 MiB; retain at most 1 GiB and
10,000 entries. Do not install or download a toolchain or change broker/account state.

Then run only the four existing `MsalConstructionScenarios` on Windows, with rejecting
HTTP, no availability or broker/account/token invocation, and no product/window/child
scenario. Bound this foreground call to 120 seconds plus five stop seconds, each
public stream/log/TRX to 1 MiB, and require actual exit, complete results and all four
cases passed. This checks Windows builder settings and original cancellation, not
WAM effectiveness. Do not repeat the accepted Linux Core/controlled-session cases or
the unchanged process/lifetime scenarios merely for this candidate.

Independently accept exact source/input/calls, current operating basis and whole charge
before the first covered Windows operation. Allocate three metadata and three safe
collection passes using the existing public-source materialization, compiler-log
projection, public-output acquisition and result qualification, with their fixed
16 MiB/30-second, 2 MiB/30-second, 5 GiB/60-second and scenario bounds. The exact call
must supply stricter finite operation selections and charges. Stop on unexpected
failure, overflow or incomplete owned completion without retry or refund. Retain failed
evidence. Accept compiler/artifact outcomes before the Windows checks, then accept
their actual/scoped outcomes before selecting the candidate for real use. No new
runner, controller, retained host, observer or account invocation is admitted.

### Forced-Interaction WSL Acceptance

After independent candidate acceptance, admit one new two-case batch for the already
selected work role, unchanged Windows-local configuration, Profile, applicable tenant,
scopes and Windows-only validator. Both calls explicitly select `force-interactive`
under the accepted contract; no engine silent call, cache clearing or account repair
is permitted. Provider-managed session reuse/updates retain the ordinary Wave boundary.
The stopped older human route and exhausted EOF/caller-death attempts stay stopped or
spent. This is a fresh finite allocation, not replay or restored capacity.

| Case, at most once | Action and acceptance |
| --- | --- |
| EOF during actual WAM | Obtain fresh readiness, keep the sole lifetime writer open, and wait for the operator to confirm an actual WAM surface while the request is pending. Only then signal the matched existing caller with SIGUSR1 to close its owned writer once. Require valid Cancelled/None, exit 1, no token, complete transport and normal owned completion; separately record subsequent observed windows. |
| Actual WAM cancellation/denial | Obtain fresh readiness and keep the lifetime writer open. The operator cancels/closes the identified WAM surface or declines ordinary delegated consent if offered. Require the reported WAM action, valid Cancelled or recognized Denied, exit 1, no token, complete transport and normal owned completion; distinguish a parent-window action and record observed closure. |

Use the frozen local OTEL phase projection, ordinary process/pipe facts and actual
operator reports; no fourth observation check or retuning is admitted. The existing
caller may change only the explicit interaction argument and accepted candidate path.
Preserve its pipe ownership, signal matching, finite loops and confidential transport.
Use 120-second product, 130-second completion, 10+5-second validator and 180+5-second
foreground bounds. Configuration/projection remains 8 KiB/1 KiB, private streams
1 MiB each, safe progress 16 KiB and validator output 4 KiB. Actual WAM confirmation
must precede EOF; an API phase or `interaction: interactive` result is insufficient.

No operator credential entry is required for these cases. An early success, missing
WAM, timeout or another valid alternative remains itself; do not manufacture a prompt
through another account, scopes, cache state, UI automation or a retry. Independently
accept each actual/scoped outcome before the next case. A safely completed alternative
may leave its claim open while the separately admitted other case proceeds; a new
ownership/safety gap stops dependent calls. Close only the owned writer on failure
and retain the remaining original product allowance and current-absence disposition.

Precharge two starts/discoveries/eligible interactive calls and zero engine silent
calls from the existing real pool, plus four metadata passes of 64 operations/16 MiB
plus 8 KiB/30 seconds and two collection passes of eight operations/1 MiB/180 seconds.
Independently admit exact source, request, candidate, validator, calls, current basis,
accounting and needed human actions before execution. No refund, account probing,
administrator consent, registration change, authenticated service request, new tool
or network exporter is included. No successful alternative, allocation or missing
observation completes actual WAM, hidden-parent UX or whole-Slice acceptance.

## Focused Provider Failure Observation Correction

Implement the Windows design's fixed `error.type` observation through the existing
sanitized provider-failure seam, owned request span and bounded local projection.
Use the existing Core and Windows controlled scenario projects. Check fixed MSAL
and broker classification, rejection of arbitrary codes/property values, committed
failure attribution, superseding cancellation/deadline, telemetry-off/broken sinks
and omission of unknown or injected attributes. This is an additive diagnostic
correction, not a change to authentication or protocol 1 outcomes.

Admit one separate offline batch with at most two preparation and two combined
build/test actions. Reuse the installed Linux SDK/runtime and retained public feeds,
locked dependencies, cleared package-source credentials, disabled audit/tool telemetry,
one node, no build servers/node reuse/shared compilation, and fresh dedicated roots.
Each foreground call has 180 seconds plus five stop seconds and 8 MiB public output;
the batch retains at most 1 GiB/10,000 entries. Exact filters cover TelemetryScenarios,
ApplicationScenarios, RequestLifetimeScenarios and MsalAdapterScenarios only. No
Windows construction, native load, account, network, window or child process runs.
Independently accept exact source/calls and precharge before SDK execution; a failed
or partial result stops dependent work without retry/refund. Independently accept
actual results and scoped completion before relying on them.

After those gates, admit one Windows candidate preparation using the established
ordinary public-source materialization, compiler shell, public-output acquisition
and qualification methods on the same host/toolchains. Use fresh destinations and
one CLI restore (180 seconds) and one Windows x64 Native AOT publish (600 seconds),
with a 780+5-second foreground bound. Allocate one preparation, one build/test and
one publication action, three metadata passes of at most 128 operations/16 MiB/30
seconds, and two collection passes of at most 128 operations/5 GiB/60 seconds.
Keep existing offline feeds, compiler ownership/stop rules, 512 KiB per log and
1 GiB/10,000-entry retention bounds. Retain only necessary public product/provenance
files. Reuse the accepted four Windows construction cases only after independent
review confirms their builder/configuration/dependency basis is unchanged; otherwise
stop and admit the smallest required replacement. No repeat of sufficient managed,
construction or process/lifetime checks is required solely for a new filename.
Accept exact inputs/calls/current basis before execution and independently accept
compiler/artifact correspondence and scoped completion before selecting the candidate.

The sole permitted caller observation change is a whitelist extraction of optional
`error.type` from the completed request event into existing safe PhaseEvents. Keep
the live phase projection, native completion block, pipe/signal ownership, clocks,
finite loops, private transport and result validator unchanged. Independently review
this narrow delta and its synthetic input cases; no fourth calibration or new observer,
controller, retained host, exporter, UIA or executable project is admitted. Candidate
path/hash binding may change after accepted artifact correspondence.

Then admit at most one distinct Work WSL diagnostic request under the same selected
Windows-local configuration, Profile, tenant and scopes, with `force-interactive`,
zero engine silent calls and the existing sole lifetime writer held open. Allocate
one start/discovery/interactive call, one metadata pass of 64 operations/16 MiB plus
8 KiB/30 seconds and one collection pass of eight operations/1 MiB/180 seconds.
Use the existing 120-second product, 130-second completion, 10+5-second validator
and 180+5-second foreground limits and existing private/output bounds. Independently
admit exact source/candidate/request/current basis and precharge; obtain fresh
readiness if ordinary sign-in, selection, cancellation or consent may need input.
The operator may cancel an identified WAM surface; no credentials or state repair
are required. Do not close the live writer to manufacture EOF evidence. Retain the
actual typed outcome, fixed classification, complete transport/owned completion
and any operator observation, without promising a prompt or a particular failure.

This diagnostic request does not replay the spent WamEof slot or caller-death case,
activate stopped routes, or spend the existing unsubmitted HumanCancellation slot.
All previous charges, failures and unknowns remain. No automatic retry, cache/config
repair, other account or raw provider output is permitted. Independently accept the
actual/scoped outcome before further authentication. The original HumanCancellation
slot may later bind to an independently accepted corrected candidate through its
unchanged acceptance procedure; diagnosis alone completes none of the open WAM or
hidden-parent claims.

## Focused WAM Account-Selection Mapping Correction

Correct the forced interactive adapter using the Windows design's unbound sign-in
mapping. Preserve selected-account discovery and ambiguity rejection, the request's
exact selector and final candidate validation, both silent-first modes, one interactive
call, parent ownership, original cancellation/deadline, protocol outcomes and fixed
OTEL projection. Remove the extra-query `prompt` mapping; do not replace it with an
undocumented native property. The accepted diagnostic's `broker_contract` category
is a failure-boundary observation, not proof of the offending parameter. Source
inspection and a controlled mapping check do not establish real WAM effectiveness.

Admit one separate offline batch using the existing Core and Windows scenario projects:
at most two preparation and two combined build/test actions, with exact finite filters
covering ApplicationScenarios, InteractionScenarios, RequestLifetimeScenarios,
TelemetryScenarios, MsalCompositionScenarios and MsalAdapterScenarios only. Check forced
intent with and without a discovered match, omission of account/hint and extra query
parameters at the real interactive-builder boundary, preservation of ordinary account/
hint/claims/tenant/scopes/parent/correlation mapping, exact identity rejection, and
original cancellation/deadline. Use a construction-only controlled builder; do not
execute it, initialize or check broker availability, load native libraries, read private
input, create windows or reach account/network state. Exclude Windows construction
and all unfiltered scenarios. Reuse the installed SDK/runtime, public locked offline
feeds, empty source credentials, audit/tool telemetry disabled, one node, no build
servers/node reuse/shared compilation and fresh dedicated roots. Each foreground call
retains 180+5 seconds and 8 MiB public output; retention is 1 GiB/10,000 entries.
Independently admit exact source/calls and precharge before SDK execution; accept actual
results and scoped completion before candidate preparation. Failures stop dependent
execution without automatic retry, charge refund or counter reset.

After those gates, admit one Windows candidate preparation through the unchanged
ordinary source-materialization, compiler shell and public artifact qualification
methods. Allocate one preparation, one build/test and one Native AOT publication;
three metadata passes of at most 128 operations/16 MiB/30 seconds and two collection
passes of at most 128 operations/5 GiB/60 seconds. Keep the same installed toolchains,
offline feeds, one CLI restore at 180 seconds and one x64 publish at 600 seconds,
780+5-second foreground limit, 512 KiB logs, ownership/stop rules and 1 GiB/10,000-entry
retention. Independently admit exact source/calls/current basis, then accept actual
compiler/artifact correspondence before selection. Reuse the four accepted Windows
construction cases only if independent review confirms the application-construction
function and its configuration/dependency basis remain unchanged; a changed containing
file alone does not require repeating the same construction evidence. Otherwise stop
and admit the smallest necessary replacement under a separate finite protocol.

After independent exact corrected-candidate/caller/current-basis admission, permit one
new Work `WamEof` attempt and the already reserved, unsubmitted Work `HumanCancellation`
slot. The new EOF attempt allocates one product start/discovery/interactive call and
zero engine silent calls; the human slot retains its earlier charge without refund or
double charge. Each call allocates one metadata pass of 64 operations/16 MiB plus
8 KiB/30 seconds and one collection pass of eight operations/1 MiB/180 seconds; reuse
already reserved passive capacity only where its exact role is unchanged. Precharge
new allocations before any covered Windows/private/product operation. Preserve all
spent EOF, caller-death and diagnostic attempts; no automatic retry is admitted.

Bind the existing caller/preflight only by corrected candidate path/hash. Do not change
observation, native held-handle completion, private memory/pipe transport, validator,
signals, sole-writer ownership or clocks. Reuse exactly three accepted observation
checks; no fourth calibration, UIA, observer, controller, retained host, exporter or new
executable project. Product `force-interactive` and validator's existing Boolean-true
permission projection remain distinct and unchanged. Both calls retain the same
Windows-local selected Work configuration, Profile, tenant and scopes, normal protected
provider state effects and historical operating-basis dispositions. No account/config/
cache repair, alternate identity, scope change, elevation, reboot or resource request.

Use the existing Remaining WSL Acceptance and Forced-Interaction WSL Acceptance
procedures unchanged: 120-second product, 130-second native completion, 10+5-second
validator and 180+5-second foreground bounds, existing private/output caps and safe
fixed projection. Obtain fresh actual readiness before each attended call. For EOF,
keep the writer open until the operator identifies WAM and the original is still live;
then signal only the identity-matched caller once through its held association. No WAM
confirmation or early completion means no signal and no EOF claim. For human cancellation,
keep the writer open and require actual cancellation/close or delegated consent denial
of identified WAM; no credential entry is needed. An unidentified parent action is not
WAM cancellation. Independently accept each actual/scoped outcome before the next
real call. Preserve protocol-valid alternatives and incomplete UI/claim evidence;
a new ownership or safety gap stops dependent execution. These allocations guarantee
no particular prompt or outcome and complete no whole-Slice claim by themselves.

## Focused Validator Runtime Binding Correction

The observed Work WAM EOF attempt reached actual operator-confirmed WAM and closed
its sole writer while the product was live. It returned complete streams and a fixed
cancellation indication, but the unchanged result validator exited 150 without check
conclusions. Preserve that failed acceptance, spent attempt and all charges. The
operator's later normal close of the remaining external WAM surface is cleanup,
not the reserved human-cancellation case. External broker surfaces retain the Windows
design's rule against forced rollback; no global quiescence is inferred.

The independently admitted public metadata read established that the validator's
unchanged runtime configuration requests `Microsoft.NETCore.App` 10.0.12 with
`rollForward: Disable`, while the designated Windows installation contains 10.0.13
and no 10.0.12 directory or CoreCLR file. This establishes a current prerequisite
mismatch; it does not recover the discarded validator stderr or validate the earlier
result. Retain the original result and transport facts without claiming typed-result,
protocol or no-token checks.

Use the same admitted validator DLL, dependency and runtime-configuration files,
with their existing hashes. Bind only its ordinary `dotnet` launch to the already
installed 10.0.13 by placing `--fx-version 10.0.13` before the DLL path. The
[documented option](https://learn.microsoft.com/dotnet/core/tools/dotnet#options-for-running-an-application)
overrides the first framework reference; this validator has exactly one reference.
Independently accept the current public host/runtime correspondence before execution.
This changes the validation helper's runtime, not the Native AOT product, parser
source, request, account configuration, result contract or authentication dependencies.
No runtime installation, repair, configuration rewrite, validator rebuild or new
executable project is included.

Before any real use, admit one credential-free Windows check batch of two existing
validator invocations: a fixed public `Cancelled` result with exit 1 must return valid
protocol and matching outcome/route conclusions; the same public result with a duplicate
member must return only the fixed validation failure with validator exit 2. Use an
explicit synthetic email under `example.invalid`, `common`, the existing Boolean-true
interaction projection and Azure DevOps default-scope association. Neither result
contains a token or provider/account state. Keep inputs below 1 KiB, each output below
4 KiB and each invocation at 10 seconds plus five stop seconds, with one 90+5-second
foreground batch. Require complete streams, actual exits and scoped completion.
Allocate one build/test action and two synthetic process scenarios, zero preparation,
publication or real-stage calls, one metadata pass of at most 64 operations/32 MiB/30
seconds and one collection pass of at most eight operations/1 MiB/90 seconds. Bind
exact public inputs, current host/runtime, source/calls and accounting independently;
precharge before covered operations and independently accept actual results. A failure
stops dependent real execution without retry or refund. Reuse sufficient prior parser,
product and construction evidence.

After those checks and exact corrected-caller/current-basis admission, permit one new
Work WAM EOF attempt plus the existing reserved, unsubmitted Work HumanCancellation
slot. Charge one new start/discovery/interactive call and zero engine silent calls,
one metadata pass of 64 operations/16 MiB plus 8 KiB/30 seconds and one collection pass
of eight operations/1 MiB/180 seconds. Reuse the human slot's unchanged real and passive
roles without double charge. Preserve every spent EOF, caller-death and diagnostic
attempt and the historical global `noExperimentLive=false`.

The sole caller change is the validator's two explicit framework-version arguments;
candidate path/hash binding may follow its already accepted candidate. Keep observation,
native completion, private transport, sole-writer/signals, clocks, finite limits and
Windows-only validation unchanged. Apply the existing WAM EOF and human-cancellation
procedures, including fresh readiness for each attended call, actual WAM confirmation
before live EOF and independent actual/scoped acceptance before the next authentication.
No fourth observation check, observer, UIA, controller, retained host, exporter,
credential entry, account/cache repair, scope change, elevation or reboot is included.
Valid alternatives and missing evidence remain incomplete; this correction guarantees
no prompt, result, window disappearance, hidden-parent UX or whole-Slice acceptance.

## Selected Visible-Parent UX Observation

After independent acceptance of the existing named WSL lifetime/action results,
admit one attended observation of the selected visible-parent implementation on
the same Windows 11 x64 interactive desktop and WSL2 caller. Reuse the accepted
candidate, explicit Profile, selected work role, applicable tenant/scopes,
Windows-local configuration, result validator and frozen observation method.
The hidden-parent candidate remains unpromoted. This supplement collects the
selected presentation's missing physical evidence; it makes no general support
or undeclared-display/accessibility claim.

Use one explicit `force-interactive` request, no engine silent acquisition, with
the sole lifetime writer held until result completion. Reuse the existing human
action caller procedure, without live EOF, signals or caller termination. Bind
it to this distinct UX observation in the exact call and accounting; no spent
HumanCancellation or other reservation is reused. Keep the existing 120-second
product, 130-second completion, 10+5-second validator and 180+5-second foreground
bounds, private-memory/pipe limits, preflight and Windows-only validation.

Before fresh readiness, explain the fixed public fork/Profile/external-owner
context and the ordinary observation/actions. Record only the existing display
scale and applicable assistive interaction, without machine/account identifiers;
make no display, account or cache changes. Observe actual readability and layout,
fork/Profile/owner and provider-controlled sign-in context before authentication,
and ordinary keyboard focus/navigation between the owned parent and WAM. Use the
existing declared accessibility facility if available; otherwise retain that
observation as missing, not infer accessibility from source or standard controls.
End the pending request using the owned Cancel control through ordinary keyboard
interaction, without entering credentials or performing delegated consent. No
screenshot, identity-bearing text, automated window inspection or manipulation is
allowed. Observe remaining windows separately; normally close residual WAM if
necessary, without claiming shared broker termination.

Accept only actually reported physical observations, alongside complete normal
transport, validated Cancelled/None without a token, product exit 1 and scoped
completion. Fixed caller UI fields remain unchanged; operator evidence is separate.
An early result, missing required surface/observation, timeout or other alternative
ends this one attempt as itself. Preserve missing claims and all charges; do not
retry automatically, force UI, change account/scopes/state or create another tool.

Allocate one new start/discovery/eligible interactive call and zero silent calls,
one metadata pass of 64 operations/16 MiB plus 8 KiB/30 seconds and one collection
pass of eight operations/1 MiB/180 seconds from the remaining shared pools.
Independently accept exact protocol/source/artifact/request/call/current basis and
accounting before execution; precharge before covered operations and require fresh
actual readiness after preparation. Independently accept the actual scoped outcome
before further authentication. Existing failure/current-absence and ordinary
provider-update boundaries remain; no installation, repair, new host/controller,
observer, UIA, calibration, exporter or separate executable project is included.

## Selected Visible-Parent UIA Observation

The first selected visible-parent UX observation ended as an accepted Timeout
without physical evidence. Its slot remains spent. Admit one further attempt that
replaces manual reporting of the owned parent's structure, notice, layout and
owned Cancel with a short PowerShell 5.1 x64 STA script using the standard
Windows UI Automation client and default Win32 proxies. Reuse the accepted
candidate, Profile, work role, tenant/scopes, Windows-local configuration,
preflight, caller, private transport, Windows-only validator, limits and
sole-writer human-action procedure of the preceding supplement. The script,
not the operator, performs the owned Cancel action.

Keep fresh actual readiness only so an operator is present to identify and
normally close any residual WAM afterward, without signing in, choosing an
account or consenting; without a ready operator, do not start. Launch the
script immediately before the one `force-interactive` request, as an ordinary
`powershell.exe -NoLogo -NoProfile -NonInteractive -Sta -File` process on the
same interactive desktop. An in-process timer exits it after 140 seconds; read
at most 4 KiB of its standard output. Errors such as early product exit or a
lost element end the script with `Aborted` and the fixed fields gathered so far.

Bind exactly one product process by its accepted executable path and a start
time after the script started, then exactly one top-level window of that process
whose class has the owned `Authentication.OwnedRequest.` prefix, found by
filtering top-level windows on that process identifier. Any other count ends
observation without action. Read only that window and its descendants: title,
the four public Profile/owner/provider/Cancel notice phrases, Text/Button counts,
enabled, focusable and offscreen states, bounding containment and overlap,
window-context and monitor-effective DPI, physical and logical window size and
whether each DPI context switch succeeded. Read only the
process identifier of the currently focused element. Output only fixed booleans
and numbers. Do not read content of, or act on, provider, WAM or other windows.

After a short dwell for the provider display, the script copies only the owned
window's own rendering with `PrintWindow`, sized from its window rectangle in
the product's own DPI-unaware context, to a private local file named by the
exact call. It contains public Profile text only; never
commit it or capture a screen region. Only when the parent and Cancel are both
enabled and on screen, the script focuses and invokes the owned Cancel button
through its UIA Invoke pattern, the control's standard clicked notification, and
waits at most 15 seconds for product exit. Otherwise it records the state and
takes no action. Normally close residual WAM afterward without claiming shared
broker termination.

Notice and layout are supported only by `TitleMatches`, all four notice
phrases, one Text and one Cancel, both inside the parent and on screen, no
overlap and Cancel enabled; any other value remains itself or missing. Focus
ownership and DPI values are recorded only. The independent actual-outcome
reviewer judges only the window's own logical-DPI rendering; physical scaled
readability remains unobserved unless an operator separately reports it.
Accept owned Cancel only with complete transport, validated Cancelled/None
without a token, product exit 1 and scoped completion.

UIA Invoke is not Tab/Enter navigation, and accessible names, rectangles or a
window rendering do not establish screen-reader behavior or readability at
other scales. Keyboard navigation, focus between the parent and WAM and
assistive-technology use remain open, unobserved items. An early result,
missing or ambiguous window, non-actionable Cancel, timeout or other
alternative ends this attempt as itself; do not retry automatically, force UI,
change account/scopes/state or extend the script into a controller or observer.

Allocate one new start/discovery/eligible interactive call and zero silent calls,
one metadata pass of 64 operations/16 MiB plus 8 KiB/30 seconds and one collection
pass of eight operations/1 MiB/180 seconds from the remaining shared pools.
Independently accept the exact protocol, script, call and accounting before
execution, precharge before covered operations and independently accept the
actual scoped outcome before further authentication.

## Hidden Owned-Parent Interactive Observation

Under the [parent selection decision](../../designs/windows-ado-authentication.md#parent-selection-decision),
admit one attended observation of the implemented hidden owned parent. Use the
same Windows 11 x64 interactive desktop and WSL2 caller. Use one existing build of
accepted `main-v2` with SDK 10.0.402; the call binds its exact product hash, and its
source-tree, artifact and current-basis correspondence is independently accepted
before execution. No new build is allocated unless that acceptance fails. Use the explicit Profile, the work
role, its applicable tenant/scopes, the Windows-local configuration and the
Windows-only result validator. Reuse the existing human-action caller procedure
with one explicit `force-interactive` request, no engine silent acquisition and
the sole lifetime writer held until result completion. Copy the accepted caller
and preflight with only the product path and pins changed, plus one fixed Boolean
reporting whether stderr contained the exact pre-interaction notice line. Keep
every limit unchanged: 120-second product, 130-second completion, 10+5-second
validator and 180+5-second foreground bounds, and the private-memory and pipe limits.

Run the accepted selected-parent UIA script once with `-NoInvoke` and a 30-second
wait, changing only its product path literal to the selected candidate; the call
pins the successor hash and starts it before the product. It binds the product
process and reports only whether a product-owned top-level window is exposed.
"No exposed product window" requires `ProductBound=true`, no multiple products or
parents, `Aborted=false` and `ParentFound=false`. It reads nothing from WAM
and takes no action. Request fresh actual readiness after preparation. Before the
call, tell the operator the public unofficial project/Profile/owner context and
the expected surface: WAM only, with no product window. The operator then reports
whether a product window appeared, whether WAM appeared and received focus, the
title WAM showed if any (no account text), and then cancels on WAM's own surface
without signing in. Accept the hidden-parent WAM presentation and human
cancellation only with: no exposed product window, an operator-reported WAM prompt
that could be cancelled, validated Cancelled/None without a token, product exit 1,
the notice Boolean true and scoped completion. The title is confirmed only if the
operator reports exactly `Unofficial hcoona/microsoft-authentication-cli`, and focus
only if WAM received focus without operator action; neither conditions the other
acceptance. Any other result, including unknown, is recorded as itself. Do not retry automatically, force UI, or change account, scopes or state.

Allocate one new start/discovery/eligible interactive call and zero silent calls,
one metadata pass of 64 operations/16 MiB plus 8 KiB/30 seconds and one collection
pass of eight operations/1 MiB/180 seconds from the remaining shared pools.
Independently accept the exact call and accounting before execution, precharge
before covered operations, and independently accept the actual scoped outcome.

## Locked-State Non-Interactive Observation

Admit one attended observation for the strategy row on noninteractive requests in
a locked or expired state. Use the same Windows 11 x64 host and WSL2 caller, the
accepted hidden-parent candidate and its pinned preflight, the explicit Profile,
the work role with its applicable tenant/scopes, the Windows-local configuration
and the Windows-only result validator. On this Remote Desktop host, a disconnected
session is the locked state: the session shows the lock screen and has no input
desktop. Copy the hidden-parent caller with only these changes: a `LockedNoUi`
case that sends `non-interactive-only`, uses no lifetime pipe and expects
`MechanismUnavailable`/`None`. Keep every existing limit.

The command script first reduces a `quser` check to one fixed Boolean, whether
exactly one session of the current user is disconnected, keeps no raw output and
makes no call otherwise. After the call, the operator reconnects
and reports whether any WAM, product window or unlock prompt appeared or remains.
Local admission requires an active session with the input desktop, so the
expected result is rejection before any provider call. Accept only with: the
session confirmed disconnected, `ProtocolValid` and `Passed` for
`MechanismUnavailable`/`None` with no token, the fixed host-session or
input-desktop mechanism indication, product exit 1, no interactive stage in
local telemetry, scoped completion, and an operator report of no such surface.
Any other result, including `InteractionRequired`, is recorded as itself. The
claim is limited to this: on this Remote Desktop host, a noninteractive request
from a disconnected session is rejected at local admission with no product, WAM
or unlock surface. Broker behavior under a connected lock screen or an expired
credential is not observed. Do not retry automatically or change account, cache or
session state beyond the operator's ordinary disconnect and reconnect.

Allocate one start/discovery call, zero eligible silent and zero interactive
calls, one metadata pass of 64 operations/16 MiB plus 8 KiB/30 seconds and one
collection pass of eight operations/1 MiB/180 seconds from the shared pools.
Independently accept the exact call and accounting before execution, precharge
before covered operations, and independently accept the actual scoped outcome.

## Historical Evidence

The prior detailed protocols, source pins, receipts, failed outcomes and bounded
controlled observations remain recoverable in the
[fixed pre-cleanup Git version](https://github.com/hcoona/microsoft-authentication-cli/blob/06ab8855e4fc4c3144852f4cadeb12086531c388/docs/research/experiments/windows-slice-validation.md).
Current validation claims link directly to their fixed historical evidence. Deleted
source and recipes remain recoverable at that same revision; they grant no current
execution authority. Retained experiment/accounting artifacts are not removed by this
source cleanup, and no historical success, closure or evidence level is changed.

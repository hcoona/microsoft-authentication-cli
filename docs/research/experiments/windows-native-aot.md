# Windows Native AOT Synthetic Experiment

This record owns the exact Issue #76 procedure and its cumulative observations. The
[accepted Wave](../../delivery-wave.md)
owns authorization; [experiment safety](../experiment-safety.md) owns general policy.
The [assessment](../v1-public-contract-baseline.md#windows-native-aot-assessment),
[Windows design](../../designs/windows-ado-authentication.md#native-aot-target-disposition),
and [validation strategy](../../validation/strategy.md#native-aot-publishing) consume
the bounded conclusion. The historical Windows MSAL and tooling protocols retain their
exhausted capacities; none of their helpers or subjects may execute here.

The retained .NET 10 Native AOT EXE has now executed on the Windows host through WSL.
The positive case created MSAL configuration and entered the upstream NativeInterop
configuration-allocation path with the native DLL loaded from the application directory.
Both missing-library and working-directory/PATH-decoy cases returned
`System.DllNotFoundException` without loading that module. All three controllers completed
normally with quiescence and no safety stop or termination request.

All experiment capacity is consumed. The retained procedure and artifacts are evidence,
not a new execution grant. Attempt 10's historical controller stop, unknown origin and
missing publish warnings remain unchanged. These synthetic results establish the tested
allocation/loading/search path, not WAM authentication, complete native cleanup,
production publishing, or support.

## Question and Exact Subject

Can the pinned .NET 10 Windows x64 synthetic program publish with Native AOT and enter
the actual upstream NativeInterop configuration-allocation import with DLL search
restricted to the application directory and System32? A failed publish, unavailable
safe entry point, or failed allocation is a valid observed blocker. Do not add broker
startup, a loader workaround, warning suppression, or a non-AOT fallback to make it pass.

The controller source is the complete accepted directory
[`tools/probes/windows-native-aot`](../../../tools/probes/windows-native-aot), including
the project, `Program.cs`, `global.json`, `nuget.config`, `run.py`, and
`Invoke-Action.ps1` and its `WindowsJob.cs` process guard. The guard is excluded from the
Native AOT project. New execution binds their exact bytes and this protocol to the same
merged amendment commit, from a detached checkout. The executable subject remains the
hash-pinned output of PR #86 (`9055a9b473ab574a27469c96e31e1416ec69b14f`); its
`Program.cs`, project, global SDK selection, and NuGet configuration must remain
byte-identical to that producing revision. The amendment changes only controller code
and the explicit retained-artifact prerequisite, not the program or dependencies. The amendment commit is recorded before every attempt; this record does
not need a self-referential commit hash. No product source is built.

| Input | Pin and selection |
| --- | --- |
| .NET | Existing Windows SDK 10.0.401, runtime/targeting/apphost/ILCompiler/ILLink 10.0.12; SDK roll-forward disabled |
| Project | `net10.0-windows`, `win-x64`, Release, `PublishAot=true`, self-contained; exact properties and commands in the accepted source |
| MSAL | Client and Broker 4.83.1; NativeInterop 0.20.3; modern selected assets expected to be net8.0, netstandard2.0, and net9.0, respectively; confirm from actual assets before interpreting results |
| Managed closure | Abstractions 8.14.0, DiagnosticSource 6.0.1, Unsafe 6.0.0, ValueTuple 4.5.0; exact direct constraints prevent transitive floating |
| SDK package candidates | Seven original 10.0.12 candidates plus the two evidenced supplemental runtime packs below; unused candidates are not claimed as resolved application dependencies |
| VC tools | Existing Visual Studio 18 Enterprise, `VC/Tools/MSVC/14.51.36231`, Hostx64/x64; actual `link.exe` file version 14.51.36257.0 and `cl.exe` 19.51.36257.0 |
| Windows SDK | Existing 10.0.26100.0 x64 UM and UCRT libraries and tools, with the selected VC x64 libraries; no floating discovery through `vcvarsall` |
| Historical build-tool selection | Producing PR #86 used `IlcUseEnvironmentalTools=true`, explicit `CppLinker`, exact child `PATH`/`LIB`/`INCLUDE`, and dotnet/link/cl/kernel32.lib/ucrt.lib identity checks. Current runtime-only checks cover the controller compiler and retained/copied artifacts as defined below; those build tools do not run. |
| Controller bootstrap | Existing 64-bit Windows PowerShell and its Framework64/v4.0.30319 standalone `csc.exe`, SHA-256 `46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00`; compile only the accepted Job Object guard, then load its dedicated DLL into the controller |

Public package versions and archive identities are retained in the fetch result. The
three authentication archives must match the SHA-512 identities in the linked
assessment before restore. The actual assets/lock files, selected asset paths, native
PE imports, and output identities are inspected as data and retained with the outcome.
An unexpected package, version, compiler path, or tool identity stops execution. No
private source, feeds, signing service, or installation is permitted.

## Public Call-Boundary Basis

These are static source/IL findings, not runtime observations. They are recoverable
from the public archives with the assessment's identities and the following public
source at MSAL commit `d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f`:

- [`BrokerExtension.WithBroker`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/BrokerExtension.cs)
  records a broker factory; the probe does not invoke that factory or availability APIs.
- [`PublicClientApplicationBuilder.BuildConcrete`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/AppConfig/PublicClientApplicationBuilder.cs),
  `PublicClientApplication`, `ClientApplicationBase`, `ApplicationBase`,
  `Internal.ServiceBundle`, and `TokenCache` construct application configuration and
  in-memory services/cache objects. They do not perform account enumeration or token
  acquisition. Construction is not a persistent-cache access experiment.
- In the public NativeInterop net9.0 DLL, `AuthParameters..ctor(string,string)` and
  `ConstructHandle` call `API.CPU.CreateAuthParameters`, whose x64 implementation
  imports `MSALRUNTIME_CreateAuthParameters` from `msalruntime`. The native status/error
  branch can call `GetStatus`, `GetErrorCode`, `GetTag`, `GetContext`, and `ReleaseError`.
  The probe emits only the exception type and numeric status, never native context.
- `API..cctor`, `CreateAPI`, and `Platform.GetExecutingAssemblyDirectory` use
  `AppContext.BaseDirectory`. The Windows helper also appends a derived
  `runtimes/native` location to this process's `PATH`. This is an upstream process-local
  effect, not a machine PATH change. Inspecting a raw OS load or this initializer alone
  would not prove the later upstream x64 import.
- `AuthParametersHandle` uses `Module.AddRef(true)`, which skips `API.Startup`.
  Disposal/finalizer cleanup can call `MSALRUNTIME_ReleaseAuthParameters` and, at zero
  references, `MSALRUNTIME_Shutdown`. These are explicitly included native operations.
  Successful managed disposal does not prove successful native release: the upstream
  safe-handle release implementation catches exceptions.
- `Core`, `Module.Startup`, logging callbacks, account/result handles, discovery,
  authentication, and broker sessions are not invoked. `Marshal.Prelink` is excluded:
  the [.NET 10 Native AOT implementation](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/coreclr/nativeaot/System.Private.CoreLib/src/System/Runtime/InteropServices/Marshal.NativeAot.cs)
  makes it a no-op.

This establishes a bounded public API/source inference that allocation/import/cleanup
can be separated from authentication and its telemetry. It does not prove every native
DLL initializer's internal behavior. If review or observation defeats that separation,
stop and record the limitation. Do not access the private OneAuth source.

## Environment and Effects

Use the existing owner-designated Windows 11 x64 host through WSL 2 Linux x64. Record
actual Windows, PowerShell, WSL/kernel, and .NET/tool versions without machine/account
identifiers. Existing interactive-user account and broker state is present or unknown;
no attempt reads, selects, signs in, signs out, clears, migrates, or compares it. The
all-zero client ID and `https://example.invalid/` are synthetic configuration strings,
not an external registration or endpoint to contact. There are no scopes, identity
requests, resource requests, token results, or expected UI. No operator sign-in step is
needed. Any authentication/account-choice/consent surface stops the experiment.

The only new persistent state belongs to
`C:\Temp\azureauth-native-aot-76` (WSL `/mnt/c/Temp/azureauth-native-aot-76`): accepted
source copies, public feed, separate home/temp/NuGet caches, restore/build outputs,
case directories, and sanitized attempt evidence. A preexisting root is rejected on
initial fetch; it cannot reset capacity or establish ownership. This is an existing
workstation experiment under documented OS/process contracts, not a hostile-code sandbox
or isolation of the Windows account. No registry, firewall, global tool, machine
configuration, credential store, or unrelated application state may be changed.

Both completed fetch batches used Python's standard-library HTTPS client without inherited proxy/auth
handlers, one fixed public flat-container URL per exact package. Restore uses only that
local feed and an initially empty dedicated package cache. Later retries may use that
cache and must not be called clean restores. Public-download success and local-feed
restore success are distinct observations. NuGet signature revocation checking is offline;
NuGet auditing is disabled for this bounded restore, not as repository security policy.

Every subject child receives a complete replacement environment. The accepted helper
sets documented .NET telemetry, certificate-generation, global-tool-PATH, and workload
notification controls, explicitly sets `DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK=true`,
disables build servers/node reuse and diagnostics, and omits
inherited feed credentials, NuGet plugins, startup hooks, proxies, and agent settings.
PowerShell uses `-NoProfile -NonInteractive`; it passes no ambient environment to the
subject. Restore and publish disable automatic response files and ancestor
`Directory.Build.props`, `Directory.Build.targets`, and `Directory.Packages.props`
imports through explicit command-line properties. No MSAL or native logging/telemetry
callback is installed. Controller/bootstrap
receipts contain only the corresponding PID and creation time; no unrelated process
inventory or command lines are retained.

NuGet's CoreCLR implementation requires `PROGRAMFILES(X86)` or its `PROGRAMFILES`
fallback when initializing default configuration, even with `--configfile`. Both are
set to the single dedicated `C:\Temp\azureauth-native-aot-76\empty-program-files`
directory. PR #84 created it during its accepted source migration. The wrapper
requires the directory to remain present,
empty, and not a link before every action. No real machine-wide NuGet configuration is
read through these variables. Existing dotnet, compiler, linker, and SDK paths remain
explicit and unchanged. Do not populate this directory, copy host configuration into it,
inherit the host variables, or add unrelated environment variables as a speculative fix.

The child environment also sets `OS=Windows_NT`, accurately identifying this existing
Windows host for MSBuild and Native AOT. MSBuild's Windows evaluation normally imports
that environment property rather than synthesizing it. Keep the upstream cross-OS guard
enabled; do not set `DisableUnsupportedError` or attempt cross-OS compilation. All
other child environment entries, commands, toolchain paths and package pins are unchanged.

## Execution and Finite Capacity

### Retained-Artifact Stop Disposition

AOT-AUTHOR-018 remains a true positive for attempt 10's historical controller stop and
missing diagnostics. Its hash-bound subject exit 0, final owned-process quiescence, and
published identities establish a reviewable retained artifact, not ordinary controller
success. The exact source supports a failure after subject exit and before diagnostic
assignment; the record cannot identify its exact cause, residual process count, or
termination branch. No absent publish transcript or warning disposition can be recovered
by this amendment. No sensitive-output finding is recorded, and no claim of absent
sensitive output is inferred from that missing field.

The reviewed continuation accepts that uncertainty for **three synthetic runtime cases
only**. They require neither further compiler operation on the subject nor use of a
surviving process or credential-bearing state. Each case starts the unchanged, hashed
artifact in a fresh owned process/directory and uses the previously reviewed synthetic
configuration call boundary. Quiescence and unchanged provenance supply the continuation
basis; the exact old stop receipt remains true and immutable. This does not establish
warning-free compilation, a clean prior controller completion, production suitability,
or full native behavior. A new stop or uncertain termination prohibits another case.

This narrow disposition does not bypass an unresolved active effect: attempt 10's final
quiescence is recorded. It does not diagnose or erase the earlier trust-processing
uncertainty. Any changed artifact, missing receipt, new effect, or contradictory
provenance defeats the disposition and stops before execution. Independent acceptance
of this exact protocol/controller and current consumer obligations is required first.

### Current Actions and Migration

Before **each** action, refresh `origin/main-v2`, confirm the accepted Wave and exact
protocol remain current, recover independent review and CI/commit-check receipts, and
inspect prior results. Material prerequisite drift requires refreshed review. The wrapper
checks the exact accepted Wave bytes from PR #89, current protocol bytes, accepted
ancestry, detached checkout, Windows source copies, prior receipt/marker hashes,
sequential consumption, all sixteen feed archives, retained earlier evidence, and the
three published file identities from the final-publish observation below.

The accepted runtime continuation used these commands in order, once each. Their
capacity is now consumed; they are retained for provenance, not replay:

```text
python3 tools/probes/windows-native-aot/run.py positive --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py missing --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py decoy --accepted ACCEPTED_COMMIT
```

`ACCEPTED_COMMIT` is this amendment's merged commit, not the producing PR #86 commit.
The pinned attempt-10 result is the artifact prerequisite; the wrapper does not demand
an impossible new publish from the amended controller revision. Only that exact
hash-verified historical stop is dispositioned. Every new receipt must bind this
amendment's exact source/protocol hashes and the declared action sequence. Both the
immediate return and later recovery require explicit typed completion: false safety stop,
true quiescence/capture, completed stage, guard exit 0, consistent subject exit and fixed
observation, zero job counts, and no termination request. Missing or ill-typed fields
fail closed (AOT-AUTHOR-019). The shared check also rejects unexpected preload,
unrestricted search, or a loaded native module in either negative case; the exact old receipts remain hash-bound and unchanged. Inspect each
new observation before continuing. A normal observed positive-case failure may be
followed by the negative cases within the same boundary, but cannot establish positive
loading compatibility. Unexpected search success, invalid output, or any controller
safety stop ends the sequence without retry.

The one-time migration requires the original root identity, exact PR #86 source copies,
all twenty receipt hashes for attempts 01–10, all five existing revision-marker hashes,
the earlier retained assets/lock and managed artifacts, the empty owned program-files
root, and the unchanged native output inventory. `runtime-revision.json` must be absent.
Replace only the seven owned source copies, then exclusively create that marker with
old/new revisions, prior consumption, the historical stop digest, and artifact hashes.
The four probe/project/SDK/NuGet files must stay byte-identical. Preserve the existing
root, outputs, caches, feed, five earlier markers, and every receipt; partial migration
fails closed. This migration does not clear a receipt or reset capacity.

The Windows helper verifies the retained EXE/DLL identities again and checks copied
case files before launch. It verifies the existing standalone compiler identity, then
compiles the controller guard only. .NET SDK, linker, and product project commands are
not executed. The replacement environment and DLL-search setup retain their accepted
values. A named two-stream capture object keeps empty stdout/stderr explicit. New results
retain fixed controller stage, failure stage and source line, capture-completed flag,
normal-exit job process count, and the actual final stop branch's active count and
termination-request/success flags. These contain no command lines, provider messages,
private paths, or unrelated process inventory. They describe new attempts only.

Before this continuation, consumption is original fetch **1/1**, supplemental fetch
**1/1**, restore **6/6**, publish **2/2**, each case **0/1**, and guard bootstrap
**8/11**. All ten prior attempts have complete receipts. No new fetch/restore/publish
capacity exists, and the current wrapper and helper expose no such actions.

| Unit | Cumulative maximum, including failed starts and manual execution |
| --- | --- |
| Public fetch batches | Original fourteen-package batch and two-package supplement both consumed; no further request |
| Restore and Native AOT publish | Six restores and two publishes consumed; no further action |
| Synthetic cases | One positive, one missing-library, one combined working-directory/PATH-decoy action; 30 seconds each; no repeat |
| Guard bootstrap | Eleven total; eight consumed, one remaining standalone compiler action per case; 60 seconds plus 10 seconds termination each; no shared compiler/server mode or installation |
| Windows controller | One per case, 1,300-second WSL wait ceiling; combined child output at most 8 Mi characters in memory |
| Subject processes and termination | At most 32 simultaneously active processes in the owned Job Object; at most 10 seconds for job termination and active-process quiescence |

The next sequential attempt directory and `started.json` reserve capacity before a
Windows controller starts. Incomplete/unreadable evidence, exceeded capacity, a new
safety stop, or uncertain termination prevents continuation. Source changes, operator
changes, interruption, and protocol revisions do not reset limits. No other machine
or manual replay is authorized. Controller/subject processes terminate under the same
ownership rules below; retain all sources, case files, outputs, and sanitized receipts.

Each case uses a fresh process and isolated application directory. Positive contains the
published executable and its published x64 `msalruntime.dll`; missing contains only the
executable; decoy places the genuine DLL only in the working directory and prepends that
directory to the child PATH. Before touching NativeInterop, the program sets
`SetDefaultDllDirectories(APPLICATION_DIR | SYSTEM32)` and rejects an unexpected preload.
Positive success requires AOT, restricted search, configuration creation, and the loaded
module's path matching the application directory. Missing and decoy should fail with no
native module loaded. An unexpected successful decoy load stops subsequent actions.
No wrong-architecture case is included in this exact protocol. NativeInterop 0.20.3
contains native assets for multiple runtime identifiers; the accepted `win-x64` restore
selects `runtimes/win-x64/native/msalruntime.dll`. The three cases above do not establish
wrong-architecture handling. AOT-AUTHOR-017 independently confirmed the earlier false
package-inventory rationale; this correction changes neither the executed subject nor
its case exclusions. The broader validation obligation remains outstanding.

The controller first compiles its guard with the pinned standalone Framework compiler,
using explicit source/output/references and a complete replacement environment. This
bootstrap has one owned compiler process, bounded output/time, and handle-based kill and
wait on failure. The accepted source is not an MSBuild project or a shared-server
invocation. PowerShell loads only the compiled guard DLL; it does not compile the subject.
Guard source/output/temp files are retained inside the dedicated experiment root.

The guard creates an anonymous Windows Job Object with `KILL_ON_JOB_CLOSE`, no breakaway
permission, and a 32-active-process limit. It creates the subject suspended, assigns it
to the job and retains its managed process handle before resuming, and gives it only
the explicit output/error pipe handles. That handle remains alive through result capture.
Assignment failure terminates the still-suspended root by its process handle; failure
to confirm termination remains an unresolved stop. Normal exit requires zero active
job processes. On timeout/failure, `TerminateJobObject` and a bounded active-process check
own the whole descendant scope without inferring it from reused PIDs. The controller
keeps the noninherited job handle alive through execution and closes it during cleanup;
Windows also closes it if the controller terminates unexpectedly. Never kill a shared
broker or all dotnet processes.

WSL cancellation alone is not a termination receipt. Recover the identity-bound local
controller/compiler receipts. During bootstrap only, if those exact processes still
exist, an emergency Windows `taskkill /PID <controller-pid> /T /F` may terminate the live
controller tree; a remaining compiler may be stopped only after its own creation-time
match. Once the guard is active, ending that same controller closes its job handle. Bound
emergency termination to 10 seconds and retain uncertainty if the identity is gone or
unverifiable; do not infer ownership from PID ancestry after exit. No further attempt
may start until the record is resolved; an actual safety stop remains a stop.

## Evidence and Completion

For the current runtime-only continuation, retain each case's accepted amendment,
producing revision and artifact identities, fixed observation, stage/capture/termination
fields, receipt hashes, and cumulative limits. Publish diagnostics remain unavailable;
new controller diagnostics cannot fill that historical gap. No SDK output is generated
or sanitized by the current helper. The following build-diagnostic rules describe the
accepted historical restore/publish evidence and do not grant another build action.

Retain start/end times, accepted commit/tree and source hashes, capacity, tool versions,
public package and output identities, resolved asset selection, warning/error codes,
exit/timeout status, and the program's fixed JSON fields. Compiler diagnostic codes may
be explained from public source/IL without replaying a publish. Existing stdout/stderr
counts, fixed exception-type matches, and command-parser Boolean remain available. The
diagnostic continuation additionally permits ordinary SDK/MSBuild/NuGet/compiler text
and public stack symbols from restore/publish only, after in-memory sanitization:

- Keep stdout and stderr separate. For each, retain at most the first 256 lines and
  32,768 characters, with explicit truncation, redaction, suppressed-line count, and
  sensitive-output flags. The existing combined 8 Mi-character transient bound remains.
- Normalize the exact experiment, VC, Windows SDK, dotnet, and Windows paths to stable
  role placeholders. Suppress entire lines containing other drive/UNC/user-home paths
  or uppercase environment-variable assignments. Do not enable environment dumps,
  diagnostic verbosity, binary logging, or extra file loggers in this amendment.
- Remove terminal escapes/control characters. Replace email and GUID identifiers.
  URLs retain only scheme and one of four public hosts (`api.nuget.org`, `www.nuget.org`,
  `learn.microsoft.com`, `aka.ms`); discard user information, paths, queries, fragments,
  and other hosts. Preserve public method/type names and parameter names in stack
  signatures, never runtime argument values or private file paths.
- Scan both raw and control-normalized text before other redactions or truncation.
  Credential/authorization assignments, bearer text, JWT-shaped values, or native
  logging markers suppress the entire affected stream and trigger a safety stop after
  owned-process quiescence. Do not persist raw output before sanitization. No exception
  to the strict synthetic-case JSON emitter or to the prohibition on native/broker
  diagnostics is granted. Controller/bootstrap exceptions still retain types only.

This is a bounded synthetic public-build transcript, not a general private-log sanitizer.
The fixed commands, source, package inputs, and replacement environment remain part of
its privacy boundary. Review sanitized excerpts before placing them in public records;
do not promote host/user details, dynamic argument values, or unrelated content into
evidence merely because a pattern did not match. Suppression or truncation can still
prevent diagnosis and must remain explicit. Verify the sanitizer using public/synthetic
fixtures without starting the compiler, SDK, or probe before acceptance.

The first diagnostic restore is an explained retry because the old capture contract
discarded unanticipated messages. Inspect its result before any downstream action.
Further attempts require an evidenced remedy or a reviewable diagnostic reason; changes
to commands, environment, or executable source require another accepted exact amendment
preserving all consumption. AOT-AUTHOR-010 was independently triaged as information loss
that blocks the renewed diagnosis, not a historical retention-contract violation or proof
that the discarded text necessarily contained the cause. No message is reconstructed.
Preserve missing output or crashes as failures, not negative-case success. Read-only
artifact inspection and sanitized record preparation are not new subject attempts.

At completion retain only identified experiment-owned source, public dependencies,
build/output artifacts and sanitized receipts for reproducibility. Local PID receipts
are operational evidence, not public observations. No account/session
cleanup is required or authorized. Do not delete unrelated files or promise remote
rollback. Record quiescence and any retention uncertainty in the result.

Publish/loading success covers this exact synthetic import/allocation slice. It does not
establish native startup, WAM authentication, account visibility, fresh-state behavior,
UI/cancellation, all managed broker methods, production artifact closure, ARM64, or a
support claim. Update the assessment, design, and validation obligations together from
the actual result; leave every untested premise explicit. Once the bounded conclusion
is accepted, close the Wave entry through its separately reviewed deletion.

## Observations

### Initial Execution

Runtime observations on September 12, 2026 used PR #78 commit
`3f21223c0d83aa8d2bb872499c40a4b08de1dcfe`, tree
`c46afd0e89d617ebdb69b4b5df8070a9081dfd07`, with its passing independent review,
commit checks, and [CI](https://github.com/hcoona/microsoft-authentication-cli/actions/runs/34668110177).
The host reported Windows version `10.0.26200.0`, AMD64, PowerShell 5.1.26100.9444,
and the pinned SDK/runtime directories. The initiating host was WSL 2, kernel
6.18.33.1-microsoft-standard-WSL2, Ubuntu 26.04.1 LTS, Python 3.13.15.
No account, tenant, scopes, authentication UI, token, or resource request applies.
Existing account/session state was not examined.

| Attempt | UTC interval | Observation |
| --- | --- | --- |
| 01: public fetch | 02:42:45.688308–02:42:53.499435 | Exit 0; fourteen exact archives, 121,318,968 bytes; no redirect/retry; quiescent and no fetch safety stop. The three authentication archive hashes matched the assessment before restore. |
| 02: first restore | 02:43:12.597034–02:43:18.0973811 | Guard compiler exit 0; subject exit 1 in 3.801 seconds; owned work quiescent; no retained diagnostic code. No assets, lock file, extracted package, published binary, or loading result was produced. The controller reported no safety stop; the later source finding below is a separate required disposition. |

The dedicated home contains a first-use sentinel and local NuGet migration marker; the
dedicated temporary directory contains one zero-byte SDK workload log. These identified
files, original source copies, public feed, guard DLL, and sanitized receipts are retained.
The empty log is not proof of either installation activity or its absence. Raw command
output was not retained and does not establish the restore failure cause.

After attempt 02, consumed capacity was fetch 1/1, restore 1/2, publish 0/2, each
synthetic case 0/1, and guard bootstrap 1/7. There was no manual subject execution, interrupted attempt, or
replay. No old authentication helper ran. The initial wrapper and its download procedure
remain recoverable from PR #78; this amendment cannot repeat that fetch.

### SDK Startup Finding

AOT-AUTHOR-007 was independently classified as a blocking true positive. The initial
replacement environment omitted an independent .NET 10 first-use control. The installed
SDK `.version` identifies dotnet/dotnet commit
`e34a38d2ae1fc26406a317517196e55c68ff83ab`; its public
[source manifest](https://github.com/dotnet/dotnet/blob/e34a38d2ae1fc26406a317517196e55c68ff83ab/src/source-manifest.json)
identifies SDK source `32593ca81f8aae7b0d41c1a7198529c3365106b8`.
At that source,
[Program.cs](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/dotnet/Program.cs)
captures first use before writing the sentinel and runs
[WorkloadIntegrityChecker](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/dotnet/Commands/Workload/WorkloadIntegrityChecker.cs).
That checker can construct an installer and install existing workloads. Notification
and MSBuild workload-resolver controls do not disable this branch. Microsoft's
[documented environment control](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-environment-variables#dotnet_skip_workload_integrity_check)
explicitly skips it; the amended helper sets that control without enabling installation.
Program.cs catches integrity-check exceptions and continues, so the missing control alone
does not explain restore exit 1. Preserve that distinction and the original receipt.

Read-only inspection of the installed `dotnet.dll` (SHA-256
`616dbda77bc20692d615e2a679f31ffff04f693e8d6b3e24779cf8838adb6a85`) and matching public
[InstallerBase](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/dotnet/Installer/Windows/InstallerBase.cs)
and [MsiInstallerBase](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/dotnet/Commands/Workload/Install/MsiInstallerBase.cs)
supports a narrower effects inference. The current SDK has the MSI-selection marker.
`InstallerBase` has a required explicit static constructor that dereferences
`PROCESSOR_ARCHITECTURE`, absent from the executed replacement environment.
`MsiPackageCache` invokes that base constructor before `MsiInstallerBase` can construct
its Windows Update agent or installation-record repository. This path cannot reach
`UpdateAgent.Stop`, successful installer return, or `InstallWorkloads`. This is an
inference from the exact source/environment/IL, not a measured installation-state diff.
The empty log does not establish the cutoff; its background writer can exit before
flushing queued events.

AOT-REVIEW-008 was independently classified as a blocking true positive: the earlier
[WorkloadUtilities](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/dotnet/Commands/Workload/WorkloadUtilities.cs)
→ [SignCheck](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/dotnet/Commands/Workload/SignCheck.cs)
→ [Signature](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/dotnet/Installer/Windows/Security/Signature.cs)
path can call `WinVerifyTrust` with online revocation allowed by its own policy.
`NUGET_CERT_REVOCATION_MODE` does not control that path. Actual policy, URL retrieval,
and Windows trust-cache effects were not measured; no actual request or mutation is
established. No registry/trust-cache inspection or cleanup was performed. Skipping the
entire integrity branch removes this prospective path as well as the installer path;
it does not retroactively establish that all earlier effects were absent.

Independent recovery and triage found no observed out-of-bound effect, unresolved
termination, or capacity gap in the retained evidence. The accepted policy does not
require proof of every internal OS/provider operation. This historical uncertainty alone
does not require a new owner risk decision or end the investigation. Continuation still
requires acceptance of this exact correction, verified original root/source/feed/receipts,
and the ordinary pre-action gates. Any actual stop condition remains binding; source
migration cannot clear it. The second restore was accepted as an explained retry after correcting
the unsupported startup path, with the original failure cause still unknown. The original
restore/publish arguments remain unchanged: exact System.CommandLine tokenizer and SDK
forwarding inspection shows their MSBuild switches are forwarded, so a CLI-parse
explanation is unsupported.

AOT-AUTHOR-009 was independently classified as a blocking true positive: Windows
PowerShell's UTF-8 result contains a BOM that the original prior-result reader rejects.
The amendment uses `utf-8-sig` for that reader, matching its existing immediate-result
reader. Read-only parsing reproduced this defect; it did not consume another attempt.

### Amended Restore and Bounded Conclusion

Attempt 03 used accepted PR #79 commit
`a2aa598e54021792402ee5eef6324ddcd702f7bc`, tree
`e26281dbaa36fbe118e79da05e28dbd364cb8a22`, after passing independent review, mandatory
commit checks, full local hk, and
[CI](https://github.com/hcoona/microsoft-authentication-cli/actions/runs/34669184276).
The host, SDK/toolchain, dependency pins, probe API, and restore arguments were unchanged.
The source amendment verified and preserved all original receipt bytes, source copies,
feed identities, and prior consumption before replacing the seven owned source copies.
The retained revision marker identifies the exact accepted amendment and prior counts.

| Attempt | UTC interval on September 12, 2026 | Observation |
| --- | --- | --- |
| 03: second restore | 03:05:47.458523–03:05:50.7137638 | Guard compiler exit 0; restore exit 1 in 1.554 seconds; owned work quiescent; controller safety stop false. Captured stdout had 427 characters and stderr zero. No retained diagnostic code, fixed exception-type match, or unrecognized-command phrase. |

The new classifiers did not identify the failure cause. No raw output was retained or
reconstructed. Read-only inspection after quiescence found no `obj` directory,
`project.assets.json`, lock file, extracted packages, HTTP-cache files, or published
output. The single earlier zero-byte workload log remains; no additional file appeared
in the dedicated temporary directory. These observations do not identify the precise
last SDK stage, prove unchanged external Windows state, or establish a package failure.
The earlier unmeasured trust-processing limitation remains as recorded above.

| Retained receipt | SHA-256 |
| --- | --- |
| Attempt 03 start | `ed065255c3cc5031051004714724e50f6591aa14cfad2ab6d70b771a6e6b8be7` |
| Attempt 03 result | `918a0425d6bb178815385ec6e8572fc6b0d1ba8e16a2abf45aaa2ae76107e7cd` |
| Source-revision marker | `60ef44676aa3285735a73e7adbf8e7ca9dc06780a9e9a3296c7083dff9208dda` |

Consumption at the original investigation's closure was fetch **1/1**, restore **2/2**, publish **0/2**, positive/missing/decoy
**0/1 each**, and guard bootstrap **2/7**. All three attempts have complete receipts;
there was no interrupted or manual subject replay. No owned subject remains running.
The identified experiment-owned feed, amended source, home markers, guard outputs,
zero-byte log, revision marker, and sanitized receipts are intentionally retained.
No account, broker-session, or installation cleanup was performed.

**Conclusion:** The fourteen pinned public packages were downloaded successfully. The
local-feed restore prerequisite remains blocked by two unexplained exit-1 outcomes in
this controller/toolchain environment. No resolved dependency graph, AOT/trim diagnostic,
published binary, positive load, or search-path negative result exists. The result is
not evidence that .NET 10, MSAL, Broker, or NativeInterop is incompatible with Native AOT.
It does not resolve the preferred Win32/Native AOT candidate, select another dependency
or host, or justify a non-AOT exception.

Supported source investigation identified and corrected the independent SDK first-use
control and receipt-decoding defects. Exact parser inspection did not support changing
the restore command. Neither finding diagnoses the remaining exit 1, and no demonstrated
AOT/dependency/host defect supports a further source remedy or provider/UI replacement.
That investigation ended with this bounded blocker and the unchanged production-publishing
gap. The diagnostic continuation above supplies a new finite procedure under PR #82's
accepted Wave while preserving these consumed attempts; unused publish/case capacity
does not supply another restore. Its first runtime observation follows.

### Diagnostic Restore and NuGet Environment Cause

Attempt 04 used accepted PR #83 commit
`acf4b01d050019064dd6698289b4fdad9ba3184b`, tree
`d6437dcbe25c7074f7e84eb6ffb2c10a327360eb`, after independent protocol/source review,
PowerShell syntax and synthetic sanitizer validation, mandatory commit checks, full hk,
and [CI](https://github.com/hcoona/microsoft-authentication-cli/actions/runs/34672879787).
It ran on the same Windows/WSL host with unchanged SDK/toolchain, package pins, command,
and replacement environment. The new diagnostics were the only subject-observation
change; no additional package was fetched and no authentication operation was introduced.

**Runtime observation:** From September 12 UTC 04:29:31.768910 to 04:29:35.0597893,
the guard compiler exited 0 and restore exited 1 in 1.407 seconds. Owned processes were
quiescent and the controller safety stop was false. All 427 stdout characters were
retained after known-path normalization, with no truncation, line suppression, or
sensitive-output flag; stderr was empty. The relevant diagnostic was:

```text
NuGet.targets(782,5): error : The type initializer for 'NuGet.Configuration.ConfigurationDefaults' threw an exception.
NuGet.targets(782,5): error :   Value cannot be null. (Parameter 'path1')
```

The task had printed `Determining projects to restore...`. Read-only inspection found
no `obj` directory or resolved dependency assets. This identifies configuration
initialization as the observed failure stage, before a resolved package graph or AOT
publish. The old empty classifiers did not match these messages because no numeric
diagnostic code or fully qualified fixed exception-type name was printed. Equal output
length does not reconstruct or identify the discarded messages from attempts 02 and 03.

**Source finding and causal interpretation:** The installed SDK's dotnet VMR
`e34a38d2ae1fc26406a317517196e55c68ff83ab`
[source manifest](https://github.com/dotnet/dotnet/blob/e34a38d2ae1fc26406a317517196e55c68ff83ab/src/source-manifest.json)
maps NuGet.Client to `c269b982bdef148f92489ef4179cdc59094f652c`.
[`ConfigurationDefaults.InitializeInstance`](https://github.com/NuGet/NuGet.Client/blob/c269b982bdef148f92489ef4179cdc59094f652c/src/NuGet.Core/NuGet.Configuration/Settings/ConfigurationDefaults.cs)
calls `NuGetEnvironment.GetFolderPath(MachineWideSettingsBaseDirectory)`.
The Windows CoreCLR path in
[`NuGetEnvironment.CalculateFolderPath` and `GetFolderPath`](https://github.com/NuGet/NuGet.Client/blob/c269b982bdef148f92489ef4179cdc59094f652c/src/NuGet.Core/NuGet.Common/PathUtil/NuGetEnvironment.cs)
reads `PROGRAMFILES(X86)`, falls back to `PROGRAMFILES` if empty, then calls
`Path.Combine(machineWideBaseDir, "NuGet")`. Both variables were omitted from the
accepted complete replacement environment, making the first argument null.

Static inspection of the installed CoreCLR IL independently confirmed this call path;
no NuGet assembly was loaded or executed for that inspection. `dotnet.deps.json`
identifies these components as 7.9.0-rc.42413. The installed SHA-256 identities are:

| Assembly | SHA-256 |
| --- | --- |
| NuGet.Common.dll | `537a15963cf134fc30e1314007cb276778309beb7672d4735d32fa8b022536b5` |
| NuGet.Configuration.dll | `b4696a39a890bbefeecb01099eedf990d3e108e7ad7d2d57d8cdf4c296dd06f6` |

AOT-AUTHOR-012 was independently triaged as a blocking true positive: this is the
replacement-environment cause of attempt 04's NuGet configuration failure. It is not
evidence of a defective MSAL, Broker, NativeInterop, or other package, a missing
dependency, or network/access blocking. No additional download is justified by this
finding. The current amendment maps the two required variables to one owned empty
directory, avoiding the host's real `NuGetDefaults.Config` and machine-wide settings.
Successful restore after that correction remains a runtime validation obligation.

| Retained receipt | SHA-256 |
| --- | --- |
| Attempt 04 start | `645d18bfd5a205ed2d049b4178a3fe152b53bafa934e08c1da5bd28e005c1ce4` |
| Attempt 04 result | `c594fd661df111688de8c34c015829472fb70ac1a0fabc1387cac6ef392c3406` |
| Diagnostic revision marker | `64e44d686794942c7ea03b86cf675348104070e33e5a04783cbf4a23975aab96` |

Consumption is fetch **1/1**, restore **3/6**, publish **0/2**, each case **0/1**, and
guard bootstrap **3/11**. All four attempts have complete receipts; no manual replay,
interruption, or unresolved owned process is recorded. Original receipts and the earlier
revision marker remain unchanged. Dedicated artifacts and sanitized receipts are
intentionally retained; the historical Windows trust-path uncertainty remains. The
remaining Native AOT, native loading, authentication, and production-publishing premises
are unchanged and untested by this diagnosis.

### Corrected Environment and Missing Runtime Packs

Attempt 05 used accepted PR #84 commit
`4cfde18c1e7348ca1341e50829b1a031af071dac`, tree
`53f67e59be2f6d83eac01386989c22f753ebfe34`, after independent review, mandatory
commit checks, full hk, and
[CI](https://github.com/hcoona/microsoft-authentication-cli/actions/runs/34673704206).
The exact amendment added only the two owned program-files environment entries to the
Windows helper. The wrapper preserved every prior receipt and revision marker and
recorded its source migration; SDK, packages, project, and restore command were unchanged.

**Runtime observation:** From September 12 UTC 04:48:04.952127 to 04:48:15.2575888,
guard compilation exited 0 and restore exited 1 in 8.361 seconds, with quiescence true
and no controller safety stop. The complete sanitized stdout contained 774 characters
before normalization, no truncation or suppressed lines, and no sensitive-output flag;
stderr was empty. The configuration initializer error disappeared. The new diagnostic
was `NU1101` for two packages absent from `public-snapshot`:

| Missing SDK download | Exact requested version |
| --- | --- |
| Microsoft.WindowsDesktop.App.Runtime.win-x64 | 10.0.12 |
| Microsoft.AspNetCore.App.Runtime.win-x64 | 10.0.12 |

The generated assets file and lock file are outputs of a **failed** restore, not a
successful resolved closure. They select MSAL's net8.0, Broker's netstandard2.0, and
NativeInterop's net9.0 managed assets, plus `runtimes/win-x64/native/msalruntime.dll`.
Their ten package libraries have the expected pinned versions. The assets explicitly
request both missing archives through exact `downloadDependencies`; their only
`frameworkReferences` entry is `Microsoft.NETCore.App`. The two missing archives were
not among the fourteen fetched inputs. Source mapping excluded the SDK library-packs
fallback; no network request failure, remote denial, private dependency, or package
incompatibility is established by these local-source errors.

**Source interpretation:** The pinned SDK's public
[`ProcessFrameworkReferences`](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Tasks/Microsoft.NET.Build.Tasks/ProcessFrameworkReferences.cs)
adds runtime-pack downloads for known frameworks when their packs are unavailable and
transitive framework-reference downloads are enabled (lines 766–773). A download request
therefore does not establish that the application references the desktop or ASP.NET
framework. Keep the project and SDK command unchanged; do not infer a UI dependency or
Native AOT desktop-framework failure from these two names.

| Retained evidence | SHA-256 |
| --- | --- |
| Attempt 05 start | `4dc9b666df2d38d68aaff0a307e9f97ced505568a14b14928eccf56c3d3d9df2` |
| Attempt 05 result | `b75eb2f1892c251a34538fe86e63860fd04174c44a6d8d7b3f05e8de3532407d` |
| Environment revision marker | `810f4a5b7d8cf90c7fe03fae16607674cd7a5673edf44773afbd12c03f04e718` |
| Failed-restore assets | `82bf316e8f0c6d71c78e4612880764256956b6d6da2940702d85541e022dda6f` |
| Failed-restore lock file | `606af5113f23548d1bc87c55657f1c1f7e4ffa017557e8cb9c7f342690cb84a3` |

Consumption is original fetch **1/1**, supplemental fetch **0/1**, restore **4/6**,
publish **0/2**, each case **0/1**, and guard bootstrap **4/11**. All five attempts have
complete receipts and no unresolved owned process. The empty program-files directory,
extracted public packages, failed-restore outputs, and sanitized receipts are retained.
The amendment preserves the two failed-restore files under attempt 05 before any retry
can replace their active paths. No authentication, publish, or loading case ran.
The original trust-path uncertainty
remains; the corrected configuration and precise local-feed omission do not establish
production publishing or Native AOT runtime compatibility.

### Supplemental Fetch, Successful Restore, and Publish Host Identity

Attempts 06–08 used accepted PR #85 commit
`2198edf2d4690b37dd80ca8ca74074a6fb30de3a`, tree
`889a88d0f9417fd4a7f879121bd7542c53b7d938`, after independent review, both independent
finding dispositions, mandatory commit checks, full hk, and
[CI](https://github.com/hcoona/microsoft-authentication-cli/actions/runs/34674562467).
The migration preserved attempts 01–05 and every previous revision marker and copied the
two hash-verified failed-restore files under attempt 05. No Windows command, environment,
project or toolchain changed from PR #84 for these actions.

| Attempt | UTC interval on September 12, 2026 | Actual observation |
| --- | --- | --- |
| 06: supplemental fetch | 05:08:05.767695–05:08:08.006253 | Exit 0; both exact public archives, 51,933,095 bytes; no retry/redirect; quiescent and no safety stop. |
| 07: fifth restore | 05:08:15.437758–05:08:22.4412595 | Guard compilation exit 0; restore exit 0 in 5.464 seconds, with successful restore text, no diagnostic codes, and no stderr; quiescent and no safety stop. |
| 08: first publish | 05:09:09.251410–05:09:18.9218069 | Guard compilation exit 0; publish exit 1 in 8.062 seconds after managed compilation; complete sanitized cross-OS guard diagnostic, no stderr; quiescent and no safety stop. |

**Restore observation:** The supplementary archives were publicly downloadable, so
attempt 05's errors were local-manifest omissions, not demonstrated network or access
blocking. Attempt 07 used the existing dedicated cache and is not a clean-cache restore.
Its assets have no restore errors and ten package libraries at the expected versions.
The selected MSAL net8.0, Broker netstandard2.0, NativeInterop net9.0 and x64 native
entries were compared byte-for-byte with their fetched archives. Cache archives also
matched the owned feed. NuGet content hashes matched extraction metadata; those values
are distinct from whole signed-archive SHA-512 identities. Five SDK download requests
remain exactly 10.0.12, and the only application framework reference is
`Microsoft.NETCore.App`. The native DLL is PE x64 (`0x8664`) with Windows system/API-set
imports and no delay-import table; static imports alone do not prove runtime behavior.
The lock file is unchanged from the failed restore, demonstrating why that file's
presence alone cannot establish successful restore.

**Publish observation:** The first publish produced the managed probe DLL and related
PDB/dependency/runtime-configuration files. Its published output directory remained
empty. The complete diagnostic was:

```text
Microsoft.NETCore.Native.Publish.targets(63,5): error : Cross-OS native compilation is not supported.
```

No AOT executable, ILCompiler analysis result, positive load, or negative loading result
was produced. This was the existing Windows dotnet process invoked through WSL; it was
not a Linux compiler attempting to target Windows.

**Source finding and causal interpretation:** The exact public ILCompiler 10.0.12
archive's `Microsoft.NETCore.Native.Publish.targets` has SHA-256
`6fcb3f0491a79fd5a67281b44439e0685c17fe4c848a07477ab2a57a10a68c60`.
Its lines 63–64 reject `_targetOS=win` when `OS` is not `Windows_NT`.
`Microsoft.DotNet.ILCompiler.SingleEntry.targets` (SHA-256
`345c9448182507befa430e80622f68c7ab09debe9c419d98b418f7f1cb79c34e`)
derives the Windows target from the pinned RID. Both files match their
[fixed runtime source](https://github.com/dotnet/runtime/tree/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/coreclr/nativeaot/BuildIntegration)
apart from archive line endings. The NuGet package's VMR
`95017c711e6afc1085133d440e42b4bd78155701` maps to that source.

The selected SDK's separate VMR source manifest maps MSBuild to
`b44cdcec4c79c50c67560876707d57d4f635fa3b`. Its
[`Evaluator`](https://github.com/dotnet/msbuild/blob/b44cdcec4c79c50c67560876707d57d4f635fa3b/src/Build/Evaluation/Evaluator.cs)
(lines 1168–1173) synthesizes the `OS` property only on non-Windows. The accepted
complete replacement environment omits `OS`, and neither the project nor command sets
it. This accounts for the observed guard branch. AOT-AUTHOR-015 was independently
triaged as a blocking true positive. The current correction supplies the true Windows
host identifier; it does not disable a guard, change target OS, or prove AOT support.

| Retained evidence | SHA-256 |
| --- | --- |
| Attempt 06 started.json | `7e5dbfb3c01c4ad5c8b64d30a2f0a559e23e1044b71f037afbe2ac7e0d02ed5b` |
| Attempt 06 result.json | `ac47a238709da78c172faf17c50f877f12b6a04ce9af7999634c08ad3cdfb5f5` |
| Attempt 07 started.json | `080c75b9122f8f0829887286b1ac6d26a014d6de8323b2c14015ccf8ba477ff4` |
| Attempt 07 result.json | `af15b47997e2eda59f3a0291892fdc9e53bf577f8544012ed2d57f4aacace98b` |
| Attempt 08 started.json | `7f9683cd9731e302b32c37957122fb91e85a76702c7b8557fd2d8644daf193c2` |
| Attempt 08 result.json | `494567236094ec67cc9486773847a759d7e44309612a8d954a70c691b2a60dd3` |
| Runtime-pack revision marker | `c5dfd88f2431dfdfdbfe5174b1151b48e05f4ff5e3124c011ff0f0adecae4d79` |
| Attempt 07 project.assets.json | `f3ef20674f6843d1356321de452abc6f93ddddb7355df45bf7da3db2c203689c` |
| Attempt 07 packages.lock.json | `606af5113f23548d1bc87c55657f1c1f7e4ffa017557e8cb9c7f342690cb84a3` |
| Attempt 08 NativeAotProbe.dll | `27054f594066ab8493cc58a5025a72a31ca719bcdc659b3e1946db1a1400882f` |
| Attempt 08 NativeAotProbe.pdb | `0de760ddb121be7cd7dc1c666637e49515723fc5f7bd52e67f0feb8f64e12968` |
| Attempt 08 NativeAotProbe.deps.json | `c1cd41f1638fee0e8b93e9afa3d5813f4a539ac1048f59b6abbc915b4ddc583e` |
| Attempt 08 NativeAotProbe.runtimeconfig.json | `16fd9da9872123c9c6ded9df23fad4b76414c1ec9fb27480158bf178283b97da` |

Consumption is original fetch **1/1**, supplemental fetch **1/1**, restore **5/6**,
publish **1/2**, each case **0/1**, and guard bootstrap **6/11**. All eight attempts
have complete receipts, with no manual replay, interruption, or unresolved owned process.
Public packages, sources, retained failed-restore evidence, successful restore outputs,
managed artifacts, and sanitized receipts are intentionally retained. The amendment
preserves the six newly identified files before they can be overwritten. No account,
authentication, broker-session, UI, or resource operation ran. Historical trust-path
uncertainty and all untested Native AOT/WAM/production-publishing obligations remain.

### Final Restore, Native Artifact, and Controller Stop

Attempts 09–10 used accepted PR #86 commit
`9055a9b473ab574a27469c96e31e1416ec69b14f`, tree
`aecc450913943737f396faf93b8d81a89f26aae8`, after independent source/protocol review,
independent finding triage, seven isolated prerequisite checks, mandatory commit checks,
full hk, and
[CI](https://github.com/hcoona/microsoft-authentication-cli/actions/runs/34675373960).
The only Windows helper change was `OS=Windows_NT`. The accepted migration preserved all
prior receipts and markers, copied the successful assets/lock under attempt 07 and the
four managed outputs under attempt 08, and recorded `host-os-revision.json`. No platform
guard was disabled, and no project, dependency, toolchain, command, or probe API changed.

| Attempt | UTC interval on September 12, 2026 | Actual observation |
| --- | --- | --- |
| 09: sixth and final restore | 05:26:51.881923–05:26:55.6390960 | Guard compilation exit 0; restore exit 0 in 1.986 seconds; no diagnostic codes or stderr, complete sanitized success text; quiescent and no safety stop. |
| 10: second and final publish | 05:27:57.192345–05:28:10.6269568 | Guard compilation exit 0; subject exit 0 in 11.856 seconds; controller safety stop true, final quiescence true, failure type `System.Management.Automation.RuntimeException`; publish diagnostics were not retained. |

**Restore observation:** Assets and lock bytes are identical to retained attempt 07.
All ten package versions, five exact 10.0.12 SDK downloads, and the sole
`Microsoft.NETCore.App` framework reference remain unchanged. The actual
`net10.0-windows/win-x64` target selects the same MSAL net8.0, Broker netstandard2.0,
NativeInterop net9.0, and x64 native entries. Their extracted bytes and the cache archives
were checked against the fetched archives before publish; NuGet content hashes matched
extraction metadata. This was a restore using the existing dedicated cache, not a new
clean-cache or network restore.

**Native artifact observation:** After final quiescence, read-only inspection found
exactly these three published files. The executable is PE x64 (`0x8664`) with a zero-size
CLR runtime directory, Windows system/API-set imports, and no delay-import table. The
published native DLL is byte-identical to the selected public archive entry. Together
with the accepted `PublishAot=true` command and exit 0, these facts establish production
of a native artifact by this synthetic publish. They do not establish its execution,
warning-free compilation, complete native dependencies, or successful broker imports.
Neither the EXE nor any managed output was executed.

| Published artifact | Bytes | SHA-256 |
| --- | --- | --- |
| NativeAotProbe.exe | 2,419,200 | `e7fbef7f06f86236ae38658052e4e46d46e3851048c7ec878e215986214ae495` |
| NativeAotProbe.pdb | 10,850,304 | `09cc29ee22678c93367bd43566dfd4544776caf30861232f5e04397da14a0cd7` |
| msalruntime.dll | 2,949,656 | `9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79` |

**Controller stop and evidence limit:** AOT-AUTHOR-018 independently confirmed the
recorded stop and the limits of its diagnosis. In the exact helper, assignment of subject
exit and elapsed time precedes the immediate job-accounting check and diagnostic
assembly. `diagnosticCodes` and both diagnostic objects are absent. The explicit
nonzero-`ActiveProcesses` branch is a possible origin; an exception while assembling the
captured streams before the first diagnostic assignment is another. The generic retained
exception type does not uniquely identify the originating statement. No job-process
count, process identity, stop stage, or actual termination branch was retained.

The final `quiescent=true` records the outcome of the owned compiler/job stop path.
`WindowsJob.Stop()` may return when no process remains or terminate the job and wait for
zero; this receipt does not identify which occurred. Do not claim a particular surviving
compiler/server, forced termination, a timing race, sensitive-output detection, timeout,
or a clean ordinary controller completion. The wrapper's exit 0 merely means it printed
the result; the inner safety-stop field remains authoritative for continuation.
No publish transcript, diagnostic count, or AOT/trim-warning disposition can be
reconstructed from absent fields. Exit 0 does not mean there were no warnings.

| Retained evidence | SHA-256 |
| --- | --- |
| Attempt 09 started.json | `f42d994b1eceebcac3fb496c2f7353c190dc8b5e79d58c8bcac6c8461ce8e138` |
| Attempt 09 result.json | `df42f0549332ae31c2e0842523d78e489ce8c71851ce78792b1b95b78f20e09a` |
| Attempt 10 started.json | `a6dbca61fe69c0aebbbde223fcfd940c42e63211b9164cfd46acfedc81fde298` |
| Attempt 10 result.json | `7937ca9fb73eda4f1be0337d39689b41c9eeaf7898a0603f2f1eb92425331b6c` |
| Host-OS revision marker | `7595b831ac11aceae750e1efbef47735209cb48c165191719805d7643a30a66d` |

**Bounded disposition:** The observed NuGet configuration failure was caused by omitted
program-files inputs. The next `NU1101` failures were two local-feed omissions;
WindowsDesktop and ASP.NET runtime packs 10.0.12 were publicly downloadable. Correcting
these inputs produced successful restores. Supplying the actual Windows OS identifier
then advanced the unchanged publish beyond its earlier cross-OS guard to a native
artifact and exit 0. These are observed preparation remedies, not evidence of blocked
public packages or Native AOT incompatibility in MSAL/Broker/NativeInterop.

The remaining experiment blocker is a recorded controller safety stop after successful
subject exit, with insufficient retained stage/diagnostic detail to identify its exact
origin. Positive, missing-library, and working-directory/PATH-decoy cases remain unrun;
there is no upstream allocation/import or restricted-search runtime result. At that point, later
execution required a newly accepted bounded grant/protocol disposition; changing a
source marker alone could not clear the stop, reuse a case slot, or reset capacity.
The current retained-artifact amendment above explicitly preserves the unrecoverable
origin and diagnostics instead of claiming they can be reconstructed. This historical
observation does not itself authorize that continuation.

Final consumption is original fetch **1/1**, supplemental fetch **1/1**, restore **6/6**,
publish **2/2**, each loading case **0/1**, and guard bootstrap **8/11**. Attempts 01–10
all have complete receipts, with no manual replay or interrupted reservation. At that execution revision, the safety
stop blocked all remaining cases despite unused case/guard capacity. Owned sources, feed,
caches, prior retained evidence, native artifacts, and sanitized receipts are
intentionally retained. No account, authentication, broker-session, UI, or resource action
was executed, and no account/session cleanup occurred. Historical Windows trust-path
uncertainty remains unchanged. Production publishing, full native cleanup, WAM behavior,
wrong-architecture rejection, and support remain unvalidated; no non-AOT exception or
alternative host is selected. PR #88 closed that bounded diagnosis Wave after accepting this evidence.

### Retained Native Artifact Runtime Results

Attempts 11–13 ran under accepted PR #90 commit
`8c090c5c6706ff777c422ed0b8eb7282e4964d92`, tree
`7a2185ae4a5679ff8faac3ffad72879a54fcd74b`, after PR #89's accepted grant and actual
postmerge fallback, independent source/protocol/consumer review, independent finding
triage, sixteen isolated prerequisite/completion checks, four in-memory Windows
PowerShell capture fixtures, mandatory commit checks, full hk, and
[CI](https://github.com/hcoona/microsoft-authentication-cli/actions/runs/34678174013).
Each action refreshed the accepted target and used the detached PR #90 checkout. The
subject remained the exact PR #86 EXE and native DLL, with no new restore, publish,
download, probe API, project, SDK-selection, or dependency change.

The accepted one-time migration preserved the old root, twenty attempt receipts, five
revision markers, native outputs, earlier retained build evidence and public archives.
Only the three controller sources changed; the four probe/configuration source copies
stayed byte-identical. The new marker records this explicit case-only stop disposition
and prior consumption. Each new start receipt binds all seven source files and the exact
executed PR #90 protocol. The wrapper and Windows helper verified artifact identities;
post-run inspection confirmed each case's exact file inventory and matching hashes.

| Attempt | UTC interval on September 12, 2026 | Actual observation |
| --- | --- | --- |
| 11: positive | 06:32:37.371433–06:32:39.4964068 | Subject exit 0; configuration created; native module loaded from the application directory. |
| 12: missing | 06:32:49.088133–06:32:51.0627661 | Subject exit 1; `System.DllNotFoundException`; native module not loaded. |
| 13: decoy | 06:32:58.478174–06:33:00.4672643 | Subject exit 1; `System.DllNotFoundException`; native module not loaded. |

**Runtime observations:** All three subjects reported `nativeAot=true`,
`restrictedSearch=true`, `unexpectedPreload=false`, and `builderCreated=true`. Positive
reported `operation=configuration_created`, empty exception type, and both native-module
Booleans true. Missing and decoy reported `operation=exception`, the fixed exception above,
and both native-module Booleans false; neither emitted a native status. The decoy case
contained the genuine DLL only in the working directory, which was also first in PATH.
All three application directories contained the same 2,419,200-byte EXE; only positive
also contained the 2,949,656-byte DLL. Their hashes are the final-publish identities above.

**Controller observations:** Every guard compilation exited 0. Every result has
`captureCompleted=true`, `stage=completed`, `safetyStop=false`, and `quiescent=true`.
Both the normal-exit and final-stop job counts were zero. No compiler or job termination
was requested; the job termination-success flag is false because that API was not called.
The recorded capture intervals were 0.254, 0.257, and 0.284 seconds, respectively. These
are controller observations from single runs, not a startup or performance benchmark.
The negative subject exits are expected observations, not failed controller executions.

**Bounded inference:** This exact Windows x64 .NET 10/MSAL 4.83.1/Broker 4.83.1/
NativeInterop 0.20.3 synthetic executable can run as Native AOT, build its in-memory MSAL
configuration, and enter the actual upstream configuration-allocation import under the
application-directory/System32 search restriction. The two negative cases demonstrate
missing-library failure and rejection of this working-directory/PATH placement. No
loader workaround, dynamic loading fallback, guard suppression, or non-AOT mode was used.
The source's managed disposal path returned, but upstream cleanup catches exceptions;
this observation does not prove every native release/shutdown operation succeeded.

| Retained runtime evidence | SHA-256 |
| --- | --- |
| Attempt 11 started.json | `45efcd1ff681867619a9b395cfb5f4d30deb99fcca3715bc707e46f3747ed70b` |
| Attempt 11 result.json | `707d9bfb3cbc14f653a2095428e2c7fe38b4228bf08382c02ae00ea0bc577c31` |
| Attempt 12 started.json | `4999179185701ed22ab87e7747d1828cba68181c3611df2db383340bf2001c5a` |
| Attempt 12 result.json | `2db27e1b262528e41a89222a2c0974d2c2b56b2776681c8019aea22712d50001` |
| Attempt 13 started.json | `16abde0120a100299833a39ba32cc75e377a37903dd38ce63c950e5396bfdd44` |
| Attempt 13 result.json | `cefdc2b0a294db54c6f172eeaf4b34dd0f601c4d65762dcf28d7044d3da4f63e` |
| Runtime revision marker | `dbf1fca23e052d3195b64dc98a2a6ab366d6bf319b16b0d6a73b33a37803f99f` |
| Executed PR #90 protocol | `8475886b8f195fa7fa048a1c515b144e089b20931a3bae6266ae84e0859c4d04` |
| Executed run.py | `30f8df44b3ed94d1955e4735aa8b33496dd4f6b86a88277942b3a1b3d3da76e2` |
| Executed Invoke-Action.ps1 | `ff4bcce993b754a911c3b11cd85e922f96f54eea2326807c540e54c6208d8586` |
| Executed WindowsJob.cs | `0dc397cb92acb3645b71e4e2a8995e00e0327d7324e389a7c3b5e55ad2b2e07a` |

**Final disposition and retention:** All thirteen sequential attempts have complete
receipts, with no manual replay or interrupted reservation. Cumulative consumption is
original fetch **1/1**, supplemental fetch **1/1**, restore **6/6**, publish **2/2**,
positive/missing/decoy **1/1 each**, and guard bootstrap **11/11**. All three runtime
cases completed within their limits, without an unresolved owned subject. Sources, feed,
caches, native/managed outputs, case files, guard artifacts and sanitized receipts remain
intentionally retained. No account/cache/session cleanup or unrelated-host change was
performed. The declared call boundary includes no account enumeration, token acquisition,
broker startup/session, UI, or resource operation; runtime success does not provide
observations of those uninvoked paths.

The synthetic runtime question is resolved for this one retained artifact and host.
Attempt 10 remains a historical controller stop with an unknown origin and unavailable
publish diagnostics; successful cases neither diagnose that old stop nor imply zero
AOT/trim warnings. Earlier Windows trust-processing uncertainty and the opaque native
initializer's evidence limits remain. Wrong-architecture handling, full native cleanup,
WAM/UI/authentication, complete application behavior, publish-warning review and production
support remain separate validation obligations. The assessment, Windows design and
validation strategy consume these narrower results without selecting a production mode
or a non-AOT exception. No further execution is authorized by this recorded procedure.

### Fetched Public Archive Identities

The original fourteen and two supplemental archives used fixed public NuGet
flat-container URLs. These are fetched inputs, not all application runtime assets.

| Package | Version | SHA-512 |
| --- | --- | --- |
| Microsoft.Identity.Client | 4.83.1 | `692ae5e6b961a2ef71b747a9877f7a7f0460a03f9fb2edc0fa7e4d457a5419a0f564afae53c6296b7e75e0ab2b1c61b3f621a9d56e99945bb047b02dcfe9a2bd` |
| Microsoft.Identity.Client.Broker | 4.83.1 | `9923928bde2049ed3ec125f871eb37f125a2bb28d20e0d5ebdf59d1a7cb1f37858f4c7d818dd25fd72f1fa7ae96a01a1320d1a21bb3ba3a1379d3fe37463f2ec` |
| Microsoft.Identity.Client.NativeInterop | 0.20.3 | `e8d30c22acc6c14d91f09c9e8204278357f2500a11e1e7befb1443f0e806a9dd5522938d37733bfe3de11a1c4e30ccea4755f80fcd1f9de6d8c87a88910ae5cd` |
| Microsoft.IdentityModel.Abstractions | 8.14.0 | `175ef8bf78b63f3c327e680d5cf7721d74f29e96460e686b22b4e67c264fb036a7a9bea1473f4a5b487337ab7a560c861b51ed1aa744777f303362262b01a8b4` |
| System.Diagnostics.DiagnosticSource | 6.0.1 | `80a0f9bf3a7afdb28d9f00e1f301feeacb39c34fe4ac8f55a392377e2e018fb546fc3fc56e2fe4336dea222b7ab3f4bab58a0b8d86eb18c71951ef2e1c752789` |
| System.Runtime.CompilerServices.Unsafe | 6.0.0 | `d4057301be4ec4936f24b9ce003b5ec4d99681ab6d9b65d5393dd38d04cdec37784aaa12c1a8b50ac3767ed878dae425749490773fec01e734f93cf1045822b3` |
| System.ValueTuple | 4.5.0 | `fa00ebb5045d12c51274f64411c551981beceb1266a8606a4731063109b95ea1f15939197bf3d2ba899db61e593dc39bfce876908bba34286823525093ae3d8e` |
| Microsoft.DotNet.ILCompiler | 10.0.12 | `a9e3932bd0d16d6c78fde79b5c6d6fe74ca4104983f54be9f09d62085aa7cf7d1683cb3cbdf3dddad3e9a9a7b4c0c9d262676f28299308483afd96b34acba562` |
| runtime.win-x64.Microsoft.DotNet.ILCompiler | 10.0.12 | `3875d56e9404026f57c1b1a0673c722b5485340b693422c7c9ea118f40301b51ed173871ee525818080de8230ee0ac6147c56e352d4da8929532b3b3959d684d` |
| Microsoft.NETCore.App.Runtime.NativeAOT.win-x64 | 10.0.12 | `bc56dd1d11b4a49874cc12cfa66f0163fa1a353fb84d8158e336e2eb779ebd7ae0aa487d660bc85043c833589a33f348ea6674cf1bf61744fe1ae9d38168e9c8` |
| Microsoft.NETCore.App.Runtime.win-x64 | 10.0.12 | `39afcb222032eabebe2c7fa51a37c491c6b0f456796ad7888431971b8eef4f689caee5454260398ce0ffafe491c565891b35e73afc67585a3e4c4bde995710ee` |
| Microsoft.NETCore.App.Ref | 10.0.12 | `b8df7c98c76bba344b41d20151dc79e5a4dc764b5fdb893844fdfdb895be05247d31cb4e93452ba668beb2f3f62a3f30ed8b1242e06b7a0c53b11125fc69ba28` |
| Microsoft.NETCore.App.Host.win-x64 | 10.0.12 | `33c2760f5936e1eb30609fc368974761bc331eb720fa0593bf92f9f050c6d91d67f673a22783160ab84c16d6736e8c02c10066ced6c06cceed378f5cbaa78588` |
| Microsoft.NET.ILLink.Tasks | 10.0.12 | `a294f93f5a7e086ef4c466af79382add0e4e64a77b319d11b35d31e137b097a6dc3dbbb848ba381749fa4410889ef04ac68475d13d75f97d0cf5d8232847ee73` |
| Microsoft.WindowsDesktop.App.Runtime.win-x64 | 10.0.12 | `05e188fca4c105c6b8a5dbaed677dfeb556f640c25cd5c2a366a3e795a93dba96db0026c42c17ffc308f26cb30f9f5e9011abe150ee954a89079de6282ff0a61` |
| Microsoft.AspNetCore.App.Runtime.win-x64 | 10.0.12 | `9fca92913dca9245d2a6ef5453be3cc3311bac3c0b3890a4386c58d03fedbd63b051751b4b6a9193989c606d92ba447bfa2d5e3bc605e2c3a5fa2bdba218513c` |

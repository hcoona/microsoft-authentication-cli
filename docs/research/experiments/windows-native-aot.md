# Windows Native AOT Synthetic Experiment

This record owns the exact Issue #76 procedure and its cumulative observations. The
[accepted Wave](../../delivery-wave.md)
owns authorization; [experiment safety](../experiment-safety.md) owns general policy.
The [assessment](../v1-public-contract-baseline.md#windows-native-aot-assessment),
[Windows design](../../designs/windows-ado-authentication.md#native-aot-target-disposition),
and [validation strategy](../../validation/strategy.md#native-aot-publishing) consume
the bounded conclusion. The historical Windows MSAL and tooling protocols retain their
exhausted capacities; none of their helpers or subjects may execute here.

The recorded outcome remains an unresolved restore prerequisite: two restores failed,
so no Native AOT publish or loading case ran. The diagnostic continuation preserves
those attempts and extends cumulative restore capacity to six under the accepted Wave.
The first continuation changes diagnostic retention only; commands, environment,
toolchain, packages, and synthetic program remain unchanged. Execution still requires
independent acceptance of this exact amendment and all pre-action gates below.

## Question and Exact Subject

Can the pinned .NET 10 Windows x64 synthetic program publish with Native AOT and enter
the actual upstream NativeInterop configuration-allocation import with DLL search
restricted to the application directory and System32? A failed publish, unavailable
safe entry point, or failed allocation is a valid observed blocker. Do not add broker
startup, a loader workaround, warning suppression, or a non-AOT fallback to make it pass.

The subject is the complete accepted directory
[`tools/probes/windows-native-aot`](../../../tools/probes/windows-native-aot), including
the project, `Program.cs`, `global.json`, `nuget.config`, `run.py`, and
`Invoke-Action.ps1` and its `WindowsJob.cs` process guard. The guard is excluded from the
Native AOT project. Execution binds their exact bytes and this protocol to the same
merged commit, from a detached checkout. That commit is recorded before every attempt;
this record does not need a self-referential commit hash. No product source is built.

| Input | Pin and selection |
| --- | --- |
| .NET | Existing Windows SDK 10.0.401, runtime/targeting/apphost/ILCompiler/ILLink 10.0.12; SDK roll-forward disabled |
| Project | `net10.0-windows`, `win-x64`, Release, `PublishAot=true`, self-contained; exact properties and commands in the accepted source |
| MSAL | Client and Broker 4.83.1; NativeInterop 0.20.3; modern selected assets expected to be net8.0, netstandard2.0, and net9.0, respectively; confirm from actual assets before interpreting results |
| Managed closure | Abstractions 8.14.0, DiagnosticSource 6.0.1, Unsafe 6.0.0, ValueTuple 4.5.0; exact direct constraints prevent transitive floating |
| SDK package candidates | Seven 10.0.12 packages enumerated in `run.py`, including the separate NativeAOT runtime pack; unused candidates are not claimed as resolved dependencies |
| VC tools | Existing Visual Studio 18 Enterprise, `VC/Tools/MSVC/14.51.36231`, Hostx64/x64; actual `link.exe` file version 14.51.36257.0 and `cl.exe` 19.51.36257.0 |
| Windows SDK | Existing 10.0.26100.0 x64 UM and UCRT libraries and tools, with the selected VC x64 libraries; no floating discovery through `vcvarsall` |
| Tool selection | `IlcUseEnvironmentalTools=true`, explicit `CppLinker`, and exact child `PATH`, `LIB`, and `INCLUDE`; the helper checks recorded SHA-256 identities for dotnet, link, cl, kernel32.lib, and ucrt.lib before a child starts |
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

The fetch uses Python's standard-library HTTPS client without inherited proxy/auth
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

## Execution and Finite Capacity

Before **each** action, the operator refreshes `origin/main-v2`, confirms the accepted
Wave and exact protocol remain current, recovers the required independent review and
CI/commit-check receipts, and checks prior attempt results. Material prerequisite drift
requires refreshed review. The wrapper checks ancestry, current Wave bytes, checkout
and Windows-copy source bytes, prior consumption, feed identities, and prerequisites.
The diagnostic amendment uses its own merged commit as `ACCEPTED_COMMIT` in a detached
checkout. The first action repeats PR #79's restore command and replacement environment
without modification. The controller retains useful sanitized ordinary build diagnostics
under the contract below. Public-fetch capacity remains one consumed batch in this exact
protocol; the wrapper cannot fetch or create another root. The Wave's conditional extra
fetch remains inactive unless a demonstrated missing dependency receives a separately
accepted exact manifest and protocol within that Wave's cumulative bounds:

```text
python3 tools/probes/windows-native-aot/run.py restore --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py publish --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py positive --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py missing --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py decoy --accepted ACCEPTED_COMMIT
```

These are WSL operator commands for this host boundary. Invoke one action at a time;
do not batch past a result requiring inspection. Source amendments require independent
acceptance before execution and must preserve the root's prior consumption. This one
amendment accepts only the original PR #78 root, the PR #79 source copies, exact receipts
01 through 03, and the original `source-revision.json`, whose SHA-256 identities are
pinned in `run.py`. Before the diagnostic restore, it verifies those copies, prior
results, and feed hashes, replaces only the seven owned source copies, and writes a new
`diagnostic-revision.json` naming the prior and current accepted source and consumption.
The original identity, revision marker, and six receipt files remain byte-for-byte
unchanged. PowerShell receipts retain UTF-8 BOM-aware reading. A partial source
replacement fails closed; another amendment requires explicit review. Later actions
require this amendment's same accepted revision. Known consumption before the first
continuation is fetch 1, restore 2, publish 0, each case 0, and guard bootstrap 2.

| Unit | Cumulative maximum, including failed starts and manual execution |
| --- | --- |
| Public package fetch | One batch, 14 package requests, no retries or redirects; 300 MiB per archive and 1.5 GiB total; a WSL process timer interrupts pending reads at a 600-second batch deadline, in addition to 30-second socket inactivity limits |
| Restore | Six cumulative Windows actions, including the two historical actions; at most 600 seconds each |
| Native AOT publish | Two Windows actions, at most 900 seconds each, after successful restore and exact resolved closure inspection |
| Synthetic cases | One positive, one missing-library, and one combined working-directory/PATH-decoy action; 30 seconds each; no repeat |
| Guard bootstrap | One standalone compiler action per Windows action, at most eleven cumulatively including the two historical compilations; 60 seconds plus 10 seconds termination each, with no shared compiler/server mode, installation, or authentication subject execution |
| Windows controller | One per Windows action, 1,300-second WSL wait ceiling; child output at most 8 Mi characters in memory, never raw provider output on disk |
| Subject process/termination bounds | Kernel Job Object limit of 32 simultaneously active processes per action; at most 10 seconds for job termination and active-process quiescence |

The sequential attempt directory is created and `started.json` written before invoking
the subject. An incomplete or unreadable receipt, exhausted capacity, safety stop, or
uncertain termination prevents continuation. Attempts and effects do not reset on a
protocol amendment, failed preparation, checkout, operator change, or machine switch.
There is no second machine authorized by this exact protocol. Spare restore/publish
capacity permits only an explained retry of the current accepted source when no
unresolved safety stop exists. Changed source requires an accepted amendment; neither
an amendment nor source replacement resets capacity or clears an unresolved effect.

Each case uses a fresh process and isolated application directory. Positive contains the
published executable and its published x64 `msalruntime.dll`; missing contains only the
executable; decoy places the genuine DLL only in the working directory and prepends that
directory to the child PATH. Before touching NativeInterop, the program sets
`SetDefaultDllDirectories(APPLICATION_DIR | SYSTEM32)` and rejects an unexpected preload.
Positive success requires AOT, restricted search, configuration creation, and the loaded
module's path matching the application directory. Missing and decoy should fail with no
native module loaded. An unexpected successful decoy load stops subsequent actions.
There is no wrong-architecture execution: this public package includes only the x64
Windows native DLL; fabricating another executable subject is unnecessary here.

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
does not supply another restore. No continuation runtime observation is yet recorded.

### Fetched Public Archive Identities

All use the fixed public NuGet flat-container URL construction in the original protocol.
These are fetched inputs, not a resolved dependency graph.

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

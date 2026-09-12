# Windows Native AOT Synthetic Experiment

This record owns the exact Issue #76 procedure and its cumulative observations. The
[accepted Wave](../../delivery-wave.md#windows-native-aot-synthetic-compatibility-experiment)
owns authorization; [experiment safety](../experiment-safety.md) owns general policy.
The [assessment](../v1-public-contract-baseline.md#windows-native-aot-assessment),
[Windows design](../../designs/windows-ado-authentication.md#native-aot-target-disposition),
and [validation strategy](../../validation/strategy.md#native-aot-publishing) consume
the bounded conclusion. The historical Windows MSAL and tooling protocols retain their
exhausted capacities; none of their helpers or subjects may execute here.

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
  the [.NET 10 Native AOT implementation](https://github.com/dotnet/runtime/blob/95017c711e6afc1085133d440e42b4bd78155701/src/coreclr/nativeaot/System.Private.CoreLib/src/System/Runtime/InteropServices/Marshal.NativeAot.cs)
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
configuration, credential store, or unrelated application state is changed.

The fetch uses Python's standard-library HTTPS client without inherited proxy/auth
handlers, one fixed public flat-container URL per exact package. Restore uses only that
local feed and an initially empty dedicated package cache. Later retries may use that
cache and must not be called clean restores. Public-download success and local-feed
restore success are distinct observations. Signature revocation checking is offline;
NuGet auditing is disabled for this bounded restore, not as repository security policy.

Every subject child receives a complete replacement environment. The accepted helper
sets documented .NET telemetry, certificate-generation, global-tool-PATH, and workload
notification controls, disables build servers/node reuse and diagnostics, and omits
inherited feed credentials, NuGet plugins, startup hooks, proxies, and agent settings.
PowerShell uses `-NoProfile -NonInteractive`; it passes no ambient environment to the
subject. No MSAL or native logging/telemetry callback is installed. Controller/bootstrap
receipts contain only the corresponding PID and creation time; no unrelated process
inventory or command lines are retained.

## Execution and Finite Capacity

Before **each** action, the operator refreshes `origin/main-v2`, confirms the accepted
Wave and exact protocol remain current, recovers the required independent review and
CI/commit-check receipts, and checks prior attempt results. Material prerequisite drift
requires refreshed review. The wrapper checks ancestry, current Wave bytes, checkout
and Windows-copy source bytes, prior consumption, feed identities, and prerequisites.
Record the first protocol merge's commit as `ACCEPTED_COMMIT`; from its detached checkout:

```text
python3 tools/probes/windows-native-aot/run.py fetch --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py restore --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py publish --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py positive --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py missing --accepted ACCEPTED_COMMIT
python3 tools/probes/windows-native-aot/run.py decoy --accepted ACCEPTED_COMMIT
```

These are WSL operator commands for this host boundary. Invoke one action at a time;
do not batch past a result requiring inspection. Source amendments require independent
acceptance before execution and must preserve the root's prior consumption; the initial
wrapper deliberately rejects adopting a root under another subject revision.

| Unit | Cumulative maximum, including failed starts and manual execution |
| --- | --- |
| Public package fetch | One batch, 14 package requests, no retries or redirects; 300 MiB per archive and 1.5 GiB total, 600 seconds plus at most one 30-second socket wait |
| Restore | Two Windows actions, at most 600 seconds each |
| Native AOT publish | Two Windows actions, at most 900 seconds each, after successful restore and exact resolved closure inspection |
| Synthetic cases | One positive, one missing-library, and one combined working-directory/PATH-decoy action; 30 seconds each; no repeat |
| Guard bootstrap | One standalone compiler action per Windows action, at most seven cumulatively; 60 seconds plus 10 seconds termination each, with no shared compiler/server mode, installation, or authentication subject execution |
| Windows controller | One per Windows action, 1,300-second WSL wait ceiling; child output at most 8 Mi characters in memory, never raw provider output on disk |
| Subject process/termination bounds | Kernel Job Object limit of 32 simultaneously active processes per action; at most 10 seconds for job termination and active-process quiescence |

The sequential attempt directory is created and `started.json` written before invoking
the subject. An incomplete or unreadable receipt, exhausted capacity, safety stop, or
uncertain termination prevents continuation. Attempts and effects do not reset on a
protocol amendment, failed preparation, checkout, operator change, or machine switch.
There is no second machine authorized by this exact protocol. Spare restore/publish
capacity permits only an explained retry of the same accepted source when no safety stop
occurred; it does not authorize unreviewed fixes.

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
to the job before resuming, and gives it only the explicit output/error pipe handles.
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
be explained from public source/IL without replaying a publish. Never retain exception
messages/stacks, account/tenant identifiers, tokens, native error context, raw broker
diagnostics, or private local guidance. Unexpected output is suppressed and stops further
subject execution. Preserve missing output or crashes as failures, not negative-case
success. Read-only artifact inspection and sanitized record preparation are not new
subject attempts.

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

No subject execution is recorded by this protocol proposal. Initial consumption is zero;
the first execution must recover the accepted merge and its gate evidence.

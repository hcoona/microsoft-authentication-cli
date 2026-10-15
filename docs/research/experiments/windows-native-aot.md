# Windows Native AOT Synthetic Experiment

This is a completed experiment record for
[Issue #76](https://github.com/hcoona/microsoft-authentication-cli/issues/76) and its
[Issue #92](https://github.com/hcoona/microsoft-authentication-cli/issues/92) readiness
supplement, retained as evidence cited by current records. It authorizes no execution.
The Delivery Wave grants it ran under were completed and removed. The full protocol,
diagnostic rounds, procedures, recipes, allocations and accounting, source pins, hashes
and execution history remain at the
[pinned revision](https://github.com/hcoona/microsoft-authentication-cli/blob/242cd292a10ee5626e783f42349e570c2e5a19a1/docs/research/experiments/windows-native-aot.md).
The synthetic probe sources remain at the same revision:
[`windows-native-aot`](https://github.com/hcoona/microsoft-authentication-cli/tree/242cd292a10ee5626e783f42349e570c2e5a19a1/tools/probes/windows-native-aot)
and
[`windows-native-aot-readiness`](https://github.com/hcoona/microsoft-authentication-cli/tree/242cd292a10ee5626e783f42349e570c2e5a19a1/tools/probes/windows-native-aot-readiness).
The [experiment policy](../experiment-safety.md) governs any future experiment; another
run requires a new accepted protocol and authorization.

The [V1 baseline](../v1-public-contract-baseline.md) owns the Native AOT assessment, the
[Windows design](../../designs/windows-ado-authentication.md) owns the publishing
selection, and the [validation strategy](../../validation/strategy.md) owns the remaining
validation obligations. This record keeps only the bounded conclusions those records rely
on.

## Question and Common Basis

The experiment asked whether a pinned .NET 10 Windows x64 synthetic program can publish
with Native AOT and enter the actual upstream NativeInterop configuration-allocation
import with DLL search restricted to the application directory and System32. A failed
publish or failed allocation was a valid observed blocker. No broker startup, loader
workaround, warning suppression or non-AOT fallback was permitted.

- **Subject.** Synthetic probes only; no product CLI or library source was built.
  Dependencies were MSAL Client and Broker 4.83.1 and NativeInterop 0.20.3, with
  Abstractions 8.14.0, DiagnosticSource 6.0.1, Unsafe 6.0.0 and ValueTuple 4.5.0 pinned
  as direct constraints. All packages came from fixed public NuGet archives whose
  identities are retained at the pinned revision.
- **Host.** One existing Windows 11 x64 host driven through WSL 2, with existing .NET SDK
  10.0.401/runtime 10.0.12, MSVC 14.51.36231 and Windows SDK 10.0.26100.0. No tool or
  package installation, account, authentication, broker session, UI or resource
  operation occurred.
- **Call boundary.** This is a static source/IL finding, not a runtime observation. At
  public MSAL commit
  [`d5d7de6b`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/tree/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f),
  application building records a broker factory without invoking it, and constructing
  NativeInterop `AuthParameters` imports `MSALRUNTIME_CreateAuthParameters` from
  `msalruntime`. Disposal can call `MSALRUNTIME_ReleaseAuthParameters` and
  `MSALRUNTIME_Shutdown`, but the upstream safe-handle release catches exceptions, so
  managed disposal returning does not prove native release succeeded. Account
  enumeration, token acquisition, logging callbacks, discovery and broker sessions were
  never invoked.
- **Process accounting.** Every build and runtime action ran inside an owned Windows Job
  Object guard. Normal completion required zero remaining Job processes; any other
  outcome was a controller safety stop.

## Diagnostic Round 05 Results

**Runtime/synthetic observation (September 12, 2026 UTC):** The final round ran accepted
source `953b5ad9ea0fb470a54dc556955ec622211e6d6d` from a clean detached checkout, with a
dedicated scratch home, temp and HTTP-cache environment for every action.

- **Restore.** Restore completed normally. Complete screened diagnostics contained no
  warning text, diagnostic code, truncation or suppression. The ten-library graph and
  every package and download-pack payload matched the reused public archives. Selected
  assets were net8.0 Client, netstandard2.0 Broker, net9.0 NativeInterop and the
  package's x64 native DLL. This is a local-feed restore, not a clean public-network
  restore.
- **Publish.** The rooted Native AOT publish exited zero. Complete screened diagnostics
  contained no AOT, trim, managed-compiler or linker warning and no suppressed or
  truncated diagnostic. The selected provider API surface was rooted for compilation and
  never invoked at runtime. No suppression or dependency exception was needed for this
  exact synthetic graph.
- **Publish completion.** One verified MSVC `vctip.exe` (VC++ Technology Improvement
  Program telemetry uploader) Job member remained after the normal drain. Under the
  prospectively accepted identity/accounting criterion, owned-Job termination succeeded
  and the final active count was zero. This is an accepted VCTIP cleanup completion, not
  a zero-process normal drain. It does not prove absence of telemetry or opaque helper
  effects, and it does not reconstruct earlier unidentified survivors.
- **Static inspection.** Both published images are AMD64 PE32+ with no CLR directory.
  Their direct imports are Windows libraries and API-set contracts, with no delay
  imports. The output contains no PDB.

| Published artifact | Bytes | SHA-256 |
| --- | --- | --- |
| `NativeAotReadinessProbe.exe` | 8,643,584 | `31fc25f4b5704bb6837e1078d60a51c3ee4e225728bdcdd6650104e7b7a5577e` |
| `msalruntime.dll` | 2,949,656 | `9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79` |

- **Cleanup case.** The published EXE ran with its bound x64 DLL in a fresh case
  directory and completed normally with zero Job processes and no termination. The
  native-AOT flag, restricted search, a first-chance exception self-check, MSAL builder
  creation, configuration allocation, cleanup-export checks, first and repeated
  disposal and application-directory module checks all passed. No unexpected preload
  and zero first-chance cleanup exceptions were observed.
- **Wrong-architecture case.** The same EXE ran with the genuine public x86 NativeInterop
  DLL, SHA-256 `ed45298d791cc6509ca5cdc3ed497b77ddfe6b5c1475c7fe9470b5c0e0f41c28`,
  substituted as `msalruntime.dll`. It returned the expected exit 1 with
  `System.BadImageFormatException`. Allocation and module loading were false, cleanup
  did not run, and the controller completed normally with zero Job processes and no
  termination. The expected negative exit is a passed rejection case.

**Inference:** Together with the pinned public call boundary, the round supports the
preimplementation Native AOT premise for the exact Windows x64 design: public asset
resolution, warning-free rooted compilation, accepted publish completion, restricted
native loading and allocation, observable release and shutdown without a managed or
wrapper-reported failure, and genuine wrong-architecture rejection.

**Limitations:** One synthetic executable on one existing host with development tools
installed. The evidence does not inspect opaque native deallocation, claim a shutdown
return status, enumerate dependencies loaded only by actual WAM or authentication paths,
or prove deployment on a host without development tools. Nonempty PE debug directories
do not select a product symbol policy. Full application, WAM, UI, account and
cancellation behavior, product symbols, performance, release and support are
**unvalidated** and remain later validation obligations.

## Retained Native Artifact Runtime Results

**Runtime/synthetic observation (September 12, 2026 UTC):** Earlier attempts ran the
retained Native AOT output of accepted source
`9055a9b473ab574a27469c96e31e1416ec69b14f` without a new restore or publish. All three
cases used the same 2,419,200-byte `NativeAotProbe.exe`, SHA-256
`e7fbef7f06f86236ae38658052e4e46d46e3851048c7ec878e215986214ae495`.

| Case | Actual observation |
| --- | --- |
| Positive | Exit 0; MSAL configuration created; native module loaded from the application directory. |
| Missing library | Exit 1; `System.DllNotFoundException`; native module not loaded. |
| Working-directory/PATH decoy | Exit 1; `System.DllNotFoundException`; native module not loaded. The genuine DLL was present only in the working directory, which was also first in PATH. |

All three subjects reported Native AOT execution, restricted search, no unexpected
preload and successful builder creation. Every controller completed with zero Job
processes, no termination request and no safety stop. The negative exits are expected
observations, not failed controller executions.

**Inference:** This exact .NET 10/MSAL 4.83.1/Broker 4.83.1/NativeInterop 0.20.3
synthetic executable can run as Native AOT, build its in-memory MSAL configuration and
enter the actual upstream configuration-allocation import under the application
directory/System32 search restriction. The missing and decoy cases demonstrate
missing-library failure and rejection of that working-directory/PATH placement.

**Limitations:** These results bind only that retained artifact. Its publish ended in a
controller safety stop whose origin is unknown and whose publish diagnostics were not
retained; these successful cases neither diagnose that stop nor imply zero AOT/trim
warnings for that artifact. Runtime intervals were single runs, not a benchmark.

## Historical Stops and Preserved Unknowns

**Runtime/synthetic observation:** Earlier preparation and rounds observed these
blockers. None was evidence of an MSAL, Broker or NativeInterop package rejection,
network blocking, or Native AOT compiler failure.

- **Preparation.** Initial restores failed until the SDK first-use control, the NuGet
  program-files environment inputs and two publicly downloadable 10.0.12 runtime packs
  (WindowsDesktop and ASP.NET Core) were corrected. Supplying the actual Windows OS
  identifier then let the unchanged publish produce a native artifact. The first
  failed restore's exact cause remains unknown because raw output was not retained.
- **Original publish stop.** The publish that produced the retained artifact exited zero,
  but the controller recorded a safety stop. Its origin and publish diagnostics remain
  **unknown**; later warning-free output does not recover them.
- **Readiness and early diagnostic stops.** Several later publishes exited zero but left
  one Job process at the immediate zero-process check, so the controller terminated the
  owned Job and stopped. Where identity was later sampled, the survivor matched the
  expected MSVC `vctip.exe` path lexically; earlier survivors remain unidentified. One
  diagnostic preflight was rejected because its encoded command exceeded the documented
  `CreateProcessW` command-line limit; its actual error was not retained. These stops
  led to the prospective completion criterion used in Round 05.
- **Public VCTIP context (public documentation, not an observation here).** Microsoft's
  [BuildXL MSVC definition](https://github.com/microsoft/BuildXL/blob/280e155410f72498fbf908913e7027a99c0892e1/Public/Sdk/Experimental/Msvc/VisualCpp/visualCpp.dsc)
  identifies `VCTIP.EXE` as the VC++ Technology Improvement Program telemetry uploader
  and lists it among surviving compiler children. The searched public guidance
  established no process-local suppression control for the pinned compiler; that is a
  search limit, not proof that none exists.

All stopped roots, receipts and artifacts were intentionally retained read-only. No
stopped root, consumed allowance or unused buffer may be replayed or reused. Historical
Windows trust-processing uncertainty also remains unchanged.

## Current Bounded Conclusion

**Inference:** Public toolchain and Win32 contracts plus the bounded observations above
support selecting Native AOT for the exact .NET 10 Windows x64 Win32 host at the
preimplementation design level, without changing authentication dependencies, relaxing
DLL search, suppressing warnings or accepting a non-AOT exception. The native DLL and
applicable Windows components remain required assets; single-executable native
compilation is not a one-file distribution guarantee.

**Unvalidated:** Clean public-network restore, dynamic WAM dependency closure,
deployment without development tools, opaque native deallocation, product build helpers
and symbols, startup, memory and size, and complete-application WAM, account, UI,
cancellation, release and support behavior. Those remain obligations of the validation
strategy and a separately authorized implementation.

# Windows Slice Implementation Validation

This protocol owns credential-free execution during [Issue #108](https://github.com/hcoona/microsoft-authentication-cli/issues/108).
The [Windows scenario basis](../../validation/strategy.md#windows-slice-design-acceptance)
owns required behavior and evidence selection. The current
[Delivery Wave](../../delivery-wave.md#first-windows-authentication-slice-implementation-and-scenario-acceptance)
owns authorization and maximum effects. This protocol initially allocates only the Linux
managed scenario loop below. Windows publish, process/UI tests and real account work
require an independently accepted supplement before execution; they remain required for
the corresponding Slice acceptance claims.

## Subject and Source Admission

The subject is the fork-owned .NET 10 authentication core and its controlled scenario
tests, compiled from one immutable candidate Git commit in a dedicated detached
checkout. The initial entry point is
`tests/Authentication.Scenarios/Authentication.Scenarios.csproj`, targeting `net10.0`.
The tests exercise the application boundary with synthetic provider results,
an explicit fake Windows host and controlled time. They do not construct a real WAM
adapter, invoke Windows executables, enumerate accounts, access application/broker
caches, acquire tokens, or contact identity/resource services.

Before each source revision executes, an independent reviewer must identify in the
coordinating pull request the exact candidate commit/tree, test/project source paths,
direct dependency pins, any exact package-fetch list, allowed commands and expected red
or green result. Identify the intended missing behavior and failing test names for a red
admission. Inspect the
actual entry points, project imports and fixture behavior to establish this protocol's
effects boundary. Admission may cover several sequential actions on that unchanged
source. Source changes require refreshed admission; modifying this protocol or its runner
requires independent acceptance on `main-v2` before using the change. Source admission
does not accept unverified product behavior or change the protocol's effects.

The exact helpers are [`run_managed.py`](../../../tools/validation/run_managed.py) and
[`fetch_packages.py`](../../../tools/validation/fetch_packages.py). Use the accepted
protocol/runner revision explicitly and verify their bytes against Git.
Confirm the accepted Wave remains present before every action. Record the target commit,
protocol revision, candidate source commit/tree and review URL in the action receipt.
The candidate must descend from the implementation grant, contain the reviewed source,
and have no uncommitted tracked modifications in its execution checkout. Record source hashes
before and after execution, excluding declared generated `bin`/`obj`/result directories.
Changed source invalidates the action and stops further execution.

Before every action, fetch and inspect current `origin/main-v2` and the applicable
independent review. A URL is a reference to human-reviewed admission, not proof by itself.
The helper verifies the supplied accepted target, protocol ancestry, source ancestry,
accepted protocol/runner bytes and the exact relied-on Wave blob. A changed Wave stops
this helper until its protocol and gate evidence are refreshed. Candidate code need not
merge before the admitted red/green execution: its exact review applies this accepted
protocol and cannot enlarge the grant or change an unaccepted design prerequisite.

## Host, Dependencies and Files

Use the existing WSL 2 Linux x64 host and its already installed public .NET SDK 10.0.401,
runtime 10.0.12. Root `global.json` retains disabled roll-forward. Verify the resolved
Linux SDK path and the recorded executable/SDK/runtime identities before invoking it;
do not use a Windows `dotnet.exe`, ambient SDK selection, installation or repair.
The SDK's public archive identity remains in `mise.development.toml` and the accepted
[developer-tooling evidence](developer-tooling.md). Installed-state reuse is not a fresh
installation observation.

The helper checks these SHA-256 identities under the explicitly supplied resolved SDK
root before starting a subject:

| Installed file | SHA-256 |
| --- | --- |
| `dotnet` | `01d89e0a0191052bfea616cd4ce624c8faf13b05bbddf7f64499c23e2a9d9269` |
| `sdk/10.0.401/dotnet.dll` | `bf8844d3d50869c1c05ff4aaf1908a81ca657106bed52be1388a8323690f5049` |
| `sdk/10.0.401/MSBuild.dll` | `c00b1a9d5e458b2775ee1ea353cd8735ee5e5bf137e7c8c7a468ffa6c90c4ab4` |
| `shared/Microsoft.NETCore.App/10.0.12/System.Private.CoreLib.dll` | `26304a2985357b9ee277f273667fcd9c892edae3ee6eba76f739033e95eb39b3` |

The initial test framework is public `MSTest` 4.1.0, with its documented embedded
Microsoft.Testing.Platform runner. It is a test-only dependency. Core code uses .NET
framework libraries; the selected MSAL/Broker/NativeInterop product pins remain unchanged
but are not executed by this initial managed loop. Direct dependencies are exact pins.
The first admitted restore may generate the lock and resolved asset graph. Before
restore, inspect downloaded package manifests and executable build imports, and admit
the complete required graph with exact versions. Independently review the resulting
public provenance and resolved graph before build/test. Later restores use
the reviewed lock unless a separately reviewed dependency change explicitly admits a new
resolution. A new graph is preparation evidence, not permission to execute its contents.

The bounded fetch helper downloads only explicitly admitted `name=version` archives from
`https://api.nuget.org/v3-flatcontainer/`. It disables proxies, rejects redirects, requires
a positive Content-Length, performs no automatic retry, retains original packages and
partial bodies, and reports package sizes and SHA-512 identities. A fetch admits at most
40 packages and reserves 128 MiB before starting. Declared body lengths must fit that
reservation; a failed or partial action still consumes the entire reservation. This
conservative accounting bounds failed transfers without reconstructing network traffic.
Review each downloaded manifest before admitting further transitive package fetches;
the helper does not select versions, traverse dependency graphs, or extract packages.

Restore uses only the dedicated local feed populated by successful fetches. Its explicit
config clears inherited sources and mappings and supplies no credentials. Disable NuGet
audit network retrieval for this offline loop; package provenance and dependency review
remain required. No public online restore claim follows from this procedure.
Set dedicated package, HTTP,
plugin, home and temporary directories under `/var/tmp/azureauth-windows-slice-108`.
Do not use the user's NuGet cache or credential providers. An initially empty dedicated
cache may be reused after provenance review; record warm/empty state accurately.

The root contains one detached source checkout and sequential per-action directories.
Create it only after this protocol is accepted, with current-user ownership and mode
0700; reject a symlink, unexpected existing ownership or unrecognized prior state.
Keep a root marker, exclusive action lock and contiguous action history. Each action has
dedicated home/temp/results/download paths; build outputs remain within that checkout.
A new independently admitted source commit may replace the checked-out commit. Reuse
restore assets only when all graph-determining inputs remain byte-identical: project,
import, central-package, lock, NuGet and SDK configuration, plus generated restore metadata.
The initial source may import only the verified SDK, admitted public package targets,
and files under `src/` or `tests/`; root `global.json` supplies SDK selection. No other
external MSBuild imports or response files are admitted. The helper hashes all non-C#
source inputs in those roots and verifies recorded restore metadata before build/test.
Adopt the reviewed generated locks into candidate source; before Git replaces an
untracked lock with its identical tracked copy, retain the generated file in the action
directory. Changed C# source still requires a successful new source-bound build before
test execution. Reuse an existing test artifact only for its unchanged source and bytes.
Retain all experiment files, including failed preparation and the current generated
outputs; earlier action receipts and hashes remain immutable while later builds may
replace the checkout's generated outputs. Do not infer replayable historical binaries
from their hashes alone. In particular,
do not remove or change historical probe roots or ordinary application state.

## Environment and Commands

Start every subject with a replacement environment. Include only the pinned Linux SDK
and system-tool paths, the dedicated home/temp/NuGet paths, a fixed UTF-8 locale, and the
documented .NET/MSBuild controls below. Omit credential/token variables, proxy overrides,
Windows interoperability variables and paths, startup hooks, additional dependency
stores, profiler settings and inherited NuGet/plugin configuration.

Set `DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1`,
`DOTNET_GENERATE_ASPNET_CERTIFICATE=false`, `DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false`,
`DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true`, `DOTNET_CLI_USE_MSBUILD_SERVER=0`,
`MSBUILDDISABLENODEREUSE=1`, and `TESTINGPLATFORM_TELEMETRY_OPTOUT=1`.
Use `UseSharedCompilation=false`, one MSBuild node and disabled node reuse; never enable
an interactive restore. Review imported public test targets before executing tests.

The admitted action must specify one of these vectors, with exact paths recorded:

1. **Fetch:** the accepted `fetch_packages.py` under `/usr/bin/python3 -I`, with the
   action's download directory and exact admitted package specifications.
2. **Restore:** `dotnet restore <scenario-project> --configfile <owned-config>
   --packages <owned-packages> --disable-parallel --verbosity minimal`, with
   `-p:NuGetAudit=false -p:RestorePackagesWithLockFile=true -p:UseSharedCompilation=false
   -m:1 -nr:false` and `--locked-mode` after the reviewed lock is tracked. No implicit
   restore in later actions.
3. **Build:** `dotnet build <scenario-project> -c Release --no-restore
   --disable-build-servers -m:1 -nr:false -p:UseSharedCompilation=false --verbosity minimal`.
4. **Test:** `dotnet <built-scenario-assembly> --report-trx --results-directory
   <owned-results>`. This uses the documented embedded MSTest runner, not a second
   application request protocol. Run the full admitted scenario assembly; the helper
   exposes no filter, settings override, exit-code override or arbitrary command option.

Use argument arrays without shell evaluation. The runner must not offer arbitrary
commands, environments, package sources, candidate mutation or Windows execution.
Only fetch may make public dependency requests. Reviewed core/scenario entry points
must have no network, credential or real-platform acquisition path. This is a reviewed
source/effects boundary within the workstation threat model, not a hostile-code sandbox.

## Capacity, Termination and Evidence

This initial loop allocates at most 12 combined fetch/restore actions and 80 combined build/test
actions from the Wave's cumulative ceilings, with at most 1 GiB of newly downloaded
public package content, charged as a full 128 MiB per fetch even when actual content is
smaller. Failed starts, interrupted actions, operator commands and later
protocol revisions consume the same units. No Windows publish or synthetic Windows
process scenario is allocated here. The unused Wave capacity is not an executable
protocol allocation.

Execute sequentially. Reserve the next numbered `started.json` exclusively before
invoking the tool; recover consumption and completed prior actions first. A missing or
ambiguous result blocks further execution until independently reviewed. A root marker
or new source directory never resets counts. Do not run the experiment in CI under this
initial protocol; ordinary repository hk/CI checks retain their existing authority.

Each fetch/restore has a 180-second ceiling; each build/test action has a 120-second ceiling.
Capture at most 8 MiB of combined output. Use an owned Linux process group with build
servers disabled. On cancellation, timeout or overflow, terminate that group, allow at
most five seconds, then kill remaining group members and reap the subject within a
further five seconds. Confirm no owned process remains before accepting a result or
starting another action. Unconfirmed termination stops the loop; preserve files and do
not infer cleanup from a missing parent alone.

Retain UTC start/end, exact command, environment controls, initial cache state, exit
code, elapsed time, termination/quiescence result, output disposition, source/toolchain
identities and graph/artifact hashes. Retain standard TRX results for scenario evidence.
Use synthetic emails and token markers only. Local standard tool output and TRX can
contain machine-specific paths and host names; sanitize them before publication. Never
use credentials, private identities or raw provider output in this loop. Retain actual
completed package sizes as provenance while charging full fetch reservations against
the cumulative ceiling, including every failed download action.

A deliberately red TDD test is useful evidence only when it executes and fails for the
specified missing behavior. Compilation/restore failure or zero discovered tests is not
a red business test. Inspect failures before changing code. Expected assertion failures
require MTP exit code 2, a single parseable TRX with executed tests and at least one failed
test, and independent confirmation that the admitted business assertions caused the
failure. The helper's TRX/exit checks do not replace that last judgment. These expected
failures permit a reviewed correction and another admitted source within remaining
capacity. Green requires exit code 0 and executed tests without failures. A controller,
restore or build failure is an unexpected result and stops the loop; any continuation
requires a reviewed accepted disposition preserving its receipt and consumption, not an
edit to make a failed result look successful.
Unexpected effects, sensitive output, source/toolchain mismatch, exhausted/uncertain
capacity or unconfirmed termination stop further execution pending reviewed disposition.

Green results establish only the tested core/contract behavior. They do not establish
Windows loader/UI behavior, real silent acquisition, external Profile acceptance,
first-use broker state, cross-process persistence, performance or release readiness.
The Issue retains progress; accepted results and their source bindings are recorded here
without duplicating the scenario obligations in the validation strategy.

## Public API Basis

- [MSTest runner setup and direct assembly execution](https://learn.microsoft.com/dotnet/core/testing/unit-testing-mstest-running-tests).
- [MTP exit codes](https://learn.microsoft.com/dotnet/core/testing/microsoft-testing-platform-exit-codes).
- [Existing developer-tool installation and controls](developer-tooling.md).
- [General experiment policy](../experiment-safety.md).

No execution has occurred under this protocol.

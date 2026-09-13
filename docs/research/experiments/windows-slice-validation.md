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
remain required. Set `DOTNET_NUGET_SIGNATURE_VERIFICATION=false` in the isolated child
environment: Linux SDK 8 and later otherwise enable signature verification, whose
certificate-chain construction can request revocation information or missing issuers
even with only a local package source. Offline revocation mode alone does not prevent
issuer retrieval. The [independent source triage](https://github.com/hcoona/microsoft-authentication-cli/pull/111#issuecomment-5650237964)
binds this behavior and the opt-out to the installed SDK's public source.

This loop supplies no NuGet signature-chain or certificate-revocation evidence. Retain
the fixed HTTPS NuGet.org provenance, original archive sizes and SHA-512 hashes, public
manifest/import inspection, and exact lock/resolved-asset review. Hash agreement proves
byte identity, not signer authenticity or certificate status. Do not change an OS trust
store. No public online restore claim follows from this procedure.
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
`MSBUILDDISABLENODEREUSE=1`, `TESTINGPLATFORM_TELEMETRY_OPTOUT=1`, and
`DOTNET_NUGET_SIGNATURE_VERIFICATION=false`.
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
- [Linux NuGet signature verification and its opt-out](https://learn.microsoft.com/dotnet/core/tools/nuget-signed-package-verification#linux).
- [Existing developer-tool installation and controls](developer-tooling.md).
- [General experiment policy](../experiment-safety.md).

## Initial Public Package Fetches

Actions 0001 through 0004 ran on 2026-09-13 under accepted protocol
`80ba853c9b9f6d254a5f09936b7c4f306af8ec5a`, using candidate source
`cffda724a7111c5dadfe539a6c16eeb3d67fdbd2`, tree
`3ea46e1aa805e170ab9733e8e53d83581a7e8765`. Each had its own independent
[PR #111 admission](https://github.com/hcoona/microsoft-authentication-cli/pull/111),
after inspecting the preceding downloaded manifests. These were Python archive fetches;
no .NET, package restore, build, test, Windows or authentication operation ran.

| Action | UTC interval | Packages | Actual bytes | Child seconds |
| --- | --- | --- | --- | --- |
| 0001 | 02:24:45.602–02:24:45.921 | 1 | 30,590 | 0.183 |
| 0002 | 02:25:42.620–02:25:46.168 | 5 | 24,061,025 | 3.441 |
| 0003 | 02:26:55.681–02:26:58.613 | 9 | 21,759,220 | 2.870 |
| 0004 | 02:30:12.006–02:30:12.781 | 3 | 4,969,307 | 0.704 |

All four returned exit zero, no termination reason, confirmed owned-process-group
quiescence and unchanged tracked source. Original archives, per-package sizes/SHA-512,
immutable starts/results, replacement environments and source/toolchain hashes remain
in the dedicated root. No retry, interruption or cleanup occurred. After action 0004,
consumption was 4/12 preparation, 0/80 build/test and 512 MiB/1 GiB charged downloads;
actual completed bodies totaled 50,820,142 bytes. Later protocol revisions and source
changes retain this consumption and recover subsequent receipts before another action.

The certificate-request issue was found through public-source review before any
restore, not through an observed network violation. The reviewed opt-out must be
accepted before restore admission. These fetches establish only public archive
preparation; complete dependency/import review, resolution and scenario evidence remain
outstanding.

## Selected-Account Core Red/Green Evidence

Actions 0005 through 0013 continued on 2026-09-13 in the same dedicated WSL2 Linux x64
root, using the existing verified SDK 10.0.401/runtime 10.0.12. Actions 0005/0006 used
the original protocol above; restore and every build/test used the accepted offline
correction at `45d142e0ba3318aabcaddc3b5881618e351ad97a`. Each source and sequential
action had an independent [PR #111 admission](https://github.com/hcoona/microsoft-authentication-cli/pull/111).
No Windows executable, WAM, account, token service, Profile file or broker cache was used.

| Action | UTC interval | Child seconds | Observation |
| --- | --- | --- | --- |
| 0005 fetch | 02:31:57.307–02:31:57.684 | 0.306 | Two public archives, 3,045,698 bytes; exit 0 |
| 0006 fetch | 02:33:08.223–02:33:08.502 | 0.215 | Two public archives, 1,094,105 bytes; exit 0 |
| 0007 restore | 02:44:25.347–02:44:29.883 | 4.459 | Local-feed resolution; exit 0 |
| 0008 build | 02:48:14.881–02:48:22.581 | 7.507 | Initial stub compiled; exit 0 |
| 0009 test | 02:48:45.862–02:48:46.793 | 0.773 | Seven executed, seven intended assertion failures; exit 2 |
| 0010 build | 02:58:29.665–02:58:36.830 | 6.932 | Selected-account correction compiled; exit 0 |
| 0011 test | 02:58:52.111–02:58:52.976 | 0.723 | 17 executed, nine passed, eight intended assertion failures; exit 2 |
| 0012 build | 03:06:25.400–03:06:32.470 | 6.883 | Candidate-validation correction compiled; exit 0 |
| 0013 test | 03:06:38.833–03:06:39.684 | 0.717 | 19 executed and passed, zero skipped; exit 0 |

Actions 0005 through 0009 bind initial source `cffda724a7111c5dadfe539a6c16eeb3d67fdbd2`,
tree `3ea46e1aa805e170ab9733e8e53d83581a7e8765`. Actions 0010/0011 bind
`14ab4f6f6a12e04bb55b0a0518388a1d31b53ea4`, tree
`ba5a316572d0a27218291a1f8c1edc65624ef8aa`. Actions 0012/0013 bind
`0a64cf1544d1223784cc3cd8faa57a4f4e5fdd0f`, tree
`05e3a1b74ad7e05f11f34fa5584ec7f6750b3c9d`. The
[first red review](https://github.com/hcoona/microsoft-authentication-cli/pull/111#issuecomment-5650398308)
and [candidate red review](https://github.com/hcoona/microsoft-authentication-cli/pull/111#issuecomment-5650501859)
confirm the intended missing behavior caused the failures after successful compilation
and discovery. Compilation or infrastructure failure was not treated as red evidence.

The independently reviewed restore resolves 19 public test packages and no core package.
Three of the 22 fetched archives are legitimately pruned by .NET 10. The
[resolved-graph review](https://github.com/hcoona/microsoft-authentication-cli/pull/111#issuecomment-5650383832)
records their public provenance, actual imports and the distinction between NuGet's
signed-package content hash and whole-archive hash. Both generated locks were adopted
byte-identically into source and retained before checkout replaced the untracked files.
Their SHA-256 values are `a29c6aa8cfb81874ff8bb78dc369d7416f28c9b8cc47e99592bfc019b20c41eb`
(core) and `ef446f7b1e091a753526bc30525b7c630b2c42c282e75c6d167cde33f561a695`
(scenarios). Later builds reused that graph without restore. Restore and all three builds
had zero warnings/errors; generated runtime controls and extension registrations were
inspected before each full-assembly execution.

The final scenario assembly SHA-256 is
`906e7ba04cd22b7417f51800fdef314c243524c43d354622ca713f27f51139f3`; action 0012's
build receipt is `e58a747e0ad23f8e444e93c31acba8dbc29a7ef612b407e2fa48e745008b218b`.
The [independent green review](https://github.com/hcoona/microsoft-authentication-cli/pull/111#issuecomment-5650579393)
confirms all 19 named case outcomes and their artifact/source bindings.
Action 0013's TRX SHA-256 is
`a27939493bac73011d4c004d553fe13a07e2a9fb359b0bffaae6501a168c6336`; its result receipt
is `767a5f1952ddcf66f23dbbb632fcb476b9a68c959531b97fc00f6df839fc05d8`.
All actions report unchanged tracked source, no termination reason and confirmed owned
process-group quiescence. No retry, interruption or cleanup occurred. Original archives,
receipts, generated locks and local outputs remain retained; raw host/path-bearing TRX
and tool output are not public records. Historical artifact hashes remain evidence for
their original source; later builds may replace generated binaries as this protocol permits.

After action 0013, cumulative consumption is **7/12 preparation, 6/80 build/test and
768 MiB/1 GiB charged downloads**, with 54,959,945 actual completed download bytes.
There has been no Windows publish or process scenario. Future revisions retain these
counts and recover every later receipt before execution.

These observations establish the tested application-boundary behavior: unique strict
personal/work account selection, ambiguity and missing-account handling, constrained
tenant preservation, candidate metadata/expiry/dynamic-scope validation, same-operation
default permission handling, and preservation of valid metadata with unconfirmed
persistence. The provider and clock are controlled substitutes after request admission.
The two default-permission cases were added with the correction and were not previously
executed red tests. Real resource/client/cloud association still depends on the future
request-local adapter. CLI/Profile admission, typed provider failures, interaction,
cancellation/deadline/commitment, real Windows/MSAL integration and required platform
evidence remain incomplete. This core increment does not complete the Slice or establish
support, release readiness, durable broker persistence, or real silent reuse.

## Request and Profile Admission Red/Green Evidence

The next managed increment continued in the same retained WSL2 root under protocol
`45d142e0ba3318aabcaddc3b5881618e351ad97a`, with current accepted target
`ad9221f5f799d119c96f8490fbb35e065ddfd28b`. The accepted CLI/Profile contracts
already owned these core rules. No Profile file, Windows API, real provider, account,
credential, service or broker cache was used; the reviewed dependency graph was reused
without another fetch or restore.

Red candidate `53646a93c34e3bf728be975d0c9565fdb0c612fe`, tree
`71b415bd771ba180887a8828a894a17a222f1d0f`, added rejecting argument/Profile stubs
and focused contract/core fixtures. Its exact
[source admission](https://github.com/hcoona/microsoft-authentication-cli/pull/114#issuecomment-5650790523)
preceded action 0014. That no-restore build ran from 03:31:07.834935Z to
03:31:14.727311Z on 2026-09-13, returning exit 0, zero warnings/errors and 6.684
child seconds. Independent [build review](https://github.com/hcoona/microsoft-authentication-cli/pull/114#issuecomment-5650804746)
confirmed source, graph, generated entry point, runtime and every retained artifact.

Action 0015 then ran from 03:32:35.744317Z to 03:32:36.757797Z, returning MTP
exit 2 in 0.825 child seconds. All 95 cases executed: 80 passed and the exact 15
admitted assertions failed, with no skips or other failure counters. The six valid
argument cases and four valid Profile documents failed their non-null assertions;
five valid tenant cases failed successful resolution. The prior 19 account/candidate
scenarios stayed green. The other 61 passes were rejection guards against reject-all
stubs and did not yet establish functioning parsing. The independent
[red review](https://github.com/hcoona/microsoft-authentication-cli/pull/114#issuecomment-5650847076)
inspected every outcome and failure location.

Both actions completed without termination, with confirmed owned-process-group
quiescence and unchanged source/graph/toolchain identities. The red scenario assembly
SHA-256 was `f220a9fb1504814e35ca3b219808bcb3ff4201bfdafeeecb3f05abf7dfaca7c4`;
build receipt `300433ce45926c8a15f663fc84d7e7c44aa609e3730c07c803f4437a09862e7b`;
single red TRX `400c06476a43137d84a9b2a70440a499004852766da3e35b86b228929534d247`;
and test result `b5bd7ee6287c9d83662fb6f31bf464878b590f3392a9c7fd0aaffd4ce9adfcc9`.

Green candidate `bb922ce000f13520d5e45a5733fc5fc600d72586`, tree
`08ca59b5de08c11ea4cf67000dde0ef2628091e7`, implemented the accepted request,
Profile and tenant rules. It also added 41 boundary cases, which have no prior-red
claim. The independent [green admission](https://github.com/hcoona/microsoft-authentication-cli/pull/114#issuecomment-5650901897)
bound that exact source and expected all 136 cases to pass. Action 0016's no-restore
build ran from 03:43:21.556389Z to 03:43:28.679013Z, returning exit 0, zero
warnings/errors and 6.908 child seconds. Its independent
[build review](https://github.com/hcoona/microsoft-authentication-cli/pull/114#issuecomment-5650914798)
verified source, graph, generated runner and all 249 artifacts before test execution.

Action 0017 ran from 03:44:47.163771Z to 03:44:48.077168Z, returning MTP exit 0
in 0.750 child seconds. All 136 tests executed and passed: 65 request cases, 52
Profile/tenant cases and the prior 19 account/candidate cases. Every non-success
counter was zero. The prior 15 intended failures were resolved, all other original
cases remained green, and the additional boundary cases passed. The independent
[green confirmation](https://github.com/hcoona/microsoft-authentication-cli/pull/114#issuecomment-5650926667)
compared every result with the red TRX and verified all retained integrity evidence.

The green build and test completed normally with confirmed owned-process-group
quiescence, no termination and unchanged source/graph/toolchain/artifact identities.
The green scenario assembly SHA-256 is
`15bc885854b3a2ec5d8ae4e07dd08ff5861e8b204a7f2b0dea7dc0dc4d40844b`;
build receipt `0213672d830fc0964c388d74f45fa1d262595a328f521950c0be2335a6c3f43c`;
single green TRX `a781c35d2924009a80b4472e8a53da82b92a3468148a53f6d9f7cc2997b821f2`;
and test result `4cd9a5748db982b9290b370b4ed5db9353b5f75994355f67ecd24478e9e76c01`.

All 17 actions are resolved. Cumulative consumption is 7 of 12 preparation actions,
10 of 80 build/test actions and 768 MiB of the 1 GiB charged download limit. Actual
downloaded content remains 54,959,945 bytes in the same 22 original archives; the
resolved test graph still uses 19 packages. No new download, restore, Windows action,
real authentication, forced termination or cleanup occurred. Experiment-owned files
remain intentionally retained; standard path-bearing output and TRX stay local.

These results establish the tested in-memory admission rules. They do not establish
Windows fixed-volume/file eligibility, read-once Profile I/O, CLI process transport,
deadline/cancellation behavior, provider construction, real WAM/UI, cross-process
reuse, deployment or overall Slice acceptance. The accepted contracts and validation
strategy retain those obligations; Issue #108 remains open.

## Interaction and Failure Scenarios

The red source for [PR #115](https://github.com/hcoona/microsoft-authentication-cli/pull/115)
is `03076c4546077251fcf402abe33b418a3ed56ab8`, tree
`6747e705ba863ba403d1e87f0863c4393e7b014e`. It adds controlled interaction scenarios
and malformed granted-scope cases while retaining the previous coordinator. The
new provider/host methods have inert defaults. Accepted protocol/helper revision
`45d142e0ba3318aabcaddc3b5881618e351ad97a` and target
`959583a5df1777954d675542f25d633812d83f43` bind these actions.

The independent [red admission](https://github.com/hcoona/microsoft-authentication-cli/pull/115#issuecomment-5651020941)
preceded action 0018's no-restore build, which ran on 2026-09-13 from
03:59:06.572365Z through 03:59:13.718058Z. It returned exit 0 with zero warnings
and errors in 6.958 child seconds. The independent
[build gate](https://github.com/hcoona/microsoft-authentication-cli/pull/115#issuecomment-5651026285)
verified the source, graph, SDK, generated entry point, five registrations, runtime
configuration and all 249 artifacts before the conditional test.

Action 0019 ran from 04:00:23.996616Z through 04:00:24.972035Z, returning MTP
exit 2 in 0.833 child seconds. All 166 cases executed: 140 passed and exactly 26
admitted assertions failed; every other counter was zero. Independent
[red confirmation](https://github.com/hcoona/microsoft-authentication-cli/pull/115#issuecomment-5651047584)
compared exact names and assertion locations. All 136 preceding cases remained
present and green. Three interaction guards and the valid empty default grant
array were the four new passing cases.

Nine failures use the fixture wrapper's fixed boundary assertion because injected
discovery/silent exceptions escape the coordinator. The TRX retains the assertion
and caller locations, not the original exceptions. Thirteen interaction failures
occur before the coordinator reaches the interactive fixture branches; they show
missing continuation and required outcomes, not execution of those later branches.
The other four failures reproduce the independently
[triaged malformed-scope defect](https://github.com/hcoona/microsoft-authentication-cli/issues/108#issuecomment-5650968273):
dynamic and default-permission candidates incorrectly succeed with null or empty
extra grant items. A valid empty grant array for the same default-permission
operation remains distinct and passes.

Both actions completed without termination, with confirmed process-group quiescence
and unchanged source, toolchain, graph and artifact identities. The red scenario
assembly SHA-256 is `b87f41d65f0316103ae19956129269c48c6f6f74bfb2d1d3825c1e21f1e4d5e5`;
build receipt `31accaf3a2ef0749fe408025fd79129376f6815d5185704f372580ad8a30b143`;
single red TRX `118deebeb07765ed1b1218440e6cae607f865819151beb060fea286cc3ba3c9f`;
and test result `4bd2413757689362b46ea602d50bc4b0362f5fd04c257120d66c334319633055`.

Green source `c7b433c3d4d96145d476baa2a3e6f8ad792c2297`, tree
`b861d60b0354306175407a83d3e0e1e2c60fed27`, changes only the coordinator from
that red source; every test remains unchanged. The independent
[green admission](https://github.com/hcoona/microsoft-authentication-cli/pull/115#issuecomment-5651075515)
covers a build followed by one conditional full test on the same source. Action
0020 ran from 04:12:23.097445Z through 04:12:30.217077Z, returning exit 0 with
zero warnings/errors in 6.956 child seconds. Before test execution, the executor
inspected complete output and command/environment/source bindings and verified
every source, SDK, graph, restore and artifact hash, including unchanged generated
entry, registrations and runtime configuration. This satisfied the admission's
conditional gate without a separate independent build-review round.

After a fresh accepted-target/Wave and published-admission check, action 0021 ran
from 04:12:56.375430Z through 04:12:57.315587Z. It returned MTP exit 0 in 0.795
child seconds: **166 executed and 166 passed**, with every other counter zero.
The exact test-name set equals the red run; all 26 prior failures now pass and all
140 prior passes remain green. Both actions completed without termination, with
confirmed process-group quiescence and unchanged source, toolchain, graph and
artifact identities.

The independent [combined green review](https://github.com/hcoona/microsoft-authentication-cli/pull/115#issuecomment-5651085588)
confirmed the conditional gate, actual command/environment controls, complete
output, exact case comparison and every retained source/artifact identity.

The green scenario assembly SHA-256 is
`9ba4cbaeaa5f8c3ac768358126c2af362a4e227c2d130e91dd66479d2f618dad`;
build receipt `6ee723a97371359d15a05272b8751623457ab0e270ea05d739f500557d6107d2`;
single green TRX `2c64dcee8c68b977773e1e092dbaeeb40ff94220e0d505d5334adcb9d6143676`;
and test result `0da4e6d70689886732887893ef588e1f0e51f266bcee4d312f2b4e102fe0548d`.

All 21 actions are resolved. Cumulative consumption is 7 of 12 preparation actions,
14 of 80 build/test actions and 768 MiB of the 1 GiB charged download limit. Actual
downloads remain 54,959,945 bytes across the same 22 archives; the resolved graph
retains 19 packages. No fetch, restore, Windows action, real authentication, forced
termination or cleanup occurred. Experiment-owned files are intentionally retained;
standard path-bearing output and TRX remain local.

These results establish the tested silent-first and permission-gated continuation,
safe provider failure outcomes, required synthetic parent readiness/closure, and
shared candidate validation. The cooperative cancellation checks and cleanup-fault
fallback are inspected source, not cancellation-race or cleanup-fault test evidence.
The complete terminal latch, original deadline, finite process/UI shutdown, result
transport, actual Windows/WAM behavior, cross-process reuse, exact Native AOT
artifact and overall Slice acceptance remain open under Issue #108.

## Action 0022 Build Disposition

Action 0022 attempted the source-bound no-restore build for
[PR #116](https://github.com/hcoona/microsoft-authentication-cli/pull/116) on
2026-09-13, from 04:43:47.026593Z through 04:43:53.717371Z. Source
`1f671c139ca24e987eebc8da6413035cf3daeea8`, tree
`c0c4db88c6d033226c700e094f8e2074c29682f9`, used accepted protocol/helper
`45d142e0ba3318aabcaddc3b5881618e351ad97a` and target
`3fc8a1657c0d61d5b00b96986c0b3a4121ba1e4a` under the independent
[source admission](https://github.com/hcoona/microsoft-authentication-cli/pull/116#issuecomment-5651200853).

The build returned exit 1 in 6.595 child seconds, with zero warnings and two
CS1061 errors at `RequestLifetimeScenarios.cs:403` and `:407`. Inside the nested
timer of the `TimeProvider` subclass, the inherited `TimeProvider.System`
property hides the intended `System` namespace. The independently
[triaged correction](https://github.com/hcoona/microsoft-authentication-cli/pull/116#issuecomment-5651213332)
qualifies those references with `global::`; it changes no business expectation
or dependency. No test ran, and no red business-test evidence exists for this
attempt. The admitted conditional test did not run because its build gate failed.

The independent [actual failure review](https://github.com/hcoona/microsoft-authentication-cli/pull/116#issuecomment-5651221809)
confirms the complete output, original source and input integrity, and effect limits.
The result remains `unexpected-result` with `continuation_allowed: false`, no
termination and confirmed process-group quiescence. Preserve that receipt, all
source/input/output bindings and consumed capacity. The partial build is not an
accepted test artifact. The source and installed SDK/restore graph retain their
recorded identities; no new download, restore, Windows or authentication action
occurred.

After independent review and target-branch acceptance, this disposition permits
the helper to recognize only the exact historical stop below while retaining it
in the contiguous history and capacity count. It does not mark the build
successful, authorize a retry, or excuse another stop. A corrected immutable
source still needs fresh independent admission, a successful source-bound build,
the unchanged graph/artifact gate, and separately checked test execution under
this protocol. The first subsequent subject action must build a different,
independently admitted corrected source. Changed or missing evidence, another failed action, an unaccepted
helper, or any ordinary source/effects/integrity failure still stops execution.

| Action 0022 evidence | SHA-256 |
| --- | --- |
| `started.json` | `5db34bcbc6740c80b58553d56c7aa8779c11cb21ffc115f21568fc2abe88cf4f` |
| `inputs.json` | `f2f2b439225c90b130c8f662d54e813e604a7c55bbec3498aba02d900151b5a8` |
| `result.json` | `c02ba234adac677a63147c57fa0fca240846839953743d08c08e2576dd43bba7` |
| `output.txt` | `b91afcbc9cd5f0437906fdb6a314f34c9b0fe3a3e9cb9d2c6044ab6032958442` |

All 22 actions are resolved and quiescent; 0022 is the sole historical stop.
Consumption is 7 of 12 preparation actions, 15 of 80 build/test actions and
768 MiB of the 1 GiB charged download limit. Action 0023 has not run. No capacity
is reset or enlarged. The overall Windows Slice acceptance remains open.

## Request Lifetime Scenario Evidence

The lifetime increment in [PR #116](https://github.com/hcoona/microsoft-authentication-cli/pull/116)
preserves the 166 preceding cases and adds 24 controlled application/terminal-rule
cases. The scenario source is `tests/Authentication.Scenarios/RequestLifetimeScenarios.cs`;
the implementation boundary is `src/Authentication.Core/RequestLifetime.cs`.
The existing Windows design and validation strategy retain the required behavior.

After the action 0022 compilation disposition above was accepted, corrected source
`5312f6ddcca43260ed9fc1b7c10de58daa631492`, tree
`3e37c1658f5acb15247b7ea5fa1e81cabcac1428`, received fresh independent
[admission](https://github.com/hcoona/microsoft-authentication-cli/pull/116#issuecomment-5651304230).
Actions 0023 and 0024 used accepted target
`414c8f100af4078a4223ba47605681dc9c239f75` and protocol/helper
`eb9d24d95a4e85578770fc167edb6c8b648e304b` on 2026-09-13 UTC.

| Action | UTC start to result | Child seconds | Actual result |
| --- | --- | ---: | --- |
| 0023, corrected-source build | 05:08:22.765352 to 05:08:30.074716 | 7.114 | Exit 0; zero warnings and errors. |
| 0024, full red test | 05:08:58.112461 to 05:09:00.998798 | 2.755 | Exit 2; 190 executed, 172 passed, 18 intended assertion failures. |

The independent [actual-red review](https://github.com/hcoona/microsoft-authentication-cli/pull/116#issuecomment-5651321205)
confirms every failed name, row, message and caller: 11 pending-operation terminal
selection assertions, three missing provider-token notifications, three incorrect
timeout/cancellation outcomes and one unsafe admission-exception escape. All 166
preceding cases and six new guards passed. Every other TRX outcome counter is
zero. Controlled tasks were released and drained; both actions ended normally
with confirmed process-group quiescence and unchanged source, SDK, graph and
artifacts. The parallel synthetic suite's duration is not product timing evidence.

The build receipt SHA-256 is
`832b00c17e553776c2afd7d9df568fd9cf4bd52c864f5d54a738c3c905073dac`;
the single red TRX is
`b62b1de57332fddfd378123ddba3054ed5df69914dbb79d1b93ba7278cd6f23f`.
Complete receipt/output bindings are retained in the independent review. The
original failed action 0022 remains unchanged and counted; it is not red evidence.

Green source `9008959bbbda0c95e0a65dabc6ee3c4072b2338a`, tree
`80ae260fe363bffb1b8869d63e8a1f5e508dd9ac`, preserves that red source in its
ancestry and leaves every test unchanged. Its independent
[green admission](https://github.com/hcoona/microsoft-authentication-cli/pull/116#issuecomment-5651355864)
bound actions 0025 and 0026 to the same accepted target and protocol/helper above.

| Action | UTC start to result | Child seconds | Actual result |
| --- | --- | ---: | --- |
| 0025, green-source build | 05:20:32.574846 to 05:20:40.103360 | 7.341 | Exit 0; zero warnings and errors. |
| 0026, full green test | 05:21:13.439752 to 05:21:14.363864 | 0.786 | Exit 0; 190 executed and passed; zero failures or skipped cases. |

The executor inspected the source-bound build, complete command/environment and
output, all 144 source entries and 249 artifact paths/hashes, eight graph inputs,
eight restore metadata files, four SDK/runtime identities and generated test
entry, five registrations and runtime configuration before the conditional test.
A separate fresh accepted-target/Wave and published-admission check preceded each
action. The full green run retained every name and data row from red. All other
TRX outcome counters were zero; both actions ended normally without termination,
with confirmed quiescence and unchanged source, SDK, graph and artifacts.

The green build receipt SHA-256 is
`64dc048bcdeea2c9240aef95816057aac53040d86e5858294a53d1ad865e6eb5`;
the single green TRX is
`5cf3159e06fe31eb3d6cc901bcb7602d4a0f8983db8b6334ec2f1bed7fef49ff`.
The independent [actual-green review](https://github.com/hcoona/microsoft-authentication-cli/pull/116#issuecomment-5651369741)
confirms these results, exact red-to-green case continuity and complete integrity;
it retains the full receipt/output and executor-gate bindings.

The tested implementation retains the original monotonic deadline, selects
cancellation/timeout while controlled dependencies remain pending, invalidates
late outcomes, and notifies the provider token without waiting for its callbacks.
Only the single commitment boundary supplies the deliverable outcome; caller
cancellation before commitment suppresses success and its warning. An already
latched failure remains authoritative. Operation observation and deferred token
source disposal do not establish UI/process quiescence or extend the future
host's shutdown allowance.

Consumption through 0026 is **7/12 preparation, 19/80 build/test, and 768 MiB/1 GiB
charged downloads**. All 26 contiguous actions are resolved and quiescent. The
original action 0022 remains the sole false continuation receipt under its exact
accepted disposition. No new fetch, restore or installation was needed. Dedicated
files remain intentionally retained; raw machine-bearing output and TRX filenames
remain local.

These are controlled Linux managed observations under the unchanged SDK/runtime,
public dependency, offline signature-chain and synthetic-state limits above.
They do not establish real WAM, Windows/WSL UI or process shutdown, pipe/result
transport, Native AOT behavior, account reuse, or overall Slice acceptance.

## Result-Contract Red/Green Evidence

Actions 0027 through 0030 ran on 2026-09-13 under the unchanged accepted Wave,
target `9e623f58654bd9ae481ec32db1a67f8c0f26d479`, and protocol/helper
`9f31b601bc7e3b64f2c030e332b49751370cb971`. The existing designated WSL2 Linux
x64 host reused verified SDK 10.0.401/runtime 10.0.12 and the reviewed public
package graph. No fetch, restore or installation occurred. Every command ran
under the accepted replacement environment and finite managed limits.

The red source was `4db00c4883e9708da33d68c298857cc308775bd2`, tree
`62315817135af4ed1cba5d181a0694ae37ec6a75`. Its
[independent admission](https://github.com/hcoona/microsoft-authentication-cli/pull/118#issuecomment-5651448083)
covered one build and conditional full test after the executor's source,
artifact, command/environment and generated-runner gate. The
[actual red review](https://github.com/hcoona/microsoft-authentication-cli/pull/118#issuecomment-5651462530)
confirmed every failed row and retained prior scenario.

The green source was `c6c36e2f3216d514f35e8c40da79d44cf1640212`, tree
`507ecf81e1690d144bf8a180917e5d8bf2685991`. Its
[independent admission](https://github.com/hcoona/microsoft-authentication-cli/pull/118#issuecomment-5651500024)
covered the corresponding green pair. Only result projection and coordinator
reason propagation changed after red; every test remained byte-identical.
The
[actual green review](https://github.com/hcoona/microsoft-authentication-cli/pull/118#issuecomment-5651511745)
confirmed full case continuity and source/artifact integrity.

| Action | UTC interval | Child seconds | Observation |
| --- | --- | --- | --- |
| 0027 build | 05:42:10.546871–05:42:17.845790 | 7.133 | Exit 0, zero warnings/errors |
| 0028 red test | 05:42:48.513330–05:42:49.575139 | 0.910 | 218 executed, 196 passed, 22 intended assertion failures; exit 2 |
| 0029 green build | 05:54:31.364569–05:54:38.531874 | 7.014 | Exit 0, zero warnings/errors |
| 0030 green test | 05:54:58.328076–05:54:59.265091 | 0.805 | 218 executed and passed, zero failed/skipped/other outcomes; exit 0 |

The 28 added cases protect protocol-1 output values, field allowlists, framing,
matching status and application reason propagation. The red failures were eight
missing success-status projections, ten missing typed-outcome projections
(including cancellation before commitment), and four lost structured reasons.
All 190 preceding cases passed. Six new guards also passed against the fixed
safe internal_failure seam. Success metadata checks after the eight exit
assertions, projection after the four reason assertions, and the cancellation
case's later duplicate-commit/operation-completion assertions were not reached
in red. Passing guards on a constant seam do not establish their later branches.

Green preserved the exact red case-name/data-row set and passed all 218 cases,
including those later assertions and the implemented defensive branches. The
explicit field writer preserves success metadata, opaque token escaping and
optional nonempty correlation without fixing field/scope order or JSON interior
whitespace. Failure projection exposes only finite outcome/reason fields.
Structured consent and provider/network/service transient reasons survive the
coordinator; later validated interactive success does not retain earlier consent.
Cancellation before commitment emits no token or persistence warning.

All four actions completed normally with no termination and confirmed owned-process
quiescence. Complete outputs, both TRX files, starts/results, command/environments,
146 source hashes, 249 artifact paths/hashes, eight graph inputs, eight generated
restore files and four SDK/runtime identities were independently checked. The
generated entry and five registrations retain their accepted contents; runtime
10.0.12 retains disabled roll-forward. No source or artifact changed during either
test. Raw machine-named TRX and path-bearing output remain local.

| Evidence | SHA-256 |
| --- | --- |
| Red build receipt, action 0027 | `a410ecfb2639e4a3e5a28ed58809de5481b592f73ba55e7b1e72a4f820ac1cef` |
| Red TRX, action 0028 | `430cac27f1cb7017f07743133fd0a976169dbd8ddc07735c84aa2719a68ba502` |
| Green build receipt, action 0029 | `46df2cbcce3201127de6d37edb14ba228a3d1d534c0965db3218f86cb9ae27b0` |
| Green TRX, action 0030 | `31c71c1c843eeabb7bc1b7c446242fdae6510fda7bafb955c79cf9eb9464e517` |

Through action 0030, history has 30 contiguous resolved/quiescent actions and
consumption is 7/12 preparation, 23/80 build/test and 768 MiB/1 GiB charged
public downloads. The original action 0022 receipt and exact disposition remain
unchanged. All dedicated evidence and generated files are intentionally retained.

These observations use synthetic emails, token/claims markers, provider outcomes
and managed hosts only. They establish neither actual stdout delivery nor matching
process exit, Windows/WSL pipe or shutdown behavior, real UI/WAM, account/cache
state or reuse, Native AOT artifact behavior, Profile activation, broader support,
or overall Slice acceptance. Those obligations remain open under their existing
canonical validation basis and required protocol/owner decisions.

## Application Invocation Red/Green Evidence

The application increment joins protocol-1 argument and Profile admission,
selected-account coordination, original request lifetime and committed result
projection. These are synthetic Linux managed observations under this protocol,
not evidence of Windows file/volume semantics, pipes, stdout/process delivery,
UI/WAM, Native AOT, account reuse or overall Slice acceptance.

The author/executor was `/root`; independent reviewer `/root/lifetime_triage`
reviewed source admission and actual evidence in [PR #119](https://github.com/hcoona/microsoft-authentication-cli/pull/119).
Both pairs bind accepted target `e177747edb28ff7c20237b0531d06226ac59779b`,
protocol/helper revision `9f31b601bc7e3b64f2c030e332b49751370cb971`, and
unchanged Wave blob `8bbc98cc2e892a33c06d190983d9c0a09a8d6282`.

| Source role | Commit | Tree |
| --- | --- | --- |
| Executed red | `d4affc6b5e5ca3cd8469efbc75ec954ab7e0eedc` | `2ba2feb5f867605ed620d195ee0d777ee0e5728a` |
| Executed green | `4d8f25c73fb11fe26ab11be41ac7ddd20e62b53d` | `fa1819ff21b3beb468be65bda86bf9527c8a1e00` |

The red [admission](https://github.com/hcoona/microsoft-authentication-cli/pull/119#issuecomment-5651631751)
and [actual-evidence review](https://github.com/hcoona/microsoft-authentication-cli/pull/119#issuecomment-5651643695)
bind the exact failed names, rows, first assertions and execution integrity.
The green [admission](https://github.com/hcoona/microsoft-authentication-cli/pull/119#issuecomment-5651670680)
requires the unchanged full case set and a new source-bound build. The independent
[actual-green review](https://github.com/hcoona/microsoft-authentication-cli/pull/119#issuecomment-5651686945)
confirms all 243 cases passed with exact red-to-green continuity.

| Action | UTC start to result, 2026-09-13 | Child seconds | Observation |
| --- | --- | ---: | --- |
| 0031 red-source build | 06:20:15.989334 to 06:20:23.177029 | 6.995 | Exit 0; zero warnings/errors. |
| 0032 red test | 06:20:48.307920 to 06:20:49.357488 | 0.893 | MTP exit 2; 243 executed, 224 passed, 19 intended failures. |
| 0033 green build | 06:29:27.055253 to 06:29:34.195778 | 6.973 | Exit 0; zero warnings/errors. |
| 0034 green test | 06:29:59.036381 to 06:30:00.056417 | 0.853 | MTP exit 0; all 243 executed/passed, zero failed or skipped. |

Red failed at thirteen wrong-outcome assertions, five missing-success-status
assertions and one missing provisional success. The latter's message names
`provisional.Success`; the runtime stack reports the line adjacent to the assertion.
All 218 previous names/data rows remained and passed. The 25 new application
cases contained 19 intended failures and six passing guards: cancelled/expired
admission, pending-read cancellation/deadline, caller timeout during reading and
unexpected construction failure. The last passed before its factory executed.
Later configuration-reason/privacy, success/Profile metadata, backing mutation,
provider-budget, interaction-order and commitment assertions were not reached in
the failed red cases. These limits remain part of the red evidence.

Green changed only invocation composition and the allowed configuration-reason
projection. All tests and expectations remained byte-identical, and the exact
243 names/data rows were retained. The invocation now validates the Profile and
tenant before creating a provider, carries explicit intent to the coordinator,
and commits the allowlisted result under the original lifetime. Later assertions
now verify safe failures, selected Profile/request metadata, the immutable parsed
snapshot, remaining budget, permission-gated interaction and cancellation before
commitment. No provider text or Profile contents are exposed in failure output.

All four actions completed normally with no termination and confirmed
quiescence. Complete source, command/replacement environment, SDK, graph/restore
and artifact integrity were independently verified. The 148 source entries,
249 artifacts, four SDK identities, eight graph inputs and eight restore metadata
files matched; the generated entry, five registrations and runtime configuration
retained the accepted contents. SDK 10.0.401, runtime 10.0.12, MSTest 4.1.0 and the
19-package graph were unchanged. No fetch, restore or installation occurred.

| Evidence | SHA-256 |
| --- | --- |
| 0031 source-bound build receipt | `f7f5e6de213e6f84dbf90b2cf11e7d44c66b763fb74dc4fa294d1641a8ab4b9a` |
| 0032 single red TRX | `11a659961baaf3cb230bdf2fafcb91d98d7fb13643e83a04044073c892e1ff1c` |
| 0033 source-bound build receipt | `7d47bf38c64218c0ba1de122a7576d62400c368116236363478cb29c39f8e616` |
| 0034 single green TRX | `5f528a856d863870937c57df8123b1a8ebb6265a6ee854988694a3badc1a6da7` |

Consumption through 0034 is 7/12 preparation actions, 27/80 build/test actions
and 768 MiB/1 GiB charged downloads. All 34 contiguous actions are resolved and
quiescent; original action 0022 retains its accepted disposition and exact bytes.
Raw machine-bearing output and TRX filenames remain local. Dedicated files remain
intentionally retained, with no historical replay or capacity reset.

The source supplies a read-only Profile seam and an immutable parsed snapshot;
its controlled bytes cannot establish the later Windows fixed-volume/open-once
reader. Prepared output is not proof of successful transport or bounded shutdown.
Profile activation and required real-account and platform evidence remain open.

## Windows Managed File Scenarios

This supplement allocates credential-free managed Windows file validation from the
existing Wave. It allocates no Native AOT publishing, child-product process scenarios,
UI/WAM, account enumeration/acquisition, account/cache/consent changes, or resource
requests. Those remaining claims require their later protocols. All earlier Linux
observations, including original action 0022, remain unchanged.

### Windows Subject and Source Admission

The initial subject is `Authentication.Windows` and
`tests/Authentication.Windows.Scenarios/Authentication.Windows.Scenarios.csproj`, using
`net10.0-windows`, SDK 10.0.401/runtime 10.0.12 and MSTest 4.1.0. It exercises the accepted
RequestInvocation through a physical Windows Profile reader, a controlled provider and
no real UI. No real MSAL application, account/cache API, native broker load or network
path is admitted in these test entry points. Compatibility analysis is not AOT publishing.

The initial ten cases cover explicit personal/work email, exactly 65,536 bytes, rejection
of 65,537 bytes, backing-file replacement after admission, missing file, directory,
malformed JSON, invalid UTF-8 and sharing denial. The fixture creates ten scenario
directories, the directory-case child and eight synthetic files, each at most 65,537
bytes, under the action's dedicated temporary directory. Intentionally retain these
files. The first constant-failure reader expects four failures at the shared success
assertion and six passing rejection guards; later assertions in those failed cases are
not established by that red run. A corrected reader must run the unchanged ten cases.

Before each immutable source runs, independently review its exact commit/tree, complete
project/import/package graph, entry point and fixture effects, commands, expected cases
and exact red or green result in the coordinating PR. Inspect generated test entry,
extension registrations and runtime configuration after build and before test. Source
changes require a new admitted build. Graph changes require a new admitted restore and
resolved-graph review. Before a later action relies on expected red, independently
review its actual failed names, rows, first assertions and passing guards. Source
admission cannot enlarge this supplement or waive those prerequisites.

### Windows Environment and Retained Inputs

Use the existing Windows 11 x64 host through WSL 2, as its ordinary non-SYSTEM user.
The dedicated Windows root is `C:\Temp\azureauth-windows-slice-108`; create it only after
this supplement is accepted. The fixed read-only PowerShell preflight checks the local
fixed volume, direct parent/root paths and any existing root's owner before WSL writes
Windows files. The action controller then verifies Windows ownership, direct paths,
complete input hashes and no-follow directory traversal before any compiler or subject.
Reject an unrecognized root, reparse point, changed input or ownership uncertainty.
The workstation threat model permits sequential verified file operations; these helpers
are not a hostile-code sandbox.

Retain a root marker, detached source checkout, original public archives, dedicated
complete package entries, controller copies and per-action outputs. The WSL-side
`windows-actions/` directory under the existing Linux root owns contiguous reservations
and final continuation receipts, including failed Windows starts. Its corresponding
Windows action directory contains the hash-bound input reservation and Windows process,
invocation, output and termination evidence. Copy source from an immutable detached Git
checkout and verify its actual bytes. Retain generated locks before adopting their
identical tracked copies; do not silently discard or change them.

Use the installed `C:\Program Files\dotnet` SDK/runtime and Framework64
`v4.0.30319` standalone C# compiler. Do not install or repair tools. Verify the fixed
executable, SDK/runtime, NuGet and Framework identities in
[`run_windows.py`](../../../tools/validation/run_windows.py) before invocation and after
quiescent execution. Root global.json selects SDK 10.0.401 without roll-forward; project
properties select runtime 10.0.12 without roll-forward. Installed-state reuse is not
fresh installation, signer, revocation or deployment evidence.

#### Complete Public Package Cache Reuse

Windows NuGet signature verification is always enabled for package installation during
restore. `DOTNET_NUGET_SIGNATURE_VERIFICATION=false` is not a Windows opt-out. A local
archive source can still cause certificate-chain network retrieval or root-store
updates; offline revocation alone does not exclude those effects. This supplement
therefore reuses only complete, verified retained global-package entries and admits no
package-installation fallback.

The input set is the accepted Linux loop's 19 MSTest graph entries plus the retained
Windows `Microsoft.NET.ILLink.Tasks` 10.0.12 entry for compatibility analysis. Original
public archive lengths and SHA-512 values are pinned in `run_windows.py`. Preserve
original `.nupkg`, `.nupkg.sha512` and `.nupkg.metadata` bytes. The NuGet signed-package
content hash is distinct from the whole-archive hash; compare each against its own
accepted evidence. Do not fabricate completion metadata or replace a content hash.

Before copying, independently review every selected entry's original public provenance,
manifest, build imports, executable assets, complete file inventory and cache metadata.
Verify payload bytes against the original ZIP parts, including NuGet's normal part-name
decoding, lowercase manifest name and omission of OPC container metadata. Reject missing
or extra payloads, invalid Windows names, case collisions and linked paths. Copy only
those verified entries losslessly into the new dedicated package root, preserving the
historical donors. The initial candidate contains 20 entries, 1,057 retained files and
195,109,241 bytes. This is a read-only preparation inventory, not a Windows copy or
execution observation. Each action binds and rechecks the actual inventory.

The installed SDK identifies NuGet `7.9.0-rc.42413` and public source revision
`e34a38d2ae1fc26406a317517196e55c68ff83ab`. At that revision,
[GlobalPackagesFolderUtility](https://github.com/dotnet/dotnet/blob/e34a38d2ae1fc26406a317517196e55c68ff83ab/src/nuget-client/src/NuGet.Core/NuGet.Protocol/Utility/GlobalPackagesFolderUtility.cs#L45)
recognizes complete existing entries and returns the retained package without new
signature verification.
[PackageExtractor](https://github.com/dotnet/dotnet/blob/e34a38d2ae1fc26406a317517196e55c68ff83ab/src/nuget-client/src/NuGet.Core/NuGet.Packaging/PackageExtractor.cs#L695)
places installation and signature verification behind the missing-metadata branch.
Its internal cache flag is not evidence that this experiment verified a signature.
The [Windows verification documentation](https://learn.microsoft.com/dotnet/core/tools/nuget-signed-package-verification#windows)
and [installed-package documentation](https://learn.microsoft.com/nuget/concepts/troubleshooting-installed-packages#package-signature-log-message)
provide the public contract context. The source identity is tied to inspected installed
NuGet assemblies, not inferred from a general SDK tag.

Keep provenance archives in a separate directory that is never a restore source. The
only configured source is the verified empty `empty-feed` directory. Clear inherited
sources, mappings, fallback folders and additional project sources; supply no credentials.
Use only the dedicated verified global cache, with audit and workload resolution disabled.
A cache miss, incomplete entry, unexpected package/download item, or graph change stops
preparation for review; do not repair, recopy, extract from an archive or retry.
Independently review the new Windows lock, selected assets, generated imports, source
mapping and package folders before build/test. No online restore or signature-chain
claim follows from this procedure, and it changes no OS trust settings.

Start each compiler/subject with a replacement environment. Bind both TMP and TEMP to
the verified action-owned fixed-volume directory: non-SYSTEM Windows temporary-path
selection prefers TMP. Bind USERPROFILE, APPDATA, LOCALAPPDATA, DOTNET_CLI_HOME and NuGet
package/HTTP/plugin paths beneath the dedicated root. Keep required Windows system
variables and only the selected dotnet/System32 paths. Omit inherited credentials,
proxies, startup hooks, profilers, developer configuration and private feeds. Disable
.NET/MTP telemetry, first-run changes, workload lookup/updates, build servers, shared
compilation and node reuse. Do not change OS privacy or account settings.

### Windows Actions, Capacity and Evidence

Allocate at most four Windows preparation actions and forty Windows build/test actions,
alongside Linux's existing twelve and eighty. Those sums fit Wave ceilings of sixteen
and 120. No new downloads, publish actions or synthetic child-product process actions
are allocated here. One test action runs all ten admitted managed file cases; no case
launches a product child. Preparation consists of exactly one helper bootstrap and at
most three independently admitted restores, including failed starts. Copying verified
source and public cache/archive inputs belongs to the recorded bootstrap/preparation;
it creates no additional execution allocation.

Both helpers use the existing Linux `action.lock` for the entire action and inspect both
contiguous histories before reserving another action. The updated Linux helper rejects
an unresolved Windows action too. Subsequent Linux execution must use this accepted
revision's symmetric history check; the previous helper remains historical evidence.
Preserve all 34 earlier Linux actions, the original 0022 disposition and consumption of
7/12 preparation, 27/80 build/test and 768 MiB/1 GiB charged downloads. No Windows action
is an executed observation merely because this supplement is accepted. Ambiguous capacity,
changed evidence or unresolved termination stops both loops. No concurrent execution or
history reset is permitted.

Invoke the accepted helper through `python3 -I tools/validation/run_windows.py` with one
of `bootstrap`, `restore`, `build` or `test`, full `--protocol`, `--source` and `--target`
commits, and the exact independent `--review` PR-comment URL. Only test accepts expected
red through `--expect red`. The helper binds the accepted Wave/protocol, source and
controller bytes before reserving the action, and records the reservation before the
fixed Windows path preflight or any compiler/subject invocation. There is no arbitrary
command, filter, retry, dependency selection, environment or expected-exit override.

The concrete commands and replacement environment are in
[`Invoke-WindowsValidation.ps1`](../../../tools/validation/Invoke-WindowsValidation.ps1):

- Bootstrap the fixed reviewed `WindowsValidationJob.cs` once with the pinned Framework
  compiler, `/noconfig /nologo /target:library`, one owned output DLL and explicit absolute
  System/System.Core references. The normal implicit mscorlib reference and compiler
  runtime/configuration are verified installed inputs. No response file, analyzer,
  generator, shared compiler, custom task or extra source is permitted. Retain the
  same compiler process object/handle through completion or stop. Bind its output DLL
  to the accepted source, command and installed inputs; later actions verify that
  artifact and source before loading it. A failed bootstrap stops, rather than retrying.
- Restore only the fixed Windows scenario project with its owned config and complete
  package cache, disabled audit/parallelism/shared compilation, one node and no node
  reuse or automatic response file. Use locked mode after the reviewed lock is tracked.
- Build that project in Release with no restore, disabled build servers/shared compilation,
  one node, no node reuse and no automatic response file.
- Execute only its source-bound DLL through the selected Windows dotnet host, using the
  embedded MTP TRX reporter and the dedicated results directory.

For each restore/build/test, the reviewed
[`WindowsValidationJob.cs`](../../../tools/validation/WindowsValidationJob.cs) creates the
child suspended, restricts inherited output handles, assigns it to the owned Job and
resumes only after assignment. Retain its incarnation handle. Set KILL_ON_JOB_CLOSE and
a 32-process ceiling without breakaway. No VCTIP or compiler-survivor exception applies.
Require normal zero-active-process completion before accepting an expected result.

The standalone bootstrap gets 30 seconds and each restore gets 180 seconds. Each build
or test gets 120 seconds. The same stopwatch covers subject start, capture and normal
Job drain; no new timeout starts at a later stage. Bound combined captured bytes to
8 MiB, retaining a bounded prefix and disposition on failure. On timeout, cancellation
or overflow, stop the owned compiler by its retained handle or terminate the Job and
verify quiescence within ten further seconds. Persist captured bytes only after
confirmed quiescence; no raw process or machine-bearing output is published directly.

The WSL helper bounds the fixed path-preflight controller wait to twenty seconds and
its action-controller wait, including input verification, to 230 seconds. SIGINT/SIGTERM
creates an action cancellation marker and allows up to fifteen seconds for normal
Windows stop. A controller timeout or unconfirmed stop invokes the fixed
[`Stop-WindowsValidation.ps1`](../../../tools/validation/Stop-WindowsValidation.ps1) for
at most ten seconds; local interop-proxy termination gets at most five seconds. Emergency
termination verifies retained PID/start-time identity, never a bare reused PID.
Controller absence and WSL exit do not prove Job quiescence: emergency or incomplete
Windows evidence stops the loop with explicit uncertainty and retained files.
No subsequent action or speculative cleanup is permitted from that state.

Every final receipt binds exact command/environment, source, tools, public archive/cache
inputs, restore metadata and applicable artifacts, plus UTC timing, exit, capture
disposition, Job accounting and stop results. Restore metadata means the explicit NuGet
assets/dgspec/generated-import files; build-only JSON is included in the build receipt.
A build cannot silently redefine restore prerequisites. After an expected test, inspect
the single TRX and exact case outcomes before further reliance. Retain all dedicated
files and failed starts. Synthetic managed file results establish only their actual
source and Windows file/application boundary; UI, WAM, process transport, WSL lifetime,
Native AOT, real account reuse and overall Slice acceptance remain open.

## Windows Action 0002 Preparation Disposition

The first Windows restore reservation stopped during WSL source preparation on
2026-09-13, from 07:36:27.939277Z through 07:38:42.857508Z. It used source
`09604cb901167f73bc9b6b1495262381f554d476`, tree
`63c7e8dfc6eec2aec7b1c79154b9494c33ba8da8`, accepted protocol/helper
`cb665807d0261bc80fa969aae2249600f2d20bb1`, target
`6110ea919ef05a32e48984ada7ab05983fdfa0bf`, and the independent
[bootstrap/first-restore gate](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5651975254).

The [failure investigation](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652009605)
and [independent triage](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652012490)
confirmed all 152 source files retain their immutable Git blob contents. DrvFS
presents each tracked mode 100644 file as executable; inherited `core.filemode=true`
therefore makes the existing-worktree diff fail with 152 mode-only changes.
Command-scoped `core.filemode=false` produces an empty successful diff. Bootstrap
created the worktree and verified bytes without exercising this later comparison.

The original result records `CalledProcessError`, `continuation_allowed=false`,
`quiescent=false`, and empty evidence. Its exception class does not identify the
failed command by itself. The exact accepted control flow, independently reproduced
mode mismatch, and retained file sets support failure at the first existing-source
diff, before the Windows action controller or restore subject. WSL action 0002
contains only its original start and result; the Windows action contains exactly
empty `home`, `home/local`, `home/roaming`, `temp`, and `results` directories. No
Windows input reservation, invocation, controller, Job, output, restore graph or
new lock exists. The bounded read-only Windows path preflight completed before
those directories were created; this is not an observation of no Windows activity.

Preserve the original false/false receipt. This disposition records the recoverable
pre-subject boundary without inventing a Windows process-quiescence result or
marking the action successful. After independent review and target-branch acceptance,
both history guards may recognize only these exact receipt bytes and the unchanged
empty Windows directory boundary. All other missing, changed, failed, uncertain or
nonquiescent evidence still stops both loops. Original Linux action 0022 and Windows
bootstrap 0001 remain unchanged.

| Windows action 0002 evidence | SHA-256 |
| --- | --- |
| WSL `started.json` | `b5f6e94a9240778dd028610f5c0c76fe9fafcea2aa0f27bf84d19e9839839142` |
| WSL `result.json` | `437df40a2c76f7e288de3fd5d36beff41f8b0318a85a55d0b2c24a3ab179d43e` |
| Local console log | `a41a97dda14ac0178aa30eeba51af8b634e58426d590279fad865f59de5439da` |

The corrected Git wrapper applies `core.filemode=false` only to commands evaluating
the dedicated Windows-volume subject. Immutable commit/tree and raw byte checks,
untracked-source and lock-adoption checks, Windows ownership/path/reparse checks,
and all other controls remain required. It changes no shared Git configuration,
filesystem permission, tracked Git mode or source content.

The first subsequent action must be a newly admitted Windows restore of the same
immutable red source. It consumes a new reservation; it is not a replay or a retry
authorized by this disposition alone. Before that action, independently refresh
source, authority, complete retained cache/tool inputs and bootstrap-helper binding.
Linux execution remains stopped until that Windows continuation completes normally.
Build/test and generated-graph gates remain separate.

During that next reserved restore only, migrate the copied `controller/run_windows.py`
from SHA-256 `5890dff4e499ab7d29efdde378c06f71cc975d49e6116daed8896f033b02fece`
to the exact newly accepted helper bytes. The helper first performs ordinary accepted
root preflight and validates the exact failed history. It exclusively creates
`retained-run_windows.py` under the new action, copies and verifies the original
bytes, then replaces only that controller file and verifies the new digest. Record
both protocol identities, both hashes and the retained filename in
`controller-migration.json`; include the retained copy and migration record in the
normal final evidence binding. A missing/unrecognized old file, existing backup,
changed replacement or interrupted migration stops continuation. This is a one-file
migration in one consumed action, not a general controller upgrade or repair path.
PowerShell/Job source, bootstrap DLL, package inputs and toolchain remain unchanged.
No pre-action overwrite, receipt edit, cleanup or bootstrap repetition is permitted.

Consumption after the failed reservation is 2/4 Windows preparation actions, including
1/3 restores, and 0/40 Windows build/test. Combined consumption is 9/16 preparation
and 27/120 build/test; charged downloads remain 768 MiB with no new download. Retain
all dedicated files and failed starts. No capacity or effects boundary is enlarged.
There is still no Windows restore/build/test result, and Native AOT, UI/WAM, real
account reuse, process/WSL behavior and overall Slice acceptance remain open.

## Windows Action 0003 NuGet Environment Disposition

The next restore used unchanged red source
`09604cb901167f73bc9b6b1495262381f554d476`, tree
`63c7e8dfc6eec2aec7b1c79154b9494c33ba8da8`, accepted protocol
`5067d92dee2f56c5f11a51c30b496fddc6eef3d2`, target
`f9f8f67ed0973386ec8d7dfc0c99ee2d27e219f4`, and its independent
[action admission](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652090072).
The [failure investigation](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652133156)
records the exact invocation, evidence, retained-input audit and bounded conclusion.
Its [independent triage](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652135829)
confirms the environment defect and this bounded correction.

**Runtime observation:** The WSL reservation began September 13 UTC
08:00:25.422465. Windows restore ran from 08:04:43.2717117 until the final
Windows receipt at 08:04:44.7657094; reported child capture duration was 1.459
seconds. All three projects failed NuGet `ConfigurationDefaults` initialization
with `Value cannot be null. (Parameter 'path1')`. The complete capture was 1,495
stdout bytes and empty stderr. Child exit was 1, with normal zero-active-process
completion, no safety stop and no Job termination request. The WSL final receipt
at 08:05:46.568339 correctly retains `continuation_allowed=false`,
`quiescent=true` and `error_type=ValueError`. This is a failed restore, not a red
business test. No generated graph, new Windows lock, build or test exists.

The prior one-file controller migration completed and remains hash-bound in the
failed action's evidence. All 1,235 protected inputs, 152 source files, complete
1,057-file package cache and admitted tools remained unchanged after execution.
Retain the dedicated first-use markers and SDK diagnostic log as well as the
complete receipts and capture. Original Windows 0002 and Linux 0022 remain unchanged.

**Source finding and causal interpretation:** The recorded replacement environment
omitted both `PROGRAMFILES(X86)` and `PROGRAMFILES`. The identical pinned SDK cause
and isolated correction are already established in the
[Native AOT environment diagnosis](windows-native-aot.md#diagnostic-restore-and-nuget-environment-cause).
NuGet's CoreCLR implementation reads those variables to construct its machine-wide
defaults path even with `--configfile`; two absent values cause the observed null
argument. The installed NuGet.Common and NuGet.Configuration assemblies match that
accepted diagnosis. Add their exact hashes to the current helper's tool checks;
no installation, download, package change or new diagnostic execution is needed.

For each subsequent action, exclusively create `empty-program-files` under that
action's dedicated directory. The Windows controller verifies it is a direct,
empty directory before subject invocation and maps both required variables to it.
The WSL helper verifies it remains empty after quiescent execution. Retain it.
Do not inherit the host variables, read host NuGet defaults through them, populate
this directory, or add unrelated environment inputs. Explicit tool paths, complete
cache reuse, empty restore source, cleared configuration and all execution limits
remain unchanged.

Both history guards recognize only these exact failed WSL receipts, then verify
every Windows evidence hash bound by the original result:

| Retained WSL file | SHA-256 |
| --- | --- |
| 0003 started.json | `98d325740fc4c3cf7e34132faadc2494396a069e8da3885eb72ade65c34fef4c` |
| 0003 windows-input.json | `e3075e32ca4d0a5dcc0221d6102ec6ced0db89ff0f3a092f8dcb184e76c2a899` |
| 0003 result.json | `891a2040d258df4af84deccadce7388092a430416df2f94bf0e7b93f4ec9527a` |

The first continuation must be a newly admitted Windows restore of the same red
source. Linux remains stopped until that continuation completes normally. Changed
receipts or bound evidence stop both loops. This disposition preserves a known
quiescent failure; it does not rewrite the failure as success or admit another action.
Refresh independent source, authority, complete cache/tool and bootstrap-helper
review before the next reservation. Resolved-graph, build and test gates remain separate.

During new action 0004 only, migrate two copied controller files to their exact
newly accepted protocol bytes. Their required original SHA-256 identities are
`5670156edbc55851435adca4212f07569d540972656c0ff2cb876b366ab7baed`
for `run_windows.py` and
`6c577f6638d5fdaa243e92bc0a5c3bc263b70b1b2ed6c847e6ac32a67af1d113`
for `Invoke-WindowsValidation.ps1`. After normal reservation and root preflight,
exclusively preserve each original as `retained-<filename>` in action 0004 and
verify it before replacement. Verify each replacement and retain both protocol
identities and each file's old/new hashes and backup name in
`controller-migration.json`; bind the record and both backups in final evidence.
Missing or unexpected originals, existing backups, changed replacements or an
interrupted migration stop continuation. Preserve action 0003's migration record
and backup. No other controller, bootstrap DLL, source, cache, history or permission
is changed; no pre-action overwrite, cleanup or bootstrap repetition is permitted.

Consumption after 0003 is 3/4 Windows preparations, including 2/3 restores, and
0/40 Windows build/test. Combined consumption is 10/16 preparations and 27/120
build/test; charged downloads remain 768 MiB. The next restore consumes the final
currently allocated Windows preparation even if it fails. No capacity is reset or
enlarged. Overall Slice acceptance and all real-platform claims remain open.

## Windows Action 0006 Generated-Input Disposition

Test reservation 0006 used unchanged source
`86c211775342c774a47fce513e0fc10616ee87e9`, tree
`021ea81162a2d66608c47f54e3ab6a7b060b74ed`, accepted target
`daa4dd9116dd323e49967534392219624f74cc08` and protocol
`df91dd42df9242bc28a26425e81a4a6b12ff9c6b`. The independent
[artifact and test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652449134)
bound successful build 0005 and all 316 artifacts. WSL reserved the test at
09:29:15.932122 UTC on 2026-09-13 and finalized at 09:33:54.988178 UTC.

The Windows controller stopped during `host-inputs` at line 96, before invocation
recording, helper loading or subject start. Its final receipt at 09:33:54.8902711
UTC records a runtime exception, exit -1, safety stop, incomplete capture and
`captureDisposition=not-started`. Its quiescent result reflects the pre-subject
path with no compiler or Job to stop; it is not Job process-accounting evidence.
WSL retains `continuation_allowed=false` and `quiescent=true`. No test executed,
and this action supplies no business-red evidence.

The [independent finding](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652477275)
and [independent true-positive triage](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652487296)
identify three unchanged `.NETCoreApp,Version=v10.0.AssemblyAttributes.cs` files:
one in each Core, Windows and Windows-scenario Release obj directory. Their comma
and equals characters fail the controller's filename class. Each file remains
SHA-256 `93d67476196ebfc80d1d7d8844b91146cfd678d105f5ce635eb900ca40610c9b`,
matching both build and test inventories. Correct only that character class to
`^[A-Za-z0-9_./,=-]+$`; retain traversal rejection, literal-path hashing, root and
volume checks, no-reparse checks and complete input/artifact verification.

Both history readers recognize only the exact original 0006 receipts below and
their hash-bound Windows evidence. Preserve the original failed result, three
Windows files (`started.json`, `controller.json`, `windows-result.json`) and six
directories (`home`, `home/local`, `home/roaming`, `temp`, `results`,
`empty-program-files`). The leaf directories remain empty. Missing, additional,
changed or linked evidence fails closed; other failed or uncertain actions still
stop both loops. Original Windows 0002/0003 and Linux 0022 remain unchanged.

| WSL 0006 evidence | SHA-256 |
| --- | --- |
| `started.json` | `4fb0599b8aaacbcbb2099a2254426b3ac8a2ff16cfd5cacb90222c08b648a8c9` |
| `windows-input.json` | `3064a64bf43690bc5efc0c9022c6fe52da8d3a36880ec76efe5d691b1fdc1989` |
| `result.json` | `4ef1514ecd4e19cf02657a38ed73e5e920cb30cf38df9d54472ca89b3784f6ff` |

The independent preservation audit verified all 1,557 reserved inputs, 316 build
artifacts, 158 source files, both original/tracked locks, complete cache, tools,
restore graph and prior histories. After this correction is accepted, the first
continuation must be a newly admitted direct-DLL expected-red test of the same
source and unchanged build 0005. Refresh the published admission, accepted target,
Wave and input/artifact checks before reservation. No restore or rebuild is
required by this controller correction. Linux execution stays stopped until that
Windows continuation completes normally. Actual failed cases and first assertions
still require independent review before green implementation.

During new action 0007 only, retain and migrate the two changed active controller
copies. Required original SHA-256 values are
`bec5e035be9d54afd871bee648f2018f4ead6fec747c871f8c1c98f9a31db105` for
`run_windows.py` and
`131a4834275afe9e7041eb8d5cc106f9220127a68a75fd2383d021309a99ae9d` for
`Invoke-WindowsValidation.ps1`. After normal reservation and root preflight,
exclusively retain each original as `retained-<filename>` within 0007 before
replacing its active copy with exact newly accepted bytes. Bind both versions and
the migration record in final evidence. Any missing, changed or interrupted
migration stops continuation. Preserve earlier migrations, bootstrap DLL/source,
source checkout, locks, restore metadata and build artifacts unchanged.

Consumption after 0006 is **4/4 Windows preparations**, including 3/3 restores, and
**2/40 Windows build/test**; combined consumption is **11/16 preparations** and
**29/120 build/test**. Charged downloads remain 768 MiB. The newly admitted test
consumes Windows 3/40 and combined 30/120 even if it fails. No capacity, effect or
product scope is added. No actual business red/green, real WAM/UI, account reuse,
process/WSL lifetime, Native AOT or overall Slice acceptance follows from this stop.

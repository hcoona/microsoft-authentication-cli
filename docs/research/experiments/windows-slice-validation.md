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

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

## Linux Restore Metadata and SourceLink

This supplement corrects only the Linux metadata classification. Windows commands,
controllers, evidence and allocations remain unchanged. Accept this protocol/helper
revision before using its changed Linux checks; independent source, graph, build and test
admission remain required. No additional restore, retry, download or capacity is granted.

Restore metadata is exactly four direct `obj` files for each of Authentication.Core and
Authentication.Scenarios: `project.assets.json`, `<project>.csproj.nuget.dgspec.json`,
`<project>.csproj.nuget.g.props`, and `<project>.csproj.nuget.g.targets`. Record these eight
files on future restores and check their complete hashes and the existing graph-input
map before every build and test. Before selecting either metadata inventory, require the
active restore record to equal the complete immutable receipt of the latest successful
restore action in the retained history. An eight-file shape alone does not establish a
new restore. Missing or changed entries stop execution. Do not treat
arbitrary recursive `obj` JSON files as NuGet restore inputs.

### Restore 0035 Classification Correction

Linux restore 0035 used accepted protocol `03ecb488e7d4f6962bc874e2c312bc6e892659fa`
and candidate `a5b9b418c81be632bf115053eca9b4efbbf85820`. It completed with exit 0,
no termination and confirmed quiescence in 2.44 seconds. The [actual graph review](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653602026)
confirmed its 14 graph inputs, empty Core dependency graph and unchanged 19-package
scenario graph. The old collector also recorded two retained build outputs:

- `src/Authentication.Core/obj/Release/net10.0/Authentication.Core.sourcelink.json`
- `tests/Authentication.Scenarios/obj/Release/net10.0/Authentication.Scenarios.sourcelink.json`

Both maps still named prior source `4d8f25c73fb11fe26ab11be41ac7ddd20e62b53d`, with
SHA-256 `47fb3766926323477157af2e77186f013dc669eec6567520de89633764bd5c0d`. The
[independent true-positive triage](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653606933)
confirmed that the pinned SDK regenerates SourceLink before compilation using current
Git information. Freezing these build outputs as restore inputs would reject a later
test after a normal fresh build. This is a source/SDK-based prediction, not an observed
failed build or test. The successful restore and its dependency graph remain valid.

Preserve all original receipts and the active restore pointer without rewriting them:

| Restore 0035 evidence | SHA-256 |
| --- | --- |
| `started.json` | `ef2898b097b53ac247e701682ba4a60c442c4e5aeca34bac1628ed6d089ed943` |
| `result.json` | `807645e1ea15ccd2b8583a4689b47f2dedf6aaa6e0d1705c48f9052b15a7ed97` |
| `restore.json` | `e8517bb57c776292e0298ba3f4c3a31661a13762b019c1d4aeade093f77f3cd6` |

For this exact hash-bound successful receipt only, derive the eight-file NuGet projection
in memory by excluding only the two named SourceLink entries. The active pointer must
contain the same complete record, including all 14 graph inputs. Reject missing NuGet
entries, changed historical receipt bytes, changed active-record content or unexplained
extra metadata. Before the first new build, verify that all ten current files still
match their historical hashes. No manual metadata edit, SourceLink deletion, replacement
restore or historical action replay is permitted.

The [draft continuity finding](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653640720)
and [independent triage](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653640834)
confirmed that an eight-entry fast path must not accept a trimmed 0035 active record.
This is static control-flow evidence; the retained active record remains complete and
unchanged. Genuine later successful restores may establish the new eight-file inventory.

The two generated SourceLink maps belong to fresh source-bound build evidence. After
each successful new build, verify that their document mapping names the owned checkout
and the admitted commit at the public repository's raw-content URL, then include both
map hashes in the immutable build artifact record. Subsequent tests require that new
build and the unchanged complete artifact map, including SourceLink. Later builds may
regenerate the maps for a newly admitted source. A prior build that lacks this expanded
artifact evidence cannot satisfy a new test admission.

At discovery, Linux actions 1-35 consumed preparation 8/11 and build/test 27/80; Windows
actions 1-13 consumed preparation 5/5 and build/test 8/40. Combined preparation is 13/16
and build/test 35/120; process reservations remain 12/36 and charged downloads 768 MiB.
These completed actions retain their consumption and conclusions. Refresh actual shared
history before each later admission; this correction does not admit the next action.

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

## Windows Profile File Red/Green Evidence

The physical-file increment exercises the existing application boundary through a
Windows fixed-volume Profile reader, with controlled provider and UI seams. It
uses the existing Windows 11 x64 host through WSL 2, SDK 10.0.401/runtime 10.0.12
and MSTest 4.1.0. These are credential-free managed observations. They do not
establish product-process transport, WSL lifetime, real WAM/UI, account reuse,
Native AOT publishing or overall Slice acceptance.

The author/operator was `/root`; independent reviewers `/root/lifetime_triage`
and `/root/wave_review` supplied source admission and actual-evidence reviews in
[PR #121](https://github.com/hcoona/microsoft-authentication-cli/pull/121).
The accepted Wave blob remained `8bbc98cc2e892a33c06d190983d9c0a09a8d6282`.

| Source role | Commit | Tree |
| --- | --- | --- |
| Bootstrap and successful restore | `09604cb901167f73bc9b6b1495262381f554d476` | `63c7e8dfc6eec2aec7b1c79154b9494c33ba8da8` |
| Executed red | `86c211775342c774a47fce513e0fc10616ee87e9` | `021ea81162a2d66608c47f54e3ab6a7b060b74ed` |
| Green reader | `4a577756ab6c8bacdf8f612d560ecad9ad2fbe5c` | `c2f2f9d85080412c0182da64e0f2b83668a54b94` |

Bootstrap 0001 bound protocol `cb665807d0261bc80fa969aae2249600f2d20bb1`
and target `6110ea919ef05a32e48984ada7ab05983fdfa0bf`. Successful restore
0004 bound protocol `df91dd42df9242bc28a26425e81a4a6b12ff9c6b` and target
`1285a4463aa4d4cac6bbe5432ba091002f61f782`. Build 0005 used that protocol
and target `daa4dd9116dd323e49967534392219624f74cc08`. Red test 0007, green
build 0008 and green test 0009
bound protocol `13b991102dfc45a892f6a5318130c429af2aca4d` and target
`8520262c7b7a3bae3baa3c5834c1c30f27f90849`.

The [restore graph review](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652286932)
verified the same public 19-package test graph and build-only dependencies against
the complete retained cache. Restore metadata names the owned empty feed and SDK
library-packs; the fixed source mapping excludes the latter. This is not a
fresh-cache, singleton-source metadata or signature-verification claim. PR #124
preserved the exact generated CRLF lock bytes; source 86c2117 adopted them without
changing the test or project source. Build 0005 retained the originals.

The [red test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652570841)
reused the successful source-bound build 0005. The [actual-red review](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652629187)
confirmed ten executed cases, four intended failures and six passing rejection
guards. The personal/work rows, exactly 65,536-byte row and replacement-after-
admission case failed first at the shared `AssertSuccess` outcome assertion:
expected `success`, actual `invalid_request`. Later success, request/Profile
metadata and snapshot assertions were not reached. The 65,537-byte, missing,
directory, malformed-JSON, invalid-UTF-8 and sharing-denied guards passed on the
constant-rejection reader; those vacuous passes do not establish reader behavior.

The [concrete reader review](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652649292)
and [green build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652677308)
bind the implementation and unchanged ten cases. The reader moves potentially
blocking path/open work off the lifetime caller, checks caller and opened-handle
volumes, opens once with read-only sharing, bounds length before allocation and
returns the completed snapshot to the existing strict parser. Expected file
failures omit original exception details; cancellation retains its original token.
System32 LibraryImport declarations use the exact three Windows W exports.

The [artifact and green-test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652722285)
verified all 158 source files and 316 artifacts, totaling 51,872,400 bytes. Only
14 expected reader/reference/scenario outputs changed from build 0005; 302
artifacts, the generated MTP entry, five registrations, runtime configuration and
dependency mappings remained unchanged. All 12 restore inputs, 12 restore
metadata files and original/adopted locks matched. The completed controller
checks and existing public provenance reviews remained applicable.

Offline inspection of the actual reader DLL confirmed exactly three kernel32 W
imports, their native-width handle and int/uint/pointer signatures, System32-only
search attributes, UTF-16 pinning and SafeFileHandle marshalling with finally
cleanup. No DLL was loaded for inspection and no extra build property or generated
source emission was required. These artifact bindings supplement source review;
they are not Native AOT or additional runtime observations.

| Action | Windows final UTC, 2026-09-13 | Child seconds | Observation |
| --- | --- | ---: | --- |
| 0001 bootstrap | 07:30:58.4195200 | 0.296 | Exit 0; empty stdout/stderr; normal compiler completion. |
| 0004 restore | 08:36:37.5439069 | 2.137 | Exit 0; 431 stdout bytes; normal zero-active Job. |
| 0005 red-source build | 09:20:52.0635828 | 11.010 | Exit 0; zero warnings/errors; 562 stdout bytes. |
| 0007 red test | 10:02:28.0340529 | 1.139 | MTP exit 2; ten executed, four intended failures, six guard passes. |
| 0008 green build | 10:25:30.3060134 | 9.214 | Exit 0; zero warnings/errors; 562 stdout bytes. |
| 0009 green test | 10:35:58.5544519 | 0.893 | MTP exit 0; ten executed/passed, every other counter zero. |

The green test's complete stdout was 639 bytes; stderr was empty throughout these
six actions. Every restore/build/test above completed with normal zero-active Job
accounting and no termination request. Green build and test WSL receipts finalized
at 10:26:57.559118 and 10:37:17.372194 UTC, respectively, with continuation
and quiescence true. The single green TRX contains 15,693 bytes.

The [independent actual-green review](https://github.com/hcoona/microsoft-authentication-cli/pull/121#issuecomment-5652763522)
confirms exact name/data-row continuity for all ten cases.
The unchanged success assertions now verify the selected personal/work email,
Profile client/name, exact tenant/scopes, synthetic token and matching success
exit. Exactly 65,536 bytes succeeds; 65,537 bytes and the five file/format defects
produce the safe configuration failure before provider construction. The
replacement callback changes its own file after admission while the in-flight
request retains the original Profile.

All ten scenario directories, the directory-case child and eight synthetic files
matched their expected final contents, including the one 383-byte replacement
Profile. The final reservation retains the same 158 source files and 316 build
artifacts, original locks and controllers. Full controller checks and prior
unchanged-input reviews remain applicable; no additional dependency audit or
new platform claim is inferred.

| Evidence | SHA-256 |
| --- | --- |
| Build 0005 receipt | `20f2539905b84a473be89e5aa6f376a49e5e917456931b19e73382d453e061ce` |
| Red 0007 TRX | `94da0e2f4eab6bd5bac773f686824cc8846a9078c84dacc602f44980ea7d1922` |
| Green build 0008 receipt | `8cb8c5964895053fe8018dcbe6185dcc488b55596dd8007ca2d5b92fd4286c00` |
| Green test 0009 TRX | `199ad82c3ea378eebaf20f45220b22320ca483bf1a5c38889d7afa96ffdff011` |
| Green test 0009 Windows final | `6065b25aeae33e1dec93cb44845d7de7f6f0edc7c71f08b556f210c0b0cdad18` |
| Green test 0009 WSL final | `671423982a15fd3cfd94a9fa70a16a8a240c972399a51019926ff2b1ef2fb48d` |

Consumption through 0009 is Windows preparation 4/4, including restores 3/3,
and build/test 5/40; combined consumption is preparation 11/16 and build/test
32/120. Charged downloads remain 768 MiB. No new fetch, restore or installation
occurred during the red/green pair.

Original failed Windows actions 0002, 0003 and 0006 retain their accepted
dispositions and exact receipts. The two-controller migration completed inside
0007, retaining both originals and its hash-bound migration record. Original Linux
0022 and all 34 Linux actions remain unchanged. No failed action was retried under
its old identity, removed or converted into success. Dedicated artifacts and
synthetic fixtures remain intentionally retained. Raw machine-bearing output and
TRX filenames remain local; no account or credential state was exercised.

## Windows CLI Process Supplement

This supplement extends the completed file loop for Issue #108. It supersedes the
earlier supplement's fixed restore/build project, future per-host preparation
allocation, package input set, and ten-case test vector for subsequent actions.
All recorded observations, failed receipts, consumed units, and historical source
and controller identities above remain unchanged. Acceptance of this protocol is
a preparation prerequisite; each exact source, graph, build, and test still needs
its applicable independent admission review before execution.

### Subject and Effects

The fixed restore/build root is `Windows.slnx`, selecting Authentication.Core,
Authentication.Windows, Authentication.Cli, and Authentication.Windows.Scenarios.
The CLI retains `net10.0-windows`, `win-x64`, self-contained and Native AOT publish
configuration. This supplement admits only managed build/development execution;
it allocates no publish command or Native AOT artifact claim.

The Windows library declares exact Client/Broker 4.83.1 and NativeInterop 0.20.3
dependencies. Their presence does not admit real provider construction, account
enumeration, token acquisition, broker loading, UI, cache/consent access, or
resource requests. The actual CLI cases stop at root help and malformed
authentication. Ten further process cases use the scenario executable's finite
test-only selector and controlled provider through the same production process
boundary. Production CLI syntax has no test selector or ambient provider mode.

The custom scenario Main records original managed entry before child dispatch.
Its normal MTP branch retains builder creation, all five generated extension
self-registration hooks, build, and run. Inspect generated registration source,
actual entry metadata, selected runtime/dependency mapping, native imports and
DLL layout after build. The exact CLI help/malformed artifact and controlled
child artifact are separate evidence subjects. Keep the existing ten accepted
Profile file cases and their assertions unchanged.

The process fixture admits only fixed reviewed DLL/argument vectors, the pinned
Windows dotnet host, a replacement environment, and three explicitly inherited
standard handles. No shell or breakaway is permitted. Close unused child ends;
the parent retains the sole lifetime writer. All children inherit the existing
nonbreakaway Job, including its 32-process ceiling and kill-on-close behavior.
No new bootstrap is needed. Synthetic Profile files, markers, child receipts and
captures stay under the action-owned temporary directory and are intentionally
retained. No actual account selector or credential-bearing input is admitted.

### One Graph-Establishing Restore

Transfer one unused Linux preparation unit to Windows. Linux preparation becomes
at most 11 actions; Windows preparation becomes at most 5, including the already
completed single bootstrap and at most 4 restores. Combined preparation remains
16. Through Windows 0009, consumption is Linux 7 and Windows 4 preparations,
Linux 27 and Windows 5 build/test actions. Linux build/test remains at most 80,
Windows at most 40, and their combined ceiling remains 120. Charged downloads
remain 768 MiB; this supplement admits no new download or toolchain installation.

The first subsequent Windows reservation must be the one new graph-establishing
restore. It consumes Windows preparation 5/5 and combined preparation 12/16 even
if it fails. It is not an automatic retry allocation. No additional Windows
restore is available afterward. No helper may reset or refund any old or new
reservation. Both history readers enforce the revised allocations and retain
all original failure dispositions and evidence hashes.

Before synchronizing the immutable graph-establishment source, retain the three
superseded selected-project locks: Core, Windows and Windows.Scenarios. Record
their bytes/hashes, prior source and accepted restore-receipt identity in the new
action. That source intentionally omits those locks; the new CLI has no lock yet.
Do not remove or regenerate the separate Linux Authentication.Scenarios lock.
The Core lock is presently an empty `net10.0` graph; do not assume its bytes will
remain identical or accept a new RID/dependency without explanation.

Generate all four selected-project locks once. Independently review their exact
graph, dependency pruning, imports, native assets, compiler/runtime download
items and content hashes. Adopt byte-identical generated locks in a new source
commit before build, preserving originals during adoption. The hk whitespace
exclusion covers these four generated locks so it cannot rewrite accepted CRLF
bytes; other checks still apply. No failed restore, lock, or generated assets
file may be repaired in place. Any changed graph or unexplained input stops
continuation pending the applicable accepted disposition.

The solution is an explicit graph input alongside global.json, every relevant
project/import/config/lock and the generated NuGet assets/dgspec/import files.
Build uses Release, `--no-restore`, disabled build servers/shared compilation,
one node, no node reuse and no automatic response file. The restore retains the
owned empty source, complete verified public package cache, disabled audit and
parallelism, and the existing explicit fallback/source exclusions. Future builds
require unchanged accepted restore inputs and metadata. Tests require a new
source-bound build and independently reviewed outputs for each changed source;
stale bin/obj files do not become execution candidates by being present.

The reviewed cache extension consists of these eight complete entries:

| Package | Version | Role |
| --- | --- | --- |
| Microsoft.Identity.Client | 4.83.1 | Selected managed provider dependency |
| Microsoft.Identity.Client.Broker | 4.83.1 | Selected broker adapter dependency |
| Microsoft.Identity.Client.NativeInterop | 0.20.3 | Selected interop/native assets |
| Microsoft.IdentityModel.Abstractions | 8.14.0 | Selected transitive dependency |
| Microsoft.DotNet.ILCompiler | 10.0.12 | AOT build integration |
| runtime.win-x64.Microsoft.DotNet.ILCompiler | 10.0.12 | Selected compiler download item |
| Microsoft.NETCore.App.Runtime.NativeAOT.win-x64 | 10.0.12 | Selected AOT runtime download item |
| Microsoft.NETCore.App.Runtime.win-x64 | 10.0.12 | Managed self-contained runtime |

Their original public archives, complete payloads and original NuGet completion
metadata are retained in the historical public donor root. The independently
reviewed inventory contains 707 files. The existing copy-and-verify algorithm
checks every payload against its original archive and preserves metadata; it
does not install an archive or suppress Windows signature verification. Only
these additions may be copied during the first new restore reservation. All
previously accepted entries must already exist unchanged. The fixed archive
lengths/SHA-512s and signed content hashes are in `run_windows.py`.

Bind the installed Microsoft.NETCore.App.Ref and Microsoft.NETCore.App.Host.win-x64
10.0.12 packs separately to their original public archives. Verify the exact
348-file targeting/analyzer payload and 12-file apphost payload before use,
include each selected file hash among the Windows tool inputs, and recheck them
after execution. These installed packs are not new complete-cache imports.
`DisableTransitiveFrameworkReferenceDownloads=true` excludes unrelated framework
packs; actual resolved downloads still require independent review. Ordinary lock
entries alone do not establish compiler/runtime/targeting input completeness.

### Process Cases, Timing and Evidence

Reserve twelve process units before every full 22-case test action. Allow at most
three such reservations, totaling 36 of the Wave's 40 process units: the planned
red and unchanged green use 24, leaving at most one separately reviewed complete
corrective batch. Every reservation remains charged, including incomplete or
failed starts. There is no automatic retry, case filter, partial-batch refund or
permission to use the four unallocated Wave units. Record reserved capacity
separately from actual child launches.

| Fixed child case | Required observation |
| --- | --- |
| help | Actual CLI root help completes without authentication. |
| malformed | Actual CLI malformed protocol returns one safe invalid_request and exit 1. |
| success | Selected synthetic request returns one protocol-1 success and exit 0 despite broken stderr. |
| file-stdin | A flagged regular-file handle is rejected before Profile/provider effects. |
| closed-stdin | Already-closed flagged pipe cancels before authentication. |
| close-pending | Sole writer closure rejects the late candidate and ends within the shutdown allowance. |
| unused-stdin | Closed stdin without the flag permits success. |
| data-close | Synthetic payload is ignored; subsequent writer closure still cancels without leakage. |
| deadline | Timeout ends uncooperative provider work and a blocked cancellation callback. |
| broken-output | Broken result transport ends with exit 2 and no fabricated replacement result. |
| blocked-output | Observed buffered output cannot keep the process alive; incomplete delivery is transport failure. |
| blocked-diagnostics | Complete authentication success and exit 0 survive blocked diagnostics with bounded process completion. |

Run children sequentially. The fixture configures six seconds of observation, an
at-most-2,000-ms native termination wait if needed, and capture draining against
the remaining eight-second stopwatch envelope. This is not a strict bound on
synchronous receipt/file I/O or arbitrary OS scheduling. The existing outer
120-second subject/capture/Job-drain limit, 8 MiB outer output limit and bounded
termination remain necessary. Each child stream capture has a 512 KiB ceiling.
Fixture enforcement is recorded separately and never proves product shutdown.

Measure product intervals with the original managed-entry timestamp, parent
writer-close before/after timestamps, buffered-output observation, earliest
observed process exit, and common timestamp frequency. TimeProvider.System uses
Stopwatch/QPC on this Windows host; the documented cross-process clock basis
supports comparison on the same machine. Writer-close cases allow one second
from the pre-close timestamp. Deadline, blocked-output and blocked-diagnostic
cases select timeout 1 and allow two seconds from managed entry. Fix observation
tolerance prospectively at 100 ms, covering 10 ms polling and scheduling
uncertainty; it does not change the product allowance. Do not enlarge tolerance
after observing a failure. Candidate-returned precedes validation and does not
start an invented product deadline.

The fixture keeps an in-memory fatal stop latch and attempts a persistent
`process-safety-stop.json` under outer TEMP. Failed child start, uncertain wait,
termination/quiescence failure, capture failure, and evidence-finalization failure
block all later launches even if writing the stop marker fails. A single shared
finalization path also runs after early assertions: confirm exit, retain actual
stdout/stderr and exit/timestamps, and write the exclusive final receipt before
releasing ownership. Never retry or overwrite failed finalization.

The controller rejects a safety marker, missing child receipt/capture/managed
entry, unexpected case names/counts, or changed protected inputs. Retain and
hash-bind all process fixtures and markers even though ordinary temporary caches
remain outside the published evidence projection. The rejecting source must
execute 22 cases: the same ten file cases pass and all twelve process cases fail
their business expectations. Every red child must exit 2 normally with empty
stdout and no child-added stderr. The blocked-diagnostics fixture preloads its
stderr pipe before launch: only that case retains exactly `diagnosticPrefill`
literal `D` bytes, with a bound of 1 through 65,536. Every other red stderr
capture is empty. The ten controlled children must retain managed-entry evidence.
Independent actual-red review must correlate the exact stub/artifacts, first
failed assertions, child evidence and normal outer completion. Compilation,
loader, discovery, setup or safety failures cannot satisfy red. Review actual
red before implementing green; keep the admitted scenario assertions unchanged.
Green requires all 22 exact cases to pass and complete child evidence.

### Controller Transition and Claim Limits

Accept this record and controller changes before use. During the first new
restore reservation only, retain the exact prior active `run_windows.py` and
`Invoke-WindowsValidation.ps1` bytes before replacing them; verify prior hashes
from accepted revision `13b991102dfc45a892f6a5318130c429af2aca4d` and bind old/new
protocols and hashes in the migration receipt. Keep the existing bootstrap DLL,
WindowsValidationJob source and stop helper unchanged. Both history readers
recover old actions and cumulative reservations symmetrically. Missing, changed
or unresolved evidence stops both loops. No historical failure becomes success.

The resulting evidence establishes only the exact tested managed Windows
process boundary. A Windows-parent pipe fixture operated through WSL does not
establish WSL caller disconnection. Console cancellation, real HWND/UI and
accessibility, actual WAM, selected-account/cache/consent/reuse behavior, Native
AOT artifact acceptance and the complete Slice remain separate obligations.
Preparation of their protocols is permitted; account-state effects still need
the concrete owner risk amendment required by the accepted Wave.

Public timing and process API basis:

- [TimeProvider.GetTimestamp](https://learn.microsoft.com/dotnet/api/system.timeprovider.gettimestamp?view=net-10.0)
- [Windows QPC guidance](https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)
- [Explicit process handle lists](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [CreateProcessW](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)

## Windows CLI Process Evidence

The first process loop used the accepted supplement above, protocol/controller
`03ecb488e7d4f6962bc874e2c312bc6e892659fa` and accepted target
`58f03cf76f5dd764cf8797baf72157ac6728f448`. The operator was `/root`; independent
reviewers `/root/lifetime_triage` and `/root/wave_review` supplied source,
artifact, evidence, and finding-triage reviews through
[PR #126](https://github.com/hcoona/microsoft-authentication-cli/pull/126).
The existing Windows 11 x64/WSL host, public dependency pins, replacement
environment, retained roots, and account-free effects boundary remain unchanged.
The four successful Profile cases exercised their controlled synthetic provider.
No real MSAL/WAM provider construction, account enumeration, token acquisition,
UI, or authenticated service request was executed.

### Graph and Actual Red

The [graph-adoption review](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653064155)
accepted restore 0010's four exact generated locks and resolved public graph.
They were adopted without byte changes in source
`3e0281ef458b0a1469e04e08856e432182e0b2ff`, tree
`f8b3b02143c8ce9f24817155ef57698294dbb938`. That source preserves the rejecting
process boundary and all ten previously accepted Profile cases.
The [build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653120160)
and [actual-artifact/test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653230468)
bind build 0011 and the single full expected-red test 0012. Build 0011 completed
with zero warnings or errors; the inspected shared process boundary remained
the constant exit-2 stub. The build review binds 167 source files, 547 artifacts,
and 376 tool inputs, including both executable entry points and generated test
registration. No further restore occurred.

On September 13, 2026, test 0012 ran from `12:33:30.0255106Z` to
`12:33:32.8385674Z`, reporting 2.78 seconds and MTP exit 2. All 22 cases
executed: ten Profile cases passed and twelve process cases failed their
intended business assertions. Every other outcome counter was zero. The
[independent actual-red review](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653327341)
correlates each first assertion with the inspected stub and child evidence.
Missing later business markers, output, and expected exits establish the
intended missing behavior; they do not establish implemented shutdown behavior.

All twelve sequential children exited normally with code 2, empty stdout, and
no child-added stderr. The blocked-diagnostics capture contains exactly the
fixture's 4,096 literal `D` bytes; the other stderr captures are empty. All ten
controlled children retained their original managed-entry evidence. No setup,
loader, capture, infrastructure, or safety failure contributed to the red result.
Outer capture completed with 18,331 stdout bytes and empty stderr. The Job had
zero active processes and 26 total processes; no termination was requested.
Both final receipts were sealed, and the successful outer session was collected.

| Evidence | SHA-256 |
| --- | --- |
| Test 0012 WSL final | `986afddf29ecbf89a81ac2040e9aa52844c6c5b883fd9e2e8067b07f22165201` |
| Test 0012 Windows final | `4c4e2b2234d6c584a2b9eb975fb35424a37d8f3e0a00db0758b0689f610d7147` |
| Test 0012 TRX | `64159dd0b685e9ae10443b1dd867fada469ee0e4d019bef52c26c71e6822173d` |
| Independent causality audit | `6061a7c30cccaad1fc26fac4272f946ca22dd2377b12a0aac05c092d986b2da1` |
| Actual-red review | `a2ee0c561c009c9b5ded952ec3d3097f80aa2765748cd7d1cb22d074bd9909af` |

After 0012, preparation consumption is 12/16 combined and 5/5 Windows;
build/test is 34/120 combined and 7/40 Windows. Process reservations are 12/36,
separate from the twelve actual child launches. Charged public downloads remain
768 MiB. Synthetic files, captures, markers, and receipts are intentionally
retained; no account or credential state was exercised. Green implementation
and execution retain separate reviews and the unchanged assertions. These
observations supply no WAM, UI, account reuse, WSL disconnection, Native AOT,
or complete Slice acceptance claim.

### Green Process Behavior and Linux Regression

The implemented source is `a5b9b418c81be632bf115053eca9b4efbbf85820`, tree
`9083b5801d33280d2798786acda2fcfba2a5142e`. All 22 admitted scenario assertions
remain unchanged from actual red 0012. The implementation supplies original-entry
lifetime tracking, an independent process watchdog, worker completion drain,
admission before Profile/provider effects, bounded native pipe/output handling,
and detached diagnostics. The production provider factory still returns
`mechanism_unavailable`; this increment does not construct a real WAM provider.

The [source/build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653491458)
binds successful Windows build 0013 under protocol
`03ecb488e7d4f6962bc874e2c312bc6e892659fa` and target
`58f03cf76f5dd764cf8797baf72157ac6728f448`. It exited 0 in 14.963 seconds with
zero warnings/errors, complete capture, normal zero-active Job accounting and
no requested termination. Independent inspection covered 170 source files,
547 artifacts, all copied package outputs, native imports, actual entrypoints,
generated test registration and runtime selection. The outer session was collected.

Linux build 0036 and full regression 0037 then used that same product source
under accepted protocol `ec96e19f184f50555b461b39e432485eaf098408` and target
`22d527d596ecfa13fa0fcc740b9be7fb3d322a57`. Build 0036 exited 0 in 7.824 seconds,
without warnings/errors, termination or uncertain quiescence. Its 251 artifacts
include both regenerated SourceLink maps naming the admitted source; the exact
restore 0035 receipt and complete active pointer remain unchanged under the
[metadata correction](#linux-restore-metadata-and-sourcelink).
Test 0037 exited 0 in 0.9 seconds: all 243 cases passed, with every other counter
zero. The [independent actual-result acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653753405)
matched all distinct class/name identities to the prior complete suite and
verified all source and build artifacts unchanged. Both outer sessions were collected.

The [single Windows green admission](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653771063)
used the new accepted protocol and target above with the exact matching executor,
reusing completed build 0013. The four Windows controllers and retained restored
graph were unchanged; no Windows migration, restore or rebuild was required.
Test 0014 completed on September 13, 2026, at `14:20:35.8295304Z`, in 6.834
seconds with MTP exit 0. All 22 exact cases passed: ten Profile file cases and
twelve process cases. Every other outcome counter was zero. Outer capture was
complete with 642 stdout bytes and empty stderr. The Job had zero active and
26 total processes, with no requested termination or safety stop. The collected
outer session exited 0 and finalized at `14:23:29.902270+00:00`, confirming
protected-input agreement, quiescence and continuation allowed.

The [independent actual-green acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/126#issuecomment-5653880772)
verified all 124 finalized evidence files, 2,515 protected inputs and 376 tools
without a mismatch. Its sealed audit SHA-256 is
`6caf437c3ad41afee4b127aaac102cd1156601fd3b3040b8c70f0e0afb9e127c`.

Every child retained `forced=false` and confirmed quiescence. These are actual
product exits; no fixture-enforced stop supplied the shutdown observations.

| Process case | Observed outcome |
| --- | --- |
| help | Actual CLI help, expected command/options, exit 0. |
| malformed | One safe protocol-1 `invalid_request` failure, exit 1. |
| success | One exact selected synthetic success despite broken diagnostics, exit 0. |
| file-stdin | `invalid_request` before Profile/provider effects, exit 1. |
| closed-stdin | `cancelled` before authentication, exit 1. |
| close-pending | Writer closure rejected late success; cancellation and candidate-return markers retained, exit 1. |
| unused-stdin | Closed stdin without the flag preserved selected success, exit 0. |
| data-close | Payload ignored without leakage; writer closure canceled the request, exit 1. |
| deadline | Uncooperative work and blocked callback ended through product exit 2; the delivered failure was a safe timeout without a token. |
| broken-output | Candidate returned, empty stdout, transport-failure exit 2. |
| blocked-output | 262,588 buffered bytes observed; incomplete delivery ended through product exit 2. |
| blocked-diagnostics | Selected success and exit 0 with the fixture's 4,096-byte diagnostic prefill retained. |

Timing uses the original timestamps and common frequency of 10,000,000 ticks
per second. From the original managed entry, earliest observed exit was
2.0220965 seconds for deadline, 1.0883609 seconds for blocked output, and
0.1000613 seconds for blocked diagnostics. From the parent's pre-close timestamp,
exit was 0.0597056 seconds for close-pending and 0.0603433 seconds for data-close.
These meet the original two-second and one-second allowances with the
prospectively fixed 100 ms observation tolerance. Fixture start-to-end duration
is a separate measurement; no deadline or tolerance was reset after observation.

| Evidence | SHA-256 |
| --- | --- |
| Windows build 0013 WSL final | `8485cacd080f447bd932e1e2e80644f2ce4a2b6f7c44c2f235b861303403423d` |
| Windows build 0013 Windows final | `80b931e48199cfafabadacd8d2019bf63dd28cf97d537468a05674be03b39748` |
| Windows build 0013 manifest | `c82a5697738a5a0b9fdfeb41173ce43131884394ae3318145ad2d0a51a0cbcc4` |
| Linux build 0036 final | `2aaf1f778dae8d8323158869b53f45bce327a1b08b21897d2427f2b9b73e71dd` |
| Linux build 0036 manifest | `9b90bc82db1f59e7e1bb2514575ed9f08ed75068733f6fc96aae13bb3d4a44c5` |
| Linux test 0037 final | `67c88b315a48cbbc0e7c3114d5fbb39f3bb097fb842a3f46f43e2a2f0343b60b` |
| Linux test 0037 TRX | `4ea100a9acd4338153daf787c096f57dd4afecf4a2a368e1eb538e0f10bcb3ab` |
| Windows test 0014 WSL final | `d71e129cfdeb8d47fc83146319242c2948d4948240fd15cee39914b45ba4653d` |
| Windows test 0014 Windows final | `b32b4370942fe521b3e6f2cc45ff7033595e47add27ed540b5a2a94c4982d71a` |
| Windows test 0014 TRX | `ec5b1dc45831e10733cf80882b3785a68aeea2816bd22b29b648aeb670c74887` |

After 0014, Linux consumption is preparation 8/11 and build/test 29/80; Windows
consumption is preparation 5/5 and build/test 9/40. Combined consumption is
preparation 13/16 and build/test 38/120. Process reservations are 24/36, including
both full batches; downloads remain charged at 768 MiB. All prior failed actions,
receipts, captures, original timestamps, synthetic files and reservations remain
intentionally retained. No repeated red, filtered run or retry occurred.

These observations establish the exact managed CLI/process and Profile behavior
above. The asynchronously written disk-output cursor correction retains its
source/artifact review; the unchanged pipe suite does not establish runtime
coverage of that disk-handle condition. Real WAM/accounts/cache/consent/reuse,
owned UI/accessibility, console cancellation, actual WSL caller disconnection,
Native AOT artifact/deployment, Profile activation and complete Slice acceptance
remain separate obligations. A later documentation-only head does not replace
the immutable source identity of these executed artifacts.

## Controlled Adapter Scenario Supplement

This supplement selects credential-free adapter scenarios after the accepted
[CLI green result](#green-process-behavior-and-linux-regression). It changes the
future fixed test command and selection/accounting rules described below; earlier
unfiltered invocations, assertions, observations and consumed reservations remain
unchanged. Exact source/artifact admission is still required for each action.

### Subject and Effects

Reuse Windows.slnx, the existing four selected projects, exact locks and restored public package graph, SDK 10.0.401/runtime 10.0.12, MSAL/Broker 4.83.1, and NativeInterop 0.20.3. Add the controlled mapper/projection/custom-UI and managed HTTP-handler cases to Authentication.Windows.Scenarios. No additional project, dependency, restore, tool installation or package download is proposed.

Only public synthetic MSAL exception/result values, the existing coordinator/lifetime, a fake host/clock, a directly called rejecting callback, and an in-memory HTTP terminal handler may execute. No real PublicClientApplication, account/cache API, broker loading, window, network terminal handler, authentication, child process or Native AOT publish is covered. Review every selected entry, static initializer, generated registration and actual artifact before execution.

### Fixed Selection and Source Admission

The current full CLI batch remains exactly its 22 unchanged cases. New adapter selection must be a separate finite helper choice with a controller-owned literal positive filter, no caller-supplied expression, arbitrary vector, exit override or settings. Keep normal MTP builder creation and all five extension registrations. Select all 21 methods below, without DataRow expansion, and verify every actual class/name identity and outcome. Reject missing, duplicate, unexpected, skipped or not-executed results; total/executed/Passed/Failed must exactly agree with the manifest, and all other counters must be zero.

A test action requires `--suite adapter` or `--suite cli`; non-test actions forbid
a suite, and only tests may select an expected red result. No caller filter or
settings argument is admitted. Both the outer helper and Windows controller own
the literal selections. The exact adapter filter is:

```text
FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ConsentRequirementHonorsInteractionPermission|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.SilentClaimsReachOneContinuationAndSecondChallengeStops|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.AccessDeniedWinsOverUiRequiredAndRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.Structured65004WinsOverRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.DenialTextAndNativeCodeDoNotImplyEntraDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.DuplicateErrorCodesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.NonNumericErrorCodesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.MalformedOrOverBudgetBodiesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ProviderUserCancellationRemainsCancelled|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalCancellationWinsOverDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalDeadlineWinsLateProviderCancellation|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.HttpTimeoutDoesNotConsumeRequestDeadline|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RetryableProviderStopsWithoutApplicationRetry|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RecognizedNetworkErrorStopsWithoutRetry|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UnknownProviderConfigurationStaysInternal|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UnexplainedCancellationStaysInternal|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UserMismatchWinsOverRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ResultProjectionPreservesObservedMetadata|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.MissingAccountAndInvalidTenantRemainMissing|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RejectedCustomUiCannotReturnAuthorizationUri|FullyQualifiedName=Authentication.Windows.Scenarios.ManagedTransportScenarios.ManagedUserAgentIsSingleStableAndForwardsCancellation
```

The inert baseline has 13 intended business failures and 8 passing safety controls; compile, fixture, loader and discovery failures cannot satisfy red. Independently review the exact immutable source and first failed assertions before admission, then actual red before green implementation. Preserve admitted scenario assertions. Green requires all 21 Passed and normal outer exit 0; red requires the embedded runner's reviewed assertion-failure exit 2.

| Fully qualified case | Inert red prediction |
| --- | --- |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.ConsentRequirementHonorsInteractionPermission` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.SilentClaimsReachOneContinuationAndSecondChallengeStops` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.AccessDeniedWinsOverUiRequiredAndRetryHint` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.Structured65004WinsOverRetryHint` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.DenialTextAndNativeCodeDoNotImplyEntraDenial` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.DuplicateErrorCodesDoNotCreateDenial` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.NonNumericErrorCodesDoNotCreateDenial` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.MalformedOrOverBudgetBodiesDoNotCreateDenial` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.ProviderUserCancellationRemainsCancelled` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalCancellationWinsOverDenial` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalDeadlineWinsLateProviderCancellation` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.HttpTimeoutDoesNotConsumeRequestDeadline` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.RetryableProviderStopsWithoutApplicationRetry` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.RecognizedNetworkErrorStopsWithoutRetry` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.UnknownProviderConfigurationStaysInternal` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.UnexplainedCancellationStaysInternal` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.UserMismatchWinsOverRetryHint` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.ResultProjectionPreservesObservedMetadata` | Failed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.MissingAccountAndInvalidTenantRemainMissing` | Passed |
| `Authentication.Windows.Scenarios.MsalAdapterScenarios.RejectedCustomUiCannotReturnAuthorizationUri` | Failed |
| `Authentication.Windows.Scenarios.ManagedTransportScenarios.ManagedUserAgentIsSingleStableAndForwardsCancellation` | Failed |

### Reservation and Controller Transition

Each selected adapter execution consumes one Windows build/test action and zero child-process units. Reject any process-* fixture or child evidence for this selection. Preserve all prior starts/results and their recorded 12-unit full CLI test reservations. Both Linux and Windows history readers recover the old and new suite shapes
symmetrically and reject altered, unknown or ambiguous selection/accounting.
For every ordinary finalized action, require the WSL start to equal the verified
Windows start after removing only its documented file/tool/helper additions.
Require both start and `windows-result.json` evidence hashes, the existing
`windows-input.json` link and Windows `reservationSha256` to agree before any
accounting. Preserve the exact disposed 0002, 0003 and 0006 exceptions and their
original evidence. Missing or inconsistent copies stop both loops; a coherent
change to only one suite/charge pair cannot refund capacity. All Windows preparation remains exhausted. Existing cumulative build/test, download and process ceilings remain unchanged; the unused third full CLI reservation is not simultaneously reallocated here.

The first action under this controller supplement is no-restore Windows build
0015, after exactly fourteen finalized actions. Verify the immutable 0014 WSL
start SHA-256 `527ed232989800a81fa9eaced39cd66c24c7eb01c309ca5f24ea83746f257f1a`
and WSL final SHA-256
`d71e129cfdeb8d47fc83146319242c2948d4948240fd15cee39914b45ba4653d`.
Its Windows final remains
`b32b4370942fe521b3e6f2cc45ff7033595e47add27ed540b5a2a94c4982d71a`.
During that build reservation only, the required prior controller hashes are
`93486d23aff1ade31b314c0d0c588af250ca200068297539507517a5946d2bb6`
for `run_windows.py` and
`bf90ffed77171eb553eed0350dabddbfc14966e1e3584fea3e77e867b6ec559f`
for `Invoke-WindowsValidation.ps1`. Retain their prior bytes and a hash-bound migration receipt through the existing narrow migration procedure during an admitted build; no standalone bootstrap, rewrite outside an action, restore, historical replay or automatic retry. Keep WindowsValidationJob.cs, bootstrap artifact and stop helper unchanged. Accept run_managed.py's matching history interpretation in the same protocol amendment. A failed or partial migration stops both loops pending its own disposition.

Future `--suite cli` regression positively selects exactly sixteen original
methods: four Profile methods expanding to ten cases, and twelve process methods.
The literal filter in both controllers uses full method equality, never a class
substring, wildcard or negative exclusion. Keep all original 22 expanded
class/name identities, assertions, process evidence and twelve reservations. The adapter-only result cannot replace that evidence. No existing historical invocation is rewritten or retrospectively described as filtered.

Retain the replacement environment, dedicated roots, complete public input/artifact hashes, current-source no-restore build prerequisite, 120-second subject/capture/Job-drain limit, 8 MiB output bound, nonbreakaway 32-process Job, original bounded termination, complete capture and quiescence conditions. The Windows controller and outer helper must independently agree on the finite selection. No completion or acceptance claim follows before both finalized receipts, collected outer session and independent actual evidence review.

### Admission, Capacity and Claim Limits

At the accepted 0014 checkpoint, Linux preparation is 8/11 and build/test 29/80;
Windows preparation is 5/5 and build/test 9/40; combined preparation is 13/16 and
build/test 38/120. Process reservations are 24/36, and charged downloads remain
768 MiB. No new restore or download allocation is introduced. Preserve all roots,
previous controller bytes, failures, receipts and reservations. Refresh actual
history and accepted target/protocol/source before each new admission.

The first red source adds only the controlled C# cases and inert adapter seams
within the existing four projects. All non-C# graph inputs, exact dependency
locks and restore metadata remain unchanged. A current-source no-restore build
and independent complete artifact review must precede its test. Confirm actual
entrypoints, static initializers, normal MTP builder and all five extension
registrations; selection alone does not prove effect confinement. The first
actual red must fail its intended business assertions, never compilation,
loader, discovery, fixture or safety checks. Independently accept that result
before green implementation; preserve assertions through green.

[MSTest's public runner contract](https://learn.microsoft.com/dotnet/core/testing/unit-testing-mstest-running-tests#configurations-and-filters)
permits direct DLL execution with `--filter` and a quoted OR expression using
`FullyQualifiedName`. This is public API evidence, not an observed local test.
The existing original CLI result also establishes the pinned TRX expanded-name
and sixteen-counter shape without another run. New suite outcomes remain
unobserved until their separately admitted actions finalize.

Real WAM/UI/accounts/cache/consent, actual WSL behavior, Native AOT and overall
Slice acceptance retain their separate gates. No adapter-only result replaces
CLI/process, real-platform or complete Slice evidence.

## Controlled Adapter Red/Green Evidence

The increment in [PR #130](https://github.com/hcoona/microsoft-authentication-cli/pull/130)
adds the accepted 21 adapter scenarios in the existing Windows scenario project.
It uses only synthetic public MSAL observations, the existing coordinator/lifetime,
a fake host/clock, a directly invoked rejecting custom-UI callback and an in-memory
HTTP terminal. The production provider factory remains unavailable. All original
CLI/Profile cases, project inputs, public dependency locks and selected versions
remain unchanged.

### Accepted Red Result

Executed red source `07ce16aa2b3fb90037ed3a29d261ac9ea6461a87`, tree
`5afb3b71dde3288d8759a0165a77145146a8200d`, used accepted protocol
`52434a9306e46962849c6bae4191c06ba21bcb98` and target
`ea868e52e93ef0dcc02650cf616eae782c1a39e1` on the designated Windows 11 x64
host from WSL2. The pinned SDK/runtime and reviewed retained public package graph
remain the execution basis. No restore, download or tool installation occurred.

The [actual build 0015 review](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654227729)
accepted the successful no-restore build, zero warnings/errors, complete source,
input, artifact and PE/PDB bindings, and the exact two-controller migration.
The previous controller bytes and migration receipt remain retained. The
[separate red admission](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654227827)
then permitted exactly adapter test 0016.

The [independent actual-red acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654345242)
confirms **21 executed cases: 13 intended business-assertion failures and 8 passing
controls**. Every other outcome counter is zero. The embedded runner exited 2 in
1.122 controller-measured seconds; complete capture contains 21,728 stdout bytes
and empty stderr. The Job ended with two total and zero active processes, with no
termination or safety stop. Windows ended at 2026-09-13T15:45:59.3181906Z; WSL
finalized at 15:48:40.094791Z, and the outer session was collected at exit 0.

The failures establish the missing failure mapping, claims continuation, original
cancellation propagation, observed result projection, rejecting-UI outcome and
managed HTTP product identity. Later assertions behind those first failures were
not reached; the accepted report identifies those limits. The eight controls
passed. Every case identity and TRX join agrees with the fixed selection, and all
175 source files, 547 artifacts, 2,520 protected inputs and 376 tool entries retain
the accepted identities. No CLI child-process batch was selected or charged.

### Reviewed Green Correction

Green implementation began only after actual-red acceptance was published.
Failure mapping follows the accepted ordinal precedence and original token;
structured denial recognition retains all size/depth/array/duplicate limits.
Projection preserves observed result fields, including missing scopes as missing
metadata. The custom-UI callback rejects navigation with the sanitized outcome.
The managed handler preserves dependency tokens and original cancellation while
emitting one existing registered product/version token.

Independent source review found that malformed raw UTF-16 and escaped malformed
property names can throw non-JsonException failures from JsonDocument.Parse,
masking independent retry hints. The [finding](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654388285),
[addendum](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654407447)
and [independent true-positive triage](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654407576)
are pinned public-source reasoning. The narrow correction handles only the known
exception categories at the parse call, leaving subsequent guarded processing and
classification precedence unchanged. Both original adapter test files remain
byte-identical to red. The existing 21 scenarios do not exercise those exact two
malformed-text/retry combinations; no runtime reproduction or real WAM occurrence
is claimed.

### Accepted Green Build

Corrected green source `b26a26e1eb2d6a7e34ff0e58b4c6d3b460547dd8`, tree
`0c44a33dc369c24226ad925baf2b895f3f85ad4f`, retains the same accepted protocol
and target above. Only MsalBoundary.cs, RejectingWebUi.cs and
ManagedUserAgentHandler.cs changed from the admitted red implementation.
MsalAdapterScenarios.cs remains SHA-256
`39916e41a3bc7399324777e1a77ff82ceb70d8621cf765f8547e1fab3c2d64fb`;
ManagedTransportScenarios.cs remains
`21dac163f0f922951590ccc65ba4fed37f260f47f70c8266d2ef22b097ab81b8`.

The [independent actual build 0017 review](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654607274)
accepted the no-restore build with zero warnings/errors, complete capture of
713 stdout bytes and empty stderr, normal exit 0, eight total Job processes and
zero active processes. No termination or safety stop occurred. The controller
measured 12.647 seconds; the build tool separately reported 11.94 seconds.
Windows ended at 2026-09-13T16:29:26.4548616Z and WSL finalized at
16:32:17.662068Z. The outer session was collected at exit 0.

The independent actual-artifact review verified 175 source files, 547 artifacts,
438 copied public-package outputs, 1,989 protected build inputs and 376 installed
tool entries, with complete actual IL/PDB bindings. All 416 scenario methods
retained their red-build IL. The compiled malformed-text correction matched the
reviewed source. Build input counts exclude the additional generated artifacts
protected during a subsequent test; they are not interchangeable counts.

| Green build evidence | SHA-256 |
| --- | --- |
| Build 0017 WSL final | `2c766fd23c2522d073e12ae8f98ba600c3f87220f2793e577d520868248396bb` |
| Build 0017 Windows final | `52616fead1d1290c56a8b912c7c7706e0d8d26a41d13ef0e84fe9ac0165c0f37` |
| Build 0017 manifest | `6f048262f3860d2afd57ccae498264f868e522bb7ac1eecff50761ed19640466` |

The [separate green admission](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654607397)
permits exactly the unchanged 21-case adapter action 0018. Its actual result and
independent review remain distinct from source/build admission.

### Green Scenario Result

Windows action 0018 executed the unchanged fixed selection against the exact
green source and build above. All 21 cases passed; the other 13 outcome counters
are zero. The controller recorded normal exit 0 in 1.035 seconds, complete
capture of 639 stdout bytes and empty stderr, two total Job processes and zero
active processes. No termination or safety stop occurred. Windows ended at
2026-09-13T16:55:01.0234879Z; WSL finalized at 16:57:45.973435Z and the outer
session was collected at exit 0. Controller duration excludes the outer
protected-input and installed-tool hashing.

| Green test evidence | SHA-256 |
| --- | --- |
| Test 0018 WSL final | `919c9e080c088138976029b4b426cc7973e8ed94384eac465ff43bc29a50abcd` |
| Test 0018 Windows final | `b2da009da472b0cae433cbcbbf3e6aee106b5872d32b3ec5800637afe36d5ed2` |
| Test 0018 TRX | `62774360efdfab51a7640ce62314adeffc8b29198f20b1e8f0e1db3493d4c476` |

After 0018, Linux consumption remains preparation 8/11 and build/test 29/80;
Windows consumption is preparation 5/5 and build/test 13/40. Combined consumption
is preparation 13/16 and build/test 42/120. Process reservations remain 24/36,
and charged downloads remain 768 MiB. The final unchanged 12-unit CLI batch is
preserved. No additional restore, process batch, filtered retry or replay occurred.

The [independent actual-green acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/130#issuecomment-5654731004)
verified all 21 case definitions/results and their complete counter joins, all
2,520 protected test inputs, 376 installed-tool entries, source/artifact continuity,
controller/restore identities, full retained history and exact-source CI.
A later evidence-only commit does not change the source that produced these results.

These controlled adapter observations do not replace the original CLI/process
result and do not establish real WAM, accounts/cache/consent/reuse, owned UI,
actual WSL behavior, Native AOT, deployment or complete Slice acceptance. Numeric
65004 remains a bounded repository mapping with the accepted diagnostic-stability
limitation. Original failures, receipts, controller backups, synthetic files and
consumed reservations remain intentionally retained.

## Owned Win32 Host Scenario Supplement

This supplement adds a fixed credential-free `owned-host` selection after the
[accepted adapter evidence](#controlled-adapter-redgreen-evidence). It extends the
future suite choices to `cli`, `adapter` and `owned-host`; non-test actions still
forbid a suite. Earlier selections, assertions, observations and consumed
reservations remain unchanged. Exact source and artifact admission is required
before each action.

### Scope and Ordering

Select a new fixed `owned-host` suite in the existing Windows scenario executable,
using the same four projects, locks, SDK 10.0.401/runtime 10.0.12, MSAL/Broker 4.83.1
and NativeInterop 0.20.3. No restore, download, installation or project change is
needed for these added C# files. The production provider factory stays unavailable.
Every provider, account selector, Profile and result in these cases is synthetic;
no public client application, native broker or account/cache API is reached.

After accepted adapter 0018 evidence, independently admit a current-source
no-restore build with a narrow two-controller transition. Preserve exact previous
controller bytes, bootstrap artifact, Job code, stop helper and migration receipt.
The first migration action is no-restore build 0019 after finalized
Windows 0018. Its WSL reservation SHA-256 is
`00c13bdb95279b555ec1f3b11a2092d2ce7db33e38dc1622de613a0ce20dac29`
and final SHA-256 is
`919c9e080c088138976029b4b426cc7973e8ed94384eac465ff43bc29a50abcd`.
Its Windows final is
`b2da009da472b0cae433cbcbbf3e6aee106b5872d32b3ec5800637afe36d5ed2`.
Prior `run_windows.py` SHA-256 is
`1b1c9aa5bd563b8c0c9aba61dc57774cc1f2f30296eb836b8bb4536acd23ecf6`
and `Invoke-WindowsValidation.ps1` is
`a42e9dc7b85972ba980ac3405e6ebd74892c21e1f59be59f0f49143dac17b100`.
No standalone helper replacement is authorized; source/protocol/execution
identities still require independent admission after this supplement is accepted.
Accept complete source/artifact and generated registration review before one
inert-red run. The zero-HWND host starts no thread, window,
provider or child; its five controls and ten business failures must match the fixed
selection. Green host implementation begins only after actual red acceptance.
Preserve every test assertion and dependency from accepted red through green.

### Fixed Commands and Initial Source

Use the accepted `python3 -I tools/validation/run_windows.py` with exact full
`--protocol`, `--source`, `--target` commits and independent `--review` URL.
The first action is `build`; after complete actual artifact review, the inert
test uses `test --suite owned-host --expect red`. A later separately admitted
green build precedes `test --suite owned-host --expect green`. There is no
automatic sequence or permission to bypass the review between actions.

The selected build remains the existing Windows scenario project in Release
with `--no-restore`, `--disable-build-servers`, one node, no node reuse, no
automatic response file and `UseSharedCompilation=false`. The selected test
remains the source-bound scenario DLL through the pinned Windows dotnet host,
with `--report-trx`, the dedicated results directory and the literal filter
below. Retain the existing replacement environment, fixed path preflight,
230-second action-controller wait and bounded cancellation/termination procedure.

The initial red candidate adds only these three files within the existing
projects. Its independent admission must bind their bytes, the complete candidate
commit/tree, all existing source and graph inputs, and the built artifact:

| Initial inert-red source path | SHA-256 |
| --- | --- |
| `src/Authentication.Windows/OwnedRequestHost.cs` | `afcf17e38a130f24665e52aa3dd1d2d7a2a405be26bae330e9627e3dfcfbdfdc` |
| `tests/Authentication.Windows.Scenarios/OwnedHostScenarios.cs` | `c3ff5f81012baa35ca21a0e413cca83d8107faba0cea13be61f130ddcd9c14b9` |
| `tests/Authentication.Windows.Scenarios/OwnedWindowObservation.cs` | `fe8a1f5e8171e780ad4f49c2e22bb161fd5b0dc78d9164d56916ad2ee709010d` |

The accepted helper replacement bytes are independently bound to the protocol
revision; the narrow first-build migration uses these new controller identities:

| Helper | SHA-256 |
| --- | --- |
| `run_windows.py` | `0b3997c5ce411f2da45eb1c4cb20030f543e2c5754e1fc32f111699a64ab330e` |
| `Invoke-WindowsValidation.ps1` | `af0b1c461171179637f12efe02d8a8151d77f258352524a5ffdacd99e30af445` |
| `run_managed.py` | `48ff49d0efa85e78e0e71ba8ef950f857d950ffe982f141a46001caa26b81929` |

The third helper receives the symmetric history interpretation in this amendment;
it is not a third live Windows controller replacement. Bootstrap, Job source and
stop-helper bytes remain unchanged. No helper executes merely because its source
or this supplement has been reviewed.

### Fixed Cases

| OwnedHostScenarios method | Inert red prediction | First failed assertion line |
| --- | --- | --- |
| `SilentSuccessDoesNotCreateOwnedUi` | Passed | None |
| `ForbiddenInteractionDoesNotCreateOwnedUi` | Passed | None |
| `MissingPresentationPreventsInteraction` | Passed | None |
| `ReadyParentCarriesAdmittedBranding` | Failed | 86 |
| `CreationFailurePreventsInteractiveAcquisition` | Failed | 109 |
| `OriginalCancellationBeforeCreationWins` | Passed | None |
| `CancellationDuringCreationRejectsLateParent` | Failed | 298 |
| `CloseDuringCreationCannotReopenHost` | Failed | 298 |
| `ClosedHostCannotReopen` | Passed | None |
| `InternalCloseDoesNotCancelCaller` | Failed | 373 |
| `CompletionWaitsForActualUiThreadExit` | Failed | 373 |
| `CancelButtonStopsPendingAuthentication` | Failed | 263 |
| `CaptionCloseStopsPendingAuthentication` | Failed | 263 |
| `EscapeStopsPendingAuthentication` | Failed | 263 |
| `PostReadinessCallbackFaultIsContained` | Failed | 373 |

The line numbers refer to the exact `OwnedHostScenarios.cs` bytes bound above.
Actual-red review must inspect every failed assertion, its explicit source message
where present, and actual source/PDB correspondence:

- Line 86: `Assert.IsNotNull(result.Success)` fails because success is absent; it
  has no custom message.
- Line 109: `Assert.IsTrue(reached)` with "The actual creation checkpoint was not
  reached." The injected creation exception is unreachable in inert red.
- Line 298: `Assert.IsTrue(gate.Entered.Task.IsCompletedSuccessfully)` with "The
  required owned-thread checkpoint was not reached." The completed operation wins
  the preceding wait; a timeout is not the expected failure.
- Line 373: `Assert.AreNotEqual((nint)0, parent)` with "The owned parent is not
  ready." This precedes any native ownership observation.
- Line 263: `Assert.IsTrue(entered.Task.IsCompletedSuccessfully)` with "A ready
  parent did not reach provider interaction." This precedes any native message.

The shared invocation-commit assertions at lines 405 and 406 and every required
teardown must pass. MSTest's generated wording and Release stack presentation
remain actual artifact evidence; do not invent their complete formatting. Matching
aggregate outcomes alone cannot accept a different failure cause.

These are source predictions conditional on successful build/discovery. Missing
creation/readiness checkpoints must fail promptly at the business assertion.
No timeout, fixture cleanup error, static stop marker, native/loader exception or
missing/discovered-extra case is accepted as intended red. Green requires fifteen
Passed, no other outcomes and normal runner/outer exit 0. Red requires only the
listed ten failures, five Passed and the prospectively reviewed runner exit 2.
Keep all sixteen TRX counters, actual class/name identities and definition/result
joins exact, without DataRow expansion. Both controllers own this literal filter:

```text
FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ForbiddenInteractionDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.MissingPresentationPreventsInteraction|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ReadyParentCarriesAdmittedBranding|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CreationFailurePreventsInteractiveAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.OriginalCancellationBeforeCreationWins|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringCreationRejectsLateParent|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CloseDuringCreationCannotReopenHost|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ClosedHostCannotReopen|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.InternalCloseDoesNotCancelCaller|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CompletionWaitsForActualUiThreadExit|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancelButtonStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CaptionCloseStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.EscapeStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.PostReadinessCallbackFaultIsContained
```

No user-supplied filter/settings, suite wildcard, environment-selected provider,
public product test flag or arbitrary native message selector is admitted. Keep
normal MTP construction and all five extension registrations. Original CLI/Profile
and adapter assertions remain untouched; this result replaces neither batch.

### Native Effects and Attendance

The inert red has zero native/UI effects. The green H suite has at most
ten top-level owned windows, never simultaneously across fixtures: seven may be
shown and three remain hidden. The five controls create none. Ready branding,
internal close, actual-thread completion, three cancellation routes and callback
containment create one visible parent each. Creation-failure injection and the two
creation-race cases allocate one hidden parent each, before injected failure or
terminal invalidation. Count controls and declared native descendants within each
parent separately; the observation helper admits at most sixteen descendants.

Visible green execution requires the designated Windows interactive session.
Actions through 0037 require an attending operator who can identify and close the
fork-branded synthetic prompts, with readiness established only after complete
preparation and exact admission. Later actions follow
[automated synthetic UI coordination](#automated-synthetic-ui-coordination).
No state-unlock, WAM surface, consent, external application control, global input,
focus/activation workaround or desktop/DPI setting change is allowed. The operator
may report an unexpected surface or request cancellation through the existing outer
controller procedure. Do not convert closing an unexpected surface into a retry.

The fixed helper observes only proven nonzero HWNDs belonging to the current
subject and descendants of that parent. It rejects null/broadcast handles, caps
text/class buffers at 2048/256 characters, roots its enumeration callback, contains
callback exceptions, and uses static System32 imports. Scalar messages target only
the known parent or actual Cancel Button; BM_CLICK is not proof of physical focus
or keyboard usability. Synchronous same-process GetWindowText retains its buffer
through actual return and is subject to the external process bound.

### Fixture Lifetime and Fail-Closed Result

Cases run serially with a fresh host/request. The finite checkpoint wait is five
seconds. Teardown releases every gate and independently attempts caller cancellation,
host close, invocation disposal/drain, invocation observation and actual host thread
completion. At most five asynchronous teardown waits are bounded at five seconds
each. Synchronous shutdown/native calls retain the 120-second total subject,
capture and Job-drain bound; the independent controller is the final enforcement.

Any uncertain cleanup, live started thread or checkpoint timeout latches the
fixture's process-wide stop before later host activation. The failed fixture and
all its shared resources remain rooted until process exit. Dispose occurs only
after every required drain succeeds. Write the fixed synthetic marker
`temp/owned-host-safety-stop.json`; a marker-write failure cannot release the latch.
The Windows controller must observe the marker while capturing and again before
normal success; the outer helper independently rejects its presence and retains
its hash among finalized evidence. Every history reader must reject a finalized
ordinary continuation that carries this safety stop. Static fixture stopping
prevents further host activation before the outer observer reacts.

The existing nonbreakaway Job, 32-process ceiling, 120-second subject/capture/drain
limit, 8 MiB combined output ceiling and bounded native stop procedure are retained.
Any safety failure stops both validation loops; preserve failed receipts, all roots,
original times, tool/source hashes, controller backups and consumed reservations.
No automatic rerun or cleanup is allowed. A green failure is an unexpected result
requiring independent classification, not permission for another run.

### Accounting and Evidence Limits

Each H suite run consumes one Windows build/test action and zero child-product
process units. No case starts a child and any process-* evidence is rejected.
Both history readers and the controller must distinguish the exact suite with
zero reservedProcessScenarios without changing old records or refunding any full
CLI batch. Existing protocol allocation remains 36 synthetic process units.
Process fault and permanent-thread-drain cases require a separate accepted process supplement;
this selection allocates no child-product launches. Preserve the final unchanged
twelve-unit CLI batch for separate admission. At finalized Windows 0018, Linux
preparation is 8/11 and build/test 29/80; Windows preparation is 5/5 and build/test
13/40; combined preparation is 13/16 and build/test 42/120. Process reservations
remain 24/36 and charged downloads 768 MiB. Recover current history before every
admission; these checkpoints neither reset capacity nor waive an intervening stop.

The production inert host and complete actual red artifact must be independently
reviewed. Later green source review must prove checkpoint placement on the actual
owned STA/background thread, HWND ownership, callback containment, context/delegate
lifetime, creation/destruction and real-thread completion. For both late-parent
cases, the direct opening task must return zero; hidden-before/destroyed-after
samples cannot exclude transient display. Explicitly review terminal synchronization
at every native show/readiness-publication path to establish that separate property.

Local callback notification does not prove the shared process fault/commit decision.
Permanent owned-thread stall/drain, actual WSL pipe/caller behavior, exact production
Native AOT, attended visual/keyboard/focus/accessibility/DPI observations and real
WAM/accounts/cache/consent/reuse retain their separate evidence obligations. No H
result completes the Slice or supplies a general platform/support claim.

### Owned-Host Inert-Red Evidence

Windows test 0020 executed the fifteen fixed H cases once on September 13, 2026,
under protocol `17dbf912d847b55c4366be7ab851f30079137f73` and accepted target
`480a9b98f9b12c6011fa6c8e2af0e55a70e7d03a`. Actual source was
`75159ace9af9ed3bf6457e35955b73533f003cee`, tree
`2dc5fb9d878bba52f43f3dd9bf2989399f1a79fc`. It retained SDK 10.0.401/runtime
10.0.12, MSTest 4.1.0 and the unchanged MSAL/Broker/NativeInterop graph. This was
credential-free managed execution on the existing Windows 11 x64 host, initiated
through the accepted WSL controller. The inert host created no thread or window;
every provider and Profile was synthetic, with no WAM, account, cache, consent,
authentication, network, or child-product operation.

The [build0019 artifact review and one-red admission](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5655081375)
accepted the actual source-bound assembly, generated entry and all five ordinary
MTP registrations. The [independent actual-red acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5655239789)
joined all fifteen definitions, results and entries, verified all sixteen counters,
and accepted precisely five Passed controls and ten intended business failures.
Every other counter was zero. All ten applicable invocation paths passed the two
shared commit assertions; all fifteen fixtures completed their required teardown.
No timeout, fixture/native/loader failure, safety stop, or incomplete capture was
substituted for an intended assertion.

The actual first failures and complete messages are retained in that review.
ReadyParentCarriesAdmittedBranding failed at the source-line-86
`Assert.IsNotNull(result.Success)` assertion, while its optimized runtime stack
displayed line 85. Actual PDB/IL and the exact caller-expression message identify
the line-86 assertion; the review preserves that distinction without claiming a
captured JIT native-to-IL map. The other nine failures match their fixed assertion
groups. Passing guards establish only the inert branches, not real UI behavior.

The admitted runner exited 2 and the fully collected outer session exited 0.
Windows completed at 18:21:04.7773811 UTC; subject/capture/drain took 1.108 seconds.
Capture contained 15,140 stdout bytes and no stderr. The Job reported two total
and zero active processes; no termination was requested. Finalized WSL and Windows
receipts report quiescence and permitted continuation. No source, dependency,
controller, or existing artifact changed during the test, and no restore occurred.

| Evidence | SHA-256 |
| --- | --- |
| WSL final result | `0d44b18848e10497b2d3c877c98b1854356491ec124c61817bc391928f3b2762` |
| Windows final result | `85fd8635b2cfb02313168251ed705d38bc5bcdff94fb1f2a1d30dedfb0df5a25` |
| Sole TRX, 37,453 bytes | `bd674d5227edcb0fef1af80129e89dd8d3838985aa0630fdab5960ccca156660` |
| Scenario assembly | `5659d722e82036b6bfc7bc7c913ce037d8dedc295a3e6ee76b1030ff145a4c94` |

After 0020, preparation remains Linux 8/11 and Windows 5/5, combined 13/16.
Build/test consumption is Linux 29/80 and Windows 15/40, combined 44/120.
Synthetic process reservations remain 24/36 and charged downloads 768 MiB.
Both 0019 and 0020 consume build/test actions; H execution consumes zero
child-product units. Earlier failed attempts, original receipts, retained roots,
controller backups and the final twelve-unit CLI allocation remain intact.
No repeated red, retry, cleanup, or machine/account-state transition occurred.

Actual-red acceptance satisfies the prerequisite for green source implementation
with the frozen assertions and dependencies. It supplies no green execution,
physical UI, shared process composition, Native AOT, real authentication, or Slice
completion evidence. Future source/artifact admission and attended readiness remain
required by the supplement above. Raw TRX filenames and machine metadata stay local.

## Wave Ceiling Binding Refresh

[PR #131](https://github.com/hcoona/microsoft-authentication-cli/pull/131) accepts the
owner-selected outer ceiling of 60 synthetic process scenarios at target
`666ed8b72c3458061d32056dfb2869cccd5779d5`, Wave blob
`956aebe0e19cce7dbd08dcaa7fe83a9ef9e01f7c`. Both managed helpers now bind that exact
Wave. This supplement preserves the existing 36-unit protocol allocation, all other
allocations, charged history and the final unchanged twelve-unit CLI batch. The
remaining outer capacity does not allocate another scenario, retry or effect.

The first Windows action under this refresh is the single H-green test 0022 on
unchanged source `ecc4c23bfc58b739b01a2b2879438cbd58fec965`, tree
`45ff7f2d40e5672257ab237afb67dc897da5199c`, using completed no-restore build 0021.
The [prior actual-build review](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5655566484)
is reusable evidence, not current execution admission after the authority change.
Before reservation, the Windows helper requires at least 21 finalized Windows
actions and these exact WSL-side build receipts:

| Build 0021 receipt | SHA-256 |
| --- | --- |
| `started.json` | `7ae88b209f6a36ba4851508376d7d92811fe6262218f12e5a95fb055cc5de857` |
| `result.json` | `58ce379fe433a11573b31163b27bfe98321d9544768cf8109d9f6d819b3a427b` |

At exactly 21 previous Windows actions, only `test --suite owned-host --expect green`
on that unchanged source is permitted. The existing history readers still reject
an incomplete, changed or stopped action. During that admitted action's existing
reservation, replace exactly the following two retained controllers through the
existing exclusive backup and migration procedure:

| Controller | Required old SHA-256 | Replacement SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `0b3997c5ce411f2da45eb1c4cb20030f543e2c5754e1fc32f111699a64ab330e` | `0e5a2a3360e19200a0e81b84f87b42d94a96e12ca56524c85800c55378574b30` |
| `Invoke-WindowsValidation.ps1` | `af0b1c461171179637f12efe02d8a8151d77f258352524a5ffdacd99e30af445` | `a63d1715179171227c9df3875bd538ba744568954809d40202cf0a4d420f0635` |

The old wrapper is 71,741 bytes and the old PowerShell controller is 21,016 bytes,
matching accepted protocol `17dbf912d847b55c4366be7ab851f30079137f73`.
Retain them as `actions/0022/retained-run_windows.py` and
`actions/0022/retained-Invoke-WindowsValidation.ps1`; `controller-migration.json`
binds both old/new hashes and protocol revisions. Both history readers and final
evidence retain these files' hash bindings. Missing or unexpected old bytes,
partial migration, or failed finalization stops both loops without refund or
an automatic retry. Acceptance of the amendment precedes either replacement;
there is no standalone migration or individually admitted partial upgrade.

The matching `run_managed.py` SHA-256 is
`108f8ae72052b7ec85b961d77e951e4a1616b35e0b249781b26f4a02c12c3cdf`. Its only additional change
validates the retained attendance bindings when the Linux loop recovers Windows
history; it is not a retained Windows controller replacement. Keep the stop helper,
Job source/bootstrap, source checkout, dependency graph and build 0021 artifacts
unchanged. No bootstrap, restore, rebuild or historical red replay is allocated.

Before H execution, independently refresh the accepted target/protocol ancestry,
the prior red and actual-build evidence reuse, exact source/artifact admission,
current history and capacity, and the protected input map with both replacement
controller hashes. Bind the complete public admission and its URL to the prospective
command. The accepted local provider-admission design from
[PR #134](https://github.com/hcoona/microsoft-authentication-cli/pull/134) does not
require this synthetic H provider to inspect real logon metadata. Its real-provider
implementation and evidence remain separate prerequisites.

Only after preparation and refreshed admission may actual attending-operator
readiness be established. Preserve the fixed fifteen H cases, seven potentially
visible and three hidden serial parents, one build/test action and zero process
units, 120-second subject/capture/Job-drain limit, 8 MiB output limit and all original
fixture stop/termination rules. At build 0021, consumption is Linux preparation
8/11 and build/test 29/80, Windows preparation 5/5 and build/test 16/40, combined
preparation 13/16 and build/test 45/120, with 24/36 process units and 768 MiB charged
downloads. Recover current history before admission; this checkpoint grants no
reset. No H execution, result or attendance follows from accepting this refresh.


### Preparation and Attending-Operator Handoff

[H-PREP-01](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5657522469)
and its [independent true-positive triage](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5657522570)
require the handoff inside the actual prepared invocation. The earlier helper start
was interrupted before reservation and migration: its outer session was collected
with exit 143, its PID was absent, both Windows 0022 directories and Linux 0038
were absent, and the retained wrapper was unchanged. The sanitized stop receipt is
444 bytes, SHA-256 `00a84e7354c36f2e01d5cadcc832d483451b36635939c2a48b4af6bec29ba30f`.
This is neither an H test result nor evidence of a completed preparation sweep;
it does not identify the exact verification substage or prove lock acquisition.
No prior charge is refunded. The withdrawn attendance response cannot be reused.

The helper requires the following handoff for every `test --suite owned-host
--expect green` invocation. The [automated-selection amendment](#automated-synthetic-ui-coordination)
below determines whether a later action requires an owner response. The handoff
is not an optional switch or a generic resume API.
Other selections retain their existing execution bounds and require no attendance
receipt. These files are sanitized operational evidence under the existing action
record, with the typed contracts below; they are not a new governed record family.

1. Finish exact admission before invoking the helper. While the operator is absent,
   perform the invocation's full WSL tool/history/archive/source/cache/build checks
   and Windows input/environment/invocation checks. Keep the shared action lock
   from tool verification through preparation, waiting, execution and finalization.
   Do not run the other loop or mutate prepared inputs, controllers, artifacts,
   installed tools or authority during that interval. Cancel if a relied-on input
   or authority materially changes; do not refresh a pending action in place.
2. Bound WSL preparation, including its work before reservation, to one 1,800-second
   elapsed-time timer. SIGINT/SIGTERM interrupts that preparation. Disarm the timer
   only when handing off to the Windows action controller or finalizing failure;
   no automatic retry follows. Existing subprocess limits remain (Git 30 seconds,
   Windows preflight 20 seconds, local proxy collection 5 seconds). Before
   reservation, interruption leaves no charged action or subject and the outer
   exit must be collected and inspected. After reservation, preserve that charge
   and stopped/incomplete receipts; both loops remain stopped. An interrupted
   preflight is not subject or Job execution. Existing finalization rules apply.
3. In Windows, load the bound Job helper and construct the empty Job after all
   input checks. Immediately before the original subject stopwatch and `Start`,
   require the single attendance gate. Publish `attendance-ready.json` by writing
   and flushing its exclusive `.pending` file, closing it, and moving it to the
   previously absent final name in the same action directory. Consumers never
   accept `.pending`. Preexisting attendance files fail the action.
4. The complete ready object has exactly `action` (four-digit action name),
   `reservationSha256`, `invocationSha256`, `controllerSha256` (lowercase SHA-256
   strings), `waitSeconds` (integer 14400 from action 0035 onward), and
   `preparedUtc` (UTC ISO timestamp). Historical actions through 0034 retain
   integer 1800 and their original release bounds; do not reinterpret them.
   The hashes bind this action's full Windows reservation, exact invocation and
   controller PID/start incarnation. The reservation binds the accepted source,
   protocol, target, admission URL and complete input/tool maps. The WSL helper
   validates the receipt before emitting one `awaiting-operator` event. Only then
   may the coordinator request a fresh explicit attending-operator response when
   the action requires one, or follow the automated-selection amendment.
5. Release only after that fresh actual response, or the independently verified
   automatic-release condition in that amendment, while the same controller is
   waiting and neither cancellation nor finalization exists. The coordinator
   exclusively creates one empty regular file named `attendance-release-<hash>`,
   where `<hash>` is the complete ready receipt's SHA-256. The exact filename binds
   the entire ready object, including reservation/action/incarnation; the empty
   body is its strict zero-byte schema. Never pre-create, overwrite, replay or
   derive release from an earlier response, silence or elapsed time. There is no
   bulk input recheck after asking for attendance. The existing cooperating-process
   trust model and unchanged-input boundary apply; no installed-tool file leases
   or protection against arbitrary same-user mutation are claimed.
6. From action 0035 onward, wait once for at most 14,400 seconds (four hours)
   using the Windows monotonic stopwatch. The empty Job and exclusive action lock
   remain held; preparation and subject work retain their separate original limits.
   Cancellation or expiry wins over a simultaneously observed release. Reject
   multiple, differently named, linked, nonregular or nonempty release markers.
   Before launch, publish completed `attendance-released.json` by the same
   exclusive close/flush/move procedure. Its exact fields are `readySha256`,
   `releaseName`, and integer `waitMilliseconds` in `[0, 14400000)`. Historical
   actions through 0034 retain `[0, 1800000)`. The controller
   checks cancellation and expiry again immediately before the original subject
   stopwatch and `Start`. Receipt acceptance does not override that last check.
7. Preserve the existing 230-second total Windows controller work allowance outside
   this one wait. The WSL wrapper actively enforces that budget before readiness
   and after release with a monotonic clock. Its exclusion starts only after it
   validates the complete ready receipt; on release acknowledgement it freezes
   the exclusion to the lesser of its observed wait and the controller's recorded
   wait. Thus it can under-credit a polling/publication interval, but cannot give
   unused wait time to work or reset the work budget. Windows also checks its own
   work elapsed before publishing ready and before launch. The absolute controller
   wall bound is 14,630 seconds from action 0035 onward; historical actions through
   0034 retain 2,030 seconds, plus existing bounded stop/collection procedures.
   Checks poll at 50 milliseconds. The original 120-second subject/start/capture/
   normal-Job-drain timer begins after release and remains unchanged. Cancellation
   has at most 15 seconds to finalize within the remaining controller bound;
   retain the 10-second emergency stop and 5-second local proxy collection limits.
8. Timeout, withdrawal, invalid release, missing controller or uncertain finalization
   never authorizes launch or another attempt. A normal pre-subject stop records
   attendance stage, safety stop, capture not started and actual empty-Job cleanup;
   it is not a failing scenario assertion. Retain any reservation and all receipts.
   Incomplete finalization invokes the existing identity-bound emergency stop;
   neither proxy nor controller disappearance proves Job quiescence. Both loops
   stop, without refund, retry or extension of the one attendance wait.
9. Before accepting green, the wrapper validates the ready/released objects and
   unique empty marker, their hashes in the Windows final result, and absence of
   cancellation. Both history readers validate the same retained bindings for
   H-green actions starting at 0022. Existing evidence hashing includes the ready,
   release, acknowledgement, controller, invocation and migration files. Preserve
   all existing source/tool postchecks and actual H15/TRX/Job evidence checks.

Preparation, attendance and execution all belong to the same reserved H action;
waiting adds no process-scenario unit and does not create a new preparation action.
A protocol merge supplies no actual attendance or test observation. Refreshed exact
independent execution admission is required before running these changed helpers.

## Windows Action 0022 Attendance-Expiry Disposition

The single H-green reservation 0022 used accepted target/protocol
`c35f833792cba5fe9d65edab3eb800e1a3a2acb2`, unchanged source
`ecc4c23bfc58b739b01a2b2879438cbd58fec965`, tree
`45ff7f2d40e5672257ab237afb67dc897da5199c`, and completed build 0021 under the
[independent admission](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5657758723).
The [independent actual-stop review](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5658156282) classifies its result
as a normal expired attendance wait before subject launch, with no material
implementation finding. This is neither H-green nor failed business-assertion evidence.

Preparation completed and the wrapper emitted validated `awaiting-operator` after
Windows published ready at 2026-09-14 01:42:53.299848 UTC. The ready reservation
matched the admitted 2,524-entry input map, unchanged 376-entry tool map and exact
inner invocation. Both controller replacements and retained backups completed
within 0022. These are actual prepared-gate and migration observations. The full
successful-action source/tool postchecks did not run after the safety stop; no
complete post-stop input-integrity claim follows from those earlier checks.

The Windows controller finalized at 02:12:53.356048 UTC in `attendance`, with
failure line 35 identifying the monotonic 1,800-second expiry check, exit -1,
`safetyStop=true`, `captureCompleted=false`, and `captureDisposition=not-started`.
Actual empty-Job accounting records zero active and total processes before and
after Stop, with no termination required. This establishes the bounded empty-Job
cleanup; process disappearance is not its basis. The 1,800.0562-second UTC interval
corroborates the accepted monotonic check without supplying a separate monotonic
trace. WSL finalized at 02:12:53.442815 UTC with `continuation_allowed=false`,
`quiescent=true` and `error_type=ValueError`. The outer session was fully collected
with exit 1 and no test counts. No release, acknowledgement, subject, capture,
cancel or fixture-stop record exists; the result directory is empty. No test
window, H assertion, real account or authentication operation ran.

Preserve every original receipt and the completed two-controller migration.
Both history readers recognize only these exact WSL receipts and their eight
hash-bound Windows evidence files:

| WSL 0022 receipt | SHA-256 |
| --- | --- |
| `started.json` | `f4d69974990731e5a32f35df7c71935982c7fc8f480ef58d90395567cfc75e29` |
| `windows-input.json` | `5b47542488f8d4ec2db81cecb3b0d8fa39e349d0c9e4cb9c71a69795b61547d1` |
| `result.json` | `c15dd433a4d9a104d27e529909f7a8ec28e5b38d2bfa2dcad450e469a6b94338` |

The Windows evidence set is exactly `started.json`, `controller.json`,
`invocation.json`, `attendance-ready.json`, `controller-migration.json`,
`retained-run_windows.py`, `retained-Invoke-WindowsValidation.ps1`, and
`windows-result.json`. The only directories are `home`, `home/local`,
`home/roaming`, `temp`, `results`, and `empty-program-files`; their leaf directories
remain empty. Reject any missing, additional, changed, linked or wrong-type
receipt, evidence file or directory. The exact failed receipt remains false and
counted. This exception does not accept a different attendance stop or relax the
ready/released/unique-marker checks for normally completed H-green actions.

After this disposition is accepted, the first continuation is one newly admitted
H-green test 0023 on unchanged source ecc4 and build 0021. Linux execution remains
stopped until that Windows continuation completes normally. Refresh exact
independent admission, accepted target/protocol/Wave, retained source/build and
current input/history/capacity bindings before its reservation. Earlier integrity
observations remain historical. The actual helper must complete all preparation
checks before requesting a fresh response for the new live ready receipt. The
expired 0022 gate cannot be released, resumed, overwritten or extended; a late
response to it cannot release 0023. No automatic retry or previous charge refund
is permitted. Keep the 1,800-second preparation and attendance bounds, 230-second
controller work allowance, 120-second subject/capture/Job-drain limit, H15 selection,
native effects, cleanup and stop rules unchanged.

During 0023's existing reservation only, retain the current 80,345-byte wrapper,
SHA-256 `0e5a2a3360e19200a0e81b84f87b42d94a96e12ca56524c85800c55378574b30`,
as `retained-run_windows.py` before replacing it with this accepted revision's
wrapper. Bind old/new hashes and protocol revisions in `controller-migration.json`
and final evidence. No standalone replacement is admitted. The PowerShell
controller, stop helper, Job source/bootstrap and completed 0022 migration stay
unchanged. The symmetric managed-reader change is not a Windows controller
replacement. Current replacement and executor hashes are bound by the new exact
independent admission, rather than duplicating future commit identities here.

Consumption after 0022 is Linux preparation 8/11 and build/test 29/80, Windows
preparation 5/5 and build/test 17/40, combined preparation 13/16 and build/test
46/120. A reserved 0023 consumes Windows 18/40 and combined 47/120 even if it stops.
Process reservations stay 24/36, charged downloads stay 768 MiB, and the final
unchanged twelve-unit CLI batch remains reserved for separate admission. No
bootstrap, restore, rebuild, red replay, process allocation, account-state effect,
support claim or whole-Slice acceptance is added.

## Owned Win32 Host Green Evidence

Windows test 0023 executed the unchanged fifteen H scenarios on September 14,
2026, under accepted protocol/target
`4e2f090196e752e453f0636d442690a5555a6083` and the
[single-action admission](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5658315847).
Actual source was `ecc4c23bfc58b739b01a2b2879438cbd58fec965`, tree
`45ff7f2d40e5672257ab237afb67dc897da5199c`. The existing Windows 11 x64 host,
SDK 10.0.401/runtime 10.0.12, MSTest 4.1.0 and public dependency graph were
unchanged. The production provider factory remained unavailable; every provider,
Profile, account and result was synthetic. No real WAM, account/cache/consent,
authentication, network or child-product operation was performed.

The [green source and one-build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5655402627)
retained every accepted inert-red assertion. The
[actual build 0021 review](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5655566484)
accepted the source-bound assembly, generated entry/registrations, native ABI,
PDB/IL and lifetime correspondence. That build completed with zero warnings/errors,
normal subject and fully collected outer exit 0, and 12.754 seconds of
subject/capture/drain. Its 547-artifact manifest is SHA-256
`941589af07f9f718b2842bd03a1872724926d2c8b8e7512bc6d3fdde5b3ba7d2`;
the reused scenario assembly is
`64c2241ef6f329262f5c2a2b895477b4dc0c1a38679beda311a3b404d20ed0a2`.
No rebuild or restore occurred for 0023.

The accepted action-0022 disposition preserved that expired reservation, its
false result, completed migration and consumed action. The separately admitted
0023 retained the old wrapper and completed only its declared wrapper replacement.
Actual preparation checked the 2,524-entry protected input map and 376-entry tool
map before publishing ready at 03:06:20.742272 UTC. The outer helper validated
that ready receipt before a fresh attendance request. After a timely explicit
operator response and a small live-gate recheck, the coordinator exclusively
created the single empty release marker bound to the complete ready SHA-256.
The acknowledgement records 1,145,071 milliseconds of waiting; no expired
response or 0022 gate was reused.

The [independent actual-green review](https://github.com/hcoona/microsoft-authentication-cli/pull/133#issuecomment-5658640064) accepted all
fifteen definition/entry/execution/result joins and all sixteen TRX counters:
total, executed and passed were 15; every other counter was zero. All frozen
business and commit assertions passed. The Windows subject started at
03:25:25.846996 UTC and finalized at 03:25:27.621700 UTC; the recorded
subject/capture/drain interval was 1.738 seconds. The runner and fully collected
outer session both exited 0. Complete capture contained 642 stdout bytes and no
stderr. The Job recorded two total and zero active processes, with no termination
requested and no safety stop. Both final receipts establish quiescence and
permitted continuation. Successful-path source, protected-input and installed-tool
postchecks completed; all thirteen final evidence-file hashes, including the
ready/release/acknowledgement and migration records, were retained.

| Evidence | SHA-256 |
| --- | --- |
| WSL final result | `2043defeed2bd068a5e9cba888c3b08b85aad4b6e40dc868216900d4e94dac41` |
| Windows final result | `3445d6dc8267c4bad1696cfb3c71d614a52a2989662deb8a5864d2cdf517bc10` |
| Sole TRX, 21,329 bytes | `3b02e52bd8923d03dd43ac57f2802743ab1fe081e0412af4d816686dab5ebc37` |
| Ready receipt | `bca8f66c6efae38f45b0c5c5dc0341a64da76c06ac0f5642098eb8c39b9b4805` |
| Release acknowledgement | `4d2fe9c5a1e23cd725e91c3249ca911a4e86805e76a492950c55a8358107be14` |
| Wrapper migration | `112a1468dc7dca712948dc6e39c6bd4ad1ff3ed47330dc76bdcb3dbf56a18fc4` |

The attending operator observed brief window flashes and could not read their
content. That observation corroborates visible activity but does not establish
readability, physical keyboard/focus behavior, accessibility or DPI presentation.
The automated Win32 assertions retain their declared content, ownership, message
routing and lifetime scope; they do not supply those separate visual claims.

After 0023, preparation remains Linux 8/11 and Windows 5/5, combined 13/16.
Build/test consumption is Linux 29/80 and Windows 18/40, combined 47/120.
Process reservations remain 24/36 and charged downloads 768 MiB. Preserve every
original charge and receipt, the retained roots and controller backups, and the
final unchanged twelve-unit CLI process batch. This result supplies H-green
evidence only. Shared process fault/commit and permanent-stall composition,
actual WSL caller/pipe lifetime, final production Native AOT, remaining UI
presentation evidence and real-provider/account acceptance remain open. No later
execution, production-provider activation, release or whole-Slice acceptance is
admitted by this observation. Raw TRX basenames and machine metadata stay local.

## Local Provider Admission Scenario Supplement

This supplement selects the fifteen controlled local-provider admission cases in
[PR #136](https://github.com/hcoona/microsoft-authentication-cli/pull/136), after
the accepted [owned-host green result](#owned-win32-host-green-evidence). The
[local Windows host design](../../designs/windows-ado-authentication.md#local-windows-host-admission)
and [scenario basis](../../validation/strategy.md#windows-slice-design-acceptance)
remain the behavior authorities. This is an execution selection within the existing
credential-free Wave, not admission of native host observations or real provider
initialization. Each actual source/build/test still requires its independent exact
admission in the coordinating PR before execution.

### Subject and Source Boundaries

Use the existing Windows 11 x64 host through the accepted WSL2 controller, pinned
SDK 10.0.401/runtime 10.0.12, MSTest 4.1.0, and unchanged public package graph.
The root remains `Windows.slnx`; use the existing cache-only no-restore Release
build and managed scenario assembly. No bootstrap, restore, dependency addition,
toolchain installation, Native AOT publish or production installation is selected.

The inert baseline adds only `LocalWindowsProvider.cs` and
`LocalProviderAdmissionScenarios.cs`. The integrated candidate retains the accepted
owned-host code and reuses its existing assembly-wide friend declaration. Baseline
provider SHA-256 is
`11d2a42d9b95dd9e16df827f858f3a83ab40d79b4275a83a831c85caddbaa6d2`;
the unchanged scenario source SHA-256 is
`d45a04fcbd6410f0c1e6d73c138095371d294672e0e0e1160d4df9372707aa5a`.
Exact commit/tree and complete current project/source bindings belong to the
independent source admission. Keep the production CLI provider unavailable.

The fixtures exercise the real request coordinator and result projection with
synthetic host-admission, initializer and provider outcomes. They cover the order
of local admission, one request-local initialization, account discovery and
acquisition; original cancellation around those effects; eligibility loss before
later acquisition; and closure after controlled readiness. The initializer remains
behind local admission. Construction itself must remain inert. Tests deliberately
allow a substitute to return after cancellation so the production boundary must
prevent the next effect rather than rely on cooperative substitutes.

Both red and green selections have zero native queries, windows, account/store
operations, WAM/MSAL initialization, network requests and child-product launches.
The parent value `1` is only an in-memory sentinel, never a native handle. Every
account, token and error marker is synthetic. Normal MTP entry and all five extension
registrations remain unchanged. Existing CLI/Profile, adapter and H assertions are
not replaced or selected by this batch. No public test flag, environment-selected
provider, wildcard filter or arbitrary suite is added.

### Fixed Cases and Red Evidence

All methods belong to `Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios`.
The line numbers below identify the exact scenario-source assertions, not a promised
Release stack presentation. Actual red review must join each reported failure to
its source, message and actual PDB/IL as needed. A different first assertion,
compilation/analyzer/loader/native error, timeout or fixture failure is not intended
red evidence.

| Method | Inert red prediction | First failed assertion |
| --- | --- | --- |
| `ConstructionDoesNotObserveHostOrInitializeProvider` | Passed | None |
| `PrecancelledRequestStopsBeforeHostAdmission` | Passed | None |
| `RejectedHostPreventsInitializationAndOwnedUi` | Failed | Line 44: admission reached once |
| `AdmittedHostAllowsOneSelectedAccountSilentResult` | Failed | Line 54: successful selected-account result |
| `CancellationDuringAdmissionPreventsInitialization` | Failed | Line 216 via line 71: cancelled outcome |
| `OriginalCancellationWinsOverAdmissionRejection` | Failed | Line 216 via line 85: cancelled outcome |
| `CancellationDuringInitializationPreventsDiscovery` | Failed | Line 216 via line 95: cancelled outcome |
| `UnavailableInitializationPreventsDiscoveryAndOwnedUi` | Failed | Line 107: initializer reached once |
| `UnexpectedInitializationFaultStaysInternalFailure` | Failed | Line 216 via line 121: internal-failure outcome |
| `UnexpectedHostObservationFaultStaysInternalFailure` | Failed | Line 216 via line 134: internal-failure outcome |
| `LostEligibilityBeforeSilentPreventsAcquisition` | Failed | Line 148: discovery reached once |
| `LostEligibilityAfterReadinessPreventsInteractionAndClosesHost` | Failed | Line 163: controlled readiness reached once |
| `CancellationDuringVolatileRecheckPreventsNextEffect` | Failed | Line 216 via line 178: cancelled outcome |
| `EligibleInteractiveContinuationUsesOriginalRequestAndOneParent` | Failed | Line 189: successful interactive continuation |
| `NoninteractivePermissionDoesNotOpenHostAfterSilentChallenge` | Failed | Line 216 via line 205: interaction-required outcome |

These predictions require successful build and exact discovery. Red requires
precisely two Passed and thirteen Failed results, runner exit 2 and collected outer
exit 0. Green requires fifteen Passed, no other outcomes, and normal runner/outer
exit 0. Preserve all sixteen TRX counters and exact class/method identities with
complete definition/entry/execution/result joins, without DataRow expansion or
missing/extra cases. Teardown disposes each fixture's synthetic cancellation source;
it starts no asynchronous/native work that requires a separate UI drain. All later
business, continuity, prevented-effect and result-projection assertions must pass
in green. Independent actual red acceptance precedes green implementation.

Both controllers contain the same fixed `local-provider` filter:

```text
FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.ConstructionDoesNotObserveHostOrInitializeProvider|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.PrecancelledRequestStopsBeforeHostAdmission|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.RejectedHostPreventsInitializationAndOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.AdmittedHostAllowsOneSelectedAccountSilentResult|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringAdmissionPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.OriginalCancellationWinsOverAdmissionRejection|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringInitializationPreventsDiscovery|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnavailableInitializationPreventsDiscoveryAndOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedInitializationFaultStaysInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedHostObservationFaultStaysInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityBeforeSilentPreventsAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityAfterReadinessPreventsInteractionAndClosesHost|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringVolatileRecheckPreventsNextEffect|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.EligibleInteractiveContinuationUsesOriginalRequestAndOneParent|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.NoninteractivePermissionDoesNotOpenHostAfterSilentChallenge
```

The normal command selection is `test --suite local-provider --expect red` or
`test --suite local-provider --expect green`, retaining the existing required full
protocol/source/target revisions and independent review URL. These are protocol
forms, not a runnable admission or automatic red/green sequence.

### Retained History and Controller Transition

The first action under this supplement is a separately admitted no-restore build
0024. Before reservation, require at least 23 finalized Windows actions and the
unchanged accepted H-green 0023 WSL receipts:

| Receipt | SHA-256 |
| --- | --- |
| `started.json` | `10fc85a750e5494f7844332154b859ef97181ce6139fadae37fa2c06c90ee9e2` |
| `result.json` | `2043defeed2bd068a5e9cba888c3b08b85aad4b6e40dc868216900d4e94dac41` |

At exactly 23 prior Windows actions, only a build may begin the transition. During
that action's existing exclusive reservation, replace only these two retained
controllers through the existing backup/migration procedure:

| Controller | Required old SHA-256 | Replacement SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `ec31b39b0cec4865cd7c0b4c8012b989ae6b0615b79938b9640a78c6cccde162` | `0e01a22ee8e63720f54ad6525976d1b282656f33a8682919fd316b7ff4633d39` |
| `Invoke-WindowsValidation.ps1` | `a63d1715179171227c9df3875bd538ba744568954809d40202cf0a4d420f0635` | `dc4019e3ba3f62cafda1222f4468f270cf1b935c7ec7ca761f0b36c2a290a3ce` |

The old bytes are the controllers used by 0023 under protocol
`4e2f090196e752e453f0636d442690a5555a6083`, retained unchanged by accepted
target `2f9dc5d734560df3ea3bb4a254faf1517be2739f`. Preserve them as
`actions/0024/retained-run_windows.py` and
`actions/0024/retained-Invoke-WindowsValidation.ps1`; the normal migration receipt
binds both revisions and old/new hashes. Partial migration or unexpected bytes stop
both loops without refund, automatic retry or standalone repair. The stop helper,
Job source/bootstrap, package caches, toolchain, original receipts and prior
controller backups remain unchanged. In particular, stopped 0022 remains false and
charged, and successful 0023 is not replayed.

The symmetric `run_managed.py` history-reader change is SHA-256
`757b038505bafb09994c93e6b1b0b92dd01baca3a6696077d210346b836fa125`.
It is not a third retained Windows controller migration. Both readers and the
Windows controller admit this new test selection only after action 0024 and require
zero reserved process scenarios; all older full CLI charges remain exact. The
Windows reader retains the common full-counter/result validation and rejects any
child-product process evidence for this suite.

### Limits, Review and Remaining Obligations

The planned initial progression is one red build/test pair followed, only after
independent actual-red acceptance and refreshed green-source admission, by one green
build/test pair. Every build and test consumes one Windows build/test action. Keep
the original 120-second subject/capture/Job-drain limit, 230-second outer controller
wait, 8 MiB combined output ceiling, 32-process nonbreakaway Job ceiling, shared
action lock and existing bounded cancellation/stop procedure. This selection has no
visible interaction and needs no desktop attendance or release marker; the existing
H-green attendance requirement is unchanged.

Recover current history before each admission. At completed 0023, preparation is
Linux 8/11 and Windows 5/5, combined 13/16; build/test is Linux 29/80 and Windows
18/40, combined 47/120. Four successfully admitted actions would bring Windows
build/test to 22/40 and combined build/test to 51/120. No preparation, download or
child-product process units are added by this selection. Keep charged downloads at
768 MiB, reservations at 24/36, the outer ceiling 60 and the final unchanged twelve
CLI process units. Earlier failures and any new failed start remain charged.

Before the first test, independently inspect the actual build, source-bound
assembly, generated entry/extension registrations, dependency/runtime mapping and
the fixed case discovery. Accept intended business failures individually; aggregate
counts alone cannot accept red. After every test, inspect actual source/artifact
continuity, complete capture, all result joins/counters, normal owned Job drain and
fully collected outer result. Preserve dedicated roots and sanitized evidence.
Unexpected results, changed inputs, incomplete capture or uncertain quiescence stop
both loops and require independent classification. No automatic rerun is admitted.

Passing this batch proves controlled admission/initialization/acquisition ordering
and cancellation behavior only. Actual local OS/product/architecture, thread-token,
own-logon, SID/station, WTS and input-desktop predicates; real provider initialization
and broker availability; owned-thread pre-create/show checks; native stalls under
the original deadline; process fault/commit composition; WSL caller/pipe lifetime;
final production wiring and Native AOT; UI presentation and real-account/reuse
acceptance retain their separate evidence obligations. No whole-Slice, release,
Profile activation or general platform-support acceptance follows from this batch.

### Local Provider Admission Red Evidence

The accepted supplement at target/protocol
`4edee1a99c2a898a481931c394a39646045fda36` governed Windows build 0024 and
test 0025 for source `691c0c9675ec7c5c547b36410f628808d60b9a80`, tree
`5dcd40936ffcefeae6458fc3f24700eccf47a524`. The no-restore Release build
completed with zero warnings and errors. Its manifest SHA-256 is
`d4ee42929f9823a0e076e95efb439e21bfbbe8587c1dbc44404da610e4a51ee6`.
The [actual-build review and single-test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/136#issuecomment-5659208285)
accepted source, assembly/PDB, generated runner, dependency and artifact bindings
before the test ran.

Test 0025 executed all fifteen selected cases once: two Passed and thirteen Failed,
matching the predicted first business assertions above. All sixteen TRX counters
were inspected: total/executed fifteen, passed two, failed thirteen, and every other
counter zero. The runner exited 2 after 1.053 seconds; the fully collected outer
process exited 0 with continuation allowed and confirmed quiescence. Capture was
complete, with no safety stop, termination request or remaining owned process. The
TRX SHA-256 is
`59ecc7eee252fb0b416bb86c09e17a45cea66b42e510352e4b1a716c6ac95d16`;
the WSL final receipt SHA-256 is
`4132b71c7d9191ccf4386916b521adb1e9887e9f18e9fe64c920a36eec829c80`.

The [independent actual-red acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/136#issuecomment-5659369358)
joins each definition, entry, execution and result to the admitted source and
artifact. For the interactive-success case, the retained stack frame is 188 and
the first assertion is at source line 189. Its unique assertion message and actual
PDB/IL identify the same first assertion; the runtime reason for that frame
presentation remains unknown. [Independent triage](https://github.com/hcoona/microsoft-authentication-cli/pull/136#issuecomment-5659351796)
accepted that attribution without changing the source, expected assertion, actual
result or protocol, and without a rerun.

At completed 0025, Windows build/test consumption is 20/40 and combined consumption
is 49/120. Preparation, downloads and synthetic child-product charges are unchanged.
Stopped 0022 remains false and charged. Source and artifacts were retained unchanged
in the dedicated roots. These synthetic observations establish the missing local
boundary behavior and permit its green implementation; they do not establish later
assertions after the first failure, native observations, real initialization, UI or
account behavior. Green source and each build/test retain separate exact admission.

### Local Provider Admission Green Evidence

Windows build 0026 and test 0027 used accepted target/protocol
`4edee1a99c2a898a481931c394a39646045fda36` and implemented source
`61685d4b51ce4c4fd959503e0be5c47af99bf987`, tree
`a78e1d74553c4d39a87bb012ab419e260abf2dbe`. The fifteen scenario cases
remained byte-identical to the accepted red source, SHA-256
`d45a04fcbd6410f0c1e6d73c138095371d294672e0e0e1160d4df9372707aa5a`.
The [green-source review](https://github.com/hcoona/microsoft-authentication-cli/pull/136#issuecomment-5659487932)
accepted the request-local implementation after actual-red acceptance. The no-restore
Release build completed in 6.485 seconds with zero warnings and errors, fully
collected outer exit 0 and confirmed quiescence. Its manifest SHA-256 is
`f100410237e0e8aa5e7c870d76ccfcae978363ef28b278707397e706245c30a7`.

The [actual-build review and single-green-test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/136#issuecomment-5659653172)
accepted the source, assembly/PDB, generated runner, dependency and artifact bindings.
Test 0027 executed all fifteen selected cases once, all Passed. All sixteen TRX
counters were inspected: total/executed/passed fifteen, failed zero, and every other
counter zero. The runner exited 0 after 0.985 seconds; the fully collected outer
process exited 0 with continuation allowed and confirmed quiescence. Capture was
complete, with no safety stop, termination request or remaining owned process.
The TRX SHA-256 is
`63409024437da757b13cb28e5c3ed0873352f45442b82aaf4dd09c7bf8a6d1eb`;
the WSL final receipt SHA-256 is
`ac1b287b7dafbb2082e173efad20585f062731b922ff593c33410184740c1456`.

The [independent actual-green acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/136#issuecomment-5659851781)
confirmed all fifteen source-bound definition, entry, execution and result joins,
source/artifact continuity, complete capture and quiescence.

At completed 0027, Windows build/test consumption is 22/40 and combined consumption
is 51/120. Preparation remains Linux 8/11 and Windows 5/5, combined 13/16;
downloads remain 768 MiB and synthetic child-product reservations remain 24/36,
within the outer ceiling of 60. The final twelve CLI process units remain reserved.
Stopped 0022 remains false and charged. Dedicated source, artifacts and sanitized
evidence are intentionally retained.

These runtime observations establish the controlled admission, initialization,
provider-argument continuity, cancellation and prevented-effect assertions in the
fixed fifteen cases. They exercise no native host query, actual MSAL initialization,
account/store operation, network request, window or child-product process. Native
admission and initialization, actual UI-thread rechecks, production composition,
process/WSL lifetime, final Native AOT, UI presentation and real-account/reuse
acceptance remain open; this result does not complete the Windows Slice.

## Controlled Windows Host Admission Supplement

This supplement selects twenty-two synthetic host-admission scenarios after the
accepted [local-provider green result](#local-provider-admission-green-evidence).
The [local Windows host design](../../designs/windows-ado-authentication.md#local-windows-host-admission)
and [scenario basis](../../validation/strategy.md#windows-slice-design-acceptance)
remain the behavior authorities. The existing credential-free Wave permits this
bounded selection; actual native metadata queries and real provider initialization
remain outside it. Each source, build and test requires independent exact admission
in the coordinating pull request before execution.

### Subject, Effects and Fixed Selection

Use the existing Windows 11 x64 host through the accepted WSL2 controller, SDK
10.0.401/runtime 10.0.12, MSTest 4.1.0 and unchanged public package graph. Keep the
existing cache-only, no-restore Release build of `Windows.slnx` and managed scenario
assembly. No bootstrap, restore, dependency addition, toolchain installation,
publish, production installation or new network request is selected.

The inert red candidate adds only `WindowsHostAdmission.cs` and
`WindowsHostAdmissionScenarios.cs`; their SHA-256 identities are respectively
`26623d3d50eb0c6aff768841065f37c57c6a97917f175c4c89840762b7dfe062` and
`ed9c0dbcb19be9de728a882d3932c3451569f3373d3494f250341f90c8566e4c`.
Exact commit/tree, complete source/project bindings and the PR carrier belong to
source admission. Keep all existing assertions and the unavailable production CLI
provider unchanged. Green implements the classifier using the same controlled
observation boundary; implementing or executing a native observer is not selected
by this supplement.

The fixtures run the real request coordinator, local provider and host-admission
boundary with synthetic platform, product, thread, logon/station, session and
desktop facts. One synchronous internal boundary returns only decision facts;
it exports no native handles, SID, LUID, session ID or returned account metadata.
The provider, initializer and parent are controlled substitutes. Construction is
inert. The sentinel parent `1` never reaches a native API. No selected fixture
queries native host state, constructs MSAL/WAM, accesses an account/store, creates
a window, performs file/network operations or launches a child-product process.
Existing controller infrastructure observations retain their previously accepted
scope. All credentials, identities and error markers in the fixtures are synthetic.

All methods belong to `Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios`.
Both controllers select exactly the following methods with literal
`FullyQualifiedName=<class>.<method>` clauses joined by `|`, without a wildcard or
DataRow expansion. Existing MTP entry and five extension registrations are unchanged.

| Method | Inert red prediction | First failed source assertion |
| --- | --- | --- |
| `ConstructionDoesNotObserveLocalState` | Passed | None |
| `PrecancelledRequestDoesNotObserveLocalState` | Passed | None |
| `OrdinaryInteractiveLogonKindsPermitSelectedAccountAcquisition` | Failed | Line 50: successful ordinary-user acquisition |
| `UnsupportedPlatformStopsBeforeWindowsObservations` | Failed | Line 309 via 76: platform observation reached |
| `ServerOrUnobservableProductPreventsInitialization` | Failed | Line 309 via 87: product observation reached |
| `ImpersonationOrUnknownThreadIdentityPreventsInitialization` | Failed | Line 309 via 97: thread observation reached |
| `MissingOrInvalidOwnLogonPreventsInitialization` | Failed | Line 309 via 111: logon observation reached |
| `ServiceIdentitiesPrecludeAccountDiscovery` | Failed | Line 309 via 125: logon observation reached |
| `NoninteractiveAndAlternateCredentialLogonKindsAreRejected` | Failed | Line 309 via 135: logon observation reached |
| `HiddenWindowStationPreventsInitialization` | Failed | Line 309 via 143: logon observation reached |
| `MissingOrDifferentWindowStationUserPreventsInitialization` | Failed | Line 309 via 152: logon observation reached |
| `InactiveOrUnobservableSessionPreventsInitialization` | Failed | Line 309 via 166: session observation reached |
| `NoninputOrUnobservableDesktopPreventsInitialization` | Failed | Line 309 via 176: desktop observation reached |
| `CancellationAfterAnyObservationStopsFurtherQueriesAndInitialization` | Failed | Line 317 via 187: cancelled outcome |
| `OriginalCancellationWinsWhenAnObservationThrows` | Failed | Line 317 via 205: cancelled outcome |
| `UnexpectedObservationFaultRemainsSanitizedInternalFailure` | Failed | Line 317 via 221: internal-failure outcome |
| `SessionLossBeforeSilentAcquisitionPreventsItsEffect` | Failed | Line 235: discovery reached before session loss |
| `ImpersonationBeforeSilentAcquisitionPreventsItsEffect` | Failed | Line 249: discovery reached before identity change |
| `InputDesktopLossAfterReadinessPreventsInteractionAndClosesParent` | Failed | Line 259: parent reached before desktop loss |
| `CancellationDuringVolatileObservationPreventsAcquisition` | Failed | Line 317 via 272: cancelled outcome |
| `EachProviderEffectHasFreshVolatileObservations` | Failed | Line 283: successful interactive continuation |
| `ObservationsRunOnTheCallingThreadWithOriginalCancellation` | Failed | Line 299: successful calling-thread continuation |

These are static predictions requiring successful build and exact discovery, not
runtime observations or promised Release stack-frame line numbers. A rejected-fact
scenario must reach its designated observation, so constant rejection cannot pass.
The fixed loops expand no runner cases: full green traverses 62 fixture iterations
and 61 coordinator requests. Red stops each failing method at its first assertion;
it cannot establish later rows or assertions. Fixtures dispose their cancellation
sources and start no asynchronous/native work requiring a UI drain.

Select `test --suite host-admission --expect red` or
`test --suite host-admission --expect green`, retaining the required full
protocol/source/target revisions and independent review URL. Red requires exactly
two Passed and twenty Failed, runner exit 2 and fully collected outer exit 0.
Green requires twenty-two Passed, all other outcomes zero and runner/outer exit 0.
Preserve all sixteen TRX counters and complete definition/entry/execution/result
joins. Individually accept intended business failures before green implementation;
compiler, analyzer, loader, fixture, native or timeout failures are not red evidence.

### History, Controller Transition and Limits

Before the first reservation require at least 27 finalized Windows actions and the
unchanged completed 0027 WSL receipts: `started.json` SHA-256
`701478479cf1bf1c4fa5dbfdce4d02d5facd015b067a825785b51515d27408dd` and
`result.json` SHA-256
`ac1b287b7dafbb2082e173efad20585f062731b922ff593c33410184740c1456`.
At exactly 27 previous actions only a separately admitted build 0028 may begin the
one-time transition. Under its existing exclusive reservation, use the accepted
backup/migration procedure for exactly these two retained controllers:

| Controller | Required old SHA-256 | Replacement SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `0e01a22ee8e63720f54ad6525976d1b282656f33a8682919fd316b7ff4633d39` | `0747221d12d689ca80b9022ffcfa6cd23a5584165398482cdd1b5bbc0bed3c5b` |
| `Invoke-WindowsValidation.ps1` | `dc4019e3ba3f62cafda1222f4468f270cf1b935c7ec7ca761f0b36c2a290a3ce` | `3263b10d1c478c723a6c9c0b3d5926d47a5cdba5bca1da5184b132543596daeb` |

The old controllers executed 0027 under protocol
`4edee1a99c2a898a481931c394a39646045fda36` and remain unchanged at accepted
target `14d494135022ceffaa430b1efdfd8510dfe71ac4`. Preserve their bytes in
`actions/0028/retained-run_windows.py` and
`actions/0028/retained-Invoke-WindowsValidation.ps1`; the existing migration receipt
binds old/new hashes and protocol revisions. Partial migration or unexpected bytes
stops both loops without refund, retry or standalone repair. Preserve all original
receipts, backups, stop/Job helpers, toolchain and package caches. Stopped 0022
remains false and charged; no prior action is replayed.

The symmetric Linux history-reader change has SHA-256
`064f1156539f9284d890a05560e548ba42fa0e5b4d8331fd1b022037dcb21388`.
It is not a third retained Windows controller migration. Both history readers and
the Windows controller admit this selection only after 0028, reserve zero process
scenarios and preserve every historical full CLI charge. Keep the common complete
TRX validation and rejection of child-product evidence for this selection.

The planned progression is a red build/test pair, then a green build/test pair only
after independent actual-red acceptance and refreshed green-source admission.
At completed 0027, preparation is Linux 8/11, Windows 5/5 and combined 13/16;
build/test is Linux 29/80, Windows 22/40 and combined 51/120. Four admitted actions
would bring Windows build/test to 26/40 and combined consumption to 55/120. No
preparation, downloads or child-product units are added. Preserve 768 MiB charged
downloads, 24/36 synthetic process reservations, the outer ceiling 60 and the final
twelve CLI process units. Failed starts remain charged; no automatic rerun is allowed.

Keep the 120-second subject/capture/Job-drain limit, 230-second outer wait, 8 MiB
combined output ceiling, 32-process nonbreakaway Job ceiling, shared action lock and
bounded stop procedure. This synthetic selection needs no desktop attendance or
release marker; the existing owned-host green attendance requirement is unchanged.
Before each test, independently inspect the actual build, source-bound assembly,
generated runner/registrations, dependency/runtime mapping and exact case discovery.
Afterward inspect source/artifact continuity, complete capture, all joins/counters,
normal Job drain and fully collected outer result. Unexpected results, changed
inputs, incomplete capture or uncertain quiescence stop both loops for independent
classification. Dedicated source, artifacts and sanitized evidence are retained.

Passing this selection establishes controlled host-fact classification, original
cancellation, sanitization and fresh volatile observations before provider effects.
It does not establish actual native ABI/layouts, per-native-query cancellation,
resource ownership, host metadata, UI-thread checks before create/show, MSAL/WAM
initialization, production wiring, process/WSL lifetime, Native AOT, UI presentation
or real-account/reuse behavior. Those original acceptance obligations remain open.

### Controlled Windows Host Admission Red Evidence

Windows build 0028 and test 0029 used accepted target/protocol
`f57bfd02309f3eab31d99d904a3ebd9a5bfd5d64` and inert source
`723f121f05859c116f2a2d01615864a3fa802bea`, tree
`fe278c2ddf687ef1beaca7b57a71f31443dc08c1`. The no-restore Release build
completed in 12.593 seconds with zero warnings and errors. Its manifest SHA-256 is
`540e3c8774b7fb9f482f84c86bf01204b315d5e46eb52cbbcad4a08014da4238`.
The [actual-build review and single-red-test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/140#issuecomment-5660636876)
accepted the source-bound assembly/PDB, generated runner, exact case selection,
dependency/runtime mapping and artifacts before test execution.

Test 0029 executed the twenty-two selected methods once: two Passed and twenty
Failed at their individually predicted first business assertions. All sixteen TRX
counters were inspected: total/executed twenty-two, passed two, failed twenty, and
all other counters zero. The runner exited 2 after 1.243 seconds; the fully
collected outer exited 0 with continuation allowed and confirmed quiescence.
Capture was complete, with no safety stop, termination request or remaining owned
process. The TRX SHA-256 is
`21cd73b1894ab70be0c35baffe995b16dfc31a708ce7f5634338753a434c15f9`;
the WSL final receipt SHA-256 is
`48498ee2301f1ef922f9ce632d17db8e5b82e14f1308c584011e5f596277c295`.

The [independent actual-red acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/140#issuecomment-5660937330)
joined every definition, entry, execution and result to the unchanged admitted
source and artifacts. Release stack frames 282 and 298 were individually bound
through the actual PDB/IL and unique assertion messages to first source assertions
283 and 299; neither source assertions nor expected outcomes changed. No repeat execution was needed.

At completed 0029, Windows build/test consumption was 24/40 and combined consumption
53/120. Preparation, downloads and synthetic child-product reservations were
unchanged. Stopped 0022 remained false and charged. The dedicated source, artifacts
and sanitized evidence were retained. These synthetic failures establish the
missing controlled classifier behavior and permit its green implementation; they
do not establish assertions after each first failure, actual native observations,
UI, provider initialization or account behavior. Green source and each build/test
retain separate exact admission.

### Controlled Windows Host Admission Green Evidence

Windows build 0030 and test 0031 used the same accepted target/protocol
`f57bfd02309f3eab31d99d904a3ebd9a5bfd5d64` and green source
`5cc9092badfabd04c691e625f5c2909dd79409e7`, tree
`9b4bda42fc96face9036bc2dd596565e75e02a24`. Only the classifier changed from
red; its SHA-256 is
`a75fbe4c3bf837b78535afba73552b7893c07e2bfaed6144eaa7ad3d8ef5fd18`.
All twenty-two scenario methods and assertions remained byte-identical. The
no-restore Release build completed in 12.493 seconds with zero warnings and errors;
its manifest SHA-256 is
`4f4b85c8f5d66ba8ef58cb2458db9bada23978d1d0c6ffd4e9319745aba05c06`.
The [actual-build review and single-green-test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/140#issuecomment-5661442413)
accepted the actual assemblies/PDBs, unchanged scenario semantics, generated runner,
exact selection, dependency/runtime mapping and prospective test inputs before
execution. No controller migration occurred in these two actions.

Test 0031 executed the twenty-two selected methods once, all Passed. All sixteen
TRX counters were inspected: total, executed and passed were twenty-two; every
other counter was zero. The runner exited 0 after 0.981 seconds, and the fully
collected outer exited 0 with continuation allowed and confirmed quiescence.
Capture was complete: 639 stdout bytes and empty stderr. Both Job processes ended
normally, with zero active at normal exit and before/after the stop check, no
termination request and no safety stop. The TRX SHA-256 is
`e7a71c5b15671ed0bd83d3f556a4a59479fcbb4e234f11aafb8e1708118bfbd1`;
the WSL final receipt SHA-256 is
`ba41f9bbcee348c694f187d8b966fb097baea450c938cc866e3bf77e6a73cd58`.

The [independent actual-green acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/140#issuecomment-5661781682)
joined all definitions, entries, executions and results to the admitted source and
artifacts, checked complete capture and source/artifact continuity, and accepted
normal zero-process completion. The passing unchanged methods cover all 62 fixture
iterations and 61 coordinator requests by their finite source paths; those counts
are not additional runner cases or per-row runtime telemetry.

At completed 0031, all 68 Linux/Windows action pairs were finalized. Windows
build/test consumption was 26/40, Linux 29/80 and combined 55/120. Preparation
remained Linux 8/11, Windows 5/5 and combined 13/16. Downloads remained 768 MiB;
synthetic process reservations remained 24/36 under the outer ceiling 60, with the
final twelve CLI process units preserved. Stopped 0022 remained false and charged.
No 0032 or Linux 0038 was started. Dedicated source, artifacts and sanitized
evidence were intentionally retained.

The controlled result establishes ordinary-user fact admission, rejection of the
selected unsupported or unobservable facts, original cancellation and sanitization,
and fresh volatile observations before provider effects. These fixtures exercise
no native query, MSAL/WAM initialization, account/store access, window, network
request or child-product launch. Per-native-query cancellation, ABI and resource
ownership, UI-thread checks before create/show, production composition, process/WSL
lifetime, the final Native AOT artifact and real-account/UI/reuse acceptance remain
open. This increment does not complete the Windows Slice.


## Owned Host Fault Lifetime Evidence

[PR #142](https://github.com/hcoona/microsoft-authentication-cli/pull/142) adds the
core lifetime notification for an owned-host fault. The scenario source uses controlled
providers, a fake host and monotonic clock on Linux; no native Windows, UI, broker,
account, cache or identity/resource service was accessed. The existing accepted
SDK/runtime, package graph, isolated replacement environment and finite managed-loop
bounds apply.

Red source `a1b0e10cf26b8874a66d48e78f1c8761429d25ec`, tree
`5c371da6d9e02b1a44d73b468a873af01dd63021`, added seven methods with an inert
`RequestLifetime.FailHost`. The source/build and actual-build/test admissions bind
accepted protocol `f57bfd02309f3eab31d99d904a3ebd9a5bfd5d64` and target
`3c4f53b0026dd1561d822065468d39cac849f656`:
[source/build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/142#issuecomment-5662017730),
[build acceptance and test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/142#issuecomment-5662144699).

| Linux action | UTC on 2026-09-14 | Subject seconds | Actual result |
| --- | --- | ---: | --- |
| 0038, red build | 09:42:48.735598–09:42:57.261014 | 8.022 | Exit 0, zero warnings/errors. |
| 0039, full red test | 09:52:40.195428–09:52:41.258132 | 0.875 | Exit 2; 250 executed, 246 passed, four intended assertion failures. |

The [independent actual-red acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/142#issuecomment-5662195715)
joins every result to its compiled case. All 243 prior cases remained present and
passed. Four added methods exposed missing failure before start, terminal selection
while discovery remained pending, withholding a validated success before commitment,
and checking an expired deadline before delayed timer dispatch. The pending-phase
loop stops at discovery in red; later phases and assertions are not red observations.
The other three added methods preserved selected failures, caller cancellation and
committed output. All twelve other outcome counters were zero.

Red build receipt SHA-256:
`7c0b229702f09e84064e621ae030785c3d32068215c5728eaa4e8d57959c1595`;
red test receipt:
`821d55b52df133fe0c22d21f897e737dccb258a339d779992f915952d8be4f60`;
sole red TRX:
`d1a4856f325d7a47a3ccc3e4eb8058fbcad0f278003632114a8d7c77e3e719df`.

Both actions completed normally with confirmed owned-process quiescence and complete
output. Source, SDK, graph, restore metadata and build artifact identities matched;
no retry, interruption or cleanup occurred. Dedicated files are intentionally retained.

Green source `a3b7c7aad6df4dde2cfcc3335985adabe04769c6`, tree
`00c7cd40e03f8aad6b0721ada0f8b7c6d10d4241`, changes only RequestLifetime after the
accepted red. The exact scenario bytes remain unchanged. A fault selects terminal
failure for a pending request, honoring existing caller cancellation and the original
deadline; before commitment it withholds a provisional success without changing the
first terminal timestamp. Already selected failures and committed output remain stable.

The [green-source admission](https://github.com/hcoona/microsoft-authentication-cli/pull/142#issuecomment-5662283509)
and [actual-build acceptance and test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/142#issuecomment-5662350433)
bind the same protocol and target, all source and restored inputs, actual assemblies/PDBs,
unchanged generated runner registrations and exact case inventory.

| Linux action | UTC on 2026-09-14 | Subject seconds | Actual result |
| --- | --- | ---: | --- |
| 0040, green build | 10:05:41.622802–10:05:49.072231 | 7.240 | Exit 0, zero warnings/errors. |
| 0041, full green test | 10:12:47.618799–10:12:48.689870 | 0.876 | Exit 0; all 250 cases passed, every other outcome counter zero. |

The [independent actual-green acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/142#issuecomment-5662450317)
confirms the complete result and its continuity with the admitted build.
The green TRX preserves all 250 definition, entry, execution and result joins from red,
including all 243 previous cases. The seven added methods exercise the fixed fault
scenarios, including every finite pending-phase loop iteration on the passing path;
those iterations are not additional runner cases or independent runtime telemetry.

Green build receipt SHA-256:
`0852988a48350af9517b07033908b248d52ae7055db9e9ff163786f6a801c1c5`;
build manifest:
`84cff68b01e736c819cd68718989ea9ef5324109534a59e31e91929eff10ec21`;
green test receipt:
`448ed356244494ce9caf0a4b6cba79b11f13c1c09c0826af85494baf09f388fe`;
sole green TRX:
`cccfb455259232442cf031639636749e3d288897f6a5c438b6b58ad084b3924f`.

Both green actions completed normally with fully collected outer exit 0, complete
capture, confirmed quiescence and continuation allowed. Source, SDK, graph, restore
metadata and artifact identities remained bound to the admitted inputs. No retry,
interruption, termination or cleanup occurred; dedicated files are intentionally retained.

At completed 0041, all 72 Linux/Windows action pairs were finalized. Linux build/test
consumption was 33/80, Windows 26/40 and combined 59/120. Preparation remained Linux
8/11, Windows 5/5 and combined 13/16. Downloads remained 768 MiB; synthetic process
reservations remained 24/36 under the outer ceiling 60, with the final twelve CLI
process units preserved. Historical stopped actions remained false and charged.
No new Windows action or child-product process ran.

These controlled core results do not establish synchronization of an actual UI fault
with production result commitment or UI-thread/process drain. Production composition,
native observations, WAM, WSL, Native AOT and real-account/reuse acceptance retain their
existing obligations.

## Owned UI Admission Supplement

This supplement selects the existing owned-host regression scenarios together with
the new UI-thread admission scenarios. The accepted
[Windows host design](../../designs/windows-ado-authentication.md#local-windows-host-admission)
and [validation strategy](../../validation/strategy.md#windows-slice-design-acceptance)
remain the behavior authorities. The current credential-free Wave permits the
bounded owned-window effects. Each source, build and test requires independent
exact admission before execution; this supplement grants no account operation.

### Subject and Fixed Selection

Use the existing Windows 11 x64 host, WSL2 controller, SDK 10.0.401/runtime 10.0.12,
MSTest 4.1.0 and retained public package graph. Keep the existing no-restore Release
build of `Windows.slnx` and managed scenario assembly. Select no bootstrap, restore,
download, installation, publish or production child-process action.

The initial red candidate is PR #143 source
`984a232995e41e90476cb0aa8b2228af2000874c`, tree
`6e2e0d8b470c04c3668f2b98588bee9503b05b73`. Its optional owned-host admission
argument is inert. The host SHA-256 is
`ef8158ebbdee79716d2b82fc971bdc73dad750577fd6fcc15d0bd82990c6942e`;
the scenario SHA-256 is
`67c2c9688577e7258f748884c37434225cc894e914cc09fc9133993d48da51c8`.
Exact source admission may bind a later integration revision only when these red
semantics and the complete reviewed source/project identities remain explicit.

The build includes `NativeWindowsHostObservations.cs`, SHA-256
`b94d448974221d7e8e79d1ab9484665b11a214651a193c4da42982e15499a7eb`.
The fixed test selection never constructs or invokes it. Native own-logon/session
metadata observations, real provider initialization and production composition are
not selected. All providers, profiles, accounts, tokens and admission observations
are synthetic. The real owned Win32 host and existing owned-window observation
helper supply the native effects; there is no broker/account/store/network access.

`test --suite ui-admission` selects exactly the fifteen method names already fixed
by the [Owned Win32 Host supplement](#owned-win32-host-scenario-supplement) plus
the following five methods in
`Authentication.Windows.Scenarios.OwnedHostScenarios`, using literal positive
`FullyQualifiedName` clauses with no wildcard. Preserve both cancellation DataRows
as separate full discovery names in result validation.

| Added method | Cases | Inert red prediction |
| --- | ---: | --- |
| `UiRejectionBeforeCreationPreventsParentAndAcquisition` | 1 | Failed: expected unavailable, synthetic acquisition succeeds. |
| `UiRejectionBeforeShowingWithholdsParentAndAcquisition` | 1 | Failed: expected unavailable, synthetic acquisition succeeds. |
| `UiRechecksUseOriginalTokenOnTheOwnedStaThread` | 1 | Failed: expected two observations, inert seam records zero. |
| `CancellationDuringUiRecheckPreventsAcquisition` | 2, arguments 1 and 2 | Failed: expected cancelled, synthetic acquisition succeeds. |
| `SilentSuccessDoesNotInspectTheOwnedUiThread` | 1 | Passed: silent success with no UI observation. |

The full selection is twenty methods and twenty-one cases. The unchanged fifteen
existing methods are expected Passed in both stages. Red requires sixteen Passed
and five intended Failed, runner exit 2 and outer exit 0. Green requires twenty-one
Passed, every other outcome counter zero and runner/outer exit 0. Bind all sixteen
TRX counters and complete definition/entry/execution/result joins. A compiler,
loader, fixture, native, timeout or drain failure is not intended red evidence.
Accept actual red independently before implementing the green UI checks, without
changing assertions to fit the observation. Preserve generated runner registrations.

### Windows, Attendance and Observation Boundaries

Both stages use the real already-implemented host and can show windows. Fixtures
remain serial and create at most one top-level owned parent at a time. The admitted
finite paths predict at most fifteen parents in red (twelve potentially shown,
three hidden) and thirteen in green (eight potentially shown, five hidden), plus
their fixed child controls. These are source-derived ceilings, not measured counts
or claims that an operator saw every surface.

Both red and green require the existing
[prepared/live-ready/release attendance procedure](#preparation-and-attending-operator-handoff).
Complete source and actual-build admission, controller setup and the
live `attendance-ready.json` observation before asking the owner to attend. Only
a fresh explicit readiness reply permits release of that exact prepared action.
Earlier replies, earlier release files, elapsed time and automation alone cannot
satisfy this handoff. Keep the finite wait selected by that procedure for the action,
cancellation, reservation binding and expiry stop; no automatic retry is allowed.
The owner may leave between the red and green stages while implementation, builds
and reviews proceed. Do not ask the owner to wait through that preparation.

All scenario inputs are programmatic and target only known owned HWNDs. Existing
helpers inspect owned controls and post bounded Win32 messages for Cancel, caption
close and Escape. They do not establish Microsoft UI Automation accessibility,
physical keyboard/focus/DPI behavior, visual readability or human usability.
Keep sign-in, account choice, consent, unlock and any later manual observation
under their separately accepted protocols and operator control. Historical
`owned-host` selection and attendance requirements remain unchanged.

The new rejection scenarios observe native creation activity and visibility at
their boundaries; final mutable observations follow natural invocation and host
completion. Preserve existing fixture teardown, stop latch and safety marker.
Snapshots cannot exclude every transient show/hide: independent green source
review must verify admission before `CreateNativeParent` and before the sole
`ShowNativeParent`/readiness path, original-token checks and terminal ordering.

### Controller Transition, Capacity and Retention

The existing controllers last executed Windows 0031 under protocol
`f57bfd02309f3eab31d99d904a3ebd9a5bfd5d64`. Its WSL `started.json` SHA-256 is
`b04688941e504d594947544e26f12d87c99d7de0bbd86b280e17c1ee20e63f68`, and its
`result.json` SHA-256 is
`ba41f9bbcee348c694f187d8b966fb097baea450c938cc866e3bf77e6a73cd58`.
The migration is exclusively part of admitted build 0032 and backs up each old
controller to `actions/0032/retained-<controller-name>` before replacing it.

| Controller | Required old SHA-256 | Replacement SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `0747221d12d689ca80b9022ffcfa6cd23a5584165398482cdd1b5bbc0bed3c5b` | `0046cb65cba438fc2650b4d8178197e18a70694177ababa9c7186f87ae6cc5ef` |
| `Invoke-WindowsValidation.ps1` | `3263b10d1c478c723a6c9c0b3d5926d47a5cdba5bca1da5184b132543596daeb` | `c91e044adaa941bb999cfe0c579c6cea0e97808331b7cde8e823a7de41b79c1b` |

The symmetric Linux history reader has SHA-256
`b7d356fd7bceaf8f98832a268ca32961777b10438aed17f8694aa72e2c4339f7`.
It is not another retained Windows migration. Both readers reject the new test
selection at or before 0032 and preserve the original attendance receipt checks
while requiring them for either new test expectation.

Require the completed thirty-one Windows actions and their unchanged receipt
bindings. Exactly the separately admitted next build performs the existing backup
and controller migration for `run_windows.py` and `Invoke-WindowsValidation.ps1`;
the Linux history reader receives the symmetric new selection/attendance rule.
Preserve all historical selections, charged stopped outcomes and retained backups.
Partial migration, changed input or uncertain quiescence stops both loops; no
standalone repair, refund or replay is permitted.

At completed Linux 0041, build/test consumption is Linux 33/80, Windows 26/40 and
combined 59/120. The red build/test and green build/test progression adds four
Windows actions, reaching Windows 30/40 and combined 63/120 if no intervening
consumption occurs. Before each reservation recover actual cumulative history.
Preparation remains 13/16, downloads 768 MiB and process reservations 24/36 under
the outer ceiling 60; preserve the final twelve CLI process units. This selection
reserves no production child-process units.

Keep the existing 120-second subject/capture/Job-drain allowance, 230-second outer
work allowance excluding the admitted attendance wait, 8 MiB output ceiling,
32-process nonbreakaway Job ceiling, exclusive shared lock and bounded stop path.
Inspect complete capture, source/artifact continuity, all results and normal Job
drain after fully collecting the original outer helper. Dedicated source,
artifacts, migration backups and sanitized evidence are intentionally retained.

Passing these controlled scenarios establishes the selected owned-host outcomes
and UI-thread checks, not actual native admission facts or real WAM behavior.
Production fault/commit synchronization, complete process/WSL lifetime, final
Native AOT, real-account/reuse and physical UI acceptance remain required. This
increment does not finish the Windows Slice.

## Windows Action 0033 Attendance-Expiry Disposition

The UI-admission red reservation 0033 used accepted target/protocol
`aa9eb65e48832cb83b86dd5a63df660eb35848c6`, unchanged source
`984a232995e41e90476cb0aa8b2228af2000874c`, tree
`6e2e0d8b470c04c3668f2b98588bee9503b05b73`, and accepted build 0032 under the
[independent test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5663169601).
The [independent actual-stop review](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5667952255)
classifies the result as normal attendance expiry before subject launch, with no
material implementation finding. This is neither red business-assertion evidence
nor a green result. Build 0032 retains its
[accepted artifact evidence](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5663082330);
it is not rebuilt by this disposition. Source 984a232 predates the integrated
Core host-fault change in PR #142; the unchanged UI-red selection does not claim
that later integrated Core. Integrate the then-current accepted target in a
distinct green source only after actual UI-red acceptance.

**Observed preparation and stop:** Windows published ready at 2026-09-14
11:37:05.861138 UTC, and the outer wrapper emitted validated `awaiting-operator`.
The prepared reservation bound the admitted 2,529-entry protected input map,
376-entry installed-tool map, exact invocation and live controller incarnation.
No controller migration occurred in 0033. These are preparation observations;
successful-action source/tool postchecks did not run after the safety stop and
do not establish complete post-stop input integrity.

Windows finalized at 12:07:05.916061 UTC in `attendance`, with failure line 35
identifying the accepted monotonic 1,800-second expiry check, exit -1,
`safetyStop=true`, `captureCompleted=false` and `captureDisposition=not-started`.
Actual Job accounting records zero total and active processes before and after
Stop; no termination was requested. Empty-Job cleanup, rather than controller
disappearance, establishes quiescence. WSL finalized at 12:07:06.009565 UTC with
`continuation_allowed=false`, `quiescent=true` and `error_type=ValueError`.
The original outer session was fully collected with exit 1 and no test counts.
No release, acknowledgement, subject, capture, cancellation, fixture-stop or TRX
record exists. No test window, scenario assertion, native admission observation,
account operation or authentication ran.

**Exact retained disposition:** Both history readers recognize only these three
WSL receipts and their five hash-bound Windows evidence files. Preserve the
original false result and its consumed build/test unit; no receipt is rewritten.

| WSL 0033 receipt | SHA-256 |
| --- | --- |
| `started.json` | `4785c692765970cd909c341470e3d8e750f448e45bc53ad3165a70e0cdaf46a7` |
| `windows-input.json` | `e07476d8b99467266698e3f212c2b687c3538b57eb8484d9812456713e1f618c` |
| `result.json` | `6c4596568982d0e44924d58d8386dee0b58f6d7f73a809047bd34860a46b1766` |

The exact Windows files are `started.json`, `controller.json`, `invocation.json`,
`attendance-ready.json` and `windows-result.json`; the final Windows result has
SHA-256 `51b6df7ccaa54b72e34e90c730ef8b937386f52f5167920cee46e37e00165fde`.
The only directories are `home`, `home/local`, `home/roaming`, `temp`, `results`
and `empty-program-files`; their leaf directories remain empty. Reject missing,
additional, changed, linked or wrong-type receipts, evidence files or directories.
The earlier 0022 disposition remains exact and unchanged. This exception accepts
no other stopped action and relaxes no successful-action attendance check.

**Continuation and migration:** After this disposition merges, the first action
is one independently admitted Windows 0034 `test --suite ui-admission --expect red`
on unchanged source 984a232 and build 0032. Recover all forty-three Linux and
thirty-three Windows actions. Refresh exact accepted target/protocol/Wave,
source/build, protected inputs, installed tools, current history and remaining
capacity before reservation; prior integrity observations are historical.
Linux execution remains stopped until Windows 0034 completes normally.

Only within 0034, retain and replace `run_windows.py` through the existing
controller-migration procedure. Its retained previous SHA-256 is
`0046cb65cba438fc2650b4d8178197e18a70694177ababa9c7186f87ae6cc5ef`; the replacement
is `5e03199cf13fa0215d159c5c57699c352b737ed2e3f3a810026d623cc30471c2`.
`Invoke-WindowsValidation.ps1` stays unchanged at
`c91e044adaa941bb999cfe0c579c6cea0e97808331b7cde8e823a7de41b79c1b`.
The symmetric Linux reader is
`aea379b8727083906a12e640c69a0d10c705aabcab82238ec0d8b11227e934b6`;
it is not a retained Windows migration. No standalone repair, new restore,
source rebuild, reservation refund or automatic retry is authorized.

The new helper must finish preparation and publish a new live ready receipt before
requesting fresh owner attendance. An earlier or late response cannot release
0034. The expired 0033 gate cannot be released, extended, resumed or overwritten.
Keep the 1,800-second preparation and attendance bounds, 230-second controller
work allowance, 120-second subject/capture/Job-drain limit, 8 MiB output bound,
32-process Job ceiling, original stop procedure and unchanged 21-case selection.
The red prediction remains sixteen passes and five intended failures. Accept its
actual complete evidence independently before green implementation.

Through Linux 0043 and Windows 0033, preparation is Linux 8/11 and Windows 5/5,
combined 13/16; build/test consumption is Linux 35/80 and Windows 28/40, combined
63/120. The newly admitted 0034 consumes one further Windows build/test unit,
reaching Windows 29/40 and combined 64/120 if no intervening consumption occurs.
Downloads remain 768 MiB and synthetic process reservations 24/36 under the outer
ceiling 60, preserving the final twelve CLI units. This disposition does not
establish UI-red success, real native admission, production composition, WAM,
account reuse, WSL or final Native AOT acceptance.


## Second UI Attendance Expiry and Four-Hour Handoff

Windows action 0034 completed preparation under accepted protocol and target
`8ad077f7283db77a8456accbd1ea7ca82c10840f`, unchanged source
`984a232995e41e90476cb0aa8b2228af2000874c`, tree
`6e2e0d8b470c04c3668f2b98588bee9503b05b73`, and accepted build 0032. It used the
[independent admission](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5668232923).
The original 0033 disposition's first continuation was this action; its new
attendance expiry supplies no red result. The disposition and next-action rule
below supersede that completed first-continuation requirement, without changing
either stopped action or its original time limits.

The [independent stop review](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5669125606)
accepts normal attendance expiry before subject launch, the completed wrapper
migration and bounded empty-Job cleanup. It admits no future action.

**Observed preparation and stop:** Windows published ready at 2026-09-14
18:01:38.6976286 UTC. The wrapper emitted validated `awaiting-operator`, and a
separate narrow check bound the live controller incarnation, complete reservation,
2,529-entry protected-input map, 376-entry installed-tool map, exact invocation
and completed one-wrapper migration. No release was created. Windows finalized
at 18:31:38.7735521 UTC in `attendance`, failure line 35, with exit -1,
`safetyStop=true`, `captureCompleted=false` and `captureDisposition=not-started`.
Actual Job total and active counts were zero before and after Stop, with no
termination requested. Empty-Job cleanup establishes quiescence.

WSL finalized at 18:31:38.873649 UTC with `continuation_allowed=false`,
`quiescent=true` and `error_type=ValueError`. The original outer session was fully
collected with exit 1 and no test counts. No subject, release, acknowledgement,
capture, cancellation, fixture-stop or TRX exists. No scenario, test window,
account operation or authentication ran. Prepared input and tool bindings remain
preparation observations: successful-action source/tool postchecks did not run
and full current post-stop integrity is not established by them.

**Exact retained disposition:** Preserve the false result and charged unit. Both
history readers recognize only these three exact WSL receipts and their seven
hash-bound Windows evidence files, using the existing strict type/path verifier.

| WSL 0034 receipt | SHA-256 |
| --- | --- |
| `started.json` | `74efac252f02bd01ca8ab75d4d6cc179d5f1fdfcfa4bcd7132f52712d03ec940` |
| `windows-input.json` | `e937ebb25470f0ec025af48a4e87d5683777423e9e283d5cc328880f9f98b46f` |
| `result.json` | `2ba6cd4445dba723dcfd30dca57772c751ccf9d3fb775e5e0bfb688da2c21d83` |

The exact Windows files are `started.json`, `controller.json`, `invocation.json`,
`attendance-ready.json`, `controller-migration.json`, `retained-run_windows.py`
and `windows-result.json`. The final Windows result has SHA-256
`1df49cd9ab262d65e37678b51cf32afbf5fc6f42392737eefc1bd3f05261d7e4`.
The only directories are `home`, `home/local`, `home/roaming`, `temp`, `results`
and `empty-program-files`; their leaf directories remain empty. Retain the
completed migration, its old wrapper backup and all original receipts. Reject
missing, added, changed, linked or wrong-type files and directories. The earlier
0022 and 0033 exceptions remain exact. This is no general expiry bypass.

**Four-hour attendance limit:** For newly admitted attended tests from Windows
0035 onward, the prepared empty-Job gate waits once for at most 14,400 seconds.
This accommodates a delayed return to the desktop after preparation. Keep the
exclusive shared action lock and unchanged-input boundary throughout the wait.
Cancel a pending action if relied-on authority or inputs materially change; do
not refresh, extend or restart it in place. No subject starts during this wait.

The ready receipt has integer `waitSeconds=14400`; the release acknowledgement
has integer `waitMilliseconds` in `[0, 14400000)`. Both live verifiers, both
historical readers, PowerShell's monotonic expiry check and the outer wrapper's
wait exclusion use that same bound. Historical actions through 0034 still require
1800 and `[0, 1800000)` respectively. No old receipt or late readiness response
is reusable. Complete preparation, verify the new live-ready receipt, then
request a fresh explicit owner response and report that action's actual deadline.
Release only that same still-waiting controller after the fresh response.
Cancellation and expiry still win over release.

The wrapper excludes only the observed attendance interval and freezes that
exclusion to the lesser of its own observation and the bound release duration.
The WSL preparation timer remains 1,800 seconds, Windows controller work remains
230 seconds outside attendance, and subject/capture/Job drain remains 120 seconds.
Keep the 8 MiB capture and 32-process Job ceilings, original stop procedure and
intentional retention. No work, execution or cleanup budget becomes four hours.
No automatic retry, periodic relaunch, account effect or new capacity is granted.

**First continuation and migration:** After merge and separate exact admission,
the first action is Windows 0035 `test --suite ui-admission --expect red`, using
unchanged source 984a232 and build 0032. Recover all forty-three Linux and
thirty-four Windows actions; refresh accepted target/protocol/Wave, source/build,
protected inputs, tools, current history and capacity before reservation. Linux
execution remains stopped until that Windows continuation completes normally.

Only inside 0035's reservation, use the existing exclusive backup/replacement
procedure for these two retained controllers and record both migrations:

| Controller | Previous SHA-256 | Replacement SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `5e03199cf13fa0215d159c5c57699c352b737ed2e3f3a810026d623cc30471c2` | `46459e4cf476c22e28432fa1397026a4b1b56f8580119e685db120dc6c7b4e55` |
| `Invoke-WindowsValidation.ps1` | `c91e044adaa941bb999cfe0c579c6cea0e97808331b7cde8e823a7de41b79c1b` | `454a59e9d5fae0993c8842f50c11701c0311c5999830bea177f5cee130f0c104` |

The symmetric managed reader is
`3881500e2e2564f2cb1869d5e27e739bff323e90e91c876285bfbee635fd0fab`;
it is not a retained Windows migration. Stop/Job helpers remain unchanged.
No standalone repair, restore, rebuild, source integration or refund is included.

At finalized Linux 0043 and Windows 0034, preparation remains 13/16, Linux
build/test 35/80, Windows 29/40 and combined 64/120. One newly reserved 0035
consumes Windows 30/40 and combined 65/120. Downloads remain 768 MiB and process
reservations 24/36 under the outer ceiling 60, preserving the final twelve CLI
units. Keep the exact 21-case selection and prediction of sixteen passes and five
intended failures. Source 984a232 still predates PR #142's Core integration.
Independent actual-red acceptance must precede a separate integrated green
implementation and admission. No production composition, actual native admission,
WAM, account reuse, WSL, Native AOT or whole-Slice acceptance follows.

## Request Context Initialization Evidence

The existing personal, fixed-work and explicit-work application scenarios now
require provider initialization to receive the same admitted email, scopes,
interaction permission and normalized tenant as acquisition. The
[Windows design](../../designs/windows-ado-authentication.md) and
[scenario basis](../../validation/strategy.md#windows-slice-design-acceptance)
remain the behavior authorities; this increment adds no public CLI option.

The [independently accepted red](https://github.com/hcoona/microsoft-authentication-cli/pull/145#issuecomment-5663137262)
used source `adf81fc494cd52933769d88d99cbf8cd312b0b5d`, tree
`ef80dbd42dffaa19dddb5f1a00111eec7c2ff612`, under protocol
`aa9eb65e48832cb83b86dd5a63df660eb35848c6`. Linux build 0042 completed normally;
test 0043 executed all 250 cases, with 247 Passed and the three intended
selected-Profile cases Failed at their preserved success assertion. Runner exit
was 2 and outer exit was 0. The later initializer-context assertions were not
reached in red.

The [reviewed green source](https://github.com/hcoona/microsoft-authentication-cli/pull/145#issuecomment-5663220522),
`23f66ee80a66b6e2e1588ab0f61d44421c083314`, tree
`86fc12ae5a86207a6c9c15354b771f88bae2491d`, forwards the normalized request through
one invocation path. The profile-only overload adapts to the request-aware factory;
Profile admission, tenant resolution, cancellation and result commitment remain
shared. All scenario bytes are unchanged from red.

The [green admission](https://github.com/hcoona/microsoft-authentication-cli/pull/145#issuecomment-5670046505)
binds accepted protocol `2dd0927b1d41b96945c22a12025576a1c1d76e94`, SDK
10.0.401/runtime 10.0.12, MSTest 4.1.0, the existing public package graph and the
credential-free Linux environment. The [accepted build 0044](https://github.com/hcoona/microsoft-authentication-cli/pull/145#issuecomment-5670148204)
completed with exit 0, zero warnings/errors, complete capture and normal
process-group quiescence in 8.7 seconds. Its complete 251-file artifact inventory,
source-bound portable PDBs and unchanged 96-method/250-case discovery were
independently verified before test admission.

The [independently accepted green test 0045](https://github.com/hcoona/microsoft-authentication-cli/pull/145#issuecomment-5670236645) executed
all 250 cases, all Passed, with every other outcome counter zero. All sixteen
counters and complete definition/entry/execution/result joins were checked.
The three former failures reached their retained success assertions and the later
initializer-context checks. Runner and fully collected outer exits were 0;
capture was complete, termination was unnecessary and process-group quiescence
was confirmed. Recorded subject time was 0.967 seconds.

| Actual evidence | SHA-256 |
| --- | --- |
| Build 0044 result | `79bcd137adb032e020daf2aacac415518fbd3aac454e250149f42230f792398d` |
| Test 0043 red result | `c46d620df476551cbf3a9ed4cf25f7f3598a4335c2f75dfaef0b7a53e0530b43` |
| Test 0043 complete TRX | `882ce89a0ee69321812e2ce2c25cb4bc6ebb3f25d6948e0890053f3e24bfa982` |
| Test 0045 green result | `ff517b9e7cae29d6aa221518967426f6acbaeccc7b234c1f3c217930e41605b6` |
| Test 0045 complete TRX | `c0c4e926b3b5c42bcb796b1f7743f87ee0d39cc8d57dc4613d8e3aa97f290372` |

At completed 0045, all 80 actions are finalized: Linux 45 and Windows 35.
Build/test usage is Linux 37/80 and Windows 30/40, combined 67/120. Preparation
remains 13/16, charged downloads 768 MiB, and process reservations 24/36 under
the outer ceiling of 60, preserving the final twelve CLI units. Earlier stopped
attempts remain charged. Dedicated artifacts and sanitized evidence are
intentionally retained; no replay, refund or new capacity follows.

This result establishes request-context forwarding in the controlled Linux
application scenarios. Providers, profiles, accounts and tokens are synthetic;
there is no Windows subject, broker/account-store access or network request.
It does not establish real provider initialization, production process/owned-host
composition, Windows/WAM/UI/WSL behavior, account reuse, Native AOT or whole-Slice
acceptance. Integration of later accepted records preserves the exact executed
Core and scenario bytes; it is not a new runtime execution.

## Automated Synthetic UI Coordination

For Windows actions first reserved under this amendment at 0038 or later, the
existing `owned-host` green and `ui-admission` selections require no owner
attendance when their exact admission confirms that all fixture actions and
required observations are automated. Visible synthetic windows alone do not
require the owner to wait at the desktop. The designated existing Windows
interactive session and every current credential-free effects, process, output,
time, ownership, stop and capacity boundary remain required.

The [prepared-action handoff](#preparation-and-attending-operator-handoff) still
runs through the unchanged accepted helpers. Complete admission and preparation,
receive the actual `awaiting-operator` event, and independently verify the exact
ready receipt and the live controller before the coordinator immediately supplies
the existing exclusive empty release marker. For these automated selections,
that release requires no owner-readiness request or reply. Do not pre-create or
replay a marker, refresh a pending action, bypass cancellation or expiry, or
change prepared inputs. All current receipt schemas and the four-hour maximum
remain unchanged; the coordinator does not deliberately wait for the owner.
The historical `attendance-*` names identify the prepared-action gate and do not
by themselves establish human attendance in these future automated actions.

The admission review must bind the exact automation, owned windows and required
observations. Existing scalar messages remain limited to the admitted subject's
proven windows and controls; this amendment adds no global input, external UI
control, state unlock, account selection, consent or WAM interaction. A new
selection or automation mechanism still requires its own accepted exact protocol.
Automated results establish only the properties they observe, including the
existing limitations concerning physical keyboard, focus and usability.

If an admitted action actually needs owner input, choice or state unlock,
finish preparation and live verification before requesting a fresh explicit
readiness response, then release only the same waiting action after that reply.
No late or earlier response can release another action. An unexpected human
interaction or surface follows the existing stop procedure; do not turn it into
an automatic retry or extend the action's effects.

Do not request attendance solely to watch these tests. Use the admitted automation
for observations, and retain any observation it cannot establish as an open
evidence obligation. Automated success cannot substitute for that missing evidence.

Actions through 0037 retain their original attendance rules, receipts, observed
responses and charged failures. This prospective procedure does not reinterpret
history, allocate another execution, refund capacity or establish a runtime
result. The general [interaction policy](../experiment-safety.md#interaction-and-telemetry)
owns when operator attendance is necessary.

## Owned UI Admission Evidence

The owned request host now rechecks eligibility on its actual STA thread before
creating a native parent and before its sole show/readiness path. Both observations
receive the original request token and occur outside the host gate so that caller
cancellation can complete. Existing terminal checks and native, thread and callback
cleanup remain required. The Windows design and scenario basis remain the behavior
authorities; this result changes no public CLI contract.

The [accepted red](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5670000828)
used source `984a232995e41e90476cb0aa8b2228af2000874c`, accepted build 0032 and
Windows test 0035 under protocol `2dd0927b1d41b96945c22a12025576a1c1d76e94`.
All 21 cases executed: sixteen Passed and five failed at the intended admission
assertions. The failures cover rejection before creation, rejection before showing,
original-token observations on the owned STA, and both cancellation-during-recheck
rows. The remaining sixteen cases, including silent success, passed. Earlier
expired attendance actions remain charged and are not test results.

The integrated green source is `5487007d6afb77324554407cd0272fddd5f99ff0`, tree
`657c88e7917e28559d13ee2ae7d4cc78be54d0ed`. It incorporates the accepted host-fault
lifetime and request-context changes at target/protocol
`0d5fa85840ca99573d8b59967afd87e245c11db8`. All UI scenario bytes remain unchanged
from red. SDK 10.0.401/runtime 10.0.12, MSTest 4.1.0, MSAL/Broker 4.83.1 and
NativeInterop 0.20.3 retain their accepted public dependency identities.

The [accepted Windows build 0036](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5670876319)
completed normally in 15.72 seconds with zero warnings/errors. Independent review
bound all 547 artifacts, the four PE/PDB identities and physical source documents,
and the exact twenty selected methods expanding to 21 cases. These Windows PDBs contain no SourceLink map; immutable source and
physical/generated document checksums supply provenance.
`NativeWindowsHostObservations` was compiled but remains unconstructed and uninvoked
by these fixtures. Its real native admission and production use remain unvalidated.

The [independently accepted green test 0037](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5671238577)
executed all 21 cases, all Passed, with all thirteen other outcome counters zero.
Complete definition, entry, execution and result joins matched the exact admission.
The five former failures now pass and the sixteen prior passes remain green.
Capture included the complete 642-byte stdout and empty stderr. Subject/capture
time was 1.776 seconds; both Job processes drained normally to zero, with no
termination or safety stop. The original outer invocation was fully collected at
exit 0, with continuation allowed and complete source/input/tool postchecks.

This action retained its actual attended handoff: preparation completed at
2026-09-14 21:27:58 UTC, independent live verification preceded a fresh owner
response, and one exact release marker was supplied at 21:38:11 UTC. The controller
recorded 613,797 milliseconds of waiting within the original four-hour limit.
The [independently triaged private checker defect](https://github.com/hcoona/microsoft-authentication-cli/pull/143#issuecomment-5671129310)
and its corrected verification changed neither the prepared inputs nor the
reservation or deadline. No additional subject or repeated test ran. The later
automated-coordination amendment does not reinterpret this attendance evidence.

These are credential-free controlled observations on the designated existing
Windows 11 x64 interactive host, initiated through the admitted WSL 2 helper.
Providers, accounts and tokens were synthetic. The admitted maximum was thirteen
serial parents, eight potentially shown and five hidden, with at most one parent
at a time. These are source-admitted bounds, not independently counted desktop
observations. No real WAM, account/cache/consent access, network resource request,
production CLI child or native admission observation was performed.

| Actual evidence | SHA-256 |
| --- | --- |
| Build 0036 manifest | `361518785200746cbae8669d5a6dd2e5588c7a2575114d9b11e2a93bab77c64a` |
| Test 0037 Windows result | `7cac46ad67cb2ffc04f5f890b8a81700ac9ba83acd4ecd6b6c00e4943aebc9e5` |
| Test 0037 WSL result | `632955ce8c14d50aff82b018d94e11d3d9994765d922d744fcce0829ed46699f` |
| Test 0037 complete TRX | `b6474e42b638df14209973842a9379c024fc703081df604f4d7194912b896ee3` |

All 82 actions are finalized: Linux 45 and Windows 37. Build/test usage is Linux
37/80 and Windows 32/40, combined 69/120. Preparation remains 13/16, downloads
768 MiB, and process reservations 24/36 under the outer ceiling 60, preserving the
final twelve CLI units. Dedicated artifacts and sanitized evidence are intentionally
retained. No capacity reset, historical replay or further execution is implied.

The result establishes the controlled owned-UI admission scenarios and their
existing host regressions. It does not establish production process/host/provider
composition, actual native eligibility, real WAM, selected-account or cross-process
reuse, WSL lifetime, physical usability, final Native AOT or whole-Slice acceptance.

## Owned Host Process Composition Supplement

This supplement selects ten credential-free child-process scenarios after the
[accepted owned UI admission](#owned-ui-admission-evidence). It connects the
existing lazy owned host to the real process worker using controlled providers,
while leaving real MSAL initialization and native host classification inactive.
It adds the finite `owned-process` selection; all prior selections, actual
source/evidence identities, expiry dispositions and charges remain unchanged.

### Subject and Source Admission

Use the existing Windows 11 x64 interactive session, WSL2 controller, Windows.slnx
four-project graph, .NET SDK 10.0.401/runtime 10.0.12, MSTest 4.1.0, MSAL/Broker
4.83.1 and NativeInterop 0.20.3 with the same locks, public packages, generated
restore inputs and retained toolchain. No restore, public download, installation,
publish, new project or dependency is selected.

The initial red candidate is based on accepted
`396d6008e94a7ecbe86506d618fbe5a2d3b769a3` and has initial candidate tree
`9b089bf2392ae513b236f67145dd02d7db481184`. Exact admission binds its eventual
immutable source commit, complete tree, nine changed source files below and
unchanged graph. A later integrated source must retain the same red assertions,
controlled effects and explicit missing behaviors, with refreshed source review.

| Initial red source | SHA-256 |
| --- | --- |
| `src/Authentication.Cli/Program.cs` | `abf5eff9e242b6efe47607d00a29573644e706888fb524f47c472a5093fde384` |
| `src/Authentication.Core/RequestInvocation.cs` | `db28af72fc7a7fddf5ab2b71c86b62b4b1b8bfcdf149a4f3fbb515acc420b3c1` |
| `src/Authentication.Windows/OwnedRequestHost.cs` | `974f46553ab5995e1a9d20eae83b26123dc5189d96326faa660bfec536424f64` |
| `src/Authentication.Windows/WindowsProcess.cs` | `725eb510e3f7936fdfc2af2ad4230bb606eba12deed3619f36fa800577a6409f` |
| `tests/Authentication.Windows.Scenarios/OwnedWindowObservation.cs` | `5f1c911705b002e214b3de626bdc42a0050e44ce554cf547065fc79ad832e869` |
| `tests/Authentication.Windows.Scenarios/ProcessChild.cs` | `5c1a4dc64cef69e75c19c0222c287b66e753ee56c0d9d443a6ca537b39e4e184` |
| `tests/Authentication.Windows.Scenarios/ProcessFixture.cs` | `fa25a80815a698cf76fe4d69deda54459c873e854d0c28a4149a1550a920e18c` |
| `tests/Authentication.Windows.Scenarios/OwnedProcessChild.cs` | `ad7d69ec442683a95a69ac7e9871f87c15b3d2bfb7500da21d79779bb4b1e03e` |
| `tests/Authentication.Windows.Scenarios/OwnedProcessScenarios.cs` | `0e79e52148b64cb5b3ec7fefd57b304985ad1a117a2bca6dc940c1cac10e7ee4` |

The red glue reuses the entry-thread watchdog and shared process worker. It
constructs an inert owned host, binds the already admitted immutable Profile,
passes the normalized request to its synthetic provider and forwards asynchronous
host notifications to the existing process cancellation/core host-fault rules.
Dormant internal checkpoints arrange observations outside result-commitment locks.
It intentionally lacks synchronous typed host observation at commitment,
pre-readiness cancellation classification, the first host-ending watchdog
observation and actual owned-host completion in process drain. Those are the
selected red-to-green obligations. The production executable has no test flags or
environment-selected provider; its provider factory remains unavailable. Merely
compiling the native observation implementation does not execute its queries.

### Fixed Cases and Expected Results

The filter contains exactly the following fully qualified methods in
`Authentication.Windows.Scenarios.OwnedProcessScenarios`. Each method reserves one
listed child exactly once. No data rows, other test classes or dynamic selections
are included. Independent artifact review must bind generated registration,
method/case count, PE/PDB/source inputs and the complete command before the test.

| Method | Child | Initial red |
| --- | --- | --- |
| `NormalOwnedClosurePreservesSuccessAndDrains` | `host-success` | Passed |
| `LocalCancellationSuppressesSuccessBeforeDelayedNotification` | `host-cancel` | Failed |
| `LocalHostFaultSuppressesSuccessBeforeDelayedNotification` | `host-fault` | Failed |
| `CancellationDuringCreationSurvivesClosureFailure` | `host-create-cancel` | Failed |
| `OrdinaryCreationFailureRemainsMechanismUnavailable` | `host-create-failure` | Passed |
| `CleanupFaultAfterNormalClosureSuppressesUncommittedSuccess` | `host-fault-before-commit` | Failed |
| `CleanupFaultAfterCommitCannotReplaceTheResult` | `host-fault-after-commit` | Failed |
| `ProcessWaitsForTheActualOwnedThreadExit` | `host-ui-join` | Failed |
| `ProcessWaitsForTheOutgoingOwnedCallback` | `host-callback-drain` | Failed |
| `NormalClosureArmsTheBoundBeforeCoreTerminalSelection` | `host-close-stall` | Failed |

The initial red admission required exactly ten executed cases, two passes, eight intended
business assertion failures, all other counters zero and MTP exit 2. Each child
enters the shared production process using its controlled provider and a real
owned parent. `host-create-cancel` and `host-create-failure` return one
`mechanism_unavailable` result with child exit 1. The other eight return one
synthetic interactive success result with child exit 0. Its empty-stderr expectation
was incorrect; the [0039 disposition](#windows-action-0039-diagnostic-expectation-disposition)
preserves the actual failed run and defines the corrected diagnostic predicate.
No child may have fixture-forced termination. Compilation, loader, discovery, checkpoint/setup,
capture, safety or unexpected child-exit failures are not acceptable red.
Independent actual-red review identifies the first failed assertion and correlates
all ten complete child captures, event markers, ordering, exit and outer Job drain.
Do not implement green until that review accepts the actual red observations or
the exact qualified 0039 disposition is accepted with its required evidence review.

Green retains every admitted business, setup, ordering and drain assertion and
synthetic provider/fixture behavior, with only the diagnostic correction below.
It requires all ten exact cases to pass, all other counters zero and MTP exit 0:

| Child | Sole protocol outcome | Child exit |
| --- | --- | --- |
| `host-success` | `success`, interactive synthetic candidate | 0 |
| `host-cancel` | `cancelled`, no token or warning fields | 1 |
| `host-fault` | `internal_failure`, no token or warning fields | 1 |
| `host-create-cancel` | `cancelled`, no token or warning fields | 2 |
| `host-create-failure` | `mechanism_unavailable`, no token or warning fields | 1 |
| `host-fault-before-commit` | `internal_failure`, no token or warning fields | 2 |
| `host-fault-after-commit` | Already committed synthetic `success` remains unchanged | 2 |
| `host-ui-join` | Already committed synthetic `success` remains unchanged | 2 |
| `host-callback-drain` | `cancelled`, no token or warning fields | 2 |
| `host-close-stall` | No output before bounded termination | 2 |

Child exit 2 is the product's exceptional transport/shutdown outcome, distinct
from the outer MTP red code. A previously committed success JSON followed by
child exit 2 does not establish usable authentication success. The two exit-0/1
controls establish normal completion; faulted or stalled cleanup cannot be
reported as normally drained. Only fixed synthetic values may appear in output.

### Windows, Scheduling and Completion Effects

Each sequential child owns at most one parent and its existing static text and
Cancel control. At most ten parents are created per action: two creation-only
hidden parents and eight potentially visible parents, with one child/parent at a
time. Use the existing supplied-HWND ownership checks and observations; do not
enumerate the desktop, inspect other windows or use global keyboard/mouse input.
The selected automation needs no human input, choice or state unlock.

The cancel/fault races post only scalar WM_CLOSE or WM_NULL to the same child's
verified owned parent. The pre-readiness cancellation case additionally sends
WM_CLOSE synchronously on that parent's creating thread, after verifying both
process and thread ownership with GetWindowThreadProcessId/GetCurrentThreadId.
It never sends a blocking cross-thread message or broadcasts. The close checkpoint
then injects a synthetic exception after actual local user-cancel dispatch.
This checks that the original cancellation survives a later close failure.
Both outgoing notification paths remain gated until after result commitment;
no callback may replace the earlier typed cancellation with another failure.

Other checkpoints inject the declared post-readiness or final-cleanup fault,
observe native destruction before actual thread exit, or retain outgoing callback
work after cancellation forwarding. The callback-only fixture first performs a
bounded join and records actual STA exit before commitment while its outgoing
callback stays pending; it does not await aggregate host completion. This keeps
callback drain distinct from still-pending thread drain. The provider candidates
remain synthetic.
Before/after-commit checkpoints do not hold any commitment gate. The Closing
checkpoint is deliberately inside the host's local close operation so its bounded
stall exposes the gap before core terminal selection. Green must publish the first
host-ending observation before that checkpoint. It must retain the existing
host-to-process-to-core lock order and lock-free independent entry-thread watchdog.

All explicit fixture waits or stalls are at most three seconds, with a four-second
request deadline. The product's one-second local shutdown allowance starts at its
first ending observation, including ordinary coordinator closure, and is not
extended by those fixture waits. The existing same-host Windows QPC clock basis
and fixed 100 ms observation tolerance apply. Retain event timestamps before/after
commitment and notification, the first host-closing marker, native cleanup and
actual child exit. Normal scenarios observe completed host work; thread and
callback stalls deliberately require the product's own bounded process exit.

Reuse ProcessFixture's six-second child enforcement, two-second termination wait,
eight-second final capture bound, fixed replacement environment, explicit inherited
pipe handle list and outer non-breakaway Job. No shell or unrelated process is
started. Any fixture-forced termination, failed launch, uncertain owned child exit,
failed capture/finalization or safety marker stops later launches and both loops.
Retain the complete existing `temp/process-*` evidence projection: reservation,
start, stdout/stderr, fixed timestamp markers and exclusive final receipt for each
child. Per-stream capture remains at most 524,288 bytes; controller and subject
output/termination limits remain unchanged. Each fixed test and no-restore build
has the existing 120-second subject allowance, and controller work has 230 seconds
excluding the exact
prepared-action wait. No new termination target or cleanup authority is added.

Apply the [automated prepared-action procedure](#automated-synthetic-ui-coordination)
to both red and green `owned-process` tests. Prepare the exact action, receive its
actual awaiting event, independently verify the same ready receipt and live
controller, then immediately create its exclusive empty release marker. Do not
ask the owner to watch or confirm attendance for these automated scenarios. The
unchanged four-hour maximum, expiry/cancellation precedence and receipt schemas
still apply. Unexpected human interaction or any other UI surface follows the
existing stop procedure; it is not permission to automate or retry it.

### Controller Transition and Capacity

The first new Windows action under this supplement is one independently admitted
no-restore build 0038, after all 45 Linux and 37 Windows actions have finalized.
Bind the accepted Windows 0037 WSL start
`6e319296ad021197545950ab6805d578df817a4b5e339e65f9eeaf4c429b08df`
and final
`632955ce8c14d50aff82b018d94e11d3d9994765d922d744fcce0829ed46699f`.
All through-0037 attendance, source, controller, artifact and result evidence keeps
its original meaning and identity. Do not replay any accepted test.

During that build reservation only, the existing migration path retains and
replaces the two active Windows controllers, binding prior/current protocols and
exact old/new bytes in its receipt. No standalone replacement is permitted.
WindowsValidationJob.cs, its retained bootstrap DLL and Stop-WindowsValidation.ps1
remain unchanged. The Linux history reader changes only to recover the new exact
selection, prepared-action receipts and protected cumulative allocations.

| Helper | Accepted prior SHA-256 | Proposed SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `46459e4cf476c22e28432fa1397026a4b1b56f8580119e685db120dc6c7b4e55` | `10c7e85802ef7ed2c2c31acaeaa871141c5ae78da3bd7c557a28fac44eb2b030` |
| `Invoke-WindowsValidation.ps1` | `454a59e9d5fae0993c8842f50c11701c0311c5999830bea177f5cee130f0c104` | `aaab817f2b56092619b6af0a0af6c08f9e187986c149d3a9fcf3fdf7c1c9c506` |
| `run_managed.py` | `3881500e2e2564f2cb1869d5e27e739bff323e90e91c876285bfbee635fd0fab` | `2066550f4fdef2ed82046c15ec8c5c6c9c59fd9c9e833d66d0acce4e7eac4d26` |

The proposed helpers preserve old selectors and assertions, including the CLI
rejecting-stub capture branch, and add the exact owned-process report/child branch.
Both history readers reject malformed or undercharged new reservations and retain
all prior charges. Allocate exactly ten process units per newly reserved
`owned-process` test, even if the action stops before launch. Admit at most one
red and one green test, twenty new units in total; a stopped test does not refund
its reservation or grant a retry.

Raise this protocol's process ceiling from 36 to 56 within the unchanged Wave
ceiling of 60. Keep the existing CLI suballocation at 36, of which 24 are consumed;
the final twelve CLI units cannot be consumed by this new selection. At most
twenty units belong to the new owned-process selection. The remaining four Wave
units are unallocated buffer and require another exact protocol before use.

After 0037, build/test consumption is Linux 37/80 and Windows 32/40, combined
69/120. The planned red build/test and, only after actual-red acceptance, green
build/test consume four Windows units, reaching 36/40 and combined 73/120 if no
intervening consumption occurs. Preparation remains 13/16, Windows 5/5, charged
downloads 768 MiB, and prior synthetic process charges 24. No restore, publish or
new download is authorized. The helpers retain the shared action lock and all
existing finite stop conditions. Admission is separate for every build and test;
this supplement does not start an automatic sequence.

Source, dependency, artifact, domain and actual-result reviews remain required.
This selection establishes only the exact managed Windows process/owned-host
composition outcomes it observes. Real native admission, real MSAL initialization,
account selection, WAM, cache/reuse, physical UI usability, actual WSL caller
lifetime, final product Native AOT and whole-Slice acceptance remain open.
Account-state effects still require the concrete owner risk amendment in the Wave.

Official API basis for the added same-thread scalar close:
[SendMessageW](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-sendmessagew).

## Windows Action 0039 Diagnostic-Expectation Disposition

Windows 0039 completed all ten selected cases under protocol/target
`9f649e8d2ca46ecc719ad36c3aa895da8e23c7fb`, using source
`8f4610a1dbdeed4e6374d05c3c62a3425fd1b425`, tree
`9b089bf2392ae513b236f67145dd02d7db481184`. Its preceding no-restore build 0038
completed with zero warnings/errors and 547 artifacts; its
[independent artifact acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672004666)
and [exact test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672019856)
retain their original bindings. This disposition does not change either subject.

The actual TRX is **10 executed, 0 passed, 10 failed**, with all other counters
zero. MTP exited 2; the outer helper exited 1, recorded `ValueError`, omitted its
`tests` field and retained `continuation_allowed=false`, `quiescent=true`.
Native execution took 6.63 seconds with complete capture, no safety stop or
termination request, and 22 total Job processes with none active. Every child
was unforced and its captures and final receipt are complete. The automated
prepared-action release required no owner interaction. All dedicated artifacts
remain intentionally retained; no account, broker, cache or external service
operation was selected.

The [originating OP-RED-02 finding](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672268083)
and [independent true-positive triage](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672256937)
identify the invalid empty-stderr expectation. All ten children emitted exactly
the permitted 34-byte `Authentication request completed.\n` indication. The
accepted design separates that fixed human indication from optional telemetry
and excludes diagnostic work from required process drain. The two control tests
first failed only the empty-stderr assertion. The other eight first failed the
intended outcome/exit assertion after their required setup and ordering checks.
The actual counters necessarily fail the helper's TRX validation; its later
child-stderr predicate would also reject the captures. The receipt has no
exception stack, so the exact recorded throw site is not established by that
source-derived sequence alone.

Independent inspection separately evaluated every original non-stderr control
assertion, including assertions skipped after the actual first failure:

- `host-success` has the required provider, candidate, closing, native-cleanup
  and host-drain markers, no pending cancellation/fault marker, unforced exit 0
  and one success result with all exact synthetic token/email/tenant metadata
  and interactive acquisition.
- `host-create-failure` has the required hidden-parent, native-cleanup and
  host-drain markers, no provider-ready or pending-cancellation marker, unforced
  exit 1 and only the protocol-1 `mechanism_unavailable` outcome/reason fields.

The disposition accepts eight observed intended business failures and these two
separately inspected control observations as the qualified basis for the four
existing GREEN obligations. It does not accept a clean 2/8 RED run, turn either
failed control into a passed test, or claim corrected tests have executed.
Acceptance requires independent research-evidence review of the exact source,
compiled-artifact binding, complete captures and markers, relevant protected
input/tool postconditions, normal Job drain and the diagnostic-only correction.
The accepted amendment and that review must precede GREEN implementation. Exact
source, artifact and action admission remain separate before execution.

### Corrected Diagnostic Predicate

Only `OwnedProcessScenarios.AssertExit` and the corresponding owned-process
helper predicate change. Preserve production diagnostics, all ten selected
methods and every business, setup, ordering, output and shutdown-bound assertion.
For one committed result, captured stderr may be any byte prefix, including
empty or complete, of `Authentication request cancelled.\n` for `cancelled`, or
`Authentication request completed.\n` for any other admitted outcome. Without
a committed result, the close-stall case requires empty stderr. No extra bytes,
telemetry events, provider text or raw exception output are allowed. This bounds
diagnostic content without requiring the optional writer to drain.

Microsoft's [anonymous-pipe contract](https://learn.microsoft.com/windows/win32/ipc/anonymous-pipe-operations)
defines full-write completion or an error, while
[TerminateProcess](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess#remarks)
cancels pending I/O. These contracts do not establish complete-or-empty capture
when a background writer ends with the process. Prefix allowance is a bounded
validation rule, not an observation of partial output in 0039. No partial
indication was observed there. The corrected source assertion SHA-256 is
`cb5197bc9c97ea10f257f26a7fb5131489782dc0b67832b253ca0fdee36dcb70`.

### Exact History and First Continuation

Preserve all original bytes and charges. Both history readers recognize only
the following exact WSL receipt set for stopped Windows 0039:

| Receipt | SHA-256 |
| --- | --- |
| `started.json` | `9ad80c13d63adec92abc0557b01ff9006e860d714f36455917b17a904f06d416` |
| `windows-input.json` | `a926fad126c073e6a0fe3127dfccc34fa3e7f846f6d920778001a66272a17bc5` |
| `result.json` | `70a2f2e0d177ce230ac7765e95f8682200878a466b40b698fb9af034e0615572` |

The final receipt binds all 194 Windows evidence files. Both readers check the
complete file set, hashes, direct paths, unchanged reservation and prepared-action
release bindings, and absence of safety markers. Its 19-directory shape is bound
by SHA-256 `0ee100b271ff3f109ea874d8f2a3fde3c20741f249898d22ca62c2b56519d2aa`
over the sorted relative directory names serialized as compact JSON. No generic
failed-action exception is added. Native final SHA-256 is
`d384323ea4bd80b1842dbee0a5ca3429b9b2d801f630338b698f320fc1e7be49`;
the sole 33,192-byte TRX is
`6e7311ea061492f9b2fc1c2bbb946e8ee0dd9356cfade1471f6df6a0df8d8e6a`.
Machine-derived filenames remain private.

The first continuation is a separately admitted no-restore Windows build 0040
of newly reviewed corrected source. During that action only, use the existing
retaining migration path to replace `run_windows.py`, whose prior SHA-256 is
`10c7e85802ef7ed2c2c31acaeaa871141c5ae78da3bd7c557a28fac44eb2b030`.
Retain its old bytes and bind prior/new protocols and helper hashes in the
migration receipt. The PowerShell, native Job and stop controllers stay unchanged;
no standalone replacement is allowed. Linux continuation remains blocked until
that Windows build completes. Proposed helper SHA-256 values are:

| Helper | SHA-256 |
| --- | --- |
| `run_windows.py` | `d1c7f31e6c68cf11520c998cbb3af78dba277484ea90ce07dca23a1f67167271` |
| `run_managed.py` | `d354c86de672ba814aebd350a91ad20d96b7b3aa34fd0bebc1e53974d6451749` |

After 0039, all 45 Linux and 39 Windows actions are finalized. Build/test charges
are Linux 37/80, Windows 34/40, combined 71/120. Preparation remains 13/16,
including Windows 5/5, and downloads remain 768 MiB. Process charges are 34/56:
24 CLI and all ten units of the stopped owned-process RED. Only the one remaining
ten-case owned-process GREEN is available; no further RED or retry is admitted.
The protected final twelve CLI units remain available, bringing planned final
process consumption to 56, within the unchanged Wave ceiling of 60. Its four
unallocated buffer units remain unavailable without another exact protocol.
No charge is refunded or reassigned. Future GREEN still requires all ten cases
to pass with MTP exit 0 and their admitted child outcomes and measured bounds.
All prior evidence limitations and remaining whole-Slice obligations remain open.

## Owned Host Process Composition Evidence

The four GREEN obligations use source
`e64229bed5c29d6ba4b6346ed76bf7a8162bf553`, tree
`508d9e75fc8e28c49fa0925628066e11006fce5f`, under accepted protocol/target
`01d0993ab41e5b7fdf47d795f794397426b8d425`. The
[independent source review](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672560416)
binds the two production corrections and unchanged ten-case business fixture.
The [qualified 0039 acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672507711)
remains its prerequisite; the actual earlier result stays 0 passed / 10 failed.

The host synchronously retains typed cancellation or host failure and consumes it
before result commitment, preserving host-to-process-to-core lock order. Cancellation
during creation completes pending readiness with the typed cancellation outcome
before closure. The first host-ending timestamp is published before closure and
read by the independent watchdog. Process completion waits for invocation completion
before the owned thread and outgoing callbacks; failed or stalled cleanup cannot
be reported as normal completion. Production provider initialization remains inactive.

| GREEN production source | SHA-256 |
| --- | --- |
| `src/Authentication.Windows/OwnedRequestHost.cs` | `41c5b0ca176da8b3adbb8db92f076fb12242d84a6c0333f886c1eb71b4390fdd` |
| `src/Authentication.Windows/WindowsProcess.cs` | `1f55cb947b4c9f95a3995360566640ae91581dc3fd7279cc556823e856c9dae5` |

The [separate build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672677481)
selected one no-restore Release build 0040. Its original outer invocation completed
with exit 0. Native build execution ended at 2026-09-15T00:29:10.4354023Z and took
12.549 seconds, with zero warnings/errors, complete capture, empty stderr, eight
total Job processes and zero active processes, without termination. The build
manifest contains 547 artifacts. Its
[independent acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672906977)
binds the actual source, PE/PDB/IL, 47 physical source documents, generated test
registration, complete command and protected-input postchecks. The registered
104 methods and 111 projected cases include exactly the ten owned-process methods;
registration is not evidence that those tests have executed. The native ABI and
all business assertions remain unchanged.

Only the active `run_windows.py` changed during the recorded retaining migration.
Its old bytes, the original stopped 0039 history and all prior charges remain
preserved. Build 0040 consumes one Windows build/test unit: Windows 35/40 and
combined 72/120, with Linux 37/80, preparation 13/16, Windows preparation 5/5,
768 MiB charged downloads and 34/56 process units unchanged.

| Actual build receipt | SHA-256 |
| --- | --- |
| WSL `started.json` | `d1850aab5f383af17820b5a806eebe0055ac2bdeaa0dcb99f53a154b15d02fd9` |
| WSL `windows-input.json` | `8a103e2e49a424230ab87d3b41213fdc10ea52f01a594046a62bbabe8bfe555d` |
| WSL `result.json` | `b1ab5bcbb9435076d07b538d064cd657753e8e308dbf59bc9e93276df2fb9ce1` |
| Windows `windows-result.json` | `78005d5aab6790000bcd742d6de71b78db77337ac106bd923ab8a8cf37b920d6` |
| Windows `build.json` | `124d191355bdd4a5d02d03834f890bc2fd8b4a4c560a60e8f0d9d767d4fcb1c6` |

The [separate GREEN test admission](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5672935900)
selected only the unchanged ten owned-process cases against those accepted artifacts.
Windows 0041 completed with **10 executed, 10 passed, 0 failed**, every other outcome
counter zero, and MTP/outer exit 0. Native execution took 9.365 seconds; stdout was
642 bytes and stderr empty, with complete capture, 22 cumulative Job processes and
zero active processes. No Job termination or safety stop occurred. The helper completed
its source, tool, protected-input and history postchecks and allowed continuation.

Preparation published the exact ready record at 2026-09-15T00:58:27.9665534Z. Independent
live-controller verification and the reviewed immediate automatic release used the same
reservation. No owner input or attendance was required. Both gate acknowledgements and
the final 190-file evidence set remain retained with the sole 15,025-byte TRX. The
original outer invocation was fully collected; no subject retry occurred.

The ten actual child outcomes and exits match the existing GREEN table. All three
synthetic success objects have the twelve required fields and omit the optional
correlation ID, which the unchanged fixture leaves null. A committed success followed
by child exit 2 remains unsuccessful shutdown/transport, not usable authentication.
The no-result close-stall child has empty output and diagnostics. The
[independent actual-result acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/148#issuecomment-5673162805)
binds every child outcome, exit, capture, required/prohibited marker and ordering.
Four normal exits occurred 45.355–68.311 ms after host-closing with aggregate drain
evidence. Six exceptional exits occurred 1,017.371–1,026.692 ms afterward without
normal drain or fixture-forced termination, within the original one-second product
allowance and fixed 100 ms observation tolerance. The private offline reader's
mandatory-correlation defect received independent triage and correction review;
its failed inspection remains preserved and did not trigger a subject rerun.

| Actual GREEN receipt | SHA-256 |
| --- | --- |
| WSL `started.json` | `5d1fd49bef654fdfd4dd5773c7f766115549e99dee348b0ad7638fa25f1274e4` |
| WSL `windows-input.json` | `988d9ed2e5133e2458858a09b77fead5c23ebe63f1e6a2769f0d75ca3875c771` |
| WSL `result.json` | `06c6a4077e3272a6584f21ec35095d3f34f6e03b7de4ba406949acec4f1b37d9` |
| Windows `windows-result.json` | `b203ea83bbe5d823d2b93a57c92094559d55b7dc3af038f391e1a6f59f052072` |
| Complete TRX | `10d3c5dafb904fd575d9af46374117a0f5cc4d5ca050fe1fa26e51f42289f1d7` |

After 0041, all 86 actions are finalized: Linux 45 and Windows 41. Build/test use is
Linux 37/80 and Windows 36/40, combined 73/120. Preparation remains 13/16, including
Windows 5/5, with 768 MiB charged downloads. Process use is 44/56: 24 CLI and all twenty
owned-process units. The final twelve CLI units remain protected, and the Wave's four
additional buffer units are unallocated. No new action or retry is admitted by this
result. All dedicated files and prior stopped histories remain intentionally retained.

These observations concern the exact managed Windows production-process/owned-host
composition with controlled providers and real owned test windows. Real native admission,
production MSAL initialization, WAM/account selection, reuse, Windows/WSL lifetime, final
Native AOT and whole-Slice acceptance remain open. No account, broker, cache, consent or
resource operation was selected. Account-state effects still require the concrete owner
risk amendment and its exact protocol.

## MSAL Adapter Composition Supplement

This supplement selects one controlled adapter red/green increment under Issue #108
and the accepted Windows Slice Wave. The
[owned-host process result](#owned-host-process-composition-evidence) at accepted
`71223ab9225f3ff9713f07c68cdb469d428d2b04` is its completed prerequisite. No earlier
scenario, stopped action or capacity allocation is reset or replayed.

### Subject and Effects

Use the existing Windows 11 x64 host and WSL2 controller, unchanged Windows.slnx
four-project graph, SDK 10.0.401/runtime 10.0.12, MSTest 4.1.0, MSAL/Broker 4.83.1
and NativeInterop 0.20.3. Reuse the accepted public caches, restore outputs and
toolchain. This supplement selects no restore, download, installation, Native AOT
publish or dependency change.

The real adapter maps the admitted immutable Profile and normalized request to one
internal MSAL session boundary. Synthetic sessions implement that boundary and return
public synthetic `IAccount`, `AuthenticationResult` and MSAL exception values. The
real coordinator and `LocalWindowsProvider` remain the business and local-admission
consumers. The loader restriction is a supplied controlled callback. No selected
path constructs a real MSAL application or configuration, calls `IsBrokerAvailable`,
initializes NativeInterop Core, invokes native host observations or DLL-search APIs,
enumerates real accounts, acquires a token, accesses reusable authentication state,
or opens provider UI. The product entry point remains unavailable during this increment.

The HTTP ownership scenario uses the actual `IMsalHttpClientFactory` implementation,
one process-owned client and the existing managed User-Agent handler over a terminal
in-memory `HttpMessageHandler`. The terminal handler has no inner network transport
and opens no socket. It records fixed synthetic header values, holds one request,
observes cancellation and drains before owner disposal. It does not establish any
broker-owned HTTP behavior. No telemetry exporter, logging callback, account file,
credential, consent, authenticated resource request or remote mutation is selected.

All sixteen cases run inside the existing managed test process. No case uses
`ProcessFixture`, launches a child, creates a real window, or requires operator input,
choice or unlock. Synthetic parent value 42 never crosses a native boundary. The
prepared-action attendance procedure is inapplicable; do not ask the owner to watch
this selection. Existing unexpected-effect and termination stop conditions remain.

### Source and Fixed Scenarios

Exact admission binds the immutable source commit and tree, all changed source files,
unchanged graph and pinned inputs, separately for each build and test. Initial source
adds `MsalSession.cs`, `MsalAuthenticationProvider.cs`, `MsalHttpClientFactory.cs`,
`MsalCompositionScenarios.cs` and `MsalHttpOwnershipScenarios.cs`. The red initializer
deliberately returns mechanism unavailability before loader/session construction;
the red HTTP factory deliberately creates a new client on each request. Every other
production and scenario file remains byte-identical to the accepted prerequisite.

The `msal-composition` filter names only the following methods. There are sixteen
methods and sixteen cases, without data-row expansion or wildcard class selection.
The six route cases share assertion code while retaining independent scenario names.

| Class | Method | First expected red failure |
| --- | --- | --- |
| `MsalCompositionScenarios` | `OrdinaryMultitenantProfileUsesCommon` | Missing selected-account success |
| `MsalCompositionScenarios` | `FixedWorkProfileUsesItsTenant` | Missing selected-account success |
| `MsalCompositionScenarios` | `ExplicitWorkTenantOverridesCommon` | Missing selected-account success |
| `MsalCompositionScenarios` | `LegacyPersonalAccountUsesTheTransferTenant` | Missing selected-account success |
| `MsalCompositionScenarios` | `LegacyWorkAccountRetainsOrganizations` | Missing selected-account success |
| `MsalCompositionScenarios` | `ExplicitResourceTenantWinsOverLegacyPersonalRouting` | Missing selected-account success |
| `MsalCompositionScenarios` | `SilentClaimsContinueWithTheSameAccountAndNoCompetingHint` | Missing permitted continuation success |
| `MsalCompositionScenarios` | `NoVisibleMatchUsesOnlyTheRequestedLoginHint` | Missing permitted login-hint success |
| `MsalCompositionScenarios` | `ASecondChallengeStopsAndDoesNotExposeProviderDetails` | Unavailability instead of interaction requirement |
| `MsalCompositionScenarios` | `DiscoveryFailureUsesTheSameSafeProviderClassification` | Unavailability instead of transient failure |
| `MsalCompositionScenarios` | `ProviderInitializationFailureUsesTheSameSafeClassification` | Unavailability instead of transient failure |
| `MsalCompositionScenarios` | `CancellationDuringLoaderSetupPreventsSessionConstruction` | Unavailability instead of cancellation |
| `MsalCompositionScenarios` | `FailedLoaderSetupPreventsSessionConstruction` | Controlled loader callback was not reached |
| `MsalCompositionScenarios` | `CancellationDuringSessionConstructionPreventsDiscovery` | Unavailability instead of cancellation |
| `MsalCompositionScenarios` | `OriginalCancellationWinsOverADiscoveryFailure` | Unavailability instead of cancellation |
| `MsalHttpOwnershipScenarios` | `OneOwnedClientSurvivesOperationsUntilCancellationAndDrain` | Distinct clients instead of one owned client |

The route cases retain the accepted ordinary/fixed/explicit tenant rules, legacy
organizations and MSA transfer-tenant routing, exact selected `IAccount` handle,
scopes, separate operation and observed correlation metadata, original cancellation
token, and no unnecessary interaction. The continuation cases retain mutually
exclusive account/login hint, silent-origin claims, one permitted interactive call,
owned synthetic parent and closure. Provider errors use the existing safe mapping;
loader/session cancellation prevents later effects. These are scenario assertions,
not claims about MSAL's internal configuration or real broker behavior.

Red requires exactly 16 executed, 0 passed, 16 intended assertion failures, all other
counters zero and MTP exit 2. Green requires the identical sixteen cases and assertions
with 16 passed, every other counter zero and MTP exit 0. Compilation, setup, discovery,
loader, timeout, aborted, capture or safety failures are not acceptable red evidence.
Do not implement green until independent actual-red review accepts the first failure
in every complete result and its expected business cause. Green may implement only
the selected adapter mapping/initialization and HTTP reuse/ownership omissions; a
new concrete broker bridge, default entry-point activation or changed assertions
requires separately reviewed source and protocol coverage.

Each no-restore Release build and managed test retains the existing 120-second subject
limit and 230-second controller limit. Preserve the outer non-breakaway Job, output
limits, bounded capture and quiescence checks, source/tool/history postchecks and
intentional retention. The terminal HTTP wait is cancelled inside the scenario and
both observation/drain waits have a two-second limit. Before each test, independently
review the actual compiled PE/PDB/IL and generated registration, all sixteen method
identities, selected effects and the complete literal command. Afterward, accept the
full report, first failures or success assertions, counters, captures, receipt bindings
and Job drain. Exact source or artifact inspection is not runtime scenario evidence.

### Controller Transition and Capacity

The first new action is a separately admitted Windows no-restore build 0042, after all
45 Linux and 41 Windows actions have finalized. Bind the accepted 0041 WSL start
`5d1fd49bef654fdfd4dd5773c7f766115549e99dee348b0ad7638fa25f1274e4`
and final
`06c6a4077e3272a6584f21ec35095d3f34f6e03b7de4ba406949acec4f1b37d9`.
Only this build reservation may use the existing retaining migration to replace the
two active controllers with the independently reviewed bytes below. No standalone
controller replacement or mutation of prior receipts is permitted. The Linux reader
changes only to recognize the new zero-child reservation; its prior history rules
remain unchanged. Job/bootstrap/stop components do not change.

| Helper | Accepted prior SHA-256 | Proposed SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `d1c7f31e6c68cf11520c998cbb3af78dba277484ea90ce07dca23a1f67167271` | `c0477077eff68182bae6f6b7d9aced6e56d3e3864d15bcd2b7ea25e8c75924e8` |
| `Invoke-WindowsValidation.ps1` | `aaab817f2b56092619b6af0a0af6c08f9e187986c149d3a9fcf3fdf7c1c9c506` | `7bbac1e2f2688d9057258c4ad7b67493c8f78926aa297387c9f2e410d4eb212f` |
| `run_managed.py` | `d354c86de672ba814aebd350a91ad20d96b7b3aa34fd0bebc1e53974d6451749` | `ddf40d86777a03881a93e7bac55736b22915b6705a221dbcf3c5e9d39731fb21` |

The helpers require accepted 0041 history, exactly one new red test and at most one
subsequent green test, with zero reserved child-process units. Admission remains
separate for every action; the supplement does not authorize an automatic sequence
or a retry. The initial red build/test and subsequent green build/test consume four
Windows build/test units: current Windows 36/40 becomes 40/40, and combined 73/120
becomes 77/120 if there is no intervening consumption. Linux remains 37/80.
Preparation remains 13/16, including Windows 5/5; charged downloads remain 768 MiB.
Process consumption remains 44/56, including all twenty owned-process units; the
final twelve CLI units and four unallocated Wave buffer units are untouched.

No allowance is refunded on failure. Insufficient capacity, unexpected effects,
incomplete evidence or failed quiescence stops further actions under the existing
rules. Further Windows allocation or native/AOT/account evidence needs its exact
accepted amendment. This controlled adapter result cannot complete the still-open
native admission, real MSAL/WAM, reuse, actual Windows/WSL lifetime or final product
Native AOT obligations; real account effects retain their concrete owner risk gate.

## MSAL Adapter Composition Evidence

This increment implements the selected adapter mapping and HTTP ownership omissions
in the [composition supplement](#msal-adapter-composition-supplement). Source
`bd7e217aba300e1a77e0fef183e24fc1bf5429fb`, tree
`632edd8daa3bd69d9a5e8ead67720b6365001b36`, adds the internal session boundary,
inert adapter/factory baseline and sixteen scenarios. Every prior source and scenario
file remains unchanged from accepted `71223ab9225f3ff9713f07c68cdb469d428d2b04`.
Accepted protocol/target `caef2cedd4bc3db06c3661c0735374c50d4691de` governs the
executions. Independent reviewer `/root/lifetime_triage` accepted actual build and
RED evidence; `/root/wave_review` supplied action admission and the source-coordinate
triage. `/root` authored the implementation and operated the actions.

### Accepted RED

The [single build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5673503206)
selected no-restore Release build 0042. Its original invocation completed with exit 0;
the Windows build completed in 12.625 seconds, with zero warnings/errors, complete 713-byte
stdout, empty stderr, eight cumulative Job processes and zero active at exit.
The [actual-build acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5673751476)
binds its 547-artifact manifest, actual PE/PDB/IL, 52 physical source documents and
generated registration. There are 120 attributed methods and 127 projected cases,
including exactly sixteen new cases. Only this reservation performed the accepted
retaining replacement of both controllers; original bytes and migration evidence
remain retained.

Current catch types and unchanged prior source were directly reviewed. Two historical
catch-TypeRef names were not retained independently, so the comparison does not claim
complete historical semantic token equivalence. Named ClassLayout owners retain their
packing and size despite metadata RID renumbering. These recorded decoding limits do
not establish a changed native ABI.

The [separate RED admission](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5673767604)
selected test 0043. Its original invocation completed with outer exit 0; MTP returned
the expected exit 2 in 1.349 seconds. Exactly sixteen cases executed and failed;
zero passed and every other outcome counter was zero. Complete stdout is 21,677 bytes,
stderr is empty, and two cumulative Job processes ended with zero active. No safety
stop or termination occurred; the final receipts allow continuation.

The [actual RED acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5673950211)
correlates every complete TRX result and stdout failure with its exact method,
compiled assertion and intended missing behavior. Eight success assertions fail
because initialization returns safe mechanism unavailability before loader/session
work. Six classification assertions require interaction, temporary unavailability
or cancellation instead. The failed-loader case passes the safe classification,
then fails because the loader callback was not reached. HTTP ownership first fails
reference equality at line 17 / IL 103, before the first send at IL 183; its covering
finally follows factory disposal.

For `NoVisibleMatchUsesOnlyTheRequestedLoginHint`, the runtime frame reports line 108
while the source/PDB assertion is line 109. The
[independent triage](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5673941488)
accepts this specific first failure using the exact method, unique first `IsNotNull`
call at IL 150, success expression and message. Both coordinates remain preserved;
no runtime stack-mapping explanation, normalized line, changed assertion or retry
is claimed.

| Actual receipt | SHA-256 |
| --- | --- |
| Build 0042 manifest | `2577a3ce26172c1330654a9fbbcb5a92ac11875e2deea2e0fb10ecbcb18f8d60` |
| Build 0042 WSL final | `ffa4e76ff59a2d0e9204368d9ac0ca9e5e7497a3dcaa66d92e53005032a2e57f` |
| Build 0042 Windows final | `997eb1fa4558c63a1723921e045507fea42773afe3f790a1e1ec78fc9fc696c6` |
| Test 0043 WSL final | `f05d091ff7532d86e24e1cd2199de3b43b90740fcbe365a2b803e813dcd54af9` |
| Test 0043 Windows final | `984f675e3296b8d77bce9839e05bc5ec64db007698f66839a2d4a3447eeb811f` |
| Complete RED TRX | `efef4ca961d2fbcd66443b781da1333e24b29656e279a17828f27f373e17dd5a` |

### Reviewed GREEN Source

After actual RED acceptance, source
`ec4303bf8be9d680155d3b3673ea3ccdccb5974a`, tree
`ece5571897a6b001785f1fdfe63e9c3855c6c172`, changes only
`MsalAuthenticationProvider.cs` and `MsalHttpClientFactory.cs`. All sixteen cases
and assertions, the internal session boundary, project/dependency inputs and default
unavailable entry remain unchanged. The
[independent source review](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5673986488)
binds controlled loader/session ordering, original cancellation, Profile/tenant/redirect
mapping, exact account handles, claims and mutually exclusive account/login hint.
Legacy MSA transfer routing applies only to silent calls without an exact resource
tenant. One owned HTTP client retains its managed User-Agent handler and supplied
transport until owner disposal after request drain.

### Accepted GREEN Build

The [separate build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5674106847)
selected no-restore Release build 0044 from the reviewed GREEN source. The original
invocation completed with exit 0; the Windows build completed in 11.759 seconds, with zero
warnings/errors, complete 713-byte stdout, empty stderr, eight cumulative Job processes
and zero active at exit. No controller migration, termination or safety stop occurred.

The [independent actual-build acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5674355065)
binds 2,005 inputs, 376 tools and 547 artifacts, including 109 freshly hashed
non-package outputs and 438 reused package identities. The actual PE/PDB/IL and
registration preserve all sixteen selected definitions and assertions. Only the two
intended production source checksums changed. Existing CLI, Core and scenario method
semantics remain unchanged; two changed catch TypeRef tokens in another Windows method
resolve directly in both builds to `System.Text.Json.JsonException` and
`System.InvalidOperationException`. This current comparison does not reconstruct the
older build 0040 decoding limitation.

Compiled mapping preserves original cancellation, exact account identity, tenant
precedence, request context, safe result/failure projection and mutually exclusive
account/login hint. The actual HTTP factory returns one owned client. The scenario
owner supplies cancellation and drain before disposal; the factory does not implement
an independent request-drain protocol. Compilation establishes no passing test result.

| Actual receipt | SHA-256 |
| --- | --- |
| Build 0044 manifest | `0cc53ebb95904ef27db08afde61447c0bdeca2c6958da7039a75804d980544a9` |
| Build 0044 WSL final | `f3eb03a037424f599f5ea7f39164bd6903749e15c9bebfe2587ab6c1a01b7145` |
| Build 0044 Windows final | `002882acccf6fb4ddb1825a55c04ec80b6a7d9d09e5100f1bace250d6df52d63` |

### Accepted GREEN Scenarios

The [separate GREEN admission](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5674411161)
selected test 0045 against the accepted build 0044 artifacts. The original invocation
completed with MTP/outer exit 0. Exactly sixteen cases executed and passed, with zero
failed and every other outcome counter zero. Windows test execution took 0.929 seconds;
complete stdout is 639 bytes and stderr is empty. Two cumulative Job processes ended
with zero active, no termination and no safety stop. Source/tool/history postchecks
completed, and the final receipts allow continuation.

The [independent actual GREEN acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5674576945) binds the complete report and captures to all sixteen
unchanged definitions, execution/result joins and compiled assertions. The report has a
Completed summary and no RunInfo or ErrorInfo. Profile and tenant mapping, account
identity, claims continuation, original cancellation and safe failure projection pass
through the real coordinator and local provider to controlled sessions. The HTTP case
observes the same client across operations, cancellation of its pending managed request,
and transport disposal only after the scenario owner drains that request. It does not
establish production-process HTTP ownership or an independent factory drain protocol.

| Actual receipt | SHA-256 |
| --- | --- |
| Test 0045 WSL start | `5e3e684f790c30eed91f4a26829f5cb4cedbe63303d5003ef0eda09cc5f18985` |
| Test 0045 WSL final | `6c0d567b62b8e3f856b3dd67d7a1cee0d4c93bdc458a1f5a6487a80a81b6023c` |
| Test 0045 Windows start | `71573fef37f1aa5ec5c0f2c6a35dafcae52c24ce33bab3c5353683b7e6f0f7bf` |
| Test 0045 Windows final | `3b3c2c82c004ffaab825d7699acd73c816340b03a4e2388d5aa3ceb017e55d42` |
| Complete GREEN TRX | `e4d220ffd29940dce34e119b3d4eb6149d509e2dc71ac042cf404016afb473bb` |

After 0045, all ninety actions are finalized: Linux 45 and Windows 45. Build/test use
is Linux 37/80 and Windows 40/40, combined 77/120. Preparation remains 13/16 including
Windows 5/5, with 768 MiB charged downloads. Process use remains 44/56, including all
twenty owned-process units. The final twelve CLI units remain protected and the four
additional Wave process units unallocated. No retry, refund or next action is admitted
by this evidence; a further Windows action needs the applicable accepted allocation and
exact admission. Dedicated artifacts and all prior stopped histories remain retained.

These are controlled adapter and HTTP ownership observations, with no real loader,
MSAL application construction, broker availability/account call, token acquisition,
network, UI, cache or consent operation selected. Concrete MSAL construction, native
and default composition, real WAM/account selection and reuse, Windows/WSL lifetime,
final Native AOT and whole-Slice acceptance remain open. The current account-state
effects boundary and concrete owner risk amendment remain prerequisites to the later
real-account operations.

## Concrete MSAL Construction Supplement

This supplement selects one construction/contract red/green increment under Issue
#108 and the accepted Windows Slice Wave. The [MSAL adapter composition result](#msal-adapter-composition-evidence)
is its prerequisite. The real availability, account operations, native/default entry,
WSL lifetime and final Native AOT obligations remain open.

### Production Boundary and Fixed Selection

Reuse Windows.slnx, its existing four-project graph, SDK 10.0.401/runtime 10.0.12,
MSTest 4.1.0, MSAL/Broker 4.83.1 and NativeInterop 0.20.3, with the existing public
caches and restore outputs. No restore, download, dependency change, tool installation
or Native AOT publish is selected.

Add a concrete factory/session behind the existing `IMsalSessionFactory` and
`IMsalSession` interfaces. One internal production `BuildApplication` helper uses the
real public MSAL builder and supplied HTTP factory. Production `Create` calls that
same helper, checks original cancellation around construction and mandatory real
broker availability, and returns a usable session only after availability succeeds.
Account discovery remains a later cancellation-aware operation. Preserve host admission
and loader restriction before factory creation; never select MSAL's OS-account sentinel.
Do not add an availability bypass, fluent-builder mock or reflected configuration model.
The default product entry remains unavailable during this increment.

Initial source adds `MsalSessionFactory.cs` and `MsalConstructionScenarios.cs`.
Every existing production/scenario file, project and pinned dependency input remains
unchanged from the accepted composition prerequisite. The RED factory calls the inert
construction helper and then reports mechanism unavailability. GREEN implements only
the construction helper and concrete session bindings; all four scenario bodies and
assertions remain unchanged. Separately bind each immutable source/tree at admission.

Only `BuildApplication` executes in this selection. The remaining factory/session
bindings receive public-API, source and compiled review without executing availability,
discovery or acquisition. Per-operation tenant mapping preserves `common` and
`organizations`; `WithTenantId` applies only to the admitted restrictive or transfer
tenant GUID. Construction results do not establish per-operation behavior.

The `msal-construction` filter selects exactly four methods in
`Authentication.Windows.Scenarios.MsalConstructionScenarios`, without data rows:

All cases use synthetic client ID `22222222-3333-4444-5555-666666666666`, public
authority host `https://login.microsoftonline.com/`, and explicit redirect
`ms-appx-web://microsoft.aad.brokerplugin/22222222-3333-4444-5555-666666666666`.
The restrictive tenant is synthetic `11111111-2222-3333-4444-555555555555`.
The ordinary, legacy and restrictive cases select `common`, `organizations` and that
GUID respectively. Listing OS accounts is configured true; MSA passthrough is true
only for the legacy case. These are local intentions, with no account call selected.

| Method | Required result | First expected RED failure |
| --- | --- | --- |
| `OrdinaryProfileConstructsCommonApplication` | Real public configuration retains the synthetic client, common authority, explicit redirect, supplied factory and broker enablement. | First non-null application assertion. |
| `LegacyProfileConstructsOrganizationsApplication` | Real public configuration retains organizations authority and the same explicit configuration constraints. | First non-null application assertion. |
| `ExactTenantProfileConstructsRestrictedApplication` | Real public configuration retains the exact synthetic tenant authority and the same explicit configuration constraints. | First non-null application assertion. |
| `OriginalCancellationPreventsApplicationConstruction` | Original already-canceled token cancels before construction or HTTP-factory use. | Required cancellation assertion. |

Each successful construction case also asserts disabled PII/default logging, no logging
callback or unsolicited capabilities, supplied factory identity and no request for its
client. The factory wraps the existing owned HTTP client over a rejecting terminal
handler with no network transport. Any client request or send is an unexpected selected
effect and fails the case. Dispose the owned client after synchronous work returns.
There is no pending HTTP request to drain in these cases.

Public `IAppConfig` does not expose `BrokerOptions`; `ListOperatingSystemAccounts` and
`MsaPassthrough` assignments receive source review and retain later real-effect
obligations. No public-getter runtime coverage is claimed for those options.

The RED construction helper deliberately returns `null!` without construction or
cancellation. RED requires total/executed/failed each 4, every other counter zero,
four intended assertion failures and MTP exit 2. Compilation, setup, discovery, loader, timeout,
aborted, capture or safety failures cannot establish RED. Independently accept every
complete first failure before GREEN implements the construction helper and concrete
session bindings. GREEN retains all four scenario bodies/assertions and requires
total/executed/passed each 4, every other counter zero, all four results Passed,
summary Completed, no RunInfo/ErrorInfo and MTP exit 0.

### Construction Effects and Public Source Basis

The pinned MSAL NET_CORE construction path uses managed dependency loading/JIT,
process-local allocations, static dictionaries/singletons/semaphores, time reads,
in-memory user and legacy token-cache objects, and a read-only Windows version query.
It is not managed-only or effect-free. The supplied non-network HTTP factory is retained
without asking for its client. No credential-bearing cache is supplied.

At MSAL commit `d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f`:

- [`BrokerExtension.WithBroker`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/BrokerExtension.cs#L48)
  selects the OS check and installs a broker creator delegate.
  [`Win32VersionApi`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/Platforms/Features/DesktopOS/Win32VersionApi.cs#L156)
  reads version data through `ntdll!RtlGetVersion`; it does not call WAM.
- [`PublicClientApplicationBuilder.Build`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/AppConfig/PublicClientApplicationBuilder.cs#L360)
  constructs the application. [`ServiceBundle`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/Internal/ServiceBundle.cs#L23)
  retains the supplied factory, selects the disabled logger, and constructs local
  services; HTTP/discovery operations remain uncalled.
- [`TokenCache`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/TokenCache.cs#L64)
  and the [`NetCorePlatformProxy`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/Platforms/netstandard/NetCorePlatformProxy.cs#L155)
  select process-local in-memory cache implementations. Certificate-store access is
  deferred to a later device-authentication operation, outside this selection.
- [`RuntimeBroker`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/RuntimeBroker.cs#L56)
  places NativeInterop.Core construction and its ProcessExit subscription inside a
  lazy factory. `IsBrokerAvailable` evaluates that path and is expressly excluded.

These are source findings, not runtime absence-of-effects evidence. Exact action
admission must bind the selected package assets and compiled helper path; this source
basis does not extend to other target frameworks, arbitrary authorities, extra callbacks,
shared/custom persistent caches or Native AOT output. Ordinary framework allocation,
URI, synchronization and lazy behavior remain within the declared trust base.

Exclude real availability/account APIs, every `ExecuteAsync`, provider/browser/UI
availability helpers, certificate/key operations, cache callbacks/serialization,
persistent credential-store access, network/default transport, NativeInterop.Core,
actual WAM and default entry activation. Loader restriction and native host observations
do not execute in these four cases. End the isolated process to discard its MSAL static
memory; no production cache cleanup or state reset is permitted. No case creates a
window, launches a child, or needs human input, choice or unlock.

### Admission, Transition and Capacity

Bind the immutable source/tree, changed source, unchanged graph and inputs separately
for every no-restore build and test. Before each test, independently review actual
PE/PDB/IL, generated registration, the four case identities and constructor effects,
full literal command/environment and selected dependency assets. Afterward accept the
complete report and captures, exact case/result joins, counters, receipts and Job drain.
Source/artifact inspection cannot substitute for runtime scenario evidence.

The first new reservation is build 0046 after all 45 Linux and 45 Windows actions
have finalized. Bind the accepted 0045 WSL start
`5e3e684f790c30eed91f4a26829f5cb4cedbe63303d5003ef0eda09cc5f18985`
and final
`6c0d567b62b8e3f856b3dd67d7a1cee0d4c93bdc458a1f5a6487a80a81b6023c`.
The [independent actual GREEN acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/152#issuecomment-5674576945)
binds their completed sixteen-case prerequisite. Only this reservation may retain and
replace the two active controllers; no standalone controller mutation or history
repair is allowed. The Linux reader recognizes the new zero-child selection and Windows
ceiling while preserving prior history rules. Bootstrap, Job and stop components remain
unchanged.

| Helper | Accepted prior SHA-256 | Proposed SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `c0477077eff68182bae6f6b7d9aced6e56d3e3864d15bcd2b7ea25e8c75924e8` | `64ca92f7778e8c80d609cff11ff577a5cfc6c1bed313c70ac14c5c22f7eda49f` |
| `Invoke-WindowsValidation.ps1` | `7bbac1e2f2688d9057258c4ad7b67493c8f78926aa297387c9f2e410d4eb212f` | `15670d2705e4f8921affe7ac030edb50815503c7aeb2ea7956772ee938cc278b` |
| `run_managed.py` | `ddf40d86777a03881a93e7bac55736b22915b6705a221dbcf3c5e9d39731fb21` | `f0d0c330ee38e92e49e453961a1e476112a5a217290c016d37ef6d465828f123` |

The helpers require the accepted 0045 history, one construction RED test and at most
one subsequent GREEN test; each reserves zero child-process units. They do not
authorize another test selection or permit a failed-attempt capacity refund.

Allocate four Windows build/test units for one RED build/test and one GREEN build/test:
Windows 40/40 becomes 44/44 and combined 77/120 becomes 81/120 if no intervening
consumption occurs. Linux remains 37/80. Overlapping platform ceilings remain subject
to the combined 120 maximum. Preparation remains 13/16 including Windows 5/5, downloads
remain 768 MiB, and process consumption remains 44/56 including owned 20/20. Preserve
the protected final twelve CLI units and four unallocated Wave process units.

Retain the 120-second subject/capture/normal-drain and 230-second controller limits,
8 MiB combined output, non-breakaway 32-process Job, zero-active completion, full
source/tool/history postchecks, bounded termination, stop conditions and intentional
retention. Each action needs separate admission; no retry, refund or automatic
follow-up is selected. Capacity exhaustion, unexpected effects, incomplete evidence
or uncertain quiescence stops further execution.

This construction increment cannot close real broker availability/discovery, account
selection/reuse, native/default composition, actual Windows/WSL lifetime, final Native
AOT or whole-Slice acceptance. The current Wave's real-account effects boundary and
concrete owner risk decision remain prerequisites to those later account operations.

## Concrete MSAL Construction Evidence

Issue #108 and [PR #154](https://github.com/hcoona/microsoft-authentication-cli/pull/154)
carry this increment under the construction supplement accepted at
`ae53bc2448c2e24d3df0eac61daf5d6bd143a4bc`. Root authored and operated the
source and actions; independent reviews identify their reviewers in the PR.
The existing Windows x64 host, SDK 10.0.401/runtime 10.0.12 and pinned
MSAL/Broker 4.83.1/NativeInterop 0.20.3 graph remain the declared environment.

### Accepted RED

RED source `946db9d47d034e5781262505dbb4fe5b7e2834da`, tree
`de98eb37a520ae57832cc102b0d8df012fbcee6a`, adds four fixed scenarios and an
inert production construction helper. [Build 0046 and its independent artifact
review](https://github.com/hcoona/microsoft-authentication-cli/pull/154#issuecomment-5675166122)
bind the exact helper, all four methods, generated registration and PE/PDB source
correspondence. The build completed with zero warnings or errors. No restore,
download or dependency change occurred.

[Actual RED 0047 acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/154#issuecomment-5675412217)
joins every definition, entry, execution and result. All four cases failed at their
intended first assertions, with total/executed/failed each four and every other
counter zero. The three configuration cases report the unique required
`Assert.IsNotNull(application)` message. Their observed shared runtime frame is
line 25; the bound assertion's static source/PDB position is line 27. The record
preserves both coordinates without rewriting the runtime frame or inferring its
cause. The cancellation case reports the required `Assert.Fail` at line 51.
Later configuration and HTTP assertions were not reached in RED.

The original test action was fully collected with expected MTP exit 2, complete
5,040-byte stdout and empty stderr, 0.989-second subject/capture/drain, two total
Job processes and zero active processes. No termination or safety stop occurred.
The sole TRX SHA-256 is
`92ea6711b538716644827d2306b25e995db67b64fc50882835e9e78d4b6bcc64`.
The separately reviewed offline collector correction repaired its prospective-map
field assumption; it did not modify or rerun the subject or its historical records.

### Reviewed GREEN Source and Build

Following actual RED acceptance, GREEN source
`16506630fc857c8b4af32653a216378b94581e3d`, tree
`278808f59f6b395f5b2ae85a0e4231f22beb8d52`, changes only the concrete factory
and nested session. The [independent source review](https://github.com/hcoona/microsoft-authentication-cli/pull/154#issuecomment-5675478257)
verifies the real public builder, original cancellation, mandatory broker
availability in full production creation, cancellation-aware account discovery,
selected-account acquisition and rejecting fallback UI. All four scenario bodies
and assertions remain byte-for-byte unchanged.

Build 0048 completed with zero warnings or errors, native exit 0, complete
713-byte stdout and empty stderr, 12.479-second subject/capture/drain, eight
total Job processes and zero active processes. No termination or safety stop
occurred. The original build and its separately reviewed offline reader were
fully collected with exit 0. The [independent actual-artifact review](https://github.com/hcoona/microsoft-authentication-cli/pull/154#issuecomment-5675839060)
accepted all ten
factory/session/state-machine methods, complete input/invocation bindings,
54 physical source documents, 124 discovered methods and 131 projected cases.
All 321 selected scenario method/IL/sequence-point records match build 0046.

The only assembly-reference addition is the already pinned
`Microsoft.Identity.Client.Broker` 4.83.1.0 in the Windows assembly, with
the expected scoped `WithBroker` member and direct helper call. No native ABI
or controller delta occurred. The managed Windows assembly SHA-256 is
`4f4a151907948243e62106e15a6e69eb1a81278500ea89594217ae7c3709e2d7`;
the scenario assembly SHA-256 is
`7349524132c7cc771029e19667f283e680f8d7d83569b7fc3525b284ca30f2c1`.
These are managed build artifacts, not final Native AOT output.

### Accepted GREEN and Retention

The original GREEN test 0049 selected the same four scenario bodies and assertions.
Its controller reports total/executed/passed each four and every other counter
zero, with original outer exit 0 and confirmed quiescence. The subject/capture/drain
took 0.889 seconds, with native exit 0, complete 637-byte stdout, empty stderr,
two total Job processes and zero active processes. No termination or safety stop
occurred. The one separately reviewed offline collection joined all four definitions,
entries, executions and Passed results, with one Completed summary and no global
RunInfo or ErrorInfo. The three configuration cases reached their unchanged
client/authority/redirect/broker-enable/logging/factory assertions; the original
cancellation case passed before construction. The [independent actual GREEN review](https://github.com/hcoona/microsoft-authentication-cli/pull/154#issuecomment-5676096910)
accepted the complete report, captures and unchanged compiled-scenario basis.
`BrokerOptions` assignments remain source/compiled findings because the public
configuration has no getters for those options. These results do not observe
real account listing or MSA passthrough effects.

| GREEN 0049 evidence | SHA-256 |
| --- | --- |
| Sole TRX | `714ce0e97ef5a0f1510000248b67b26f8edb9171a9f819467ae7156cbdb84a9a` |
| WSL start | `746dffeac49b23fa9b061522e25a8f88afe14d4c802372615f62c2b3fbfbdea2` |
| Windows start | `a042a8cfa70404adde91bfcd0de9657153f54cc49c6493c5eed9b67c20f46da3` |
| WSL final | `75a3b87ffe77ca8f5935e6628e7e5604e48ce392f68ac62a48dc0c4515703e8f` |
| Windows final | `996177e70c0a6310456f93c618358c7a239f71834d132cb5f74f47f9e690331f` |
| Raw invocation | `f9379b7f12c396bfe4dcd13d6f80472dd44cf0fcd5522edc2dd1c0c02dc7dcd4` |

After this four-action construction cycle, all 45 Linux and 49 Windows action
reservations are finalized. Windows build/test consumption is 44/44, Linux is
37/80 and combined consumption is 81/120. Preparation remains 13/16, including
Windows 5/5; downloads remain 768 MiB. Process consumption remains 44/56,
including owned-process 20/20. Preserve the protected twelve CLI process units
and four unallocated Wave process units. Source, artifacts, action receipts and
captures remain in the dedicated roots; no historical action was replayed,
refunded, repaired or deleted. A new selection requires its accepted allocation
and protocol before execution.

### Evidence Boundary

Only the shared production construction helper is selected for runtime validation.
The selected path includes process-local MSAL initialization and the admitted
read-only Windows version query. Full creation's availability call, account/token
operations and default entry activation are outside this selection. Construction
evidence cannot close real WAM/account reuse, native/default composition, actual
Windows/WSL lifetime, final Native AOT or overall Slice acceptance.

## Shared Default HTTP Composition Supplement

This supplement covers one controlled shared-composition HTTP ownership increment
under Issue #108. The [concrete MSAL construction result](#concrete-msal-construction-evidence)
is its accepted prerequisite. Real native admission, WAM/accounts, Windows/WSL
lifetime and final Native AOT retain their separate evidence obligations.

### Purpose, prerequisites and exact selection

This proposal can be prepared without executing an action. Its later protocol promotion requires actual construction RED/GREEN acceptance and current-state rebinding. The bounded cycle is one RED no-restore build, one RED test, one GREEN no-restore build and one GREEN test for shared default HTTP ownership. Every action requires separate admission, and actual RED acceptance precedes GREEN implementation. Reuse existing process/host/HTTP/fixture mechanisms; do not replay consumed suites or allocations.

One internal selection, default-http-composition, contains exactly two nonparameterized methods declared by `Authentication.Windows.Scenarios.DefaultHttpCompositionScenarios`, with one ProcessFixture child each. The method identities and exact controller filter are fixed together:

| Method | Child | Required GREEN result |
| --- | --- | --- |
| SharedDefaultHttpOwnershipSurvivesCancellationUntilDrain | default-http-cancel-drain | Original cancellation reaches pending managed HTTP/provider/callback work; real core/host/pipe/process drain precedes HTTP disposal; one cancelled JSON and matching exit 1; no fixture enforcement. |
| SharedDefaultHttpDisposalStallRetainsTheProcessWatchdog | default-http-dispose-stall | Actual completed request drain and committed synthetic success precede a three-second disposal stall on request work; independent product watchdog ends child with exit 2 under the local bound; no replacement result or normal process return. |

The triggering sequence and first expected RED assertions are fixed below; this supplement owns the fixed marker whitelist. No data rows, third normal case, hidden child, preflight, repeat or retry is included. Both children use existing ProcessChild synthetic Profile/email/scope/tenant, interactive-if-needed, four-second timeout, real --cancel-on-stdin-close pipes and real WindowsProfileSource. Controlled discovery returns no accounts, opening one actual owned STA parent per child. The synthetic session returns only existing synthetic results and consumes the shared owner through a terminal non-network handler.

The public default and internal fixture entry must use one request-local production composition. Internal-only substitutes provide one shared token-checking admission object, a cancellation-checking loader callback, controlled session factory and terminal HTTP transport. NativeWindowsHostObservations and real MSAL are not selected. There is no public test option, environment-selected provider, skip-availability switch or duplicate default implementation.

One passive BeforeHttpDisposal checkpoint follows actual invocation.CompleteAsync, ownedHost.Completion, pipe.Completion and process.CancellationCompletion, before owner.Dispose and process.Finish. It performs no drain itself. Bind that exact source/compiled location and underlying completion semantics, alongside actual task/host snapshots and external disposal/process witnesses. Preserve owner retention on partial initialization failure through source review, without adding another case.

RED must enter both scenarios and fail first at the fixed missing-disposal assertion after setup/existing-drain prerequisites succeed. It normally returns cancelled exit 1 or synthetic success exit 0 because the new ownership disposal is absent. GREEN retains the same methods/assertions and supplies the missing connection. Source/PDB/report must bind actual first failures; setup or harness failures are not useful RED.

### First RED assertions

Each case must first establish the shared owner, controlled HTTP/provider path,
owned parent and existing production drains described below. Then require the
missing `http-dispose-entered` witness with the exact assertion message:

| Method | First intended RED assertion message |
| --- | --- |
| `SharedDefaultHttpOwnershipSurvivesCancellationUntilDrain` | `Shared process ownership must dispose HTTP after drain before completion.` |
| `SharedDefaultHttpDisposalStallRetainsTheProcessWatchdog` | `Shared process ownership must enter HTTP disposal before completion.` |

The first case must already have completed the drained cancelled path with exit 1.
The second reaches committed synthetic success and the pre-disposal drain boundary;
its missing-disposal assertion precedes the later watchdog/exit-2 requirements.
RED normally returns exit 0 in that second child because disposal is absent.
Do not require a stall marker in RED, add a RED-specific branch to the tests, or
weaken existing production drain behavior. GREEN changes only the missing disposal
connection after independently accepted actual RED and retains both tests.

### Selected real effects and excluded native identity work

Each test launches two sequential scenario children, at most one child and one owned parent at a time. Across the RED/GREEN cycle: at most four children and four transient parents, each with the existing Static label and Cancel button. Compiler/runner/framework descendants remain within the original Job accounting; child-unit allocations do not redefine Job processes.

| Surface | Exact bounded selection |
| --- | --- |
| Process launch | Existing ProcessFixture uses fixed C:\Program Files\dotnet\dotnet.exe, admitted scenario assembly/literal arguments and CreateProcessW with current no-window, Unicode-environment and extended-startup flags. Retain SetHandleInformation and Initialize/Update/DeleteProcThreadAttributeList with only stdin-read/stdout-write/stderr-write inherited. No shell, alternate executable, helper child or Job breakaway. |
| Environment/files | Preserve the fixed replacement SystemRoot/WINDIR/Windows/.NET environment and per-child TEMP/TMP/USERPROFILE/APPDATA/LOCALAPPDATA. Fresh child directories contain exclusive reservations/start/final receipts, one synthetic Profile, fixed markers, stdout/stderr and case 1's one exclusive release-drain control file. Retain these intentionally; no production installation/configuration or account-state cleanup. |
| Pipes/owned handles | Same three anonymous CreatePipe pairs; close parent copies of inherited child ends. Case 1 closes its input writer using existing CloseInput and records both close timestamps. No input payload, extra pipe, regular-file stdin, broken output reader, blocked output/diagnostics or overlapped fixture pipe is selected. CloseHandle/SafeFileHandle ownership remains unchanged. |
| Lifetime/output | Child GetStdHandle/GetFileType/PeekNamedPipe on borrowed stdin observes EOF and/or normal Stop. WindowsLifetimePipe.Completion drains cancellation forwarding. One result uses existing synchronous pipe WriteFile. The fixtures do not select payload Discard, overlapped I/O or disk-output positioning paths. |
| Capture/supervision | Existing bounded FileStream background capture, WaitForSingleObject/GetExitCodeProcess/CloseHandle and TimeProvider/QPC observations. Fixture TerminateProcess is safety-only and invalidates intended outcomes. Case 2 deliberately selects product GetCurrentProcess/TerminateProcess(exit 2), with existing Environment.Exit fallback. No unrelated process is observed/terminated. |
| Profile snapshot | Existing bounded local fixed-volume read, GetDriveTypeW/GetVolumePathNameW/GetFinalPathNameByHandleW and owned file handle/buffer lifetime, only for the fixture-created Profile. No external path, directory scan, provisioning or account metadata read. |
| Owned STA construction/show | Existing GetModuleHandleW, read-only SystemParametersInfoW(SPI_GETNONCLIENTMETRICS), CreateFontIndirectW, shared LoadCursorW(IDC_ARROW), RegisterClassExW, AdjustWindowRectEx and CreateWindowExW create one child-owned parent/Static/Button. Same-thread SendMessageW(WM_SETFONT); existing SetWindowPos no-activation/no-z-order flags. Ordinary managed/STA runtime infrastructure may run. |
| Owned message pump/teardown | Existing GetMessageW/IsDialogMessageW/TranslateMessage/DispatchMessageW/DefWindowProcW, owned PostMessageW(WM_APP+1), PostQuitMessage, DestroyWindow, DeleteObject for owned font and UnregisterClassW. Module/cursor/system-brush references remain borrowed. No global input or foreign windows. |
| Owned observations/cancellation | GetWindowThreadProcessId/IsWindowVisible/IsWindow only on the supplied child-owned HWND. Case 1 posts scalar WM_CLOSE via PostMessageW after ownership verification. No synchronous cross-thread close, broadcast, SendInput, global hotkey, desktop enumeration, UI Automation, screenshots or human account input. |
| Managed HTTP | One MsalHttpClientFactory/HttpClient/ManagedUserAgentHandler per child over a terminal HttpMessageHandler, one synthetic send and bounded cancellation/callback work. Case 2 delays handler Dispose exactly three seconds. No network inner transport, SocketsHttpHandler/HttpClientHandler, DNS, socket, proxy, credential/cookie/certificate or service request. |

This is real process/pipe/owned-window native execution, not no-native-effects evidence. Do not construct or invoke NativeWindowsHostObservations: no own-thread/process token queries, GetTokenInformation, LsaGetLogonSessionData, SID/station-user comparison, WTS/session/input-desktop or own-logon admission. Real loader restriction is replaced internally. No real MSAL Build/IsBrokerAvailable/GetAccountsAsync/ExecuteAsync, NativeInterop.Core, WAM, browser, certificate store, accounts/token/cache/consent operation or actual default valid-input runtime path is selected.

The source-reviewed default dependency selection may be concrete without executing it in these controlled scenarios. Actual own-identity reads retain the independently triaged owner-risk requirement; the future combined real-account/native proposal remains necessary.

### Scenario scheduling, timing and output

Case 1: after shared composition/HTTP/owned-parent readiness, owned WM_CLOSE starts the outgoing callback and `host-callback-pending`, but forwarding waits for HTTP notification. The parent immediately closes the real stdin writer; actual EOF is the first process cancellation forwarding. The HTTP linked-token callback only records an in-memory timestamp and TrySetResult notification with asynchronous continuations, then returns without waiting or file/marker I/O. The separately registered original-token observer may hold only after observing that notification; if it arrives too early, it emits/signals `cancellation-order-invalid` outside the HTTP callback and returns without holding, making the attempt a prerequisite failure. Register it before the send, but verify the actual ordering/check in source and IL instead of relying on registration order alone. Keep send/provider operations pending independently of notification. The outgoing callback invokes the process-cancel delegate, retains its Task, records `host-callback-forwarded` without awaiting completion, and waits for release before awaiting that retained Task. A bounded child observer records `pending-drain-observed` only after HTTP notification and invocation of the process-cancel delegate have occurred, while the actual retained send and provider tasks, actual `OwnedRequestHost.Completion`, and both held callbacks remain pending. The transport must still be undisposed, and both disposal-entry and process-return markers must be absent. The observer must not await the held work or drain any production task to establish this conjunctive snapshot. The parent alone creates one exclusive empty `release-drain`; the child records `drain-release-observed` and releases the held gate. The parent makes that same release attempt in prerequisite-failure cleanup if the file is still absent; no overwrite, replacement child, refund or production-task drain is permitted. All holds remain at most three seconds and normal release must fit the already-running local watchdog allowance. Production alone performs the real drains before disposal.

Case 2: one normal synthetic HTTP/provider result completes; existing before/after-commit evidence and complete success output precede cleanup. After actual drains, handler Dispose records `http-dispose-entered` and `dispose-stall-entered` and blocks request work for three seconds. Product watchdog alone must produce exit 2; neither `http-dispose-completed` nor `process-returned` is allowed. A success JSON already committed cannot be retracted/replaced; exit 2 makes this transport failure rather than normal matching success.

Preserve four-second request deadline, one-second local product shutdown allowance from its first ending observation and the same-host Windows QPC basis with fixed 100 ms observation tolerance. Retain host-closing, writer-close interval, commitment, disposal-entered and actual exit timestamps. Measure no later than 1,100 ms from the first established local ending bound; disposal does not reset it. All explicit control waits/stalls are at most three seconds, but normal cancellation release must fit the already running product allowance. Slow setup does not permit a longer budget or retry.

Retain ProcessFixture six-second child enforcement, two-second termination wait, eight-second final capture bound and 524,288 bytes per child stream. Preserve 120-second subject/capture/normal-drain allowance, 230-second controller bound excluding prepared wait, 8 MiB combined output, outer non-breakaway 32-process Job, shared action lock, stop procedure and zero-active completion. No unbounded in-process test or new terminator is selected.

Both tests use the existing automated prepared-action procedure: exact preparation, actual awaiting event, independent matching ready-receipt/live-controller check, exclusive empty release marker. Preserve four-hour prepared-wait maximum, expiry/cancellation precedence and receipt schema. No human attendance confirmation is required for these owned scripted surfaces. Unexpected input, unlock, foreign UI or machine/state switch follows the existing stop rule.

Complete each child's reservation/start/captures/timestamps/exclusive final receipt before acceptance. Apply the corrected owned-process diagnostic predicate: only a prefix, possibly empty, of the expected fixed completed/cancelled indication is allowed; arbitrary bytes or fabricated complete diagnostics are not accepted. Exact-one-result JSON and exit semantics remain as above.

Fixture enforcement, failed launch, uncertain child/Job exit, incomplete capture/finalization, unexpected effects, safety marker or latched stop ends later launches and both loops. An expected domain assertion failure after complete evidence is classified through independent RED review, not automatic continuation. No stopped/unlaunched child refunds its reservation.

### Fixed marker whitelist and ordering

This proposed protocol owns the exact whitelist below for these two selectors only. Each child starts in its existing fresh reserved directory. Each listed marker may be emitted at most once and contains only one invariant decimal TimeProvider.System timestamp followed by a newline, using ProcessChild.Mark. Names are fixed literals, never arbitrary caller input or a payload escape hatch. No callback-returning aliases or additional informational markers are admitted. `release-drain` is the single parent-created empty control file, not a timestamp marker. Existing reservation/start/final receipts, Profile and capture files keep their own fixed schemas.

R/G means required in both the intended RED path and GREEN. The different phase expectations explain the same unchanged test assertions; tests must not branch on expected RED/GREEN. Failure-only markers are allowed diagnostic filenames but must be absent for intended evidence. Case-specific markers are prohibited in the other case. Missing setup/drain witnesses fail prerequisites before either fixed missing-disposal assertion.

| Marker | Cancellation/drain case | Disposal-stall case | Fixed timestamp meaning |
| --- | --- | --- | --- |
| `entered` | R/G | R/G | Child entry, using the existing entry timestamp. |
| `provider-created` | R/G | R/G | Entry to the one shared request-local composition; not completed provider initialization. |
| `http-owner-created` | R/G | R/G | The one real HTTP owner has been allocated and retained on request work. |
| `loader-entered` | R/G | R/G | Controlled loader callback checks original cancellation and records its entry; no real loader action. |
| `session-created` | R/G | R/G | Controlled factory has checked synthetic settings and shared owner/admission identity and created its session. |
| `ui-thread-started` | R/G | R/G | Existing ThreadStarted checkpoint verifies the actual owned STA thread. |
| `hidden-parent-created` | R/G | R/G | Existing HiddenParentCreated checkpoint verifies this child owns the still-hidden HWND. |
| `provider-ready` | R/G | R/G | Controlled interactive call has verified the supplied parent belongs to this child and is visible. |
| `http-send-entered` | R/G | R/G | The single terminal non-network send has entered; in case1 its linked-token notification is registered. |
| `host-closing` | R/G | R/G | Existing Closing checkpoint observation; it is not a later cancellation/disposal timestamp. |
| `native-cleanup-completed` | R/G | R/G | Existing native-cleanup checkpoint verifies the owned HWND no longer exists; does not imply aggregate host completion. |
| `before-commit` | R/G | R/G | Existing BeforeCommit checkpoint, before the result commitment attempt. |
| `after-commit` | R/G | R/G | Existing AfterCommit checkpoint after commitment succeeds; output writing still follows this checkpoint. |
| `drain-boundary` | R/G | R/G | Passive BeforeHttpDisposal checkpoint only after every actual required completion succeeded. |
| `http-dispose-entered` | G; missing is RED | G; missing is RED | Entry to the real terminal handler Dispose reached through production owner disposal. |
| `http-dispose-completed` | G only | Absent | Normal handler disposal completion; never emitted by the wrapper. |
| `process-returned` | R/G | R only | Child wrapper has returned from WindowsProcess; never an owner-disposal signal. |
| `premature-http-disposal` | Failure only | Failure only | Disposal observed a retained actual task/host or controlled callback still pending; always invalid evidence. |
| `host-callback-pending` | R/G | Absent | Outgoing callback entered before it invokes the process-cancel delegate. |
| `http-cancel-observed` | R/G | Absent | Published outside the HTTP callback, carrying that callback's actual notification timestamp. |
| `provider-callback-pending` | R/G | Absent | Original-token observer saw prior HTTP notification and is entering its bounded hold. |
| `host-callback-forwarded` | R/G | Absent | Process-cancel delegate was invoked and its Task retained; does not claim Task completion. |
| `pending-drain-observed` | R/G | Absent | Child verified all specified pre-release pending/undisposed observations without draining them. |
| `drain-release-observed` | R/G | Absent | Child observed the parent's empty release file immediately before releasing the held test gate. |
| `cancellation-order-invalid` | Failure only | Absent | Original-token observer ran before HTTP notification; it returned without holding and the prerequisite fails. |
| `candidate-returned` | Absent | R/G | Controlled session is returning its complete existing synthetic success after the send completed. |
| `dispose-stall-entered` | Absent | G only | Handler enters its exact three-second synchronous disposal stall on request work. |

The common path must establish owner retention, controlled loader/session settings and verified owned readiness before its terminal send. In case1, retain the causal order: `http-send-entered` -> `host-callback-pending` -> the parent CloseInput interval/actual EOF -> HTTP notification -> original-token hold and host delegate invocation -> `pending-drain-observed` -> parent release -> `drain-release-observed` -> successful production drains -> `drain-boundary`. The original-token hold and host delegate invocation need not be ordered relative to each other. HTTP notification must precede either's blocking wait. Native cleanup and commitment observations may interleave with the held work; do not invent a total order for independent events.

For a normal disposal return, require `drain-boundary` -> `http-dispose-entered` -> `http-dispose-completed` -> `process-returned`. In case2, require `candidate-returned` before commitment, successful actual output writing before the post-drain location, and `drain-boundary` -> `http-dispose-entered` -> `dispose-stall-entered`; completed-disposal and process-return markers must remain absent when the product watchdog exits. `after-commit` alone proves commitment, not completed output writing. Preserve the complete captured success JSON and source/compiled ordering of output before cleanup.

Markers witness the reviewed source locations and controlled observations only. Preserve actual task completion, STA/callback join, pipe cancellation forwarding, output bytes, receipts and first-ending timestamps as the underlying evidence. No marker resets a watchdog bound or certifies a failed/skipped drain. The two failure-only markers and fixture safety failures cannot be classified as the intended missing-disposal RED.

### Exact capacity and protected twelve

Following accepted construction and a refresh confirming no intervening consumption, raise Windows protocol build/test ceiling 44 -> 48 and process protocol ceiling 56 -> 60. Wave combined build/test stays 120 and Wave process stays 60. Allocate exactly four new child units to default-http-composition; do not reuse exhausted owned-process or protected CLI units.

| Counter/allocation | Accepted construction baseline | After this cycle, absent intervening use |
| --- | --- | --- |
| Windows build/test consumed/ceiling | 44/44 | 48/48 |
| Linux build/test | 37/80 | 37/80 |
| Combined build/test | 81/120 | 85/120 |
| Charged child units | 44 | 48 |
| Protocol process ceiling | 56 | 60 |
| CLI allocation | 36 total; 24 consumed, final 12 protected | Unchanged |
| Owned-process allocation | 20/20 consumed | Unchanged |
| New default-http-composition allocation | 0/4 | 4/4 consumed |
| Total including protected final CLI | 44+12=56 | 48+12=60 |
| Unallocated Wave child buffer | 4 | 0 |

RED build, RED test, GREEN build and GREEN test each reserve one Windows build/test unit. Each exactly-two-case test reserves both child units before launch even if a case is stopped/unlaunched. At most one RED and one GREEN test; no retry, refund or buffer remains. A third case/data row requires a new accepted capacity decision before dependent work.

Preserve the existing final CLI selectors and assertions unchanged: help, malformed, success, file-stdin, closed-stdin, close-pending, unused-stdin, data-close, deadline, broken-output, blocked-output, blocked-diagnostics. None is selected here and their final twelve units remain protected. Preparation remains 13/16 including Windows 5/5, downloads 768 MiB; no restore/download/publish/toolchain installation is selected. Actual reservation admission must refresh consumed totals rather than assume the forecast arithmetic.

### Controller migration and staged admission

Original construction test 0049 has completed and been fully collected with outer exit 0 and four passed cases. Its executed protocol is `ae53bc2448c2e24d3df0eac61daf5d6bd143a4bc`; its WSL start SHA-256 is `746dffeac49b23fa9b061522e25a8f88afe14d4c802372615f62c2b3fbfbdea2` and WSL final SHA-256 is `75a3b87ffe77ca8f5935e6628e7e5604e48ce392f68ac62a48dc0c4515703e8f`. The [independent actual GREEN acceptance](https://github.com/hcoona/microsoft-authentication-cli/pull/154#issuecomment-5676096910) accepts the bounded concrete-MSAL construction observations for executed source `16506630fc857c8b4af32653a216378b94581e3d`, tree `278808f59f6b395f5b2ae85a0e4231f22beb8d52`, under original protocol `ae53bc2448c2e24d3df0eac61daf5d6bd143a4bc`. These executed identities remain distinct from the PR #154 documentation merge. This construction acceptance does not admit the future default-HTTP cycle.

| Promotion prerequisite | Binding |
| --- | --- |
| Independent actual construction GREEN acceptance review URL | [Accepted original action 0049](https://github.com/hcoona/microsoft-authentication-cli/pull/154#issuecomment-5676096910) |
| PR #154 accepted merge commit and tree | `f1f102cd4a37c4d4538c6a24a98557043de91a3f`, tree `1b5c6012a57023ebc7ba5f8426a82d64a7e3918d` |
| Refreshed accepted Wave/prerequisite identities and consumed counters | Accepted target `f1f102cd4a37c4d4538c6a24a98557043de91a3f`; Wave blob `956aebe0e19cce7dbd08dcaa7fe83a9ef9e01f7c` remains unchanged. The completed 45 Linux and 49 Windows reservations retain the construction-baseline counters above; no subsequent reservation exists at promotion. |
| Independent final design, protocol and controller proposal reviews | Required in the proposing pull request for the exact integrated protocol and controller tree before merge. Separate source, build, artifact, test and actual-result gates below remain required. |

After those prerequisites and this protocol are accepted, the first new reservation is no-restore build **0050**, following the complete original 0049 history. It must build separately admitted new immutable source, distinct from the preceding construction source `16506630fc857c8b4af32653a216378b94581e3d`. The controller verifies the exact preceding WSL start/final receipts and executed protocol, retains the existing active controller bytes, and replaces only the two active Windows controllers during this first build reservation. There is no standalone migration, history repair, replay or additional action. Bootstrap, WindowsValidationJob, stop components and every historical migration retain their existing identities and meaning.

| Helper | Accepted ae53 SHA-256 | Proposed final SHA-256 |
| --- | --- | --- |
| `run_windows.py` | `64ca92f7778e8c80d609cff11ff577a5cfc6c1bed313c70ac14c5c22f7eda49f` | `67830befaac40cbe5be94f8b9f29a0c0936bdd32501bc0e23b77ba194e7ae739` |
| `Invoke-WindowsValidation.ps1` | `15670d2705e4f8921affe7ac030edb50815503c7aeb2ea7956772ee938cc278b` | `c19e7830088476d6b03b078bf42af3daee0b08e1a76da0827ce974a10b9b7216` |
| `run_managed.py` | `f0d0c330ee38e92e49e453961a1e476112a5a217290c016d37ef6d465828f123` | `fbf223e2d258cdc696514e36974f85499eef473ea8c8e5dabc9461fdc3ba6b6a` |

`run_managed.py` is the shared Linux history reader updated in the proposed protocol checkout; it is not a third active Windows controller replacement. The retaining migration records the previous protocol as ae53 and the new protocol from the required immutable runtime argument. Its two active previous hashes must match the table; the new hashes bind the exact prospective bytes above.

The controllers bind action 49 and the actual preceding identities. They preserve mandatory immutable protocol/source/target/review arguments, accepted-byte and history checks, source/artifact protection and separate admission. A new protocol commit, RED/GREEN source commits, actual artifacts and each admission review are supplied and independently bound at the applicable staged gate; no controller self-hash or future artifact identity is fabricated in source.

The controller permits exactly the four subsequent action kinds: RED no-restore build, RED test, GREEN no-restore build and GREEN test. Both tests select only the two methods above and reserve two children each. No other suite may consume these four new Windows slots or the protected final CLI allocation. A failure or changed prerequisite retains the existing fail-stop behavior; subsequent work needs its separately accepted gate. Controller constants do not authorize execution.

Reviewed controllers/history readers must add only the exact two-case selector, +2 charge per test/+4 total, Windows 48/process 60/combined 120 ceilings and preserved CLI twelve/owned twenty. Retain old selectors/assertions, source/artifact checks and fail-stop parsing. Extend existing child marker/report projection only for the exact fixed witnesses in the admitted future source; no arbitrary child or marker support. The exact prospective old/new hashes are fixed in the table above; any candidate change requires rebinding and independent review.

Before each test, independently review actual PE/PDB/IL, generated registration, exact two method/case identities and one-child mapping, original source/assertion coordinates, unchanged dependency graph, literal command/environment and substitutions/effects/drain/watchdog paths. After every action, independently accept complete report/captures, exact case/child/result joins, first actual failures, markers/timing, counters, receipts and zero-active Job result. Actual RED acceptance precedes GREEN. Source review must prove public default calls the same common composition; this does not claim its real dependency branch ran.

### Staged protocol, source, artifact and result gates

1. **Protocol proposal and merge.** Before promoting this proposal, bind actual construction RED/GREEN acceptance and refresh accepted Wave/prerequisite identities and consumed counters. The tracked protocol fixes these two cases, first intended assertions, the exact marker/effects/time/capacity boundaries, unchanged owner-risk exclusions, prepared-action routing and reviewed controller/reader changes. Accept required routed reviews and exact old/new retaining-migration hashes before protocol merge. Future scenario build artifacts are not inputs to this protocol-acceptance gate; the accepted protocol is what permits the later bounded build.
2. **Each source and build admission.** After protocol acceptance, separately bind/review the immutable RED source/tree, unchanged graph/dependencies, fixed child selection/marker calls/assertions, shared production composition and nonblocking notification/drain/disposal paths. Bind its exact no-restore build map, literal command/environment, time/effects limits and prepared-action handling. The first separately admitted build alone may perform the protocol's retaining controller migration. Before GREEN source/build work, both actual RED first failures must already be independently accepted. No action follows merely because a protocol or source change merged.
3. **Actual build acceptance, then each test admission.** Fully collect the original build and independently review its actual PE/PDB/IL, source checksums, generated registration, the exact two methods and one-child mapping, marker sites, public/shared composition, cancellation/drain/ownership/watchdog paths, dependency outputs and complete build receipts. Only then bind those accepted artifacts to the separate test's exact input/invocation maps and literal command/environment, fixed selection and child charge, current counters and prepared-ready/release procedure. Future artifact hashes are required here, not before the protocol enabling the build is accepted.
4. **Actual test acceptance and transition.** Fully collect every child and the original runner; review complete captures, exact case/child/result joins, marker/time semantics, counters, receipts and actual quiescence. Independently accept both complete first RED failures before GREEN implements the missing disposal connection. GREEN reuses unchanged scenarios and repeats its own source/build/artifact/test gates. Mechanical collection and markers alone cannot establish contextual acceptance or authorize another action.

The exact source/compiled line coordinates are bound when those inputs exist; the protocol freezes the required semantic assertions now. No phase may waive a prior accepted gate. Broader effects, a third child or a weakened completion contract require a revised accepted proposal before dependent work.

Future source and artifact identities must be bound at their corresponding admission gates. Real own-identity/default/broker/account/WSL and final Native AOT obligations remain open.

## Shared Default HTTP Composition Evidence

The shared default HTTP increment uses accepted protocol and target
`7b12039c10c5a196b6cb99385bf7d849c4f23820`. Public and controlled entries share one
request-local composition. The controlled selection replaces native admission, loader,
MSAL session and network transport; it exercises actual owned Windows processes,
pipes, STA parents, cancellation, HTTP ownership and process completion.

### Accepted RED and GREEN Source

RED source `1bddba0fd2ffc94cfa3fd33e8cd77cfc46ddf0be`, tree
`2553ee4872123e46b5cc4530b90d57f3cee7e019`, contains two nonparameterized scenarios,
each launching one sequential child. The
[actual build 0050 review](https://github.com/hcoona/microsoft-authentication-cli/pull/156#issuecomment-5677043079)
accepts its 547 artifacts, actual PE/PDB/IL, 57 physical source documents and generated
registration. There are 126 attributed methods and 133 projected cases; only the two
shared default HTTP methods are selected by the separate test admission.

The [actual RED 0051 review](https://github.com/hcoona/microsoft-authentication-cli/pull/156#issuecomment-5677684197)
accepts exactly two executed and failed cases, with every other outcome counter zero.
Their first failures are the intended missing `http-dispose-entered` assertions at
source lines 49 and 69, joined to actual PDB/IL and complete reports. The cancellation
child completes its existing drains and returns cancelled JSON with exit 1. The
synthetic-success child completes its drains and returns success JSON with exit 0;
the missing disposal prevents it from entering the later stall/watchdog assertions.
All prerequisite markers, captures and child receipts are complete. Neither fixture
enforcement nor a safety marker occurred.

The original test invocation was fully collected with outer exit 0. The test runner
returned expected exit 2 in 1.619 seconds; six total Job processes ended with zero
active, complete capture and no termination or safety stop. Host-closing-to-observed-exit
intervals were 89.3521 ms and 63.3389 ms, within the fixed 1,100 ms bound.
One offline collector correction added the source-required `correlationId` to the
exact synthetic success schema with canonical nonzero UUID validation. Independent
triage and acceptance used the original completed run; no test was repeated.

| RED 0051 evidence | SHA-256 |
| --- | --- |
| WSL start | `d5455126f811c4a93348c18db730ff0250d9115bacadb2969a185dcc7e5fd60b` |
| Windows start | `656250b320033d34a4ea1711aa1d804f7bbaa782decbac45a76497c7348a5fc4` |
| WSL final | `ccb9d5cfdb5885c86366a2d0e2de94f3784f44ff61957d05092bef05b521af6f` |
| Windows final | `64edd959c495a686a2a6701023fc53f6995aeaee032c70980dd2fbe78e1f3955` |
| Complete TRX | `766ffc2a82fe2434f784b7062d50ae7499189585bd02b3a5c748d2a86f52d003` |

After actual RED acceptance, GREEN source
`7188ea56da826f6025b703a26458d16bb9c7faf5`, tree
`42bb296c88df8c9d3eb55a9c37176a79952c7001`, adds only the retained `disposeHttp()`
call after invocation, owned-host, pipe and process-cancellation completion. The
[independent source and build admission](https://github.com/hcoona/microsoft-authentication-cli/pull/156#issuecomment-5677861691)
binds the one-line change and unchanged tests. Disposal
runs on the request worker before process completion is published; the calling-thread
watchdog remains active. All other 195 tracked files, including 32 test files and 17
project/build/lock files, are unchanged. Source review alone does not establish the
GREEN runtime result.

### Accepted GREEN Build

The [actual GREEN build 0052 review](https://github.com/hcoona/microsoft-authentication-cli/pull/156#issuecomment-5678218400)
accepts four projects with zero warnings or errors, complete captures and normal
quiescence. The build took 6.365 seconds; four total Job processes ended with zero
active and no termination or safety stop. Its complete 2,010-entry input map,
376-entry tool map and invocation equal the admitted maps.

The 547 outputs comprise 109 freshly hashed nonpackage outputs and 438 unchanged
copied package outputs. Actual PE/PDB/IL review joins the same 126 methods, 133
projected cases, 57 physical source documents and 27 fixed marker sites. Tests are
unchanged. The sole compiled method delta adds the shared disposal invocation in
`WindowsProcess.Execute`, after the actual retained work drains and before process
completion. The other 1,569 selected method bodies remain equivalent. This does
not independently establish a join of the pipe observer's operating-system thread.

| GREEN build 0052 evidence | SHA-256 |
| --- | --- |
| WSL start | `7af2f971c69d7ac8fd07377d714f5a0a01fbe1904f84c36066466516762e4c2d` |
| Windows start | `4f84e8a746296ba5abd9fcd81dc11bbd4d1feba5589521c019ec7c81e92956d4` |
| WSL final | `83191d517037e3619a214add289d2ad3a858bc75468bdf2d4da6f16bef2760a1` |
| Windows final | `4770ca948516f9a8b0be438fb3227632acb1bd61e68a4ac623ae561bb7f6935c` |
| Artifact manifest | `9128d1c4008201ad48057e52f96ac93769dd24722d9c27f4fe6ad13449d299b8` |

### Accepted GREEN Scenarios

The [actual GREEN 0053 review](https://github.com/hcoona/microsoft-authentication-cli/pull/156#issuecomment-5678817646)
accepts the two unchanged scenarios from GREEN source
`7188ea56da826f6025b703a26458d16bb9c7faf5` under the original `7b12039` protocol.
The complete TRX has exactly two executed, passed cases and every other outcome
counter zero. Each method joins to its one admitted child and complete captures.

The cancellation child observes pending HTTP, provider and cancellation work,
releases the held drain, and returns complete cancelled JSON with exit 1. Actual
request, owned-host, pipe and process-cancellation completion precedes HTTP disposal;
disposal completes before process return. No premature disposal or cancellation-order
violation is observed. The disposal-stall child returns the complete synthetic
success object, then enters HTTP disposal and the fixed stall. The product watchdog
terminates it with exit 2; disposal completion and process return are absent. Neither
child needs fixture enforcement, and no safety marker is present.

The cancellation child's entry-to-observed-exit interval is 212.9687 ms. The stall
child's candidate-returned-to-observed-exit interval is 1,034.4391 ms; that source-bound
marker precedes its internal terminal selection. Both conservatively satisfy the
1,000 ms shutdown allowance plus 100 ms observation tolerance. Host-closing intervals
are 90.0006 ms and 1,028.1662 ms, respectively; the host-closing marker alone does not
identify the earliest internal ending. Both children also satisfy the unchanged
4-second request deadline and original 5,100 ms observation bound. Source and compiled
review preserve the watchdog's original ending timestamps throughout drain and disposal.

The original invocation is fully collected with outer exit 0. The Windows test runner
returns exit 0 in 3.016 seconds, with complete 640-byte stdout and empty stderr. All
six Job processes end with zero active, complete capture and no controller
termination or safety stop. Automated preparation and release require no human input.

| GREEN 0053 evidence | SHA-256 |
| --- | --- |
| WSL start | `512a6fff83fe2c20075a60f27bb48d95ee66c0cbe4248c10b0652986f685a4fb` |
| Windows start | `74d802115cb0eb69368c1f36dc0f7e3d7aa55c5af71c1e8c4ae5cd193815e972` |
| WSL final | `d5a19df41f143141df9b0de804da0be0bf52b0d7efc27c04b11b71927fbc9b51` |
| Windows final | `13f59f733b8714e10ab1e32b48318db4b217bcc348753ab4b8c3a49be0bde642` |
| Prepared-ready receipt | `a5e7ce4b4ebc729730db248544f4a4d8cc9e9c299c5575b02f4a56ee72c45a15` |
| Automatic-release receipt | `5e5d34b9ac45474edd9d83d561c879f54a46a314c10d4a3fa1d9456ca09d0a0b` |
| Complete TRX | `dd780d7ecbbb11f51b00fc16d9c6facf2840e7ff52a51a4027a5d0a26b0c64ec` |

### Consumption and Evidence Limits

The completed four-action RED/GREEN cycle consumes its entire allocation. Windows
build/test is 48/48, Linux build/test is 37/80, and combined build/test is 85/120.
Synthetic process consumption is 48/60, including owned-process 20/20 and shared
default HTTP 4/4. The remaining twelve process units are reserved for the unchanged
final CLI selection. Preparation remains 13/16, including Windows 5/5 and Linux 8/11;
downloads remain 768 MiB. This evidence update reserves no capacity and admits no
retry, additional child, restore, publish or authentication action.

These controlled observations establish shared default HTTP ownership through actual
Windows process drain and disposal, including retention of the product watchdog.
They substitute native admission, DLL search setup, MSAL session and network transport.
No account enumeration, token acquisition, real WAM interaction, authenticated resource
request or account/cache effect occurs. Synthetic success uses the exact thirteen-field
schema, including a canonical nonzero correlation UUID; it is not an acquired token.
Artifacts and sanitized experiment evidence are intentionally retained. Executed source
and protocol identities remain distinct from the later PR #156 documentation merge.
Real dependency activation, WAM and selected-account reuse, actual WSL caller lifetime,
final Native AOT and overall Slice acceptance remain open.

## Final Native AOT Guard Preparation Supplement

This supplement allocates one compiler-only preparation action for the dedicated
final-publish guard. The current Delivery Wave already permits that infrastructure
preparation within its existing effects and cumulative preparation ceiling. It does
not authorize final product publication, synthetic final CLI or WSL execution, or any
real account operation. Each of those retains its separately accepted protocol and
admission prerequisites.

### Capacity and Preserved History

Transfer one unused Linux preparation unit to Windows: Linux's ceiling changes from
11 to 10, Windows's from 5 to 6, and the combined ceiling remains 16. Only the new
`final-guard-prepare` category may consume the transferred unit. Ordinary Windows
bootstrap and restore remain limited to their existing five reservations. The guard
charges one preparation and zero build/test, publish, download or synthetic process
units, starting at its durable WSL reservation even if startup or compilation fails.
There is no retry or refund.

The completed shared default HTTP sequence records Linux preparation 8, Windows
preparation 5, combined preparation 13, Linux build/test 37, Windows build/test 48,
combined build/test 85 and synthetic process consumption 48. With no intervening
preparation, the guard would produce Linux preparation 8/10, Windows 6/6 and combined
14/16. Current complete histories and counters must be independently bound and then
refreshed under the existing shared lock before reservation; this arithmetic does
not replace that check or choose an action number.

Use the existing paired Linux/Windows histories and contiguous reservation order.
Preserve all original controller and bootstrap artifacts, receipt bytes, failed-action
dispositions and retaining migrations. Windows action 0002 still has its original
two WSL files and five empty Windows directories, with no native final receipt.
The completed default HTTP cycle stays closed. The ordinary PowerShell controller
is unchanged, and the final guard does not replace its original guard or load it
for compilation.

### Exact Source and Compiler Recipe

The dedicated managed guard preserves the reviewed final-only no-kill mode and its
scoped factory/caller routes. Before compilation, independently accept its exact
activated source and the preparation dispatcher/controller, preflight, compatible
history readers and final caller source identities in an immutable source/protocol
snapshot. Draft source acceptance is not activation acceptance. No actual DLL hash
is required or invented before the compiler produces it.

The final-mode factory also requires the later final caller's already established
earlier absolute Windows performance-counter deadline. It retains the original
running controller/action Stopwatches and intersects all applicable remaining
time with that shared deadline. It checks after Job/root creation, assignment and
handle acquisition and before resume. A proven-never-resumed root can be stopped
only while shared, controller and action time remain; the single stop/confirmation
window is at most ten seconds inside those bounds. A delayed native return cannot
start a new wait after a bound expires or establish timely confirmation. Possible
resume still forbids termination. Ordinary guard behavior is unchanged. The
disabled final caller rejects a missing shared deadline; this is not final-publish
activation or a new timing allowance.

The sole compiler is the existing pinned x64 Framework `csc.exe`, with its existing
configuration, `System.dll`, `System.Core.dll`, implicit `mscorlib.dll` and x64 Windows
PowerShell host. The sealed compiler recipe fixes these six tool hashes, one C#
source, `/noconfig /nologo /target:library`, exactly two explicit references and one
new output DLL. It selects no response file, analyzer, generator, shared compiler,
SDK project, restore, linker, PDB service or new tool installation. Final product
symbol generation is unaffected.

Derive the four-digit action number once from the durable contiguous reservation.
Within that action, copy the exact accepted C# source to
`final-guard/source/WindowsValidationJob.cs`, use that source directory as compiler
working directory, and write only `final-guard/WindowsFinalPublishGuard.dll` as the
compiled artifact. Retain action-local copies of the exact preparation controller,
preflight and authority envelope. Existing destinations, links, source rewriting or
additional compiler inputs reject. Source and tool identities are checked before
and after compilation.

The compiler clears inherited environment and uses the fixed thirty-entry bootstrap
replacement environment with only the action-number path substitution. Its existing
telemetry, first-run, build-server and action-local home/temp controls remain. There
is no final-publish endpoint or inherited compiler override. The fixed package-cache
path string in that environment does not select package access or a restore.

### Authority, Clocks and Completion

Before use, a separately reviewed literal launcher pins one exact external authority
envelope. The envelope binds the current accepted target/Wave/protocol, immutable
source/component identities, source and execution reviews, their complete public
publication bindings, the independently accepted post-0053 handoff, recipe, root
markers and receipt policy. The handoff manifest precedes its independent acceptance;
neither record contains its own future review hash. They bind original history and
do not create a replacement ledger. A caller Boolean, environment variable or URL
cannot supply missing authority.

Public authority and freshness GETs use the existing GitHub CLI 2.88.0 at
`/home/shuaizhang/.local/share/mise/installs/github-cli/2.88.0/gh_2.88.0_linux_amd64/bin/gh`,
exactly 38,613,154 bytes with SHA-256
`8854d3cbf95e3a426df6e47e9471c7d2e4d33d2815813229b078283a55a6cb0a`.
The dispatcher verifies this regular, nonlinked executable through bounded reads
inside the existing thirty-second Git/GET sublimit. Fixed GET arguments, headers,
authentication environment and output limits remain unchanged. No PATH fallback,
installation, shim or authentication change is permitted by this correction.

Preserve the existing evidence root and original post-0053 manifest, handoff
acceptance and receipt-policy paths and bytes. Refreshed source review, execution
admission and publication bindings use `source-review-v2.json`,
`execution-admission-v2.json` and `publication-v2.json` within that same root.
The unchanged handoff acceptance therefore still refers to its original manifest
path. No prior immutable authority input is overwritten and no history rerun is
implied. New source/protocol acceptance and a separately reviewed literal launcher
remain prerequisites to the sole guard compilation.

The original WSL action clock is 230 seconds. One bounded external admission load,
one target-freshness check before reservation, fixed Windows preflight, source copy,
compiler, capture and completion all remain within it. There is no attendance wait.
The Windows ready message and sole WSL remaining-time reply bind the original
reservation, invocation and nonce. Windows derives its deadline from the earlier
ready ticks plus the remaining allowance, never the reply-receive time. The fixed
preflight and handshake each have a twenty-second sublimit; neither resets the
original clock.

One original retained compiler Process/handle owns start, exit, capture and any
permitted compiler stop. Its thirty-second clock starts immediately before Start
and includes complete capture. Combined compiler output is at most 8 MiB. On timeout,
cancellation or overflow, the controller may stop only that original standalone
compiler and wait at most ten seconds within the original remaining allowance.
There is no PID replacement, process scan, old emergency-script fallback or guard
load/self-test. Unknown ownership or completion is retained and blocks continuation.

Preparation succeeds only with original compiler/controller/proxy exits zero,
confirmed compiler completion, both streams at EOF, complete empty diagnostics,
unchanged inputs and one nonempty expected DLL. Retain complete source/tool,
command/environment, clock, capture, artifact and paired receipt bindings. Later
zero exit does not erase a failure. Original preparation and artifact receipts keep
their false artifact-acceptance and continuation flags; an independent review owns
acceptance of actual original completion and managed PE/IL/source/compiler evidence.

### Later Reader and Loader Acceptance

The two compatible original Python readers recognize exactly one separately
accepted guard preparation while preserving ordinary historical validators and
capacity checks. The concrete consumer first verifies external binding B and its
independent review R, then independent original-completion and artifact-acceptance
records, before reading the seventeen bound original action files and DLL. It
checks exact closed schemas, unchanged source/protocol/recipe/clock/capture/receipt
joins, original false flags and final input continuity. Its fixed-path no-link
reads have thirty seconds, 128 reads and 64 MiB total; clocks are at most 2 KiB,
ordinary inputs 1 MiB, DLL/handoff 8 MiB, and successful compiler streams empty.

The dependency order is source acceptance, actual preparation, independent original
completion/artifact acceptance, B, independent R, then a separately reviewed literal
launcher L. L verifies accepted provenance, contextual reviewer independence and
current authority before supplying the exact B/R descriptors. No future evidence
hash is inserted into already accepted reader source. Missing evidence rejects;
original receipts and active controllers are never repaired.

The consumer returns the existing thirteen-field final-loader identity projection.
It neither creates the future Windows artifact-acceptance copy nor loads the DLL.
Any later accepted final caller must verify and materialize those same acceptance
bytes, reject an already defined guard type, load only the exact accepted DLL with
`Add-Type -Path`, and verify assembly identity/location before selecting the scoped
final factory. That later invocation retains its own exact final publish protocol,
capacity, source/recipe and no-kill failure rules. Guard preparation alone does not
admit final publication or establish Native AOT or whole-Slice acceptance.

A separately admitted, one-time data-copy operation may materialize only the
already independently accepted managed-artifact acceptance bytes for original
0055 at its exact `final-guard/artifact-acceptance.json` Windows destination.
Before this operation, accept its exact source, this canonical supplement and
literal invocation on the current target. Original successful B/R, completion
and artifact acceptance, actual L outcome acceptance and its unchanged
thirteen-field G are required. This allowance creates no new artifact-acceptance
schema, product reservation or permission to execute a final caller.

Use the existing WSL Python host and the fixed `/mnt/c` projection of that
Windows destination, under the existing shared action lock. The private source
is the exact original 1,886-byte acceptance record; copy its raw bytes without
JSON rewriting. Bind six fixed private roles: that source, B, R, original
completion acceptance, original G output and independent actual L outcome
acceptance. Read each once initially and once for continuity after the write.
Do not recursively follow their descriptors or read original receipt or DLL
content. These joins preserve original receipts and their false flags; they do
not establish a fresh complete ledger or current global process quiescence.

The destination's existing parent must already exist. Use fixed no-follow walks
of at most sixteen components and one exclusive create at exactly the bound
leaf. An existing file, directory, link or replacement rejects; do not read an
existing destination or choose another name. Make one write of exactly 1,886
bytes, require its full return, synchronize the new file and its existing parent,
and perform one exact byte/hash/identity readback through the owned descriptor.
Retain the completed readback identity. At the final check, require both the
current no-follow leaf and held descriptor to equal that retained identity, while
preserving the existing parent and lock checks. No directory creation,
rename, overwrite, receipt repair, DLL load, Windows process or cleanup occurs.
Any partial destination is intentionally retained and blocks continuation until
separately disposed. There is no retry, including after a pre-write failure.

The entire copy, input continuity, resource finalization and complete descriptor
output share one original thirty-second source deadline and latched cancellation.
A separately pinned GNU watchdog permits at most 35 seconds before TERM and two
additional seconds before KILL of this sole WSL process; it cannot justify late
normal completion. Retain the original invocation, exact exit and complete
combined output. Bound output to 4 KiB. The successful intentional read schedule
is thirteen reads: twelve private-role reads and one owned-destination readback,
64,990 payload bytes plus thirteen EOF sentinel requests, at most 65,003 requested
bytes. Runtime startup is separately reviewed; this count is not an OS I/O claim.
Only the destination creation, one content write and file/parent synchronization
are permitted write effects. Ordinary counters and the fixture debit are unchanged.

The sole copy invocation requires prior canonical acceptance and exact source,
runtime, command, working-directory, output, watchdog and existing-authority
review. A prepared inactive script or this proposal supplies no execution grant.
An independently accepted original zero exit and exact output/readback evidence
are required before the copy may enter a later v2 handoff. Actual v2 handoff
assembly, complete final source/graph/K and final publication admission remain
separate; this operation neither runs L again nor opens those gates.

### Inactive Whole Final-Caller Integration

The final-publication source integrates the existing env35 Csc/Exec consumers,
original-guard provenance joins and narrow successor-history compatibility. This
increment prepares one final Native AOT publication procedure. All four source
entry gates remain disabled, and the reviewed literal-launch binding remains
absent. Merging this source or protocol text does not activate a final caller,
reserve a publication, run a metadata observer or establish an actual graph,
handoff, K, native artifact or support claim. Separate whole-source/protocol,
actual-input and exact invocation acceptance remain required. Any later source
activation must itself be independently accepted as exact immutable source; no
runtime patch or caller Boolean may bypass these gates.

The source files below are the complete inactive component bytes. Original guard
preparation records and their earlier disabled-loader identities remain historical
inputs; their hashes are not replaced by this integration's current file links.
The original guard C# source, compiled guard, readers and preparation controllers
are unchanged. Source integration uses these Git filenames. The later private
materialization keeps the existing `.draft` filenames required by the component
contract, and verifies equality to the corresponding accepted Git blobs.

| Inactive component | Bytes | SHA-256 |
| --- | ---: | --- |
| [`run_windows_final_publish.py`](../../../tools/validation/run_windows_final_publish.py) | 7611 | `bccf09306d92b1aa0f7e341c28414d9fa9bb64ce4cd556a243372c7fb64f0d69` |
| [`final_publish_contracts.py`](../../../tools/validation/final_publish_contracts.py) | 120176 | `e56e09b5616cf7b2ace5e6bd12fda1fa558c3986a383e2383b46adb7a8a4a444` |
| [`Invoke-WindowsFinalPublish.ps1`](../../../tools/validation/Invoke-WindowsFinalPublish.ps1) | 86205 | `9ec02f16468d06869052e956f9a471fa79fb7da6f3cd67d0f404795d6b4f96c4` |
| [`Start-WindowsFinalPublish.ps1`](../../../tools/validation/Start-WindowsFinalPublish.ps1) | 12107 | `7ce257e4e23fbc1cdc3e97602a002f1d518fcaf98513fc5c5b0064ba1647d362` |

#### Selected Product, Recipe and Effects

Select only product commit `503360753accd0829801953823b1b57a4f852440`, tree
`8506cdd9781c8a331ea12ea8fe27a55292eec073`. Its exact complete `src` and
`global.json` inventory must match the independently accepted source and actual
dedicated `sources/` materialization. Retain SDK 10.0.401/runtime 10.0.12,
MSAL/Broker 4.83.1 and NativeInterop 0.20.3. Existing public restore bytes may be
reused only after exact final project/import/reference/RID and path-consumption
correspondence is established. Historical `subject/` paths are not blindly
rewritten, assumed unused or treated as a complete final graph. This procedure
allocates no restore, fetch, tool installation, guard compilation, fixture or
synthetic process case.

The existing sealed recipe carrier is exactly 5,223 bytes, SHA-256
`2fcf2e7e265b91e1103b0c91e240079e04d87dfd505d633c281a4abe53e900c2`.
Its single external descriptor remains part of source, graph, K and execution
acceptance. The source reads those exact bytes from the existing private package
`recipe.json`; it does not introduce another tracked recipe authority. A missing,
changed or noncanonical recipe rejects admission. Copying that same accepted
recipe into the owned action preserves its identity and creates no new recipe.

Launch only the nominated `C:\Program Files\dotnet\dotnet.exe` in the admitted
source root to publish `src\Authentication.Cli\Authentication.Cli.csproj` for
Release, win-x64, self-contained Native AOT and runtime 10.0.12. The fixed vector
retains `--no-restore`, `--disable-build-servers`, `UseSharedCompilation=false`,
`IlcUseEnvironmentalTools=true`, the recipe's exact `CppLinker`, `-m:1`,
`-nr:false` and `-noAutoResponse`; compilation remains included. Preserve trim
and compiler diagnostics, warnings-as-errors and ordinary symbols. No blanket
warning suppression, symbol stripping, provider override or extra response input
is allowed.

The env35 recipe makes exactly its existing four changes to the prior retained
recipe: `MSBUILDPRESERVETOOLTEMPFILES=1`, detailed verbosity, `-tl:off`, and
`-clp:ShowEventId;ForceNoAlign;DisableConsoleColor`. It has exactly 35 replacement
root environment entries. Resolve only the existing action, source and package
root slots and once-reserved endpoint. Retain the exact PATH, LIB, INCLUDE,
telemetry, build-server, dedicated home/cache/temp and NuGet-signature policy.
Serialize unique case-insensitive names in ordinal-ignore-case order as the
existing UTF-16LE native block. Do not mutate the controller or host environment.

The only endpoint override is `_MSPDBSRV_ENDPOINT_`, containing the one nonzero,
lowercase 32-character UUIDv4 generated during the original durable reservation.
Reject known reuse against admitted original starts; do not invent a historical
endpoint or enumerate host services. Keep `_MSPDBSRV_`, `LINK`, `_LINK_`, `CL`,
`_CL_` and the signature-disabling variable absent, including case variants.
The exact five recipe-selected linker/PDB tool pins and their existing toolchain
paths remain unchanged. A fresh ordinary linker and its direct child environment
must be established by source and graph acceptance, not inferred from a filename.

The existing ordinary PDB endpoint conclusion remains conditional on successful
environment read and duplication. It does not prove isolation on every error,
exclusive service ownership or finite server lifetime. No new allocator, helper,
process, service, installed-root or account investigation is implied.

#### Exact External Inputs and Graph Closure

Use `final-publish-external-authority-v2` with the existing nine exact input roles:
source review, handoff, handoff acceptance, graph, graph acceptance, guard
acceptance, caller authorization K, execution review and publication bindings.
The envelope joins selected product, exact component Git blobs, integration and
protocol ancestry, current target/Wave, recipe, original root markers and the
unchanged thirteen-field G. Both current target identity and accepted protocol
bytes must match. Source and execution acceptance cannot be inferred from a URL
or Boolean; retain the existing six public review bindings and contextual
independent review of their exact subjects. No new external input schema or
alternate authority path is introduced.

The existing K carrier joins the accepted B/R, original completion and managed
artifact records, exact original L source and opaque original L outcome
acceptance. K does not rerun L, parse a replacement acceptance schema or create
the Windows artifact copy. Preserve its eight inputs, two passes, sixteen reads,
16 MiB aggregate and 1 MiB per-input bound. The independent reviewer must assess
actual L semantics and the existing source/history/fixture joins. Unknown actual
K, graph and handoff bindings remain absent in this preparation.

Require `final-publish-exact-graph-v2` and the existing
`final-publish-tool-response-contract-v1`: complete source/protected-input closure,
exact absent ambient inputs, selected SDK/runtime/import/task/tool/consumer pins,
effective properties, finite generated paths and ordered producer/consumer plans.
The nine host roles remain sdkHost, sdkForwarder, msbuild, corelib, taskHost,
logger, utilities, cscTask and execTask. Bind each to one exact protected input.
No evaluated property, source/reference/restore-path use, native dependency or
compiler branch is invented merely because its source is available.

Keep the original WriteLinesToFile ILC/link adapter and its exact CRLF/BOM rules.
Csc has its separate source-bound UTF-8 BOM response with no added newline.
Select the actual built-in apphost or `dotnet exec` branch, bind the compiler DLL
and selected host, and prove the unused apphost absent when required. Preserve
ordered Csc overrides `DOTNET_ROOT=` then the pinned SDK root. The exact direct
ToolTask-child environment is derived from the root recipe, ordered SDK
overrides and ordered task overrides; final names remain unique ignoring case.

Require exactly one ILC and one linker Exec companion, with their exact native
consumer, static response association and source-bound OEM or UTF-8 no-BOM batch
serialization. Pin the command processor and conditional codepage tool where
actually selected. Preserve the single logging service, no out-of-process task
hosts, detailed UTF-8 en-US stdout event branch, planned project/target/import
occurrences and globally monotonic task IDs. Original command, ordered environment
override and preservation messages must join the same successfully closed task
by exact byte offsets, lengths and hashes.

Static and tool response plans together remain at most 32; static generated paths,
temporary-directory roles and tool plans share the existing 10,000 bound. Each
response remains at most 8 MiB, command templates at most 1 MiB and console lines
at most 2 MiB. Temporary roles use existing finite full-match names and require
complete retained membership; stale, undeclared or ambiguous members reject.
There are no preexisting top-level or unreviewed nested response files. Do not
substitute an unexpanded wildcard, guessed SourceLink value or invented output
bytes for a complete plan. Actual response bytes and source/task diagnostic
receipts remain original-execution evidence.

##### ASCII Default-Detect Batch Inputs

The existing `batchEncoding` contract also admits exactly
`{"mode":"ascii-default-detect","useUtf8Encoding":"Detect","codePageTool":null}`
for the two selected native Exec companions. This closed variant contains no numeric
OEM or selected-codepage field. Both the fully substituted original command and the
resolved working directory must contain only ASCII characters. Preserve the existing
non-UNC working-directory predicate, exact native consumer/response joins, quoting,
ordered task/environment evidence and original response-byte comparison. Reject an
unknown mode, extra fields, non-ASCII input, a nonnull codepage tool or any encoding
override other than the original `Detect` default. The existing numeric variant and
its source-derived selection and conditional tool-pin rules remain available.

This is a source-derived equivalence for the selected input case. MSBuild
[`ToolTask.UseUtf8Encoding`](https://github.com/dotnet/msbuild/blob/b44cdcec4c79c50c67560876707d57d4f635fa3b/src/Utilities/ToolTask.cs#L204)
defaults to `Detect`.
[`Exec.CreateTemporaryBatchFile`](https://github.com/dotnet/msbuild/blob/b44cdcec4c79c50c67560876707d57d4f635fa3b/src/Tasks/Exec.cs#L198-L277)
selects its encoding using the command plus working directory;
[`EncodingUtilities.BatchFileEncoding`](https://github.com/dotnet/msbuild/blob/b44cdcec4c79c50c67560876707d57d4f635fa3b/src/Shared/EncodingUtilities.cs#L228-L260)
retains the default OEM encoding for representable Detect input and suppresses a
UTF-8 preamble. The selected
[`IlcCompile` and Windows linker Exec tasks](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/coreclr/nativeaot/BuildIntegration/Microsoft.NETCore.Native.targets#L320-L398)
do not override that default. Under the ordinary supported Windows OEM encoding
behavior in the accepted workstation model, ASCII maps to identical bytes. The
selected and default codepages remain equal, so Exec emits no `chcp` line and has
no codepage-tool input for this branch. No numeric OEM value is asserted or inferred.

The expected batch has exactly these five lines, each terminated by CRLF, without
a BOM: `setlocal`, `set errorlevel=dummy`, `set errorlevel=`, the fully substituted
original command, and `exit %errorlevel%`. Both current validators reject non-ASCII
input before serialization; the Python encoder also uses strict ASCII. The
PowerShell encoder receives only that checked command and fixed ASCII framing.
Keep the original retained batch-byte equality check and complete successful task
join. These planned bytes do not assert that an original batch has been produced
or consumed. The equivalence concerns batch inputs, not arbitrary native-output
decoding; the original UTF-8 MSBuild logger contract remains unchanged.

The final graph and literal source admission must bind this variant before use.
This amendment adds no query, helper, execution, capacity, current-machine codepage
observation or new runtime claim. It does not activate the disabled validators or
complete the remaining compiler/native-input, graph, artifact or scenario gates.

#### Original Lifetime, Completion and Retention

The original WSL clock starts before admission and retains a 700-second outer
bound through reservation, capture, collection and finalization. The shared lock
covers current-history validation, original reservation and collection. Derive the
next action only from accepted contiguous history, preserve its durable charge and
create only its exact Windows pair and bridge. Any partial reservation remains
charged and retained. No retry, replacement endpoint or capacity refund occurs.

The original Windows controller clock starts before its admission and never
restarts. The twenty-second ready/remaining-time exchange anchors the cross-host
deadline to the earlier Windows ready counter, subtracting the existing one-tick
ordering allowance. The complete 600-second action and ten-second never-resumed
root allowance must fit before creation. The action clock begins immediately
before root creation and includes capture and natural drain. Drain is at most
2,000 ms or remaining action time, with at most 100 ms observation tolerance and
no crossing of 600 seconds. Combined capture remains 8 MiB; the nonbreakaway Job
allows at most 32 active members.

Load only the independently accepted original guard DLL through the existing
exact loader; reject a preloaded/ambiguous guard type and check assembly identity
and location. Select only its final no-kill factory. Assign the suspended root
before resume and retain the original process/handle. Omit kill-on-close for this
mode. A single exact-handle stop is allowed only for a root proven never resumed,
within its existing ten-second allowance. Unknown resume outcome is a possibly
executed failure and takes retention. No Job, descendant, helper or resumed-root
termination is permitted.

After original native root zero exit, both original streams at EOF and natural
zero active Job members at drain, the still-running Windows controller snapshots
generated responses and issues `final-publish-postconditions-v2` within the
original timing and cancellation bounds. Overall success additionally requires
original controller and bootstrap completion with zero exits, complete
unsuppressed diagnostics, unchanged source/inputs, all timing predicates and
natural zero active Job members at final accounting. A WSL proxy zero alone is
insufficient. After that original controller/bootstrap completion and final
accounting, WSL independently re-renders, joins original messages and compares
original and snapshot bytes before acceptance. Retain actual native image, asset
and symbol bytes for separate artifact acceptance before any product use.

After disposing the retained original controller and durably saving its final
receipt, the original bootstrap checks its final zero-exit decision against the
same original deadline counter, bootstrap stopwatch and existing action cancel
marker. Normal completion must remain true and the original deadline must be
present. Check cancellation before sampling the clocks; require elapsed bootstrap
time below 700,000 ms and the current Windows counter strictly before that
original deadline. A failed check or exception returns nonzero without rewriting
the durable receipt. No finalization write, new timer, retry or process operation
may intervene between this final check and zero exit.

Any timeout, cancellation, changed input, capture/ownership failure, nonzero exit,
unknown completion or survivor latches failure. The passive emergency observation
is at most ten seconds within the original outer deadline; it never terminates
Windows work. Retain all available evidence and possibly live work, close local
handles without kill-on-close and stop dependent execution. Later quiescence does
not erase failure, and finite controller observation does not bound survivor
lifetime. No PID reopen, process scan, historical cleanup exception or symbol-free
fallback is allowed. Original false artifact/continuation flags remain unchanged.

Final source activation, complete graph/recipe/K/handoff acceptance and exact
literal execution admission remain distinct. The twelve reserved final CLI
synthetic cases, actual WSL caller lifetime, real WAM/account journey, release and
whole-Slice acceptance retain their own gates. No authentication, account/cache/
consent effect, resource request, deployment or support commitment is admitted.

### Prospective Final-Caller Successor History

A later complete final caller uses `final-publish-after-guard-handoff-v2` while
retaining the six fields `schema`, `source`, `histories`, `recomputedCounters`,
`knownEndpoints` and `guardAction`. Ordinary entries retain the existing complete
entry shape and evidence checks. Windows action
0054 has its closed exception, represented by exactly `number` and
`failedGuardDisposition`. Its number
is `0054`; its descriptor equals the original successor authority's exact failed
history disposition. No other platform, action number, extra field or alternate
failure may use this variant. It does not assert a complete 0054 tree inventory.

Preserve the accepted post-0053 manifest and acceptance bytes. The later handoff
contains the exact original 45 Linux and 53 Windows entries, followed only on
Windows by disposed 0054, independently accepted successful 0055, and the exact
[disposed 0056 variant](#exact-0056-failed-history-disposition). Preserve the complete
accepted post-0055 handoff bytes as the predecessor of that added suffix. Source-bound
hashes of the compact, ordered original entry lists enforce that prefix without
another provenance input. The handoff reviewer verifies their derivation from the
unchanged accepted manifest. The paired action order remains contiguous; reject
an intervening product reservation, duplicate, reordered or third guard. Only
successful 0055 supplies the thirteen-field loader identity and successful
completion/artifact joins. A final caller derives 0056 only from that accepted
history; the post-collection check permits only its own original reservation.

The original handoff-acceptance field shape may remain unchanged. Its
`completePairedHistoryAccepted` statement means complete ordered paired history
with this narrow disposed-failure variant, not complete fresh 0054 metadata or
current process quiescence. Independent acceptance binds the exact v2 handoff,
unchanged original dispositions and original guard acceptance. A new schema
value or a caller Boolean alone does not supply that acceptance.

#### One Original 0055 Local-Names Observation

To supply only the successful-0055 `localEntryNames` value, permit one separately
admitted names-only observation of the existing WSL `windows-actions/0055`
directory under the dedicated Linux experiment root. This is one original
invocation, including a failed admission or lock acquisition; there is no retry.
Before it runs, independently accept the exact source, this protocol revision,
original successful guard evidence and completed Windows acceptance-copy outcome,
then admit the exact runtime, literal command, working directory and output path.
Whole final graph and K acceptance are not prerequisites to this limited input
observation, but remain prerequisites to final publication. An inactive source
package supplies no observation or execution grant.

Use the existing shared action lock with one nonblocking exclusive acquisition;
do not create, truncate or read its contents. Open the one fixed directory through
no-follow ancestors, with at most sixteen components, and retain its descriptor.
Perform exactly one direct enumeration, reading names only. Admit at most sixteen
names, each at most 255 UTF-8 bytes; observing a seventeenth entry rejects. Reject
invalid UTF-8, control characters and non-leaf names. Do not open or query child
entries, recurse, enumerate the Windows directory or touch action 0054. Check
held/current directory kind and identity before and after enumeration and before
completion; size, mtime or ctime changes reject. This establishes the bounded
original observation, not an atomic snapshot against an uncooperative writer or
a fresh complete history, process-ownership or global-quiescence claim.

Sort the observed names using the existing Python handoff ordering. Write one
exclusively created private record of at most 8 KiB, carrying those names and the
original source/protocol/observation identity; synchronize, seal read-only and
read back that owned record once. Capture at most 2 KiB of complete descriptor
output. Original file content reads and further metadata/content discovery are
prohibited. All lock, directory, output and finalization work shares one original
thirty-second monotonic source deadline and latched cancellation. An independently
pinned WSL watchdog permits at most 35 seconds before TERM and two further seconds
before KILL of this sole observer; late completion cannot satisfy the source bound.
No Windows process, product reservation or capacity debit occurs.

Missing or linked paths, lock contention, changed identity, overflow, incomplete
capture or any I/O/cancellation/time failure stops this sole invocation and blocks
use of a partial list. Retain originals, every partial private output and the
complete original tool transport; no repair, deletion or replacement observation
is allowed. Independently accept original completion and the complete names before
inserting them into the existing ordinary entry. The final caller still performs
its existing admission-time and post-completion history comparisons. This
allowance creates no new handoff schema, general collector or execution helper.

#### Original Provenance and Final History Continuity

The original successor authority already read by K must join the exact original
manifest and acceptance, failed disposition, singleton fixture and successor
limits. K may retain these already-checked values in internal admission state;
it adds no provenance read or persistent carrier. Preserve K's eight inputs,
two passes, sixteen reads, 16 MiB aggregate, 1 MiB per-input limit and existing
deadlines. K's independent reviewer must establish that the separately accepted
actual L consumed the same accepted history module, disposition and fixture.
Pinning raw L and its acceptance does not establish those contextual semantics.
Do not execute L again as part of K or introduce another loader identity field.

For this later final caller only, current failed-history continuity uses exactly
two source-bound checkpoints under its existing shared lock: before the final
reservation and after original completion collection. The first checkpoint
observes the seventeen fixed metadata roles, then reads the seven fixed content
roles once. The second reads those same seven roles once, then observes the same
seventeen metadata roles. Compare the two complete snapshots. A failed, repeated,
reordered or interrupted checkpoint cannot obtain another pass. This prospective
schedule does not change the original compiler-reader transaction or replay L.

Across both checkpoints, permit at most fourteen regular-file read operations,
123,152 admitted payload bytes and fourteen additional one-byte EOF sentinel
requests, for at most 123,166 requested bytes. Permit at most 34 fixed metadata
leaf observations and sixteen components in each fixed no-follow ancestor walk.
The metadata roles remain fourteen expected absences, the zero-byte regular
Windows cancel marker and both action directories. No descendant enumeration or
metadata-only content read occurs. Directory kind and the two current snapshots
supply continuity; historical directory allocation size is not a fresh predicate.
Each content read verifies exact size/hash and stable device, inode, mode, size,
mtime, ctime and link count before/after reading and against its current leaf.
The second checkpoint requires the same current identities and bytes as the first.
No historical ctime discrepancy waives a new discrepancy.

Both checkpoints share one remaining allowance of thirty seconds of active
failed-history verification, including all fixed-role I/O and validation. Deduct
each actual interval from that same allowance; never restart it at the second
checkpoint. The original final caller's outer deadline and cancellation remain
in force throughout the gap and every check. A checkpoint's deadline is the
earlier of that outer deadline and the remaining shared verification allowance.
This is an explicit prospective final-caller schedule, not another thirty-second
compiler-reader transaction at each checkpoint. Unrelated ordinary history,
K, source/graph and completion checks retain their existing limits and do not
borrow this allowance. Exact final source and invocation review must accept the
whole combined schedule before either new current-state observation is admitted.

Preserve the original failed result flags and derive exactly one preparation
charge from its accepted disposition. Count both guard preparations once. Exact
post-0055 product counters are Linux `[8,37,0,0]` and Windows `[7,48,0,48]`;
preparation ceilings remain Linux 9, Windows 7 and combined 16. Preserve the
external singleton fixture debit in every relevant combined-capacity check:
`37+48+1=86/120` at that post-0055 boundary. The later dedicated 0056 charge raises
the current combined count to 87/120 as specified by its
[exact disposition](#exact-0056-failed-history-disposition). A final publication charges zero preparation and
build/test, one publish and zero synthetic process scenarios. There is no refund,
extra guard or new fixture/product reservation.

The separately admitted Windows artifact-acceptance copy above remains its own
materialization and verification gate. Neither B/R/L nor the failed variant
creates it. Require independent acceptance of its original completed invocation;
the successful-0055 ordinary entry must include its exact hash.
The final caller compares its bytes with the same independently accepted actual
artifact record already read by K. Original receipts and their false flags are
never rewritten. No copy or original-root observation is performed by preparing
this source and contract proposal.

This subsection defines prospective history compatibility only. Final entrypoints
remain disabled and future actual K, v2 handoff, graph, copy and invocation
bindings remain absent until independently accepted. A complete final protocol,
exact source/environment/SDK/runtime/task/import/response graph, actual L evidence,
public review bindings and separately reviewed final literal admission remain
required. This subsection grants no final publication, historical retry, process
query, cleanup, account action, installation, support or whole-Slice acceptance.

The guard preparation dispatcher and any later complete final caller must check
their original deadline and latched cancellation after durable final receipt
persistence and again after lock release and signal-handler restoration, before
normal return. A late or cancelled original invocation fails
even when its preserved receipt contains an earlier normal observation. The
receipt is retained unchanged and cannot alone establish original completion;
there is no retry, rewritten success or replacement clock.

### Integrated Source Binding

This supplement follows the accepted [shared default HTTP evidence](#shared-default-http-composition-evidence)
and preserves its original source and execution receipts. The immutable source admission
for this preparation must bind the following repository files; SHA-256 values identify
the complete source bytes, not a compiled artifact. The two final-publish entrypoints
remain disabled and retain rejecting admission and completion hooks.

| Component | Repository path | SHA-256 |
| --- | --- | --- |
| dispatcher | [`run_windows_final_guard_prepare.py`](../../../tools/validation/run_windows_final_guard_prepare.py) | `fbe2ff7adbc18cb15cccc1ee91c7f32e0756a4dff8d7569b2decea79c3861db0` |
| controller | [`Invoke-WindowsFinalGuardPrepare.ps1`](../../../tools/validation/Invoke-WindowsFinalGuardPrepare.ps1) | `f3224a309a2ec6f6f988518d97e815eaacd4783a54ae85fea7d8738c078b5598` |
| guard | [`WindowsFinalPublishGuard.cs`](../../../tools/validation/WindowsFinalPublishGuard.cs) | `d38846b080d5ee092fae9e21c9031712b56289093b50ca048d50589cca50ff4b` |
| preflight | [`WindowsFinalGuardPreflight.body.txt`](../../../tools/validation/WindowsFinalGuardPreflight.body.txt) | `11a93b9504b70e2caf1e7e6c2f333f1cda178e0adcf88d5998d3eca83450e8b9` |
| finalPublishDispatcher | [`run_windows_final_publish.py`](../../../tools/validation/run_windows_final_publish.py) | `fc7fe6539b2927994bbd51e81259872c3bee8df7a16e41c02c25a3319d39e176` |
| finalPublishController | [`Invoke-WindowsFinalPublish.ps1`](../../../tools/validation/Invoke-WindowsFinalPublish.ps1) | `ef16811f0f8cf481ee6a54b9b7f0552c14bbd6eeeca32bb391c255e52d35628e` |
| linuxHistoryReader | [`run_managed.py`](../../../tools/validation/run_managed.py) | `49d0f29668bd002ff4488fe95cb561e314d60ea877c8d26df0be28d4e5a79d4b` |
| windowsHistoryReader | [`run_windows.py`](../../../tools/validation/run_windows.py) | `b9fc3b79d8137be6547ad0f8d8bca8c933b9e37bf4893b485cfb1a631dcd1b84` |
| windowsHistoryController | [`Invoke-WindowsValidation.ps1`](../../../tools/validation/Invoke-WindowsValidation.ps1) | `c19e7830088476d6b03b078bf42af3daee0b08e1a76da0827ce974a10b9b7216` |

The compiler recipe, six installed-tool pins, thirty-entry replacement environment,
authority shape and fixed preflight are defined by these exact source bytes. Acceptance
does not replace retained controllers or read evidence. Those operations require the
separate literal launcher and actual authority bindings described above.

## Final Guard Preparation Failure and Entry-Point Correction

### Original Failure and Partial Observation

The sole guard preparation used the accepted PR #158 source/protocol at
`dc3a342a24970aba77eed8a900292d1db6b78cf2`, tree
`4650a4c22ce3746845bbdcb28f39ab3d8671803b`, with the original controller
`ea93b4eecfea6eed623a3149b648e93686db4f8bafa81561ff28ad0379e4ebae`.
Its [source review](https://github.com/hcoona/microsoft-authentication-cli/pull/158#issuecomment-5680246772)
and [execution admission](https://github.com/hcoona/microsoft-authentication-cli/pull/158#issuecomment-5680309745)
remain historical bindings. The original WSL launcher call completed with exit 1
on September 15, 2026, at 12:51:07 UTC. Its complete 169-byte result reports
`failureType=RuntimeError`, with `normalCompletion`, `quiescent`,
`artifactAccepted` and `continuation_allowed` all false. No original normal-call
completion record was created; no normal postpreparation collector or DLL parser ran.

A separately reviewed file observer then consumed its single invocation and failed
with `Observed path changed during bounded read`. Its full envelope was fifteen
seconds, 64 file reads, 2 MiB read bytes, 1 MiB output and 1,024 path operations.
It retained only three private copies before failure: WSL `started.json`, WSL
`result.json` and WSL `windows-input.json`. No final observation inventory, complete
second pass or completed collection acceptance exists. Preserve both failed calls,
all partial copies and every original receipt unchanged; the observer's remaining
loop body, one-call allocation and original clock cannot be reused.

| Retained evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Original launcher output | 169 | `99263a024b0463175678aa46330b36f830f5501845ae28caa92730320b37222c` |
| Original launcher failure record | 1,551 | `2e2b3cd67bb32d4c19ba8eb8b45b91f00a04249925fd4b1db5abe52848af385b` |
| Original observer failed-call record | 1,459 | `e10c1d0c105e8a64b6c47bfe2659979998c93548a2685da9a1eacd3c64339b7f` |
| Partial WSL start copy | 1,632 | `3ed0846d150abd790c9a0793df686d04a3e924eaccaca68f96f802c67ae89a07` |
| Partial WSL result copy | 194 | `feee51e22fab6207ddc7f9ec7c0a2db03b038a9a350cad4c1f050f7750c10d58` |
| Partial Windows-input copy held in WSL | 83 | `77031c737e1dc79a1201be35503c10ca9a11b29fdf592e69062d59714c157193` |

Independent partial-evidence review joined those three copies to the original
authority, post-0053 handoff, source and failed result. The WSL result matches the
original launcher result; `windows-input.json` hashes the copied WSL start. The
durable start identifies action 0054 and charges one preparation, with all other
action charges zero. Retain that charge: the recorded-counter projection is Linux
preparation 8/10, Windows 6/6 and combined 14/16. This projection is not a fresh
complete-history acceptance. A failed start is not refundable, and unused combined
capacity does not grant a second guard preparation or raise the Windows ceiling.

The traceback identifies a later Windows content snapshot, but its exact role is
unknown: missing roles produce no copy, so any of eleven later Windows content
roles could have rejected. The observer discarded the mismatching metadata before
raising; the changed field, filesystem cause and original before/after values are
unavailable. Do not attribute the rejection to a particular receipt, benign
timestamp drift, file modification, DrvFS or a concurrent process. Partial file
evidence does not establish the actual Windows failure stage, controller/compiler
execution, original proxy completion, process ownership or present quiescence.

### Corrected Source and Continuing Gates

Independent triage accepted source finding
`GUARD-PREPARATION-CONTROLLER-ACTIVATION-001`: the original controller defined
`Invoke-GuardPreparationCandidate` but never invoked it, and ended in an
unconditional `UNBOUND` throw. That is a confirmed source defect. The completed
second observation below binds the retained original Windows controller bytes and
supports a separately qualified historical failure disposition.

The corrected controller invokes the existing function exactly once, requires a
scalar `Int32` result equal to 0 or 1, and explicitly exits with that result. It
adds no catch, conversion, replacement clock or receipt change. Existing function
bodies, compiler restrictions, finalization, normal-completion predicates and false
artifact/continuation flags remain unchanged. PowerShell's documented
[return behavior](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_return?view=powershell-5.1)
includes all success-stream output, so unexpected extra output must reject instead
of being coerced into a successful exit. The explicit exit preserves the documented
[`powershell.exe -File` result](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).
This is source acceptance only; the corrected controller has not executed.

The source table above binds the corrected bytes for prospective review; it does
not replace the original controller or revise the old admission. Both original
history readers still require exactly one normally completed, independently
accepted guard preparation. They do not accept this failed action. The dispatcher
still rejects an existing guard reservation. Further preparation requires an
explicit accepted finite allocation within the Wave, independently accepted failure
and safety disposition, narrow failed-history compatibility in both readers and
the dispatcher, and refreshed exact source/protocol/launcher admission. This change
supplies none of those execution permissions and allocates no additional compiler,
build/test, publish or synthetic process action.

Normal collection, managed artifact acceptance, B/R/L and the final caller remain
blocked. Any future reader or source change must refresh their actual paths and
source bindings, including the prospective final-caller provenance check. A failed
action cannot supply a successful guard projection or DLL acceptance. Preserve
the original false flags and the limits of the disposition below; do not synthesize absent
receipts, reuse the failed action number, load an old guard or perform speculative
cleanup. Real WAM, selected-account reuse and overall Slice acceptance remain open.

### One Additional Failure-File Observation After the Guard Stop

The sole guard preparation and its first failure-file observer both ended with
nonzero original exits. Preserve those failures, original receipts and private
partial copies. The transferred preparation unit remains charged; this amendment
allocates no new compiler preparation, restore, build/test, publish, download or
synthetic process unit. It does not activate a corrected controller or reopen
normal collection, B/R/L, DLL inspection, process cleanup or final publication.

The first observer stopped before completing its first content pass and before
its continuity/readback inventory. Three retained WSL copies join the original
failed reservation/result, but missing earlier Windows roles produce no copy.
Neither the rejecting Windows role nor the changed metadata field is known. A
later observer cannot recreate those discarded historical values. Do not infer
a file-system defect, active writer, successful compilation or quiescence.

Subject to independent source/admission/invocation review after this protocol
amendment is accepted, permit exactly one additional file observation, ordinal 2
for this same failed guard call. Preserve the first observer and its admission
unchanged. Charge its entire declared envelope cumulatively; elapsed time or
unused reads cannot become a new first invocation. There is no third observation,
retry, automatic diagnostic broadening, repaired receipt or replacement guard clock.

The tracked source `tools/validation/observe_windows_final_guard_failure.py`
remains inactive with `SECOND_OBSERVATION_ADMISSION = None`. Before use, independently
bind one exact external admission at
`/tmp/windows-final-guard-failure-observation2-admission-v1.json`. Its closed fields
are schema, accepted, scope, protocol, originalFailure, firstObserverFailure,
authority, observationOrdinal, candidateActionNumber, limits and cumulativeLimits.
Use schema `final-guard-failure-observation-admission-v1`, accepted true, scope
`one-additional-read-only-failure-observation`, ordinal 2, candidate `0054`, and
exact source limits below. Protocol binds the actually accepted commit, tree,
canonical protocol path and SHA-256. Original failure, first observer failure and
E descriptors must equal the preserved exact source pins. Acceptance comes from
the accepted amendment and independent review, never the Boolean alone.

Materialize the exact accepted source in a new private file and replace only the
null admission assignment with that actual path/bytes/SHA-256 descriptor. Preserve
the tracked inactive source and both original observers. Independently bind the
actual source, sole assignment delta, accepted protocol/admission and invocation
before use. The sole command is `exec /usr/bin/python3 -I -B
/tmp/observe_windows_final_guard_failure2.accepted.py`, with the original repository
cwd, login false, no added argv/environment/optimization, and one completely
collected original tool call. This read-only step needs no attendance wait.

The read surface is exactly the prior 24 roles at the same candidate action paths.
The fixed WSL prefix is
`/var/tmp/azureauth-windows-slice-108/windows-actions/0054`; the Windows projection
is `/mnt/c/Temp/azureauth-windows-slice-108/actions/0054`. The candidate derives from
the original 53-entry M and is not a new reservation or acceptance of current state.
Fourteen roles are content eligible; their per-role ceilings are unchanged:

| Role | Prefix | Relative path | Maximum content bytes |
| --- | --- | --- | ---: |
| wslStarted | wsl | started.json | 8192 |
| wslResult | wsl | result.json | 4096 |
| windowsInput | wsl | windows-input.json | 2048 |
| windowsStarted | windows | started.json | 8192 |
| invocation | windows | invocation.json | 32768 |
| authority | windows | authority.json | 16384 |
| controller | windows | final-guard/controller/Invoke-WindowsFinalGuardPrepare.ps1 | 65536 |
| ready | windows | clock-ready.json | 2048 |
| readyPending | windows | clock-ready.json.pending | 2048 |
| reply | windows | clock-remaining.json | 2048 |
| compiler | windows | compiler.json | 4096 |
| compilerPending | windows | compiler.json.pending | 4096 |
| windowsResult | windows | windows-result.json | 16384 |
| windowsResultPending | windows | windows-result.json.pending | 16384 |

Each eligible present regular file receives at most one bounded content read;
permit only one extra byte beyond its ceiling to detect growth, then stop that
read and retain a typed oversized anomaly. The ten metadata-only roles remain
the two candidate action directories, both cancel paths, Windows
`temp/owned-host-safety-stop.json`, `temp/process-safety-stop.json`, `guard-build.json`,
`stdout.bin`, `stderr.bin`, and `final-guard/WindowsFinalPublishGuard.dll`. No content
of those last four files or of a safety marker is opened or hashed.

Use no-follow descriptor-relative directory traversal, metadata, leaf opens and
exclusive output creation. Capture each before/after path dictionary, its parent
identity, each opened-file dictionary before/after the bounded read, and typed
read/OS errors. Preserve observed atime separately; it was not part of the original
mismatch predicate. The original status/type/device/inode/size/mode/mtime/ctime
comparison remains, and all differences remain anomalies. Skip linked, nonregular,
oversized, unavailable or changed opened-identity content. No predicate is weakened
to obtain success.

Persist each obtained metadata/error dictionary as a bounded append-only JSON
journal event and fsync it before subsequent classification. Persist classification
in the journal and raw-copy descriptors in the final inventory. A per-role missing path, typed OS failure,
metadata difference, partial read or size anomaly must preserve its full obtained
metadata and continue only to the next already listed role. No arbitrary path is
followed. Global timeout, cancellation, resource exhaustion, unavailable durable
output or unexpected programming failure stops the observer and preserves all
partial files; already lost or unpersisted data cannot be invented.

After at most one content attempt per role, perform only bounded private-copy
readbacks and prerequisite continuity reads. The eight fixed private prerequisites
are original guard failure/output/E/M, first observer failure, and its three partial
WSL copies; do not traverse historical paths in M. The ninth input is the newly
accepted small diagnostic admission. Keep every original source/evidence pin and
failed flag unchanged. The original failed observer's metadata is unavailable;
this second observation records new facts only.

The second invocation has 30 seconds, at most 64 file reads and 2 MiB actual total
read bytes including private prerequisites/readbacks, 1 MiB written output,
1,024 path operations and 16 KiB chunks. Journal and final inventory each have a
256 KiB ceiling. Its maximum successful read count is 48: nine private inputs read
twice, fourteen original content attempts, fourteen raw-copy readbacks, journal
readback and inventory readback. Cumulative bounds including the first observer's
entire reserved envelope are exactly two diagnostic invocations, 45 seconds,
128 file reads, 4 MiB read, 2 MiB written and 2,048 path operations. The failed
guard's original 230-second clock is closed and is never restarted or extended.

The only new output is exclusive
`/tmp/windows-final-guard-failure-observation2-offline-v1`, with at most fourteen
role.bin copies, `events.jsonl` and `observation.json`. Retain the output-directory
and journal descriptors. Journal writes are sequential through the original file
descriptor; a 0444 pathname does not imply that its retained writer has completed.
Each obtained event is file-fsynced; the created journal and copies are parent-fsynced.
Raw copies are exclusive 0444 files with exact readbacks; the final journal and
inventory are independently hash-bound and reread after journal closure. No output
or input directory is enumerated, and no predecessor is overwritten or removed.

Report transportComplete independently from stableEvidenceAccepted. Only full
completion of the original second-observer tool call and all fixed role attempts
can support complete transport; role anomalies remain explicit even when transport completes. Both
inventory and result retain false stable-evidence, stage/consumption (where
applicable), process ownership, quiescence, artifact and continuation acceptance.
A nonzero original observer result invalidates complete transport even if an
inventory was written earlier. Classifying a mismatch must not erase its recorded
before/after dictionaries. Independent review owns actual partial/complete evidence
interpretation and bounded failure/capacity disposition.

No process enumeration, PID lookup/reopen, stop/signal of another process, Windows
helper, native API, SDK/compiler, account/cache, DLL load, network call or source
repair is selected. Later file existence, receipt PIDs and typed errors cannot
establish current process ownership or quiescence. Unknown safety state continues
to block experiment continuation. If the second observation is incomplete or
insufficient, preserve it and return to source-only disposition; no further
original observation or experiment follows under this amendment.

### Completed Second Failure-File Observation

The additional observer executed exactly once under accepted protocol commit
`7ef831b8c95aa8ba2387f2c6b4cea5a3799a26c8`, tree
`4c82254296cf37e0472a8c6bee6c95a24b39ee20`. Its original tool call returned exit 0
in approximately 0.39 seconds, with complete, untruncated output and no yielded
session. The original output was preserved from the execution handoff with that
provenance stated explicitly. No human interaction was required.

The observer attempted all 24 fixed roles and retained seven raw content copies,
a 93-event journal and the final inventory. Offline readback verified their
declared lengths and SHA-256 hashes. Transport completed; the observer retained
false stable-evidence, process-ownership, quiescence, artifact and continuation
acceptance flags. Neither the successful observer exit nor the presence of its
inventory changes the failed guard result.

| Retained evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Second observer original output | 476 | `a5243748164384386b96145a07a68faaff52bf9d021e546b42da3fbfa00407e3` |
| Second observer original-call record | 1,342 | `26036800f0ab97ccd5be62ddb2d3dc8b372e42d6dc6affe2ecdbd8e397110215` |
| Second observer inventory | 30,694 | `46b119069d4f3d18fb9c067a32f2f6d8e2605b49365d99b0a2a982cb8f992614` |
| Second observer journal | 29,775 | `f2efe2a56d230c0617a93c8e828f275547f3da3b5fcf408a303dfa60f2c7833b` |
| Windows invocation copy | 7,001 | `0a825b6d574b939e735e039ba4649510c4776f668b40c6ac70f610798982f936` |
| Windows authority copy | 7,161 | `eab860fa6249ec583e33a637c2c9b0c12ae3302d3b1d2ae4bd3278fb729a55cc` |
| Original Windows controller copy | 43,873 | `ea93b4eecfea6eed623a3149b648e93686db4f8bafa81561ff28ad0379e4ebae` |

The WSL start, result and Windows-input copies match the three first-observer
copies recorded above. The copied Windows start is byte-identical to the WSL
start. The authority and controller copies match the original admitted bytes;
the controller is the version with the confirmed missing entry-point call.
These are retained-file observations, not a snapshot of code loaded in memory.

Fifteen roles have anomaly classifications: fourteen absent paths and one metadata
difference. The absent roles are both ready paths, the clock reply, both compiler
paths, both Windows-result paths, WSL cancel, both safety-stop paths, guard-build,
stdout, stderr and the DLL. The Windows cancel marker is present. Missing files
remain observed absences and do not individually prove that a process never ran.

The invocation's `ctimeNanoseconds` differs between the initial path observation
and the opened-file observation. Opened-file metadata before and after the read
and the final path metadata agree. Device, inode, file type, size, permissions,
mtime and separately recorded atime agree across all four observations. Preserve
the ctime discrepancy: neither its cause nor the first observer's rejecting role
or discarded metadata can be recovered from this later observation. Do not call
the discrepancy a content mutation, benign timestamp drift or a filesystem defect.

Both diagnostic allocations are consumed. Their cumulative reserved envelope
remains two calls, 45 seconds, 128 file reads, 4 MiB read, 2 MiB output and 2,048
path operations. The guard's closed 230-second clock and consumed preparation
charge remain unchanged. This evidence update adds no observation, preparation,
build/test, publish, download or synthetic process capacity.

### Failed Preparation Safety Disposition

Independent offline review accepted the complete diagnostic transport and the
following narrow historical inference. It did not accept globally stable metadata
or change the observer's comparison predicate or false flags.

The invocation copy is byte-identical to an independent reconstruction using the
original dispatcher's literal recipe and JSON serialization, original reservation
and copied authority. This establishes the captured invocation's content and
semantic identity independently of the unresolved ctime discrepancy. Together
with the exact start, authority and controller joins, it supplies the positive
historical inputs needed for the inference. It does not establish uninterrupted
file metadata stability or explain either observer's metadata behavior.

Under the accepted workstation and immutable-history assumptions, the original
dispatcher's positive Windows-input and invocation writes occur only after
successful preflight. The observed absence of ready, reply and later completion
outputs excludes successful clock exchange, normal collection and subsequent
admission or history checks. In the pinned original source, the remaining
`RuntimeError` path observes the original controller/proxy exit before clock
handoff. The failure handler preserves the actual exception class; it does not
convert unrelated read, write, cancellation or timeout failures into that class.
The retained original controller defines its preparation function without calling
it and terminates in the unconditional throw, so that top-level path starts no
compiler or other experiment child.

These combined source and historical observations support safe intentional
retention of failed action 0054. This is an inference about that failed attempt,
not a direct current-process inventory, measured numerical native exit, normal
completion or accepted compiled artifact. The original `quiescent: false`,
`normalCompletion: false`, artifact and continuation flags remain unchanged. No
cleanup, process query or signal was performed to obtain this disposition.

The failed reservation still consumes one preparation unit: Linux 8/10, Windows
6/6 and combined 14/16 in the recorded-counter projection. No capacity is refunded.
The single guard preparation and both diagnostic allocations remain exhausted.
Further preparation still requires the explicit finite allocation, narrow
failed-history compatibility and refreshed source/protocol/launcher admission
specified above. Normal collection, DLL acceptance, B/R/L, final publication and
real-account execution remain closed under this evidence-only change.

## One Further Guard Preparation After Disposed Failure

The [accepted failed-action disposition](#failed-preparation-safety-disposition)
retains action 0054 and its preparation charge. This supplement allocates exactly
one further compiler-only preparation using the corrected controller and existing
compiler recipe, preceded by one charged offline validation-infrastructure fixture.
It supersedes only the prospective authority form, history compatibility and
allocations identified below. Original evidence and consumed allocations remain
unchanged. Neither failed invocation nor either consumed observer can run again.
Final product, final CLI/WSL and real-account gates remain separate.

### Successor Capacity and Action Identity

Transfer one unused Linux preparation unit to Windows: Linux ceiling 10 becomes
9, Windows ceiling 6 becomes 7, and combined preparation remains 16. Ordinary
Windows bootstrap/restore remains five. Cumulative guard preparation is exactly
one disposed failure and at most one new preparation. Preserve product-history
counters Linux `[8,37,0,0]` and Windows `[6,48,0,48]` before the new action.
Its durable reservation charges one preparation even if preparation fails,
producing Windows `[7,48,0,48]` and combined preparation 15/16. There is no refund,
retry or third guard. Publish, synthetic process, download and account-effect
allocations remain unchanged.

The fixture consumes exactly one build/test unit from the existing combined 120
ceiling, separately from the unchanged product-history counters: `37+48+1=86/120`,
with 34 units remaining. It consumes no preparation, publish or synthetic process
unit. This fixed singleton debit is not a new platform ledger or a Python/tooling
test exemption. Both readers, dispatcher and controller include it exactly once
in every successor or prospective combined-capacity check, including checks nested
through another validator. Product-history ceilings Linux 80 and Windows 48 stay
unchanged. Later final callers must preserve the same accounting.

Use the unchanged accepted post-0053 manifest and handoff acceptance, plus one
separately bound disposition of original 0054. Require exactly that prefix, no
intervening Linux/Windows product-history reservation and no reserved successor.
Only the explicitly named, charged external fixture may intervene. Derive 0055
from contiguous durable product history; a caller cannot select its number.
Permit one original successor dispatcher invocation only, including a failed
preflight or admission. Exact source, protocol, authority and literal launcher
admission remain prerequisites to its side effects.

### Exact Failed-History Compatibility

The original post-0053 manifest and acceptance remain byte-for-byte unchanged.
One private disposition binds the actually accepted canonical failure conclusion,
original authority/call/output, original handoff/acceptance, second-observer
inventory/journal/call/output and independent actual-evidence review. Its exact
closed source-defined contract fixes seven original content roles and seventeen
metadata roles, one preparation charge and all original false result flags.
Independent review and exact source/admission bindings establish its authority;
a Boolean alone does not. It is not a complete post-0054 tree inventory.

During a separately admitted successor action, revalidate only those fixed roles
under the existing shared lock. Require the seven admitted content hashes,
paired start/result/authority/source joins, fourteen expected absences, a
zero-byte regular Windows cancel marker and both action directories. Preserve
no-follow traversal and strict within-read identity, size, mtime and ctime
checks. Fresh directory checks establish directory kind and within-check
continuity; the historical allocation size is not a fresh predicate. The pinned
historical invocation ctime discrepancy cannot waive any new discrepancy.
Do not enumerate 0054 descendants, read metadata-only role contents, repair
receipts, query processes or infer current global process quiescence.
Unexpected content, kind, link, marker, disappearance, newly present
expected-absent role or continuity failure rejects the new invocation.

Both history readers count exact failed 0054 once and return only its typed
retained preparation charge. It supplies no loader projection, DLL, artifact
acceptance or successful completion. Only separately accepted successful 0055
may enter the common normal completion, clock, compiler, capture, source and
artifact validators. Reject any other failed guard, duplicate, reordered or
third guard and intervening product history. Successful 0055 prior counters
equal original handoff counters plus the failed preparation charge. Original
success requirements remain in force.

The dispatcher, both readers and Windows preparation controller must agree on
one closed successor authority, disposition/fixture bindings and finite ceilings.
The original v1 authority remains immutable failed-0054 history; it is not an
alternative successful-0055 authority. The successor uses a new private authority
and evidence root for source review, admission and publication bindings. Retain
original handoff, acceptance and receipt-policy paths. Independently rebind exact
component tables and actual detached reader paths before use.

### Shared Finite History and Continuity Reads

Each history-reader transaction shares one 30-second deadline, 128 regular-file
reads and 64 MiB cumulative bytes across failed 0054, private provenance,
fixture disposition and successful 0055. Nested validation never resets these
bounds. Dispatcher under-lock failed-history verification has at most 30 seconds
capped by the original 230-second deadline. Later already-required private input
continuity checks use the original outer deadline and the same cumulative read
and byte counters; they neither acquire another 30-second interval nor require
the whole compiler action to finish inside the initial history interval.

Original 0054 content is limited to two passes over seven files: at most fourteen
regular-file reads and 123,152 bytes. Metadata-only observations are limited to
two passes over seventeen roles: at most 34 leaf probes. Each fixed ancestor
walk has at most sixteen components. Ordinary private files have a 1 MiB limit;
the original handoff manifest has an 8 MiB limit. Existing smaller clock, empty
stream and successful-artifact bounds remain applicable.

Use a source-defined closed private-role table, with no recursive traversal of
provenance descriptors. Load it once initially, then recheck only at the existing
three dispatcher continuity checkpoints or the reader's one continuity pass.
Count repeated occurrences against the shared budget, including fixture records.
Independent exact source review must identify all roles and the worst-case read,
byte, probe and continuity schedule before runtime binding. If it cannot fit,
amend the protocol prospectively before any execution.

### One Charged Offline Compatibility Fixture

Before successor preparation, independently admit one exact offline fixture of
the production-used validation bodies on the existing WSL2 Linux x64 host. Pin
the actual existing Python interpreter, immutable module and harness paths and
bytes, source/protocol revisions, recipe, dedicated output root and literal
command. No dependency resolution, installation, Windows process, compiler,
network, original experiment-root access or nested candidate subprocess is
permitted. No product action may run concurrently while this fixture is pending.

The sole invocation uses one Python process and a 30-second outer limit enforced
by that process's Linux alarm. The launcher arms the sole alarm before reading,
compiling or importing the harness; the harness inherits the remaining interval
without restarting it. No external timeout supervisor is selected. It
has at most 24 named cases, 72 calls to actual production validation bodies,
8 MiB of synthetic input bytes and 64 KiB combined captured output/report.
Record one exclusive, durable start and fixed charge one before importing or
calling candidate code. Failure, interruption or failure to start the candidate
consumes the allocation. Retain the original start, result and output in its
dedicated private root; do not overwrite or retry. A missing or ambiguous charge,
failed fixture, timeout or incomplete original result stops successor admission.

Use only the smallest production-used import-safe validation body and narrow
byte/metadata I/O seam. Production wrappers keep their actual `__file__`, source,
admission, fixed-path and no-follow checks. The fixture imports real pinned
modules and supplies immutable in-memory synthetic bytes and metadata with a
requested-I/O log. The immutable recipe may embed exact hash-bound bytes from
the accepted offline failed-action copies and private provenance as historical
fixture seeds. All presented I/O observations remain fixture inputs; synthetic
0055 records and metadata establish no new runtime observation. It opens no
original evidence path. Do not spoof module paths,
toggle acceptance or draft globals, call production main/reservation/launch entrypoints,
copy or extract predicates into substitute validators, or stub successful
validation. Source review covers actual filesystem behavior and the PowerShell
mirror; this fixture cannot establish real Windows or no-follow syscall behavior. The separately hash-bound
same-process fixture launcher may call the import-safe harness
`main(admission_binding)`; the entrypoint prohibition applies to production
candidate components.

The positive failed case yields only the retained charge. The positive synthetic
0055 case must retain all ordinary success gates. Within the same finite matrix,
negative cases cover changed bindings/content/review/false flags, unexpected
markers/kinds/links/metadata changes, old authority on 0055, wrong action/order,
duplicate/third guard, intervening product history, counter mismatches and missing
normal success gates. Include product-history sum 119 plus fixture one fitting
120, sum 120 plus fixture one rejecting, and nested helpers counting the debit
once. Keep the fixture outside hk; source inspection and hk do not claim to have
executed it.

Independently accept the exact original fixture outcome before binding its fixed
charge and disposition into successor authority. A synthetic fixture disposition
inside the matrix supplies no production authority. Its acceptance does not
establish actual guard completion or replace source, artifact or launcher review.

### Preserved Preparation and Completion Bounds

The new preparation retains the original 230-second outer clock, 20-second
preflight and clock handshake, 30-second compiler limit, 8 MiB combined compiler
output and at most ten seconds of permitted compiler termination inside the
original remaining allowance. No attendance wait, old guard load, self-test,
PID reopening, process scan, installation, package resolution or new toolchain
is selected. Preserve compiler recipe, tool pins, replacement environment and
action-local source/output rules; derive recipe paths from the new reservation.

Preparation still requires original compiler/controller/proxy exits zero,
complete empty diagnostics, unchanged admitted inputs and the expected DLL.
Its original artifact and continuation flags remain false. Independently accepted
original-call completion and managed-artifact review precede any B/R/L or final
caller admission. Failure preserves evidence and consumed capacity, stops
dependent execution and supplies no diagnostic retry or speculative cleanup.

### Successor Source Binding

The following exact source bytes implement this supplement. The shared history
module is an explicit `guardHistory` component owned by the protocol revision.
The fixture harness remains import-safe and is outside hk. Exact detached paths,
commit/tree identities, interpreter, recipe, private inputs and literal commands
require independent admission after this source and protocol merge. These source
bindings do not report a fixture or compiler execution.

| Component under `tools/validation/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `Invoke-WindowsFinalGuardPrepare.ps1` | 44,658 | `6fa31902c4960277c8f7b9b15061112eca957f2d46d69cfc65f0e96173b9645b` |
| `final_guard_history.py` | 56,316 | `96e30b1576b3e7524ddf05c7dc4229ca83c1530402d39594d0de172673668df3` |
| `run_managed.py` | 47,657 | `dd13f97e79fe84719c7540dced4a975ed22e43a85d6fbd57038264cf6056fca4` |
| `run_windows.py` | 140,320 | `1a81fc6f88b5f4e0918c84921ecea6756dd24d555a5c4dc004e7fa54acc62606` |
| `run_windows_final_guard_prepare.py` | 66,953 | `c4d5bd722ccef384d77d805f4484638d7c08b080820ca0e9a1824a0ffd186d61` |
| `validate_final_guard_successor_fixture.py` | 15,807 | `13a5dcb5f57cec6c2b855a684d19979d861adb4a343968c2caf3c22f2b77f195` |

## Final-Publish SDK and Compiler Identity Copy

This section permits preparation of one separately admitted raw-data copy for the
missing direct SDK, MSBuild task, and Roslyn compiler identity inputs. Its outcome is
fifteen required file copies and four conditional presence/content results at the
fixed paths below. It does not establish complete SDK, shared-runtime, dependency,
compiler-input, Native AOT, or Slice closure. DLL and executable bytes are data only.
Do not load, inspect through a runtime API, invoke, or execute any selected file.

Use the existing WSL Linux review environment and the existing public Windows SDK
10.0.401/toolchain and dedicated public-package locations. The SDK19 operation makes
no Windows process, network request, dependency download, installation, SDK/MSBuild
evaluation, restore, build, test, compilation, link, publish, account, WAM, UI, consent,
or authentication-cache observation or update. It neither materializes final product
source nor places or rewrites restore files. The six accepted native2/dispatch4
metadata copies and twelve accepted restore copies are excluded from collection and
remain reusable within their accepted scopes.

### Fixed Input Selection

Each row is one literal slot. The inactive source contains the exact corresponding
`/mnt/c/` path, with no argument-supplied path, property expansion, wildcard, directory
listing, recursive walk, alternate SDK selection, or metadata-driven follow-up. Confirm
the intended built-in SDK/Roslyn layout against the selected source before exact
admission; a different or unresolved layout is not permission to discover another path.

| Slot | Exact Windows path | Outcome required | Maximum bytes |
| --- | --- | --- | ---: |
| seed-01 | `C:\Program Files\dotnet\sdk\10.0.401\dotnet.runtimeconfig.json` | Required content | 65,536 |
| seed-02 | `C:\Program Files\dotnet\sdk\10.0.401\dotnet.deps.json` | Required content | 4,194,304 |
| seed-03 | `C:\Program Files\dotnet\sdk\10.0.401\dotnet.runtimeconfig.dev.json` | Content or exact leaf absence | 65,536 |
| seed-04 | `C:\Program Files\dotnet\sdk\10.0.401\dotnet.dll` | Required content | 16,777,216 |
| seed-05 | `C:\Program Files\dotnet\sdk\10.0.401\MSBuild.dll` | Required content | 16,777,216 |
| seed-06 | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.Build.dll` | Required content | 16,777,216 |
| seed-07 | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.Build.Framework.dll` | Required content | 8,388,608 |
| seed-08 | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.Build.Tasks.Core.dll` | Required content | 16,777,216 |
| seed-09 | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.Build.Utilities.Core.dll` | Required content | 8,388,608 |
| seed-10 | `C:\Temp\azureauth-windows-slice-108\packages\microsoft.dotnet.ilcompiler\10.0.12\tools\netstandard\ILCompiler.Build.Tasks.dll` | Required content | 4,194,304 |
| csc-01 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\Microsoft.CSharp.Core.targets` | Required content | 1,048,576 |
| csc-02 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\Microsoft.Build.Tasks.CodeAnalysis.dll` | Required content | 8,388,608 |
| csc-03 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\csc.dll` | Required content | 16,777,216 |
| csc-04 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\csc.exe` | Content or exact leaf absence | 4,194,304 |
| host-01 | `C:\Program Files\dotnet\dotnet.exe` | Required content | 1,048,576 |
| csc-05 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\csc.runtimeconfig.json` | Required content | 65,536 |
| csc-06 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\csc.deps.json` | Required content | 4,194,304 |
| csc-07 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\Microsoft.Build.Tasks.CodeAnalysis.deps.json` | Content or exact leaf absence | 4,194,304 |
| csc-08 | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\csc.runtimeconfig.dev.json` | Content or exact leaf absence | 65,536 |

Five slots retain these accepted 0052 historical hashes. They must match on the initial
read. The other present files receive a prospective first-capture hash exactly once
per selected slot; every later original/readback read requires that exact observed hash,
length and identity. A prospective hash is an observation, not accepted SDK authenticity,
public provenance, source correspondence or historical continuity.

| Slot | Historical SHA-256 |
| --- | --- |
| `seed-02` | `7cf8fff4144ef3484f052c4a4734a53f4d65023798f11da62f3c45ae4353d8e8` |
| `seed-04` | `616dbda77bc20692d615e2a679f31ffff04f693e8d6b3e24779cf8838adb6a85` |
| `seed-05` | `22f7b95c5cc1e7287a9d561a0e88719c4d545c5f3892e3e6501051f5abcbe147` |
| `seed-10` | `dbd168e677d11e9a3daeac5839c63a22d66b3719d5f9d1b4b7dffe3eda05c6c0` |
| `host-01` | `21a46f1e5235cf4e844b9de5429f0e198b9c97a41f0503a66442f1d639ca3ee6` |

For each of the four conditional slots, only an absent leaf beneath an existing,
no-follow directory chain is an accepted absence outcome. Missing parents, inaccessible
paths, symlinks, nonregular leaves and other errors fail the invocation. Observe each
initially absent leaf a second time after the content copies and under the same stable
parent identity; presence or parent change fails. Do not convert an unreadable file into
absence, create a missing parent, produce an empty placeholder, or select an alternate
host. Two observations are bounded absence evidence, not an atomic or continuing
filesystem guarantee. Present conditional slots receive the same content, continuity
and readback checks as required slots.

The added Csc development-config predicate follows the conditional pinned host-source
rule: the runtime parses the selected application development config before the main
config, and development-config probing paths can survive later main-config parsing
([runtime source](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/native/corehost/runtime_config.cpp#L342-L419)).
Independent triage accepts this one predicate; it does not accept the entire host trace
or bind an installed host to that public source. If `csc.exe` is present, its bytes
require a later offline managed-target and bundle-state check before accepting the
adjacent `csc.dll` route. Apphost existence alone does not establish that mapping.
Required-content rows are capture expectations, not a universal claim that the host
rejects every missing main-config or dependency-manifest file.

### One Invocation and Finite Effects

SDK19 has exactly one invocation. Record its start and the remaining one-time capacity
before launch. A failed start, inactive-source rejection, input error, output collision,
lock contention, interruption, timeout, partial transport or nonzero exit consumes it.
There is no retry, repair, resume, alternate output directory, or broader selection.
Existing action counts and all previous consumed helper admissions remain unchanged;
this credential-free review copy does not add a restore/build/test/publish/process
scenario or refund an earlier action. Any later target or precompiler observation needs
its own accepted source/effects admission.

Before launch, recover the current accepted Wave/protocol and prior dispositions,
finish any active source or observer operation, and independently admit the exact
source, runtime, literal invocation, output location and capacity record. Preparing
this section or its inactive source performs no original-root access and does not grant
its own execution. The current names observer and its single invocation are unchanged.

The sole future invocation retains the existing lock
`/var/tmp/azureauth-windows-slice-108/action.lock`: open that existing regular file
read-only through no-follow traversal, acquire a nonblocking exclusive lock, verify its
held/path identity before and after collection, and release/close it during finalization.
Do not create the lock, read or write its contents, wait for it, or retry contention.
Do not read any other original-root file beyond the nineteen listed inputs. Concurrent
experiment or observer work is not permitted during this invocation.

Use these cumulative limits for the collector's intentional data operations:

| Bound | Maximum |
| --- | ---: |
| Literal input slots | 19 |
| Required present files | 15 |
| Optional leaf observations, including rechecks | 8 |
| Individual file bytes | The exact per-row limits above |
| Aggregate original content | 134,217,728 bytes (128 MiB) |
| Content reads, including original continuity and private readbacks | 58 |
| Aggregate bytes read | 402,718,720 bytes (384 MiB + 64 KiB) |
| New file output bytes, including inventory | 134,283,264 bytes (128 MiB + 64 KiB) |
| Canonical inventory bytes | 65,536 bytes |
| Counted path operations | 4,096 |
| Read/write chunk | 65,536 bytes |
| Original collector clock | 90,000 milliseconds |
| Outer TERM deadline, including interpreter startup | 95 seconds |
| Nonresetting KILL grace | 2 seconds |
| Complete original combined tool capture retained for acceptance | 16 KiB |

If `P` files are present and their total length is `S`, normal completion uses exactly
`3 * P + 1` content reads: each original once, each original again for continuity, each
new raw copy once, then the inventory once. It reads `3 * S + I` bytes and writes
`S + I`, where `I` is the inventory length. The per-row content ceilings sum to
132,382,720 bytes, below the aggregate original bound. The 128 MiB ceiling is a
conservative budget for this fixed nineteen-slot frontier, with 1,835,008 bytes of
headroom above those per-file ceilings. It is not an observed content total or a bound
for complete SDK/dependency closure. The corresponding maximum normal read total is
397,213,696 bytes and maximum normal output is 132,448,256 bytes, including the full
65,536-byte inventory allowance. Missing optional leaves are not content reads. They use four initial optional observations plus one recheck per absent
leaf, at most eight. These counters describe intentional collector data/path operations;
ordinary Linux interpreter, standard-library, ELF loader and watchdog startup are covered
by their separate runtime review, not an exhaustive system-wide I/O count.

The source clock is monotonic, starts once in `main`, and never resets. Check it and
latched cancellation before and after bounded I/O, sync, output validation, resource
finalization and final stdout flush. The external watchdog includes startup and cannot
turn a late source-clock result into success. These are bounded-operation/watchdog
controls under the accepted OS assumptions, not a guarantee against an uninterruptible
kernel/filesystem stall or proof of global process quiescence.

### Output, Source and Runtime Admission

Create only the new private directory `/tmp/windows-final-publish-sdk19-offline-v1`
with mode `0700`, after every initial required/present-content read and optional absence
observation passes. Require exclusive no-follow creation; reject a preexisting root.
Use only the nineteen fixed flat output labels in the source and `inventory.json`.
Absent leaves have an inventory entry and no raw file. Never enumerate the directory.
Create raw/inventory files exclusively with initial mode `0600`, sync complete bytes,
seal them `0444`, sync again and sync the held output directory. Retain held directory
identity and verify its final path identity. Read back every raw copy and the canonical
ASCII, sorted-key, compact JSON inventory with one trailing LF.

Original content reads require stable device/inode/length/mtime/ctime across the opened
file and final no-follow leaf lookup, regular-file type and the exact applicable hash.
The later original reads additionally require the first-read identity, length, hash and
raw-byte equality. These are bounded continuity checks; the operation does not write
original content or claim an atomic snapshot against hostile concurrent replacement.

The prepared inactive source is 27,884 bytes with SHA-256
`6b997d1ed3cc4d1db3b8f87c2509845fc30debe678cf8618601295e7d44400ac`.
After independent source/procedure acceptance, the only proposed activation changes
`ACTIVE = False` to `ACTIVE = True`, producing 27,883 bytes with SHA-256
`edb0ef1887f6556d757b07b421a962852201639f17b54ef8775eb29f848ec20b`
at `/tmp/collect_windows_final_publish_sdk19.accepted.py`. This predicted source has
not been materialized or executed by preparation. Its preparation-basis protocol pin
is provenance only; exact execution admission must bind the then-current accepted
protocol amendment and Wave independently.

Use the existing reviewed Linux runtime, with fresh identity and startup-context checks
at exact admission. The prior accepted identities below are reuse candidates, not a
claim that preparation re-read the installed files or validated the future environment.

| Runtime file | Bytes | Prior accepted SHA-256 |
| --- | ---: | --- |
| `/usr/bin/bash` | 1,540,520 | `3efccc187bafa75ff1e37d246270ab3e7aa559f242c7a52bf3ec2a1b5450bdbd` |
| `/usr/bin/gnutimeout` | 39,968 | `1ba715580334044dbd32873bddd7f8a19687cda1cf5e9f44be7266af6c048766` |
| `/usr/bin/python3.14` | 7,477,160 | `52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41` |

The proposed literal is the following command in
`/tmp/azureauth-windows-names-accepted-108`, with nonlogin `/usr/bin/bash`, no TTY,
no pipeline/status wrapper and complete original capture:

```sh
exec /usr/bin/gnutimeout --signal=TERM --kill-after=2s 95s /usr/bin/python3.14 -I -B -S /tmp/collect_windows_final_publish_sdk19.accepted.py
```

Require isolated, no-bytecode, no-site and nonoptimized Python startup. Recheck the
accepted shell/loader/startup injection boundary and selected GNU watchdog identity;
do not substitute `/usr/bin/timeout`, use `--foreground` or `--preserve-status`, add
code injection, or load candidate modules for a test. No Windows executable or SDK
dependency is launched. Source/AST inspection remains data-only preparation.

Accept an outcome only after independent review of the original normal zero exit,
complete original transport, exact inventory/copy bytes and finite counters, finalization,
source/runtime/literal bindings, and each conditional absence or content classification.
An inventory descriptor alone cannot establish completion. Keep `graphAccepted`,
`artifactAccepted`, `continuation_allowed`, `sdkHistoricalContinuityEstablished`, and
`sdkProvenanceAccepted` false. On every failure preserve all complete or partial private
output and the original start/transport evidence; do not delete, rewrite, recollect or
accept partial data as successful transport. This operation supplies only the admitted
direct identity frontier. Any shared-runtime/dependency selection, Csc plan, precompiler
observation, original response join or final publication retains its separate gates.

## Fixed Host and Runtime Identity Follow-up

After the independently accepted SDK19 outcome, this section permits preparation of
one separately admitted raw-data collection of fourteen fixed leaves and two bounded
name observations of one fixed directory. It resolves the next missing identity and
selection inputs for the existing final-publish work. It does not admit an SDK process,
MSBuild evaluation, precompiler observation, compilation, final publication, or account
operation. All earlier one-time collectors, parsers, observers and experiments retain
their consumed capacity and cannot be replayed.

SDK19 completed its sole invocation with an independently accepted original zero exit,
complete transport, seventeen content copies and two bounded leaf absences:
`seed-03` and `csc-08`. Its copied payload totaled 16,821,497 bytes; the 16,432-byte
inventory has SHA-256
`2f5c537c1161aae5c6a915d55039b1e94770d03cb24ffa06287870fac1fe285a`.
These are raw-copy outcomes, not an SDK, compiler or authentication execution result.

Use the existing WSL Linux review environment and the existing public Windows
SDK 10.0.401/runtime 10.0.12 installation. Read each selected DLL as inert data. No
Windows process, network request, dependency download, installation, restore, build,
test, publish, WAM, UI, token, account, consent or authentication-cache effect occurs.
Reuse the accepted SDK19, native2, dispatch4 and restore12 data within their scopes;
none of their files are collected again.

### Fixed Leaves and One Directory

Each table row is a literal input. The inactive source fixes its corresponding
`/mnt/c/` path and flat private output name. Arguments, metadata and observed directory
names cannot select any additional file. Required content is a capture expectation,
not a claim that every runtime rejects a missing manifest.

| Slot | Exact Windows path | Required outcome | Maximum bytes |
| --- | --- | --- | ---: |
| `entry-01` | `C:\Program Files\dotnet\sdk\10.0.401\.version` | Content or exact leaf absence | 65,536 |
| `entry-02` | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.DotNet.Cli.CoreUtils.dll` | Required content | 4,194,304 |
| `entry-03` | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.DotNet.Cli.Utils.dll` | Required content | 8,388,608 |
| `entry-04` | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.DotNet.Configurer.dll` | Required content | 4,194,304 |
| `cscdep-01` | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\Microsoft.CodeAnalysis.dll` | Required content | 16,777,216 |
| `cscdep-02` | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\Microsoft.CodeAnalysis.CSharp.dll` | Required content | 33,554,432 |
| `framework-01` | `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.12\Microsoft.NETCore.App.deps.json` | Required content | 4,194,304 |
| `framework-02` | `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.12\Microsoft.NETCore.App.runtimeconfig.json` | Required content | 65,536 |
| `framework-03` | `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.12\Microsoft.NETCore.App.runtimeconfig.dev.json` | Content or exact leaf absence | 65,536 |
| `runtime-01` | `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.12\hostpolicy.dll` | Required content | 4,194,304 |
| `runtime-02` | `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.12\coreclr.dll` | Required content | 16,777,216 |
| `runtime-03` | `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.12\System.Private.CoreLib.dll` | Required content | 33,554,432 |
| `fxr-01` | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\bincore\hostfxr.dll` | Content or exact leaf absence | 4,194,304 |
| `fxr-02` | `C:\Program Files\dotnet\host\fxr\10.0.12\hostfxr.dll` | Required content | 4,194,304 |

Only `runtime-03` has a required prior historical hash:
`1125acc8106c43fc8bad2d203c4c4485df6182d292846c2fff415c1040c54678`,
from the accepted 0052 exact tool-map path. Other present leaves receive one prospective
first-capture hash; all later original/readback reads require that exact hash, length,
identity and bytes. A prospective hash establishes an observed identity, not signer,
revocation, installation or complete source-equivalence evidence.

The three optional leaves follow SDK19's existing-parent, exact-leaf absence rule:
observe each once initially, and recheck each absent leaf after copying under its
unchanged parent identity. Missing parents, inaccessible files, symlinks, nonregular
leaves and other errors fail. Do not create placeholders or infer absence from an error.

The one directory is exactly `C:\Program Files\dotnet\host\fxr`, observed through
`/mnt/c/Program Files/dotnet/host/fxr`. Hold its no-follow directory identity and take
two complete immediate-name snapshots around the fixed-leaf collection. Each successful
snapshot has at most 32 entries. One additional entry may be retrieved solely to detect
overflow and fail; at most 66 entry observations occur across both snapshots. Require
strict UTF-8 with at most 1,024 bytes per name and 65,536 name bytes across both
snapshots; the complete canonical inventory also has a separate 65,536-byte ceiling.
Do not read entry
contents, inspect discovered child paths, recurse, follow links or use a discovered
name in a file path. Reject incomplete enumeration, encoding ambiguity, duplicate
names, changed name sets or changed held/path directory identity.

The name set is deliberately a conservative superset of the directory-only names used
by the public host selector. The fixed `fxr-02` path supplies the expected version's
directory and file identity. Collection does not parse versions, choose a host, or
require the name evidence to establish a runtime choice while original files are open.
After independent raw-outcome acceptance, offline review must apply the exact
source-bound version parse, comparison and rendering rules to establish an unambiguous
maximum of `10.0.12`. A higher or ambiguous candidate, canonical-name mismatch, or
unexpected app-local `fxr-01` content bars the proposed runtime route; it never permits
another read target or alternate host selection under this operation. Refresh relied-on
selection and file continuity before a later separately admitted execution. Two
snapshots do not establish atomic or continuing filesystem state.

### Why These Inputs Are Needed

SDK19's accepted configurations request `Microsoft.NETCore.App` 10.0.12. The compiler
configuration also declares `Major` roll-forward; the unchanged explicit
`DOTNET_ROLL_FORWARD=Disable` is applied later by the
[host configuration source](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/native/corehost/runtime_config.cpp).
This is a conditional source inference, requiring the actual selected host and
parent/child environment before execution. It does not select a hostfxr version.

The [hostfxr selector](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/native/corehost/fxr_resolver.cpp)
selects the highest parseable direct version-directory name, including prereleases,
then checks its fixed `hostfxr.dll`; framework roll-forward settings do not choose it.
The compiler's app-local hostfxr check is separate. SDK19's narrow native-byte analysis
supports the adjacent `csc.dll` and non-bundle relationship; its application version
resource does not establish native apphost search options.

The selected framework's
[configuration parsing](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/native/corehost/fxr/fx_resolver.cpp)
includes its own development configuration. SDK19's SDK/compiler development-config
absences do not cover that different leaf. Framework declarations remain candidate
assets and settings until their exact content and relevant selection are reviewed.

The SDK's [version-file parser](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/Microsoft.DotNet.Cli.CoreUtils/DotnetVersionFile.cs)
uses the second line verbatim for `BuildNumber`. A yielded first line shorter than ten
UTF-16 code units, including an empty line, throws before fallback. Only a null
`BuildNumber` selects
the [Product version-resource fallback](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/Microsoft.DotNet.Cli.CoreUtils/Product.cs).
An empty second line does not select fallback. Bind the actual owning assembly and
successful parsing before deriving any first-use sentinel filename. This collection
creates no sentinel and does not change the current publish recipe.

The two compiler dependency leaves are distinct names declared by `csc.deps.json` and
requested by the captured compiler assembly. Repeated dependency declarations do not
justify duplicate collection or recursively following other asset names. The three
SDK entry assemblies supply the specific first-use and forwarding identities; shared
runtime copies supply the next host/runtime identity inputs. No complete SDK audit or
whole binary-to-source proof is implied.

### Single Invocation, Bounds and Acceptance

This operation has exactly one invocation. A failed start, inactive-source rejection,
lock contention, input error, collision, cancellation, timeout, partial transport or
nonzero exit consumes it. Record the start before launch; no retry, repair, resume,
alternate output directory or capacity refund is allowed. This inert copy does not
consume a restore/build/test/publish or synthetic-process scenario, and does not reset
any existing cumulative counter.

Retain SDK19's no-follow existing `action.lock`, read-only open, nonblocking exclusive
lock, held/path identity checks and final release. No other original-root file is
read. Perform no original-path, lock or planned-output preprobe during preparation.
There is no concurrent original observer or experiment during this invocation.

| Bound | Maximum |
| --- | ---: |
| Fixed leaf slots | 14 |
| Required present leaves | 11 |
| Optional leaf observations, including absent-leaf rechecks | 6 |
| Direct directory snapshots | 2 |
| Entries in one successful snapshot | 32 |
| Entry observations, including overflow detection | 66 |
| Strict UTF-8 bytes per name | 1,024 bytes |
| Name bytes across both snapshots | 65,536 bytes |
| Aggregate original content | 150,994,944 bytes (144 MiB) |
| Content reads, including continuity and readback | 43 |
| Aggregate bytes read | 453,050,368 bytes (432 MiB + 64 KiB) |
| New output bytes, including inventory | 151,060,480 bytes (144 MiB + 64 KiB) |
| Canonical inventory bytes | 65,536 bytes |
| Counted path operations | 4,096 |
| Read/write chunk | 65,536 bytes |
| Original collector clock | 90,000 milliseconds |
| Outer TERM deadline, including startup | 95 seconds |
| Nonresetting KILL grace | 2 seconds |
| Complete original combined tool capture | 16 KiB |

The per-leaf ceilings sum to 134,414,336 bytes. If `P` leaves are present with total
content `S`, and the inventory has `I` bytes, normal completion performs `3 * P + 1`
content reads, reads `3 * S + I` bytes and writes `S + I` bytes. The maximum normal
read total from the row ceilings is 403,308,544 bytes; maximum normal output is
134,479,872 bytes, including the full inventory allowance. Name observations and
optional absences are counted separately and do not read leaf content.

Retain SDK19's one monotonic source clock, latched cancellation, checks around bounded
I/O, sync, readback, finalization and final stdout flush, plus its original external
watchdog and runtime/startup-context admission. Ordinary Linux interpreter, standard
library, ELF loader and watchdog startup retain their separate reviewed boundary;
these counters are not exhaustive system-wide I/O totals.

Create only `/tmp/windows-final-publish-host14-offline-v1`, mode `0700`, after all
initial required/present reads, optional observations and the first bounded name
snapshot pass. Reject an existing root. Exclusively create the fixed flat raw copies
and canonical `inventory.json`, initially `0600`, then sync, seal `0444`, sync again,
sync the held output directory, verify its final identity, and read back complete bytes.
Absent leaves appear only in inventory. Do not enumerate output. Use SDK19's stable
original identity, raw-byte continuity, canonical ASCII JSON with trailing LF, complete
original transport and normal-zero-exit acceptance requirements.

The reviewed inactive source is 31,499 bytes with SHA-256
`0b701cabe6183c550f7c376471ec50ae4175e3352b8d0d16cb38be0bb918a05c`.
Its only permitted activation changes the single `ACTIVE = False` assignment to
`ACTIVE = True`; the resulting source is 31,498 bytes with SHA-256
`0f1f64e8883098bbb943945b05fd660117a615856eea879f1893da4e188efa98`,
exclusively materialized at `/tmp/collect_windows_final_publish_host14.accepted.py`.
The accompanying procedure is 26,143 bytes with SHA-256
`46e70373497e853aab2b3679f9b8b79049591ea9fc022ace31868be5642cde32`.
Do not import, invoke or test the inactive source during review.

After independent admission, use nonlogin, noninteractive `/usr/bin/bash`, no TTY,
and working directory `/tmp/azureauth-windows-sdk-compiler-identity-accepted-108`.
The only literal invocation is:

```sh
exec /usr/bin/gnutimeout --signal=TERM --kill-after=2s 95s /usr/bin/python3.14 -I -B -S /tmp/collect_windows_final_publish_host14.accepted.py
```

Independent admission binds the accepted amendment,
unchanged Wave, exact source/runtime/literal, fixed input/output locations, one-time
capacity, finite operation accounting and complete capture. Keep every final execution
component disabled. Independent outcome review permits only offline interpretation of
accepted raw copies and names; graph, artifact, source-provenance and execution
acceptance remain separate. On any failure preserve all partial outputs and original
start/transport evidence without rewriting or accepting partial transport.

### Accepted Host Identity Collection and Offline Interpretation

HOST14 completed its sole invocation under protocol commit
`4a0de51a129575301c53a59538af12edea150136` with original exit zero and complete
transport. Independent review accepted twelve raw copies totaling 49,290,603 bytes,
the bounded absences of `framework-03` and `fxr-01`, and equal complete immediate-name
snapshots containing `6.0.36`, `8.0.31` and `10.0.12`. The collector recorded 37
intentional payload reads totaling 147,885,871 bytes and 49,304,665 output bytes.
Its remaining invocation capacity is zero.

A separately source- and runtime-reviewed offline parser then completed exactly once
with original exit zero. It read the accepted raw-outcome record and twelve copies:
thirteen payload reads totaling 49,317,033 bytes. Independent outcome review accepted
the completed supported-subset projection. It performed no original or installed-root
read, absent-leaf probe, DLL load, IL execution, or earlier-parser replay. Its remaining
invocation capacity is also zero. The original projection retains false semantic,
runtime-selection, graph, artifact and execution acceptance flags; the contextual
conclusions below do not rewrite that receipt.

| Retained evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Original HOST14 transport | 1,041 | `788fcee73a2af3c81a669bb7d0ba7260360a840156c0ba1e9e0efbc093f0e4b9` |
| HOST14 inventory | 14,062 | `2e10a7bddb0bdaeb3e525bc7c82499a27cfe3e7a1365c9e85e884a402c11d512` |
| Independent raw-outcome acceptance | 26,430 | `d21945e8bbae11c284d6401c77c871aa5d0e0ff630da4c61e6605f7c1a3c3822` |
| Executed offline parser source | 47,326 | `08c299f04277e44d0ab1a29bb32b723d5f2df716f519763a9e0ae797a1311fc7` |
| Independent parser source/runtime admission | 6,908 | `6c2a2d5474306fb333ccf63eb908d97359f45beb0cb5e1d8b33a539173fa4c77` |
| Original parser transport | 1,192 | `765997054d5926709945672338f09ee565d401cc35ae862421f08a9f5574d85c` |
| Completed inert projection | 188,341 | `df62bdc5f4cc6e0449a72a5599556fc7c0bc114f60dc63b2b29b96d31d369dd5` |
| Independent parser outcome acceptance | 5,318 | `d4378003b8eb9761417a529bc5b27c3f7314e058eadcb9d30a614f8725a45053` |

The supported parser subset does not implement the runtime's complete metadata loader,
signature validation, fallback version-resource language selection, or every custom
attribute. A review-helper assertion incorrectly required sorted JSON reserialization
to reproduce the original bytes after numeric object keys became strings. That helper
stopped before creating an acceptance record. The corrected review checked the original
exact hash, stable identity and duplicate-rejecting JSON. The parser itself neither
failed nor retried, and its output did not change.

The accepted `.version` projection contains valid UTF-8 without a BOM and five lines.
Its first line has forty UTF-16 code units, with first ten `e34a38d2ae`; its second
line is the nonempty `BuildNumber` `10.0.401`. The remaining fields are `win-x64`,
`10.0.401-servicing.26423.113` and feature band `10.0.400`. Applying the pinned
`DotnetVersionFile` and `Product` sources cited above selects `Product.Version`
`10.0.401` without the version-resource fallback, conditional on the selected owning
CoreUtils assembly and its source/location correspondence.

CoreUtils contains the expected `Product`, `DotnetFiles` and `DotnetVersionFile` type
declarations. CoreUtils, Cli.Utils and Configurer declare assembly version
`10.0.401.0`; the two Roslyn dependency assemblies declare `5.9.0.0`. Their
informational versions identify aggregate commit
`e34a38d2ae1fc26406a317517196e55c68ff83ab`. The immutable
[aggregate source manifest](https://github.com/dotnet/dotnet/blob/e34a38d2ae1fc26406a317517196e55c68ff83ab/src/source-manifest.json)
maps this aggregate to SDK `32593ca81f8aae7b0d41c1a7198529c3365106b8`, MSBuild
`b44cdcec4c79c50c67560876707d57d4f635fa3b` and Roslyn
`f7797ed513e3035983346552ac2d9ca2281bc2ec`.

The hostfxr, hostpolicy, coreclr and CoreLib version-resource declarations identify
aggregate `95017c711e6afc1085133d440e42b4bd78155701`. Its immutable
[source manifest](https://github.com/dotnet/dotnet/blob/95017c711e6afc1085133d440e42b4bd78155701/src/source-manifest.json)
maps runtime to `4271d88e0aebf3d04f188f1334c2220d80555ef6`. Native fixed versions
are `10.0.1226.42308`; coreclr's comma-separated ProductVersion string is a formatting
difference, not a conflicting runtime selection. CoreLib's copied hash matches the
required historical hash. These are contextual identity joins under the existing
public-toolchain trust basis, not complete binary/source equivalence or loading evidence.

The framework configuration declares only `tfm: net10.0` in `runtimeOptions`; its
dependency manifest declares runtime target `.NETCoreApp,Version=v10.0/win-x64` and
library `Microsoft.NETCore.App.Runtime.win-x64/10.0.12`. Applying the pinned hostfxr
name-comparison rule to the accepted complete name set gives the unique conditional
maximum `10.0.12`; the fixed captured path supplies its parent/leaf identity. The
framework development-config and Roslyn app-local hostfxr absences remain bounded
observations. They do not establish continuing absence or actual runtime loading.

The SDK's
[first-use sentinel source](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Cli/Microsoft.DotNet.Configurer/FirstTimeUseNoticeSentinel.cs)
therefore derives the filename `10.0.401.dotnetFirstUseSentinel`. This is a source
conclusion for later isolated SDK preparation. No sentinel or planned final source root
was created or probed by this work. Its actual location, preparation, existence checks,
host/root selection, environment and input continuity remain later execution predicates.

No product reservation or build/test, preparation, publish, download or synthetic-process
capacity was added or consumed by these review operations. All four final-publication
components remain disabled. Precompiler observation, final Native AOT publication,
final CLI and WSL scenarios, and real account acceptance remain open under their own
protocol and admission requirements.

## One Core Csc Diagnostic Observation

This supplement allocates one credential-free diagnostic build/test action for Issue
#108. Its question is the original Core Csc task's bound inputs and command-line
arguments in the selected CLI Publish/reference context. It stops before compilation.
Final Csc input values, generated source and argument text are observation outputs;
a complete final publication graph or Native AOT artifact is not a prerequisite to
this separate action. The existing account-effects prohibition remains applicable.

### Source, Invocation and Materialization

Use product commit `503360753accd0829801953823b1b57a4f852440`, tree
`8506cdd9781c8a331ea12ea8fe27a55292eec073`, SDK 10.0.401/runtime 10.0.12
and the existing public package root. The diagnostic root is
`C:\Temp\azureauth-windows-slice-108\observers\core-csc-5033607\source`.
The separate planned final source root is not read, probed or materialized by this
action. No restore, download, toolchain installation, compiler or product invocation
is selected by this diagnostic protocol.

Materialize all 34 `src`/`global.json` source inputs, totaling 150,146 bytes. Preserve
33 Git blobs; the sole overlay adds a 110-byte unconditional fixed Import immediately
before the closing Project element in the original 395-byte
`src\Directory.Build.props`. The resulting 505-byte file imports the observer outside
product source globs. Preserve the three project files and ordinary project-reference
metadata, including library RID and SelfContained propagation. The exact source
manifest, payloads, active observer and their projection back to product source must
receive independent admission before materialization.

Reuse the twelve accepted, unchanged restore inputs, totaling 233,709 bytes, in their
proper per-project `obj` directories. Do not rewrite restore metadata, resolve an
Import as a collection selector, or perform another restore. A separately admitted
inert parser has completed its sole six-file invocation under protocol
`e80b4134ffe20f1c5dbae0c6f845cbbc398a57f3`, with original exit zero and complete
transport. Independent review accepted six projections with fifty XML elements from
6,566 input bytes. The projection is 20,502 bytes, SHA-256
`87a565311dfcd26adc8c870cfe0a6020986c91d9ae4b7f0bdcd131c9e26bfaff`.
Core's generated props and targets contain no Import; CLI props select ILLink and
ILCompiler, Windows props select ILLink, and CLI/Windows targets select NativeInterop.
These are inert XML facts. Conditions, imported SDK/package effects and actual file
selection retain their source and physical predicates. Parser capacity is exhausted.

Invoke the selected muxer through its built-in `msbuild` route with the seventeen
source-reviewed Publish properties and the additional diagnostic global property
`MSBuildUserExtensionsPath=${ACTION_ROOT}\home\msbuild-user`, target Publish,
`-restore:false`, one node,
disabled node/build/compiler servers and the unchanged 35-entry replacement
environment. Use detailed output, `-noAutoResponse`, `-tl:off` and the one binary
logger at
`C:\Temp\azureauth-windows-slice-108\observers\core-csc-5033607\observer.binlog`
with `ProjectImports=None`. The exact argument vector and native encoding are fixed
by the independently admitted proposal and caller, not reconstructed from captured
command text. Preserve the SDK logger's three documented internal environment
additions as differences from the final publication recipe.

The user-extension property fixes the wildcard import consumers to a new ordinary,
empty owned directory, checked before startup and after the natural diagnostic stop.
Preserve it as a global through ordinary project references; no TreatAsLocalProperty
or child removal/replacement is admitted. This deliberately changes the diagnostic
import path and must remain visible in the later diagnostic-to-final projection.
It does not suppress MSBuild's earlier initialization lookup of the Windows local
application-data known folder. That in-process metadata lookup remains a declared SDK
initialization effect; the diagnostic neither reads the ambient user-extension
directory nor captures its private path.

The tracked sources are [the observer](../../../tools/validation/CoreCscObserver.targets),
[Windows controller](../../../tools/validation/Invoke-WindowsCoreCscObserver.ps1),
[WSL dispatcher](../../../tools/validation/run_windows_core_csc_observer.py), and
the observer-only entrypoints in
[the existing history contracts](../../../tools/validation/final_publish_contracts.py).
All execution gates and both target Conditions remain false in Git. Exact admission
must bind their accepted Git revision, private activation deltas, runtime identities,
static authority, source and restored payloads, and complete original literal call.
The history module's observer-only activation must leave `DRAFT_ONLY = True` and
every final-publication entry gate disabled. No SDK project, controller, adapter or
target may be imported, parsed for execution, tested or invoked merely because this
source proposal exists.

After its durable reservation, the WSL dispatcher stages exactly 34 source payloads,
twelve restored payloads and the independently admitted active observer in the new
action's `observer-payloads` directory. Its `observer-support` directory receives
the fixed controller, proposal, source manifest, materialization map, eleven review
inputs and the static authority. Hash-bound pairs fix each Linux input and Windows
destination. A dedicated `wslGuardProjections` mapping stages exactly two additional
accepted offline guard-evidence copies in that same support directory: the 967-byte
WSL result as `guard-wsl-result.json` and the 4,068-byte completion acceptance as
`guard-completion-acceptance.json`. Their source descriptors must match the respective
`guard.wslResult` and `guard.completionAcceptance` byte counts and SHA-256 values;
both guard destinations must be literal paths in the reserved action's support
directory before the controller reads them. Charge these two reads and 5,035 payload
bytes to the existing dispatcher limits. Keep the eleven review inputs separate and
reuse the already accepted Windows artifact-acceptance copy. Do not read the original
WSL result, reconstruct evidence, stage a third guard projection, or allocate another
action for this transfer. The authority remains independent of the subsequently derived
reservation hash; the external invocation supplies that authority's exact hash. The only Windows
bootstrap is the installed Windows PowerShell with `-NoLogo -NoProfile -NonInteractive
-File` and this action's fixed controller. No shell interpolation or alternate helper
is admitted.

### Five Fixed SDK XML Identity Inputs

Before observer activation, prepare one separately admitted inert collection of the
five remaining reached SDK XML identities. Use the existing WSL review environment;
do not start Windows, MSBuild, an SDK or a compiler. This is a new five-leaf collection,
not a replay of SDK19, HOST14 or any completed parser. Each input is required content
at its exact corresponding `/mnt/c/` path:

| Slot | Exact Windows path |
| --- | --- |
| extensions-entry | `C:\Program Files\dotnet\sdk\10.0.401\Current\Microsoft.Common.targets\ImportAfter\Microsoft.NET.Build.Extensions.targets` |
| test-entry | `C:\Program Files\dotnet\sdk\10.0.401\Current\Microsoft.Common.targets\ImportAfter\Microsoft.TestPlatform.ImportAfter.targets` |
| extensions-main | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft\Microsoft.NET.Build.Extensions\Microsoft.NET.Build.Extensions.targets` |
| test-main | `C:\Program Files\dotnet\sdk\10.0.401\Microsoft.TestPlatform.targets` |
| compiler-api | `C:\Program Files\dotnet\sdk\10.0.401\Roslyn\Microsoft.Managed.Core.CurrentVersions.targets` |

The pinned [Build.Extensions import](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Tasks/Microsoft.NET.Build.Extensions.Tasks/msbuildExtensions-ver/Microsoft.Common.targets/ImportAfter/Microsoft.NET.Build.Extensions.targets),
[Build.Extensions main targets](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Tasks/Microsoft.NET.Build.Extensions.Tasks/msbuildExtensions/Microsoft/Microsoft.NET.Build.Extensions/Microsoft.NET.Build.Extensions.targets)
and [TestPlatform targets](https://github.com/microsoft/vstest/blob/6f58ced50b40e074a07ffc21fb2d2eef95d31b60/src/Microsoft.TestPlatform.Build/Microsoft.TestPlatform.targets)
explain their conditional imports and declarations. The fifth file is produced by the
[Roslyn generator](https://github.com/dotnet/roslyn/blob/f7797ed513e3035983346552ac2d9ca2281bc2ec/src/Compilers/Core/MSBuildTask/Directory.Build.targets#L22-L31)
from its CompilerApiVersion property. Public
source correspondence does not supply the installed bytes or their line endings.
Take a prospective first-capture hash once per slot; require that exact observed hash,
length and stable identity on original continuity and private readback. Do not treat
this first capture as authenticity, source correspondence or historical continuity.
Missing or unreadable inputs fail; no alternate leaf, directory listing, glob,
discovered Import, package path or fallback is selected.

Retain SDK19's existing no-follow read-only `action.lock`, nonblocking exclusive
acquisition, held/path identity checks and final release. No other original experiment
file is accessed. Retain its no-follow regular-file and parent checks, stable original
identity, exclusive output, sync/seal/readback, latched cancellation, complete original
transport and normal-zero-exit requirements. Do not probe the lock, originals or output
root while preparing or reviewing the source. No concurrent experiment or original
observer is permitted.

Use at most 32 KiB per leaf and 64 KiB aggregate original content. Normal completion
performs sixteen content reads: five initial originals, five original continuity reads,
five raw-copy readbacks and one canonical inventory readback. Aggregate bytes read are
at most 212,992, including the 16 KiB inventory; new output bytes are at most 81,920.
Count at most 1,024 path operations, use read/write chunks no larger than 32 KiB, and
retain at most 16 KiB complete combined tool capture. Keep the original 90,000 ms
collector clock, 95-second outer TERM deadline and nonresetting two-second KILL grace.
The separately reviewed interpreter/loader/watchdog startup boundary remains distinct
from these intentional data-operation counters.

After all five initial reads succeed, exclusively create only
`/tmp/windows-core-csc-sdk-five-offline-v1`, mode `0700`. Write the five slot-named
`.bin` files and canonical `inventory.json`, initially `0600`, then sync and seal them
`0444`, sync the held directory and read back complete bytes. An existing destination
or partial output is a failure; preserve it without repair, replacement or retry.

The collection has exactly one invocation. Record its start and remaining capacity
before launch; a failed start, lock contention, input error, collision, interruption,
timeout, nonzero exit or incomplete transport consumes it. Follow SDK19/HOST14's
existing classification: this inert review copy consumes no dependency-preparation,
build/test, publish or synthetic-process unit and resets no prior counter. Its own
one-time consumption remains explicit. Independently admit the exact inactive source,
activation delta, runtime/startup context, accepted Wave/protocol, output, capacity
record and complete original literal before execution. This section alone cannot
activate the collector or the observer.

After independent acceptance of the original outcome, a separately admitted offline
source-correspondence pass may read these five fixed copies once, at most 64 KiB total,
under one thirty-second nonresetting deadline. Bind their accepted hashes, the pinned
public source/generator and any explicit byte transformation. Do not follow Import
values, inspect original paths, execute markup or infer the full effective graph. Any
unexplained content difference keeps observer activation blocked. Preserve the original
inventory and all false graph, artifact and continuation flags.

### Reached Effects and Physical Predicates

Before SDK startup, exclusively create the empty regular first-use sentinel at
`${ACTION_ROOT}\home\.dotnet\10.0.401.dotnetFirstUseSentinel`. Both reached SDK
Exists checks must succeed. Create the separate zero-byte claim marker at
`C:\Temp\azureauth-windows-slice-108\observers\core-csc-5033607\first-core-compile.claim`.
The observer's fresh exact reads, 27-byte append and exact readback enforce the
independently reviewed at-most-one skipped Csc premise under one node, no yield,
no competing writer and unchanged task/target ordering. Both markers are retained
after every outcome. A marker I/O failure stops the action.

Bind the actually reached imports, customization hooks, task identities and helper
effects before activation. The minimum source predicates include the standard
CoreCompile ordering and empty resource batching, the original Csc/ManagedCompiler/
ToolTask implementation, no host-object or command-processor path, no shared compiler,
no RoslynCommandLineLogFile, and no overriding compilation controls after the observer.
The logger is constructed before SkipCompilerExecution, so the latter alone is
insufficient to exclude its file effect. Generated Common.props imports, ancestor
Directory.Build/customization files, wildcard imports, source-control discovery and
editor configuration require exact current physical predicates. Earlier absences are
not continuing evidence. The generated Managed.Core.CurrentVersions import requires
its own correspondence; a public-source 404 is not an empty-file observation.

The independently admitted static authority supplies literal `physicalAbsences` and
`physicalMembership` lists; neither is derived from discovered file contents. Check
both before the subject starts and after natural completion. Required absent leaves
cover the three nearer project props, ten ancestor Directory.Build.targets, three
project user files, ten ancestor `.git` names, twenty ancestor editor/global config
names, the six default Custom before/after imports, and the selected entry-development
and servicing/hostfxr slots. Additional optional SDK leaves need exact source-selected
expansion and a declared absence or leased existing identity before admission. Do not
read unexpected content. Reject reparse points, inaccessible paths, nondirectory
ancestors and ambiguous failures. These checks establish metadata observations in the
declared workstation model, not race-proof filesystem traversal.

Wildcard membership checks are limited to six installed SDK hook domains, six domains
under the owned user-extension root, six project `obj` props/targets patterns and the
standard VisualStudioVersion props pattern. Pin the expected standard members before
activation; do not assume installed SDK domains are empty. Every expected matching
member must already have a leased input identity or be an exactly materialized input.
Enumerate only the admitted top-level directory and compare matching ordinary file
names; no recursion or discovered content selector is allowed. An absent directory is
accepted only for an empty expected membership. Extra or missing matching members stop
the action. This does not inspect the ambient user-extension directory.

The source-selected direct host route is muxer to hostfxr 10.0.12, SDK 10.0.401,
in-process MSBuild and framework 10.0.12. Both ProgramFiles variables select the
owned ordinary empty `${ACTION_ROOT}\empty-program-files`; its `coreservicing`
child must be absent. No alternate SDK/framework/store inventory or complete aggregate
source audit is required for this route. SourceLink's no-repository branch and the
package providers' non-git SourceRoot branches retain their explicit predicates.

Permitted writes are the declared diagnostic/action files and owned intermediates:
source and restore materialization, markers, normal generated text/cache bookkeeping,
one binlog, captures and paired receipts. Include ordinary transactional temporary
writes, move retries, error deletion and LockCheck/Restart Manager diagnostics where
reached. Do not substitute Clean or suppress ordinary OnError handling. The source
assessment must distinguish imported NativeAOT targets from actual execution: the
ordinary Publish Build dependency encounters Core's intentional failure before ILC,
linking or publication copying. No package/toolchain mutation is admitted.

### Limits and Original Completion

One nonresetting 180,000 ms caller observation/success deadline covers admission,
reservation, staging, launch, handshake, subject, joining and finalization. The WSL
handshake ends at the earlier of that deadline and twenty seconds after the timestamp
captured immediately before Popen. Persist launch attempts, then recheck cancellation
and the original deadline immediately before the actual Popen or ordinary Start.
Windows Start keeps 20,000 ms for subject cleanup, ordinary Stop admission requires
more than 15,000 ms, and receipt/drain work keeps 5,000 ms. No failure refunds a charge
or authorizes another start.

The unchanged guard's ordinary Start may finish its fixed CreateProcess, assignment,
handle and resume sequence after a delayed native return, even after the caller's
deadline. Assignment-failure recovery has a fixed 10,000 ms wait after its termination
request. Ordinary Stop has a separate 10,000 ms accounting loop after termination,
with up to a final 50 ms polling overshoot. Native-call latency is not bounded by
these values. Late completion is incomplete; no new caller loop obtains fresh time.
Record actual Stop request/result flags even on throw, and record Dispose/kill-on-close
separately. Closing a Job does not establish observed quiescence.

Retain at most 4 MiB combined stdout/stderr. Emergency drain rejects after its 64 KiB
processed threshold, with at most 8 KiB of issued/in-flight overflow, for a 73,728-byte
read envelope. Record processed bytes, observed overflow and possible unobserved
in-flight capacity separately; issue no new reads after rejection. Incomplete capture
cannot become accepted observation. Poll file effects at the reviewed cadence with
at most 720 samples, 512 directory entries per sample, 128 new directories, 256 files,
128 MiB aggregate new-file and 32 MiB binlog thresholds. Generated text has separate
32-file, 1 MiB-per-file and 16 MiB aggregate acceptance limits. Count staged/preseeded
JSON/XML as inputs and include them in new-file totals. These are stop/acceptance
thresholds, not instantaneous filesystem quotas; retain any overshoot as failure.

The directory threshold includes both new scan roots and all observed descendants,
including staging and preseeded directories. Reject the 129th directory before
traversing it. Keep the latest attempted directory count separately from the last
completed file sample, so a rejecting sample retains its overflow count in the failure
receipt. Successful original joining requires the final complete sample's directory
count to agree with that receipt and remain between two and 128.

Absence checks admit at most 256 literal leaves per checkpoint, with at most seventeen
components below `C:\` and 1,024 characters per expanded path. They make at most
9,216 attempted GetAttributes metadata calls across two checkpoints, stopping at the
first missing component. Membership checks admit at most 32 domains with 32 expected
members each, the same path limits, and at most 2,176 attempted GetAttributes calls.
They accept at most 512 yielded entries per checkpoint, 1,024 total; one overflow
entry may be observed solely to reject the action. These counts are separate from
the existing cancellation metadata checks and owned-empty-directory checks. Before
each metadata call or enumerator advance, recheck original cancellation/deadline with
the 20,000 ms reserve. A native metadata/enumerator call may return late; it does not
gain another deadline. Receipts retain attempted checkpoint, metadata-call and yielded
entry counters, including failed checkpoints. Successful original joining requires
both complete checks twice and strict integer counters within their acceptance limits.

Each dispatcher/controller input reader has at most 256 reads and 256 MiB requested
bytes, with the source's smaller per-input and buffered-input limits. The observer-only
history adapter has a separate allowance of 4,096 reads and 256 MiB requested bytes
across its two history checkpoints. Preserve the existing disposed-0054 verifier's
fourteen content reads, 123,166 requested bytes, thirty seconds shared verification
time and thirty-four metadata probes within those checkpoints. Fixed Git queries and
public GitHub GET checks use the existing thirty-second per-helper limit inside the
same original action deadline; they cannot invoke an SDK, compiler or Windows proxy.

Successful provisional completion requires the original Windows controller exit zero,
natural subject/Job completion, complete capture, no termination request, permitted
file effects, the claimed marker and intentional nonzero subject exit containing
AUTH108CSCSTOP. A later independent interpretation must establish the complete unique
Core Csc input/argument/output sequence and binlog completion. Text matching alone
does not establish uniqueness. Original graph, artifact, independent-observation and
continuation flags remain false.

The shared history lock stays held through the dispatcher's local finalization attempt.
On cancellation/timeout it does not wait for the Windows proxy or Windows finally;
that completion remains unknown. Releasing the local lease is not evidence that both
receipts completed. A fresh original deadline/cancellation check after all local
persistence and lock/handler finalization decides the original caller's success.
A provisional success-looking receipt cannot override a late, nonzero, cancelled or
uncollected original invocation. An incomplete pair blocks subsequent work until
its separately accepted exact failure disposition; retain owned partial state
without speculative cleanup or a replacement receipt.

### Dedicated Allocation and Later Consumers

Allocate exactly one Windows build/test unit for this observer. Prospectively lower
the Linux ceiling from 80 to 79 and raise the aggregate Windows ceiling from 48 to 49,
while leaving ordinary Windows build/test capacity at 48. The Wave combined ceiling
remains 120. With unchanged history, the charge produces `37 + 49 + 1 = 87/120`,
including the existing fixture debit exactly once. Preparation remains 15/16, publish
0/12 and synthetic processes 48/60; the twelve final CLI scenarios remain protected.
The original execution below consumed the dedicated unit. The allocation and
historical limits remain unchanged; no replacement invocation is admitted.

Recover the original counters and derive the action number under the existing shared
lock. Preserve the immutable 45-Linux/53-Windows prefix, disposed 0054 and accepted
0055. The unchanged history makes the next number 0056; reject any different history.
Record the one-unit start durably before materialization or launch. Every failure,
including failed start, consumes the unit; a partial reservation blocks continuation.
Use the existing paired history/handoff carrier, with no second ledger.

The prospective ordinary readers fail closed when they encounter this observer,
including a provisional successful receipt, except for the subsequently accepted
[exact failed-0056 disposition](#exact-0056-failed-history-disposition). That disposition
updates the existing handoff and its current consumers together before later
publication or validation. Preserve all old receipts, flags, historical
48/80 limits and dispositions. A failed observer does not receive another unit.

Before this action can execute, independently admit the complete current physical and
source predicates, prepared inputs, exact activated source/runtime/literal and finite
effects. No account step or human input is selected here; automated preparation and
observation do not require desktop attendance. The separate final-publication graph,
Native AOT artifact, final CLI/WSL scenarios and real account acceptance remain open.

### Original 0056 Failure and Initial Evidence Recovery

The observer executed once under accepted protocol commit
`698ca30f95502a4f1cf8023ef51c0fc40918a083` and returned exit code 1 with complete,
empty tool output. This is a failed original invocation. Its original WSL result
records `RuntimeError`, `outcome: incomplete`, `normalCompletion: false`,
`safetyStop: true`, `originalWindowsCompletionJoined: false` and `quiescent: false`.
Neither a successful observation nor an accepted compiler graph was obtained.

The separately admitted initial read-only recovery then executed exactly once and
returned exit code 0. It attempted eleven fixed optional content roles, copied six
stable regular files, and recorded fixed-path metadata for cancellation and three
pending receipt names. It performed no process survey, SDK or Windows execution,
cleanup, account operation, original-receipt rewrite or additional reservation.
The recovery completed 6 original reads requesting 11,890 bytes and 7 offline
readbacks requesting 18,874 bytes. Its seven output files contain 18,867 bytes,
including the 6,983-byte report. All counts remained within its admitted bounds.

| Retained evidence role | Bytes | SHA-256 |
| --- | ---: | --- |
| Original observer tool transport | 1,520 | `cbd183a7cb55e1460324e41ae090919d9436edad3c8a3e150486fb1837e61a9d` |
| Initial recovery invocation admission | 8,159 | `174db4d7808307dcb36f384ae2cba2298449821d3a7a6e1257ca5facd63a37df` |
| Initial recovery tool transport | 1,257 | `49067e1d95af609b40becce774d90b91cf8d036a2dc72de8263042bddf066856` |
| Initial recovery report | 6,983 | `08b2171399b61923fdc578b01fe323804f986aceb17e1e0d504ad530173b8db4` |
| Original WSL result copy | 702 | `c59142ee188f40b10fdd1023d32e97d915f07d5e3851b07f3b745ee289475ad2` |
| Original paired start copies, each | 844 | `cf7354484567563e7269ab255e7d2e47f3372c775a223213ad6c3b70aeba9fdf` |
| Original WSL controller-attempt copy | 106 | `8735ca9319f97ee9a406133598420b094bf0e3de4ad33c3a241f7b6f70265746` |
| Original paired invocation copies, each | 4,694 | `896dcf2a0ccfae09dcecf7dfaec46db7f06dd8faf846b0157ab2cbc64b60d54f` |

The byte-identical paired starts record action 0056, the accepted protocol and product
source, the previous Linux `[8,37,0,0]` and Windows `[7,48,0,48]` counters, and a
one-unit build/test charge. The paired invocations, controller-attempt record and WSL
result bind that reservation by hash. The durable debit is therefore consumed:
Windows aggregate build/test usage is 49, and combined usage including the existing
fixture exactly once is `37 + 49 + 1 = 87/120`. Preparation remains 15/16, publication
0/12 and synthetic scenarios 48/60. The dedicated unit cannot be refunded or reused.

The WSL result records a launch attempt and launch/handshake timestamps, but no
completed clock exchange or Windows completion join. Its `proxyExitCode` is null.
The Windows result, clock-ready, clock-remaining and subject-start-attempt leaves
were absent at their individual observations; the cancellation leaf was a regular
empty file by metadata. The three inspected pending leaves were also absent.
These observations are not an atomic snapshot and do not independently prove that
no process started or that every process has exited. At the initial recovery, the exact underlying failure
and Windows/helper quiescence remained unresolved. The later
[current-bootstrap result](#current-bootstrap-observation-outcome) resolves only
its stated current lifetime question. The controller's outer admission
catch does not persist its exception, and the dispatcher discarded bootstrap output;
the retained evidence cannot recreate those diagnostics.

Both the observer and its initial recovery invocation are consumed. Preserve all
original receipts, partial state and false graph, artifact, independent-observation
and continuation flags. The exit-zero receipt copier remains ineligible. Current
history readers rejected this incomplete pair before the later
[exact failed-history disposition](#exact-0056-failed-history-disposition). This original
failure record itself creates no successor handoff or continuation grant. Before dependent
execution, resolve the outstanding lifetime evidence and accept the required bounded
protocol and current-consumer changes. No observer retry, additional recovery,
speculative cleanup, publication or account operation is authorized here.

Source review identified a separate early-admission defect in the original
controller's `Assert-Direct`: after following `FileInfo.Directory` or
`DirectoryInfo.Parent`, it read the provider-added `PSIsContainer` property on the
returned CLR object. [Get-Member's provider-property example](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-member?view=powershell-5.1#example-7-determine-which-object-properties-you-can-set)
and the documented [Directory](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo.directory?view=netframework-4.8.1)
and [Parent](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo.parent?view=netframework-4.8.1)
return types support this finding; [StrictMode](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/set-strictmode?view=powershell-5.1)
rejects missing-property access. The tracked inactive controller now branches on
`DirectoryInfo` and `FileInfo`, preserving ancestor traversal and reparse rejection
and rejecting unsupported types. This source correction does not identify the lost
original exception or establish runtime success. The executed active source remains
unchanged, and the correction grants no activation or execution.

## One Current 0056 Bootstrap Observation

The original 0056 observer remains failed and its dedicated build/test unit consumed.
This amendment selects one separate read-only observation of its Windows PowerShell
bootstrap's current presence, absence or unknown state. It does not repeat the
observer, collect another original receipt, execute a compiler, or change account
state. The existing credential-free Wave entry covers this bounded lifetime question;
no desktop attendance is required.

### Source Basis and Remaining Question

The source finding above supplies a qualified reachability exclusion for the exact
old active controller, SHA-256
`731ba855e775b326c1716c242ed630b02f472f2d322e621a71464ae16cd1c4d5`,
under the accepted ordinary Windows PowerShell 5.1/.NET Framework/FileSystem-provider
trust. Its first authority `Read-Bound` enters the defective `Assert-Direct` before
opening an input stream. The raw nonroot parent lacks the provider note property;
StrictMode terminates that path before the clock handshake, guard load, Job
construction or `guard.Start`. Earlier bootstrap/admission failure cannot reach
those operations either, and the outer catch/finally has no alternate subject entry.
Thus this selected route cannot create the guarded subject or its descendants.
This source conclusion does not identify the discarded original exception or claim
an observed historical no-launch result. Ordinary runtime/provider/OS activity is
within the existing trust boundary, not an additional descendant-survey obligation.

The independent source-exclusion addendum is 11,278 bytes, SHA-256
`e936924ef6c587be62c4123dd7c6a4dad204d838a32b4927ac0b949683b447a8`.
The remaining observation concerns only the fixed original PowerShell bootstrap.
No original PID, Job handle, descendant inventory, original-root read or cleanup is
selected. Preserve the original nonzero outcome and every original receipt flag.

### Exact Query and Effects

Use [the dedicated source](../../../tools/validation/Observe-WindowsCoreCscBootstrap.ps1)
as one independently admitted `EncodedCommand` of its exact UTF-16LE source text.
Invoke the existing Windows PowerShell image with `-NoLogo`, `-NoProfile` and
`-NonInteractive`, from the existing WSL environment through nonlogin Bash with no
TTY. Independently bind the accepted commit, exact source bytes, runtime route and
literal tool arguments before the sole call. No source parsing, test invocation or
native preflight is authorized as a separate attempt. No Windows script file is
created; encoded source cannot match the original raw controller-path selector.

The source performs one module-qualified `Get-CimInstance` query in local
`root/cimv2`, with no ComputerName, CimSession, InputObject, remote transport or
privilege change. [The documented default route](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1)
uses local WMI through COM. Ordinary installed runtime, module and provider trust
remains unchanged; no SDK/tool installation, loader inventory or account/store
access is selected.

The fixed WQL predicate selects `powershell.exe` rows with a null/empty command line
or the literal old 0056 controller-path substring, using escaped backslashes and
only the two surrounding LIKE wildcards. It requests CommandLine and ExecutablePath
only. Each returned row is either the exact old bootstrap tuple or ambiguous;
none is silently discarded. The image path must match ignoring case, and all
fourteen original argv tokens must match the literal order, paths and both entire
authority/invocation hashes. Each whitespace-free token may have paired outer
quotes; alternate spellings, extra/reordered tokens and partial quotes are unknown.
The source fixes these values from the admitted original arguments; it does not
read them from the failed action. No PID, creation-date or parent filter excludes a
late original bootstrap. Missing attribution, duplicate matches and inaccessible
properties remain unknown.

Rows are classified in memory. Do not emit or retain raw command lines, image
paths, process rows, account names, environment values or provider errors. Do not
invoke a process/Job control method, launch a subject, inspect an account/cache,
write Windows files, read original experiment files, or adjust security settings.

### Bounds, Original Completion and Disposition

Exactly one launch attempt and one query are permitted. Every outcome, including
failed startup, consumes the observation. There is no retry or additional query.
Record the original invocation once in the existing private execution carrier;
this observation adds no restore/build/test/publish or synthetic-scenario debit.
The failed observer's durable shared-history charge remains unchanged at 87/120.

The query requests a five-second operation timeout. The script's nonresetting
elapsed acceptance limit is 15,000 ms, checked before querying, on each streamed
row and after enumeration. At most sixteen rows receive property examination;
the seventeenth row aborts before its properties are read. Each examined command
line is limited to 4,096 UTF-16 code units and each image path to 512. Oversized
values abort as unknown. These are source consumption/acceptance bounds, not
quotas on internal WMI work or already materialized rejected rows.

Accept at most one sanitized JSON line and 2,048 combined original stdout/stderr
bytes. The original tool invocation has a 30-second completion acceptance deadline,
including startup. If it yields a session, collect only that original session within
the remaining allowance. Native call latency is not a hard termination guarantee:
timeout, late/missing host completion, extra output or transport uncertainty remains
unknown. Stop dependent work at the deadline and retain unresolved lifetime without
process control or a replacement call. A printed line alone or an outer watchdog
is not proof that the Windows host exited.

Accept `absent` or `present` only with complete timely original host exit zero,
the exact output schema, `queryCompleted: true`, `reason: complete`, elapsed time
within 15,000 ms and consistent counters. Absence requires zero rows, exact matches
and ambiguities; presence requires exactly one row/match and zero ambiguities.
Every other outcome stays unknown. Independently review that original outcome.
Current absence may combine with the accepted source exclusion to resolve only
this bounded lifetime question. It does not accept the original observer, graph,
artifact, publication or account scenarios. Keep current history readers blocked
until the required existing handoff/current-consumer disposition is accepted.

Retain the sanitized original transport and its review in the existing private
execution carrier. Preserve original and partial artifacts without cleanup. This
amendment does not refund the observer, rewrite original receipts or enable any
other experiment.

### Current Bootstrap Observation Outcome

The sole query executed under accepted protocol commit
`a42b6a648d4dfe4dc542256b9a8cc3faf70e0bd7` and the exact tracked source above.
Its original tool invocation yielded once; collection of that same original session
completed with exit code zero. The complete combined output was one 160-byte JSON
line ending in CRLF: `status: absent`, `reason: complete`, `queryCompleted: true`,
zero rows, zero exact matches, zero ambiguous rows and `elapsedMs: 1630`.
The conservative Linux monotonic interval, including pre-call bookkeeping,
Windows startup and original completion collection, was exactly 2,687,223,000 ns
(2,687.223 ms), within the 30-second acceptance deadline.

| Evidence role | Bytes | SHA-256 |
| --- | ---: | --- |
| Exact query invocation admission | 7,222 | `c6bf6399e9c7a719f2c9c6f90ef27b31375afb5c8d5693c53f5e9343c8cf25bf` |
| Complete original query transport | 1,920 | `629bf72891f0785693df27f36c798e8b293853705b2b82dbcc23317461d603cd` |
| Independent original outcome review | 6,267 | `6f83fab9ad93260677671763237d0e57e53f5a5096a896efc01a73e78b8a296e` |

Independent review accepted the current absence of the exact original bootstrap.
Combined with the separately accepted old-source reachability exclusion, this
resolves the selected current bootstrap/subject lifetime question under the
existing ordinary runtime/provider trust. The bootstrap absence is a current
observation; the guarded-subject exclusion remains a source-qualified inference.
Neither conclusion recovers the original exception, observes historical no-launch,
proves future absence or establishes general host/provider quiescence.

The observation consumed its only attempt. No query capacity remains, and this
result grants no retry, cleanup, account operation or SDK execution. No original
files were read or changed by the query. Preserve the failed observer's original
receipts, all false flags and its consumed build/test charge. Compiler graph,
artifact, final CLI/WSL and account evidence remain incomplete.

## Exact 0056 Failed-History Disposition

Accept only action 0056 as the original failed `core-csc-observer`, with its bounded
current lifetime resolved by the evidence above. This is a historical failure
variant for the existing readers and handoff; it does not accept the observer,
compiler graph, artifact or original Windows completion. Keep the exact original
WSL `RuntimeError`, `safetyStop: true`, `launchAttempted: true`, null proxy status
and all original false completion, quiescence and continuation flags.

The existing `final-publish-after-guard-handoff-v2` carrier retains its six fields,
unchanged 45-Linux/53-Windows prefix, disposed 0054 and successful 0055. Append only
Windows entry `0056`, with exactly `number` and `failedObserverDisposition`.
The latter descriptor binds the private `core-csc-observer-failed-history-disposition-v1`
instance to the existing canonical protocol section, predecessor handoff, original
tool result, accepted recovery report and six copied originals, accepted source
exclusion, current-bootstrap transport and independent outcome review. The
canonical protocol/source revision is supplied by the enclosing exact admission;
the private evidence binding does not grant authority. Preserve the predecessor
manifest and acceptance bytes, and independently accept the new exact handoff
through its existing acceptance carrier before any consumer executes.

The six known original roles are the paired starts, paired invocations, WSL result
and WSL controller-attempt record. Their exact sizes and hashes remain those in
the initial recovery table. The byte-identical starts and invocations, their
reservation joins, original product and protocol identities, previous counters
and fixed `[0,1,0,0]` charge identify this exact failure. No other action number,
platform, observer, reordered suffix or arbitrary failed receipt may use this
variant. Unbound, changed or incomplete required evidence rejects.

### Prospective Fixed-Role Verification

The private disposition instance is 3,202 bytes, SHA-256
`6a241958bfd4693de219393c5920277e18ead52f8d039cd265f412837d142525`.
Each of the three current consumers retains an unbound
`CORE_CSC_FAILED_DISPOSITION_BINDING`; separately reviewed source materialization
must supply exactly that descriptor before use. Do not accept an alternate path,
CLI/environment override, different instance or arbitrary accepted Boolean.
The existing enclosing source/protocol and original-history acceptance gates remain.

One ordinary-reader pass reads that fixed private instance and the six fixed
original roles, each for its exact length plus one byte. There are seven reads
requesting at most 15,093 bytes, including 11,890 requested original bytes. Paths
are source-fixed and direct; each walk checks at most sixteen ancestors. Require
regular files, exact sizes/hashes and stable device, inode, mode, size, mtime, ctime
and link count before/after reading and against the current leaf. No directory
listing, absent-leaf probe, additional original read, private historical-review
reread or Windows operation is selected by this verification. The seven fixed
paths require at most forty ancestor stat calls and twenty-one held/leaf identity
observations, sixty-one metadata calls per pass.

The final publication caller uses the same seven-read check at its two existing
history checkpoints, for at most fourteen reads requesting 30,186 bytes and
122 metadata calls. Both
passes share thirty seconds of active verification time and require the same
current identities and bytes at the second checkpoint. The original caller's
outer deadline/cancellation remains in force through the gap and each check;
the earlier deadline always wins. A failed pass latches failure, and neither
consumer may restart the allowance or obtain a third pass. The ordinary reader's
single pass also has a thirty-second allowance. These checks add no experiment
reservation and borrow no time or reads from the unchanged 0054/0055 schedule.
They remain prospective until the complete enclosing source, schedule, handoff
and literal invocation have their separate exact admission.

This failure variant does not assert a complete 0056 directory inventory or a
new snapshot of the old report's absence observations. In particular, the original
`windows-input.json`, staged payload inventories and current missing Windows
receipt are not needed to count and retain this resolved failure. Do not fabricate
their content or promote source-expected output to an observed file. Retain all
original and partial state without cleanup. Future fixed-role continuity checks
are separate current observations and cannot replace the failed original outcome.

Count one observer build/test charge and zero preparation, publication or synthetic
charges. Current totals are Linux `[8,37,0,0]`, Windows `[7,49,0,48]` and combined
`37 + 49 + 1 = 87/120`, including the existing fixture exactly once. Ordinary Windows
build/test remains exhausted at 48; the aggregate 49 includes this sole dedicated
unit. Linux's prospective ceiling remains 79. The twelve final CLI scenarios,
preparation 15/16 and publication 0/12 are unchanged. Derive the next Windows number
from the admitted contiguous history; with this exact suffix it is 0057. This
number does not allocate or authorize another action.

The final caller's second 0054 continuity checkpoint therefore requires reserved
action 0057 for this exact suffix. Its first checkpoint still has no reservation;
the original pass order, failure latch, evidence, continuity and budgets remain.

Current consumers recognize the exact failed branch before their ordinary-success,
complete-inventory and Windows-completion checks, without rewriting those original
receipts. Final publication selects successful guard 0055 by its exact number rather
than assuming it is the last action. Preserve all 0054/0055 validators and their
original provenance, all other historical dispositions and the existing final
source, graph, K, artifact, publication and literal-execution admission gates.

The ordinary wrappers validate their current executing source through their existing
current-source admission and actual `__file__` identity check. Their unchanged
historical 0055 validator receives the fixed retained original reader paths already
recognized by the final caller. It continues checking those original bytes against
the original 0055 authority. Passing a later current wrapper as though it were the
historical source would fail those pins before reaching 0056; do not repair that
mismatch by rewriting original pins, weakening the historical check or substituting
historical-source acceptance for current-source admission.

## One Compile-Through Native-Input Diagnostic

The inactive implementation consists of the [fixed target](../../../tools/validation/CompilerNativeInputs.targets),
[Windows controller](../../../tools/validation/Invoke-WindowsCompilerNativeInputs.ps1),
[WSL dispatcher](../../../tools/validation/run_windows_compiler_native_inputs.py) and
the existing [shared history adapter](../../../tools/validation/final_publish_contracts.py).
These sources implement this supplement; they do not independently grant execution.

This supplement allocates one new credential-free build/test action for Issue #108.
Its bounded question is the original ordered compiler inputs for all three selected
product projects and the native inputs available at the original
WriteIlcRspFileForCompilation boundary. Complete the Core, Windows and CLI Csc tasks,
capture the original ILC response and named linker-input producers, then stop
unconditionally before ILC or linker execution. The original failed 0056 remains
consumed and unchanged. This is a new diagnostic with a fresh root and action identity;
it does not retry the skipped-first-Core procedure or publish an AOT artifact.

### Selected Source and Reused Inputs

Use unchanged product commit `503360753accd0829801953823b1b57a4f852440`, tree
`8506cdd9781c8a331ea12ea8fe27a55292eec073`, SDK 10.0.401/runtime 10.0.12,
MSAL/Broker 4.83.1, NativeInterop 0.20.3 and the accepted public packages/toolchain.
The new dedicated root is
`C:\Temp\azureauth-windows-slice-108\observers\compiler-native-inputs-5033607-v1`;
its source subdirectory receives the same 34 product inputs and a single independently
bound fixed observer Import overlay. Preserve 33 Git blobs; only the original 395-byte
src/Directory.Build.props receives a 134-byte unconditional Import before its closing
Project element, naming compiler-native-inputs.targets immediately under the new root.
The resulting file is 529 bytes and the complete diagnostic source is 150,170 bytes.
Preserve all three project files and their ordinary project-reference metadata. The
sole source overlay replaces neither an SDK target nor a compiler. Its exact bytes,
payloads and product projection must be admitted before materialization. Reuse exactly
twelve unchanged retained restore inputs, totaling
233,709 bytes, under their proper per-project obj directories. No restore, download,
installation, cache mutation or product execution is selected.

Reuse the corrected no-reparse path walk, staged 34+12 input pipeline, current paired
history, fixed public runtime inputs and completed ordinary guard 0055. Preserve the
two accepted WSL guard projections and eleven source-review inputs as separate roles.
No guard compilation or historical SDK/host/parser/observer invocation is authorized.
The original 0056 authority can support unchanged identity facts only; its root,
source activation, reservation, literal call and failed completion cannot authorize
this diagnostic. Keep the separate planned final source root unmaterialized and
unprobed by this action.

Invoke the selected muxer through its built-in msbuild route, target Publish, with
the existing seventeen Publish properties, `-restore:false`, one node, disabled
node/build/compiler servers, `-noAutoResponse`, `-tl:off`, detailed output and one
binary logger with ProjectImports=None under the fresh diagnostic root. Preserve
the 35-entry replacement environment and the already selected
MSBUILDPRESERVETOOLTEMPFILES=1. Fix MSBuildUserExtensionsPath to the new action's owned
empty home/msbuild-user directory through ordinary project-reference propagation.
The complete source-reviewed vector and exact bootstrap literal are independently
bound before execution; a captured command string is not an invocation authority.
Retain the binary logger's three internal environment additions as diagnostic
context differences from the final recipe.

### Actual Compilers and the Native Cutoff

The exact admitted source enforces one Core net10.0 context, one Windows
net10.0-windows context and one CLI net10.0-windows/win-x64 context, in that order.
Require the selected Release/Publish/reference properties, no resource batching,
original built-in Csc task/host identities, no shared or host compiler and no command
processor. SkipCompilerExecution remains false or empty; TargetsTriggeredByCompilation
remains empty. Set only ProvideCommandLineArgs=true to retain supplementary arguments;
its original false/empty value and the newly reached compiler/generator effects must
be reviewed. Preserve original response-file bytes through the existing ToolTask
temporary-file preservation event, joined to the exact successful Csc task. Split
CscCommandLineArgs items never substitute for that original response. The pinned
[CoreCompile Csc task and output mapping](https://github.com/dotnet/roslyn/blob/f7797ed513e3035983346552ac2d9ca2281bc2ec/src/Compilers/Core/MSBuildTask/Microsoft.CSharp.Core.targets#L97-L189)
passes ProvideCommandLineArgs and SkipCompilerExecution separately, maps the original
CommandLineArgs output to CscCommandLineArgs and conditionally calls
TargetsTriggeredByCompilation. CoreCompile adds EditorConfigFiles to EmbedInBinlog.
With the selected ProjectImports=None, the pinned
[binary logger](https://github.com/dotnet/msbuild/blob/b44cdcec4c79c50c67560876707d57d4f635fa3b/src/Build/Logging/BinaryLogger/BinaryLogger.cs#L380-L415)
does not collect their contents through that route: its new
[event writer](https://github.com/dotnet/msbuild/blob/b44cdcec4c79c50c67560876707d57d4f635fa3b/src/Build/Logging/BinaryLogger/BuildEventArgsWriter.cs#L1041-L1072)
has no EmbedFile subscriber. Compiler configuration reads and ordinary item/task
metadata logging remain within the declared effects; item presence does not establish
embedded file content. This source finding does not supply current installed-file
correspondence or physical continuity.

One preseeded zero-byte append-only marker has seven exact CRLF lines: core-begin,
core-complete, windows-begin, windows-complete, cli-begin, cli-complete and
native-inputs-captured. Six compiler lines total 85 bytes; the terminal claim is
109 bytes. Fresh exact marker reads, single-node unbatched execution, no competing
writer and the original target ordering enforce uniqueness. Never reset a claim or
create a substitute assembly to continue a failed compilation. The marker alone
cannot establish successful compilers or complete native inputs.

The source-bound cutoff runs after the original WriteIlcRspFileForCompilation,
whose [pinned dependency chain](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/coreclr/nativeaot/BuildIntegration/Microsoft.NETCore.Native.targets#L198-L331)
includes Compile, ComputeIlcCompileInputs, SetupOSSpecificProps and PrepareForILLink. Reject multi-module/framework-library
recursion, non-Windows/non-x64/non-Exe branches, native-library modes and alternate
tool discovery. Capture once and unconditionally raise AUTH108NATIVEINPUTSTOP.
BeforeTargets backstops reject BuildFrameworkLib, IlcCompile and LinkNative bodies;
BeforeTargets=LinkNative alone would be too late. Admit no overriding target,
competing hook, continued-error path or native OnError route that bypasses the cutoff.
No ILC Exec, linker Exec, native object/exports generation or publish copy is admitted.
Ordinary compiler, generator, source-control and SDK bookkeeping effects remain
within owned intermediates and their exact source/physical predicates.

### Fixed Evidence and Later Interpretation

Retain three complete original successful Csc task contexts, their command/response
text, original preserved responses and declared implementation/reference/PDB outputs.
Bind source, reference, analyzer, generated source, editor configuration, SourceRoot,
SourceLink and project/task/environment identities. At the cutoff retain the original
ILC response and its WriteLinesToFile producer, ordered IlcArg and LinkerArg,
AdditionalNativeLibraryDirectories, selected managed/framework/native-pack inputs,
NativeObject/NativeBinary/ExportsFile and ManagedBinary path/metadata values, Windows
branch controls and ILC environment/default controls.

The hook explicitly names nine compiler item arrays per project, 33 native item arrays,
58 native scalars and four ManagedBinary metadata values: at most 60 companion item
files and 92 named scalar/metadata Message occurrences. Its literal item-count caps
are rejection limits, not observations. Compiler arguments and IlcArg have at most
8,192 items; remaining arrays retain their smaller exact source limits. The original
complete binlog must preserve task identities, ordered item boundaries and metadata.
Companion text files alone cannot disambiguate embedded newlines or retain metadata;
do not reconstruct arrays from console delimiters or promote them to original RSPs.
Keep the existing maximum 32 combined response plans and 8 MiB per response.

The later Windows link response may be source-rendered from the captured ordered
inputs using the unchanged native target: quoted NativeObject, /OUT, conditional
/DEF, ordered /LIBPATH and ordered LinkerArg. This is an expected producer plan,
not an observed link response or consumed native object. Derive the later ILC
DOTNET_gcServer override from the captured value and original target branch.
Diagnostic-to-final paths and generated values require pinned producer derivation
and final physical predicates; string substitution does not prove SourceLink,
SourceRoot, generated files or output identity. Missing inputs remain unresolved.
Final graph, complete native identity closure, original response/task receipts,
actual publication and artifact/scenario acceptance retain their separate gates.

### Finite Original Execution and Failure Evidence

One nonresetting 900,000 ms caller observation/success deadline covers admission,
reservation, staging, bootstrap, handshake, subject, joining and finalization. The
handshake ends at the earlier of that deadline and twenty seconds after the timestamp
captured immediately before Popen. Persist each launch attempt and recheck original
cancellation/deadline immediately before Popen or Start. Keep 20,000 ms for subject
cleanup at Start, more than 15,000 ms for ordinary Stop admission and 5,000 ms for
receipt/drain work. The unchanged guard's native-call latency, fixed 10,000 ms
assignment-failure recovery, 10,000 ms ordinary Stop loop and possible final 50 ms
polling overshoot retain their existing limits; a late native return gains no new
caller time. Closing the Job remains distinct from observed quiescence.

Retain at most 8 MiB combined stdout/stderr. Keep the existing emergency-drain
64 KiB processed threshold plus at most 8 KiB issued/in-flight overflow, with no new
reads after rejection. At the reviewed polling cadence allow at most 3,600 samples,
512 entries per sample, 128 new directories, 512 files, 256 MiB aggregate new-file
bytes and 64 MiB binlog bytes. Generated text is bounded by 96 files, 1 MiB per file
and 32 MiB aggregate. Include staged/preseeded files in totals and both scan roots in
the directory count; reject the 129th directory before traversing it. Retain attempted
overflow counts separately from the last complete sample. These are stop/acceptance
thresholds, not instantaneous filesystem quotas; overshoot is failure.

Reuse both physical checkpoints and their fixed absence/membership input lists with
the same 256-leaf, 32-domain, component/path, metadata and yielded-entry ceilings.
For this compiler/native-input diagnostic, add exactly one directory-membership
exception to the existing ordinary-file domains: canonical
`C:\Program Files\dotnet\host\fxr`, pattern `*`, with exactly `10.0.12`, `6.0.36`
and `8.0.31`. Require that domain once per checkpoint, with its literal spelling,
pattern and unique names; reject omission, duplicates, aliases or any other set.
Require ordinary non-reparse ancestors and directory members. Reject missing,
inaccessible, unexpected or non-directory entries without descending into them.
Only this fixed domain bypasses the per-member leased-file requirement; retain
ordinary-file identity checks for every other domain and the separately pinned
`10.0.12\hostfxr.dll` physical input and source-selected app-local absences. This
binds the native host's highest-version directory selection before framework
roll-forward, which cannot substitute for this predicate.

The additional domain raises the fixed list from 19 to 20 domains. Across the two
successful checkpoints it adds six yielded entries and sixteen metadata probes,
with no new content read, process, file or directory. Reuse the existing shared
counters and ceilings. These observations establish checkpoint continuity under
the existing no-competing-installation-change premise; they do not establish an
atomic snapshot or exclude transient changes between checks. Rebind newly reached
inputs, changed controller source identity/size and fresh-root effects before
admission; earlier absence or membership is not continuing evidence. Preserve
cancellation/deadline checks with the 20,000 ms reserve before each metadata/enumerator
operation. Each controller and
dispatcher input reader keeps 256 reads/256 MiB requested bytes; the history adapter
keeps 4,096 reads/256 MiB across two checkpoints. Retain the exact disposed-0054
verifier and the two fixed failed-0056 passes, including their shared active-time,
identity, metadata, original-role and failure-latch limits. Do not add an inventory
or missing-receipt probe for 0056. Public Git/GitHub helpers keep thirty-second
limits inside the same outer clock, with no SDK or Windows proxy fallback.

The new controller intentionally emits one ASCII JSON bootstrap frame of at most
1,024 bytes with schema compiler-native-inputs-bootstrap-v1 and only stage, outcome
and exceptionType fields. Its admitted source fixes closed stage/type vocabularies;
unknown exception types become OtherException. A candidate frame requires
controller-exit and null exceptionType. Intentional emission excludes exception
messages, stacks, private paths, account details and arbitrary exception properties.
No pre-admission owned-path receipt write or second recovery query is permitted.

The dispatcher privately retains bounded original stdout/stderr before interpreting
the frame, including unexpected invalid interpreter output. Retain at most 4,096
combined bytes plus one returned overflow byte: at most 4,097 bytes returned by
os.read across both pipes. At most 36,004 pump passes may reach reads, each making
at most two nonblocking calls requesting at most 4,096 bytes. This implies at most
72,008 calls and a conservative cumulative API-request-size ceiling of 294,944,768
bytes, including EAGAIN, EOF and short reads. Requested sizes are distinct from
bytes returned or retained, and from the separate descriptor-input allowance.
Rejected pump entries can increment the attempted counter without reading. The
same allowance covers the handshake, observation and final drain. Retain a transport
metadata receipt of at most 4,096 bytes with separate returned-byte, read-bearing
pump, call and requested-byte ceilings; do not claim an actual requested-byte total.
Never display or publish these raw transport files. A valid frame requires complete
EOF capture, empty stderr, exactly one ASCII line and the closed schema; invalid,
missing, overflowing or incomplete transport remains failure/unknown. Preserve the
original clock and no-wait-after-cancellation behavior during capture/finalization.
After owned-path admission, keep ordinary failure receipts and partial state.

Provisional completion requires original controller exit zero, intentional nonzero
subject exit, the exact complete marker/stop event, complete capture/binlog and file
checks, natural subject/Job completion and zero active processes without termination.
Later independent interpretation must establish all three successful compiler tasks
and the unique original native-input cutoff. Timeout, truncation, unexpected task,
missing output, partial original completion or a survivor is failure. The shared
history lock remains held through local finalization; on cancellation do not wait
past the original deadline for the proxy/finally. Releasing that lease does not
establish paired completion. Keep original graph/artifact/continuation flags false
until the corresponding accepted evidence supplies their separate dispositions.

### One Dedicated Unit and Exact Admission

Transfer one unused prospective allocation: Linux ceiling 79 to 78 and aggregate
Windows ceiling 49 to 50, leaving ordinary Windows capacity at 48 and the combined
Wave ceiling at 120. Preserve original counters Linux [8,37,0,0] and Windows
[7,49,0,48], all original 45 Linux/53 Windows prefix entries, disposed 0054,
successful guard 0055 and disposed 0056. The sole new charge produces
37 + 50 + 1 = 88/120 including the original fixture once. Preparation 15/16,
publish 0/12, synthetic scenarios 48/60 and their protected twelve remain unchanged.

Under the existing shared lock derive successor 0057 from the exact accepted handoff;
reject a different history or an existing/partial slot. Record one build/test charge
durably before staging or launch. Every failed start consumes it; no refund or retry
is permitted. Keep the existing paired history/handoff carrier. Current ordinary
readers fail closed on the new suffix until its exact original result and updated
handoff/consumer interpretation are independently accepted. No provisional success
or marker grants later execution. Do not alter original flags or historical limits.

All new controller/dispatcher/target/history entry gates remain disabled in Git.
The accepted protocol is a prerequisite, not sufficient source or invocation
admission. Independently accept the complete new source, exact private activation,
materialization maps/payloads, newly reached compiler/generator/native setup effects,
current physical predicates, runtime/guard identities, handoff, literal invocation
and finite result interpretation before any execution-oriented parsing, import,
materialization or launch. Reuse accepted unchanged mechanisms without reopening
completed unrelated SDK/runtime/provenance audits. No account operation, human input
or desktop attendance is selected. Retain dedicated artifacts after every outcome;
no speculative cleanup, historical replay or final-publication acceptance is granted.

### Original 0057 Failure and One Fixed WSL Receipt Recovery

The sole compile-through diagnostic invocation returned original exit code 1 with
complete, empty tool output and no running tool session. Its retained original
transport is 730 bytes with SHA-256
`d8c601fa8e9efad36048f6e2acf68ca603ce8eaa037dbb001960d375d9b23084`.
This is a failed invocation. The original reservation, reached effects and lifetime
remain unresolved; short elapsed time and empty output do not establish no launch,
no persistent state, quiescence or a particular exception. The sole invocation is
consumed, with no retry or refund. Preserve the previous accepted counters and keep
the dedicated unit unavailable until its exact failed-history disposition is accepted.
The normal-result copier is ineligible.

The existing Wave permits one new credential-free, read-only recovery of this
specific failure. The [inactive fixed collector](../../../tools/validation/collect_windows_compiler_native_failure.py)
selects only these three WSL receipt names beneath the exact
`/var/tmp/azureauth-windows-slice-108/windows-actions/0057` directory:

| Role | Exact leaf | Maximum bytes |
| --- | --- | ---: |
| Durable reservation | `started.json` | 8,192 |
| Reservation-helper failure | `reservation-failure.json` | 4,096 |
| Dispatcher result | `result.json` | 65,536 |

All three are optional content roles. This is the first recovery for 0057; the
earlier prohibition on a second recovery query remains in force. Historical SDK19,
guard and 0056 invocations remain consumed. Reuse their no-follow, bounded raw-copy
mechanisms, not their invocation grants. No build, compiler, Windows proxy, account
operation, process query, payload, binary, diagnostic stream, binlog or Windows-root
observation is selected. No desktop attendance or human input is required.

The existing WSL root and windows-actions parent must be ordinary directories
reached by component-wise, descriptor-relative no-follow traversal. The exact 0057
directory may be absent; record that observation and recheck that same leaf once.
Do not reinterpret a missing ancestor, denied access, link, non-directory or other
error as absence. If 0057 is present, require the opened directory and its final
no-follow lookup to retain device, inode, mode, length, mtime and ctime. Observe each
fixed receipt once; an absent receipt gets one final same-leaf recheck. Never list a
directory or follow a path found inside a receipt. Nonregular, oversized, changed,
inaccessible or incomplete inputs fail the whole recovery without repair.

Reuse only the existing `/var/tmp/azureauth-windows-slice-108/action.lock`, opened
read-only and no-follow as a regular file, with one nonblocking exclusive lock
attempt. Compare the held and exact-path identity before and after collection. Do
not read, create or write lock content, wait, retry contention or run a concurrent
experiment. Release and close the lease during finalization; lease release is not
evidence of original Windows or helper quiescence.

Copy present receipts as uninterpreted bytes; never display or publish raw receipts.
Require complete EOF, stable opened
and final-leaf device/inode/mode/length/mtime/ctime, one subsequent original read
with identical identity and bytes, and one exact private-copy readback. Preserve
integer timestamps with Python integers. Parsing or interpreting receipt contents
is a later independent acceptance of these private copies; this invocation cannot
claim a reservation, completion, compiler graph or original lifetime disposition.

Create only `/tmp/windows-compiler-native-inputs-0057-failure-offline-v1`, exclusively
with mode 0700 after the initial observations pass. Its fixed possible files are
`started.bin`, `reservationFailure.bin`, `result.bin` and `inventory.json`. Missing
roles receive no raw file. Create files exclusively and no-follow with initial mode
0600, sync their complete bytes, seal them 0444 and sync again. Sync the held output
directory and its parent, verify final directory identity, and read back each raw
file and the inventory. Do not enumerate output. Retain every created file and
partial directory after all outcomes; no cleanup, alternative location or resumption
is granted.

The closed admission record is the only private content input, at the exact path
`/tmp/windows-compiler-native-inputs-0057-failure-recovery-admission-v1.json`, bounded
by 16,384 bytes and bound by the externally admitted literal SHA-256 argument.
Its source-defined fields bind action 0057, the original failed transport descriptor,
one invocation, current accepted target/protocol/Wave identities, active source and
runtime review. The external admission must independently establish those identities;
syntactically valid hashes are not self-authenticating. The collector neither reads
those referenced files nor invokes Git. It does not read the original transport.

| Intentional collector bound | Maximum |
| --- | ---: |
| Original content slots / aggregate bytes | 3 / 77,824 |
| Private admission bytes / inventory bytes | 16,384 / 16,384 |
| Logical content reads, including continuity and private readbacks | 11 |
| `os.read` calls / cumulative requested bytes | 31 / 266,251 |
| Cumulative returned bytes | 266,240 |
| New directories / files / aggregate file bytes | 1 / 4 / 94,208 |
| Counted no-follow path/open/metadata operations | 1,024 |
| Maximum read/write chunk | 16,384 bytes |
| One nonresetting source clock | 90,000 milliseconds |
| Outer TERM deadline, including interpreter startup / KILL grace | 95 seconds / 2 seconds |
| Complete original combined tool capture retained for acceptance | 16 KiB |

For P present receipts totaling S bytes, admission A and inventory I, successful
collection uses `3 * P + 2` logical reads, returns `3 * S + A + I` bytes, and writes
`S + I` bytes. When each request returns all requested data, each logical read
requests the observed exact length plus one EOF sentinel, giving
`3 * S + A + I + 3 * P + 2` requested bytes. Short reads may increase requested
bytes and API calls; the independent fixed cumulative ceilings above still reject
overflow before the next read. These limits cover
intentional collector data operations; separately reviewed interpreter, standard
library, ELF loader and watchdog startup retain their own runtime admission.

The source clock begins once in main. Preserve latched cancellation and checks
around bounded I/O, sync, finalization and final stdout flush. Use the previously
reviewed Linux interpreter/watchdog mechanism with separately accepted current
source/runtime/literal bindings. Keep the checked-in ACTIVE gate false. Only the
one-line ACTIVE activation is eligible after this amendment merges and the exact
source, runtime, literal, capacity record and finite result interpretation are
independently accepted. A failed start, inactive rejection, missing required ancestor,
lock contention, output collision, interruption, timeout, nonzero exit or incomplete
transport consumes the recovery. No second attempt is authorized.

The inventory is provisional and deliberately retains false completion, graph,
artifact, independent-observation and continuation flags. Success requires the
original collector exit zero, complete closed transport, all final checks and
independent acceptance of the fixed copies and inventory. A saved inventory cannot
override a failed or late tool invocation. Unknown or absent receipts remain unknown
evidence, and no successful collection creates a successor handoff. Preserve the
original diagnostic failure and resolve its remaining lifetime/history gates before
dependent execution. This amendment grants only this recovery, not another diagnostic
or AOT publication.

The collector's one closed ASCII transport frame contains schema, normalCompletion,
stage, role, exceptionType, inventory descriptor and cumulative counters. Stage uses
only its source literals: admission, lock, action-directory, initial-read,
output-create, copy-write, copy-readback, original-continuity, directory-continuity,
inventory-write, inventory-readback, output-finalization, lock-finalization and
finalization. Role is null or started, reservationFailure or result. Exception type
is null, a source-allowlisted Python or finalization name, or OtherException. No raw
receipt, exception message, path, stack or input-derived diagnostic is emitted.
The fixed stage identifies the operation being attempted, not its absence of effects.

The dormant dispatcher source also corrects an independently triaged observability
defect prospectively. A handled failure emits at most one ASCII JSON line, with a
trailing LF and a 1,024-byte ceiling, through its existing stdout. The closed schema
is `compiler-native-inputs-dispatcher-failure-v1`, with only stage, outcome and
exceptionType beyond schema. Outcome is incomplete. Stage is one of
history-reservation, invocation-binding, materialization, controller-launch,
clock-handoff, controller-observation, result-joining or finalization-or-completion.
Exception type is a source-allowlisted Python name, OtherException or null; no
message, stack, path or arbitrary exception property is emitted. A stage identifies
the failed call and never implies that the call had no partial effects. This uses
no new clock or owned-path receipt and does not retry a short or failed output
write. It applies only to exit-one failures, cannot generate success, and leaves
before-try source-admission failures unchanged. The executed original source and
empty transport remain unchanged. All dispatcher execution gates remain inactive;
this correction and this recovery grant do not authorize another diagnostic.

### Fixed 0057 Recovery Observation

The sole recovery ran under accepted protocol commit
`05edbc54c540399b873b31276e427034874b4560`, tree
`07bf0670fc2dff9d476fa73c2cbebf7c47b99112`. Its exact source, runtime,
activation, literal and original completion were independently accepted. The original
collector returned exit zero with one complete closed transport frame and no yielded
session. It used two logical reads, four read calls, 2,294 requested bytes, 2,292
returned bytes and 54 counted path operations, and wrote only the 1,623-byte inventory.

The exact WSL action 0057 directory was absent at the initial and sole final permitted
checks. No individual receipt leaf was observed and no original receipt content was
copied. Independent interpretation accepted this observation after accepting the
original transport and the bounded, exact inventory read. The recovery is consumed
1/1; no retry, alternate query, repair or cleanup is granted.

This absence alone does not establish the original diagnostic's reservation debit,
reached effects or lifetime. The separate source finding below narrows reachability;
it does not turn directory absence into execution evidence. The original exit-one
failure and consumed invocation remain unchanged. The dedicated unit stays
unavailable; no successor diagnostic, final publication, graph or artifact acceptance
follows.

### Original 0057 Handoff Format Rejection

Independent source and exact-input review found a deterministic conflict in the
original history loader at `a578b7cb7da9f80860817ca782519941ebb11395`.
`load_core_csc_history` selects the fixed compiler handoff, verifies its 211,842-byte
length and SHA-256
`fe13f88846f537825049dface75869cccad84f6df3bc2a748968a466c8443ba6`,
then requires canonical compact JSON. The pinned bytes are valid strict JSON with
indentation; their canonical serialization has 175,202 bytes and SHA-256
`6295feaedba883966ef0c42189916acc3a72b10d0b3b91d4c01ef9e00ef29fae`.
These formats cannot satisfy the same exact-byte contract.

Under the accepted executed-source, input and runtime bindings, missing or changed
handoff bytes fail the descriptor check, while the exact pinned bytes fail canonical
decoding. The loader therefore cannot return to reservation. Its later root-marker
reads, shared-lock acquisition, durable 0057 start/debit, staging and Windows process
launch are unreachable. This is an independently reviewed source/input proof, not an
observation of the actual failing instruction; an earlier error remains possible.
Up to five preceding immutable local Git queries remain a separate lifetime question:
their failure paths do not establish completed termination. No global quiescence,
counter refund or continuation is claimed.

The dormant loader now exempts only the compiler-mode handoff from canonical-byte
formatting. Its exact length/hash, duplicate-field and nonfinite-value rejection,
structural checks and later semantic joins remain required. The legacy Core observer
handoff policy and all retained input bytes remain unchanged. This correction does
not activate a source, resolve the preceding-helper lifetime question or grant a
replacement diagnostic.

**Case-specific prior-helper disposition:** The accepted Wave decision and
experiment-safety exception dispose of the unresolved lifetime of the original
invocation's preceding immutable Git verifiers and possible descendants for
credential-free Windows Slice validation within the Wave scope and cumulative
ceilings accepted with that decision. Preserve the source/input proof
that original 0057 could not reach its later root-marker reads, reservation lock,
durable start/debit, staging or Windows launch. Do not infer its actual first
exception or global quiescence.

The original diagnostic remains failed and consumed; its dedicated unit is not
refunded or made available. Its receipt recovery is consumed 1/1. At most one
additional corrected compiler-native-inputs diagnostic is permitted, including a
failed start. It must have a distinct admission, an additional charged build/test unit
within unchanged cumulative ceilings, and a separately accepted complete exact
protocol. That protocol must correct the handoff-format conflict, repair future
verifier process ownership/termination, preserve prior accounting without
manufacturing absent history, define its exact action locations and retained
outputs, and independently bind source, runtime, literal, limits and result
acceptance before execution. Existing dependent Native AOT compilation and the
twelve remaining CLI/WSL synthetic scenarios retain their ordinary prerequisites
and separate exact admissions. The single diagnostic limit does not terminate
this historical disposition, and the disposition satisfies no build, graph,
artifact, source, capacity or result prerequisite. It admits no command by itself.
Any new ownership or termination uncertainty stops further execution; no further
diagnostic attempt follows from this exception. The disposition ends when the
current Wave grant closes and neither transfers to a successor grant nor expands
through later boundary changes.

## Independent Linux Supervisor Validation

This supplement evaluates the installed systemd user manager as a prospective
supervisor for Linux validation helpers. It is independent of original 0057: it
does not access that attempt's roots, receipts, inputs, processes or descendants,
resolve its lifetime uncertainty, or permit the stopped diagnostic or dependent
compiler/Native AOT work to continue. The original failed invocation, its unavailable
unit and consumed recovery remain unchanged. At this batch's admission, its owner
risk decision remained open; the later case-specific disposition above applies
the accepted Wave risk decision.

The scope is development validation tooling only. It introduces no systemd or
cgroup dependency into the Windows authentication executable, no product service,
and no change to existing Windows Job Object or cross-host termination policy.
Prefer the installed service manager's lifecycle mechanisms over a custom cgroup
manager. A future verifier integration still needs its own exact source and effects
admission; this supplement tests the mechanism, not a replacement compiler launcher.

This batch requires the accepted Wave's cumulative ceiling of 80 synthetic-process
scenarios. Allocate exactly four of those scenarios here, preserving the 48 consumed
scenarios and twelve protected final CLI cases. Existing narrower product-history
allocations remain unchanged. The remaining sixteen scenarios beyond these allocations
are not assigned by this supplement. Protocol acceptance and exact source admission
remain prerequisites to execution.

### Source Basis and Admission

The public systemd v259 source at
`9ca433482f2281d71718718705ca8cd3bf562ad6` documents:

- [Transient services and scopes, exec startup, pipe/wait behavior, argument expansion and collection](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/man/systemd-run.xml).
- [Cgroup exit tracking and service startup/runtime/stop limits](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/man/systemd.service.xml).
- [Control-group termination and final SIGKILL](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/man/systemd.kill.xml).
- [Quiet result handling and service exit-code propagation](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/run/run.c#L2657-L2668).

The outer watchdog is the installed uutils coreutils 0.8.0 `timeout`. Its immutable
[source](https://github.com/uutils/coreutils/blob/c4093734e2ebe2efb7d65e216cd1444664bcf26a/src/uu/timeout/src/timeout.rs#L242-L256)
defines group signaling outside foreground mode. The local verifier and its
systemd-run clients retain that group; only the manager starts the fixture services.

These are immutable documentation premises, not observations that this host's
supervision works. A separate read-only development inspection found installed
systemd package metadata `259.5-0ubuntu3.4` and an existing user bus. One bounded
`org.freedesktop.DBus.Properties.Get` of the existing user manager's `Version`, with
activation and interactive authorization disabled, returned that version. This
establishes metadata and reachability only; no transient unit or test ran during
that inspection.

The exact test source is
[`check_systemd_supervision.py`](../../../tools/validation/check_systemd_supervision.py).
Before execution, independently accept its commit/tree and SHA-256, this protocol,
the accepted 80-scenario Wave, fixed tool identities in `TOOLS`, four fixture entry points,
and source-only review of its subprocess and result paths. Merge the protocol and
test source into `main-v2`, then use a clean detached checkout of that accepted
commit. Do not import or execute a candidate during source review. AST-only syntax
checks and ordinary repository hk/CI checks retain their existing authority.

Use only the existing WSL Linux x64 environment, installed systemd 259.5 user
manager, `/usr/bin/systemd-run`, `/usr/bin/timeout`, `/usr/bin/env` and installed
Python 3.14. The script
checks their fixed file hashes, including the installed manager executable; these
checks do not establish all loaded manager/library bytes. Rely on the installed OS
and documented service contracts within the workstation threat model. A missing,
changed or unavailable prerequisite stops the check; no installation, manager
startup, enablement, lingering, service configuration or host-policy repair is
permitted. Native Windows executables, .NET, public/private network operations,
authentication, account/store access and production installations are excluded.

### One Fixed Batch

The sole invocation in that accepted detached checkout is:

```sh
/usr/bin/timeout --signal=KILL 90s /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/python3 -I -S tools/validation/check_systemd_supervision.py --execute
```

Independently verify the fixed watchdog hash before admission. Do not add
`--foreground` or put a systemd-run client in a new session/process group. Timeout,
interruption, nonzero transport status or missing final evidence cannot pass. The
watchdog's SIGKILL bounds local work; the manager retains its separate service
deadline. If that deadline is not observed to complete, preserve uncertainty and
stop without speculative cleanup. The invocation exclusively creates
`/var/tmp/azureauth-systemd-supervision-108-0001` with mode 0700. Existing or partial
state forbids replay. Retain that root and all its files; do not read, modify or
recover the original Windows Slice experiment roots for this check.

Reserve one build/test unit and four synthetic-process units through the new root
and its durable `started.json`
before any test subject starts. The accepted retained construction baseline is
combined build/test 87 plus the unavailable original 0057 invocation unit: 88/120.
This independent batch consumes one further unit, including a failed start, leaving
89/120. Reserve all four synthetic-process cases as consumed when the batch starts,
including interrupted batches that do not reach every case; no refund or retry is
permitted. Cumulative synthetic-process consumption becomes 52, preserving twelve
protected final CLI cases under the accepted ceiling of 80. The batch
executes no product CLI and consumes no preparation, publication or download unit.
Before admission, confirm no intervening use and recover the existing accepted
consumption from retained evidence. Future dependent admissions must join this
additional reservation/result and charge; an old ledger cannot omit it. This
supplement does not authorize a ledger rewrite or another capacity inspection.

Run exactly four sequential cases, at most once each, stopping after any unexpected
result. Each uses a unique `azureauth-supervision-108-<run-id>-<case>.service` name,
recorded before its client starts. Each transient service uses `Type=exec`,
`ExitType=cgroup`, `KillMode=control-group`, `SendSIGKILL=yes`, `Restart=no`,
`TimeoutStartSec=3s`, `RuntimeMaxSec=3s` and `TimeoutStopSec=2s`. The client uses
`--user --no-ask-password --quiet --wait --pipe --collect
--expand-environment=no --job-mode=fail`. Do not use scope mode or a persistent unit file.

The systemd client receives only PATH, a fixed locale, and the designated existing
user-bus/runtime location. The service executes `/usr/bin/env -i` with only PATH
and locale, then the exact Python fixture with `-I -S`. No credential, proxy,
interop or startup-hook variable is forwarded to the fixture. This is a controlled
fixture, not a hostile-code isolation claim.

| Case | Controlled behavior | Required observation |
| --- | --- | --- |
| success | Root starts a leaf in a new session and exits; the leaf prints a fixed marker after 0.5 seconds. | Wait returns zero after leaf completion, output is exactly `leaf-finished` plus LF, and the owned cgroup is empty or removed. |
| command-failure | Root exits with code 7. | Wait returns 7, output is empty, and the owned cgroup is empty or removed. |
| descendant-timeout | Root exits; its new-session leaf ignores SIGTERM and would finish after 30 seconds. | Manager runtime/stop bounds end the leaf before its marker; wait returns 1, output is empty, and the owned cgroup is empty or removed. |
| client-loss | After fixture membership is recorded, terminate and reap only the locally created systemd-run client through its retained subprocess object. | The manager's deadline still ends the leaf; client exit is SIGKILL, output is empty, and the owned cgroup becomes empty or removed. |

The fixture records only its own PID, kernel start ticks, monotonic observation
time and unified cgroup membership; the batch records its boot ID privately. It
may read `/proc/self/stat`, `/proc/self/cgroup`, the boot ID, and only the observed
unique unit's `cgroup.events` beneath `/sys/fs/cgroup`. Do not enumerate processes,
units or unrelated cgroups. Both root and leaf must identify the same unit. A
missing cgroup is meaningful here only after that controlled fixture recorded
membership; it says nothing about original 0057 or unrelated work.

### Limits and Result Acceptance

The batch allows at most four systemd-run clients, four fixture roots and three
fixture leaves; no retries or arbitrary commands. A case has a 15-second
observation, local client cleanup and outcome-acceptance budget, with its last two
seconds reserved for client reap. Check the remaining observation budget immediately
before client startup; do not reset it after preparation. Reject a late outcome or
failed cleanup before publishing the case result. Result publication remains under
the whole-invocation watchdog rather than a separate per-case watchdog. Each case retains at most
16 KiB of combined client/service output through a nonblocking pipe. Only the
verifier writes the retained output file, never beyond that cap; one excess byte
detects overflow and stops the batch. Success also requires original pipe EOF.
The entire invocation has a 90-second external watchdog limit, including
preparation and recording. The manager's startup,
runtime and stop limits remain independent of client survival. Only the fixed
fixture leaf's deliberate 30-second wait is allowed, and the tested manager must
end it sooner. A failed client cleanup, expired observation, unexpected output,
changed source, uninitialized fixture or unproved owned-cgroup completion stops
the batch. Do not launch another case or speculate about cleanup.

The script never signals a PID recovered from a file, writes to cgroup controls,
stops a shared manager or invokes a general process-tree killer. `--collect`
permits the manager to release completed transient units; it does not authorize
deleting evidence or treating unavailable results as successful. Preserve state
on uncertainty. Record each exact command, unit, local fixture identities, client
exit, elapsed time, cgroup observation, failure classification and source hash in
the dedicated root. The public conclusion contains only sanitized case outcomes
and their limits; do not publish boot IDs, PIDs, user-bus/cgroup paths or raw logs.

Independent acceptance must check the original invocation result and the retained
case evidence before claiming any case passed. A successful batch supports only
the four tested Linux supervision behaviors on this installed environment. It
does not establish arbitrary-process containment, global quiescence, safety of
terminating Windows interop, public build/CLI acceptance, or permission to resume
original 0057.

### Linux Supervisor Validation Observations

The sole admitted batch ran on September 19, 2026, from clean detached commit
`2fdefd3a48b503678451e937a917c405922341f0`, tree
`dda878ed3bd748c9b82854de1ad51d5928159368`, accepted in
[PR #178](https://github.com/hcoona/microsoft-authentication-cli/pull/178).
The executed script's SHA-256 was
`2f6c56fc9a9bb71a00b28cadd8718b7008bf6971033e80b370eb5f6a991f67b2`;
the accepted protocol's SHA-256 was
`c3da7f8e9f71443dd68104c9ec986c454bfb65b50b9049e6a4fe045f55f6828c`.
The accepted 80-scenario Wave and all five installed tool hashes matched their
admission bindings, including an independent pre-execution watchdog hash check.

The initiating and execution host was the existing WSL2 Linux x86_64 environment,
kernel `6.18.33.1-microsoft-standard-WSL2`, using installed Python 3.14 and systemd
package metadata `259.5-0ubuntu3.4`. Installed-file identity does not establish every
loaded manager or library byte. MSAL, broker, Profile, authority, scopes and account
state were not applicable: this fixture performed no authentication, account/cache
operation, Windows invocation, network request, installation or UI interaction.
No operator action was required. The exact admitted command used the protocol's
90-second watchdog and clean environment without adding a process-group boundary.

The original invocation returned exit code zero. Its summary matched the retained
batch and per-case evidence; total recorded batch duration was 11,823 milliseconds.
The observations were:

| Case | Client exit | Retained output | Recorded duration | Owned cgroup at completion |
| --- | ---: | --- | ---: | --- |
| success | 0 | Exactly `leaf-finished` plus LF | 796 ms | Empty or removed |
| command-failure | 7 | Empty | 130 ms | Empty or removed |
| descendant-timeout | 1 | Empty | 5,337 ms | Empty or removed |
| client-loss | -9 (SIGKILL) | Empty | 5,479 ms | Empty or removed |

Every case completed with original pipe EOF within its observation/cleanup budget
and output cap. The root and its leaf, where present, recorded membership in the
same unique unit. For client-loss, the verifier killed and reaped only its retained
local systemd-run subprocess; the service subsequently reached the observed empty
or removed cgroup under the manager's separate deadline. The source hash recheck
matched. These are runtime observations of the four controlled behaviors on this
host, not claims about arbitrary-process containment or all manager internals.

There was one batch, four cases, no retry and no speculative cleanup. All dedicated
batch evidence was intentionally retained locally, including private fixture
identities and raw output; those values are not published here. The batch consumes
one build/test unit and all four reserved synthetic units. Combined build/test
occupancy is now 89/120: 87 previously recorded units, the unavailable original 0057
unit, and this batch. Synthetic consumption is 52/80, leaving 28, of which twelve
remain protected for final CLI cases and sixteen remain unallocated. Preparation,
publication and download consumption did not change. Subsequent admissions must
include this reservation and result rather than rely on the older ledger alone.

The observed mechanism is suitable evidence for preparing separately admitted
Linux helper integration. It adds no dependency to the authentication executable
and does not establish Windows interop termination, compiler or Native AOT success,
product CLI acceptance, account behavior or broader platform support. Original 0057
and its recovery remain consumed and stopped; its helper lifetime remains
unresolved. The later case-specific disposition above applies the accepted Wave
risk decision. No further invocation is authorized by this observation.

## One Corrected Compile-Through Diagnostic

This supplement implements the accepted original 0057 prior-helper disposition for
one additional compiler-native-inputs invocation, numbered 0058. It is a new charged
invocation, including a failed start, and cannot be retried. Original 0057, its
unavailable unit and consumed receipt recovery remain unchanged. The current Wave,
case-specific experiment-safety exception and complete independent exact admission
must all be accepted before execution. This supplement grants no old-process cleanup,
new authentication effect, graph/artifact acceptance or dependent publication.

### Source, Roots and Historical Capacity

Use the four existing inactive compiler-native-inputs sources after this correction.
Keep all execution gates disabled in tracked templates. Exact activation and source
materialization retain their existing independent admission, original-result and
finite effects requirements. The new observer root is the same fixed Windows path
with final component `compiler-native-inputs-5033607-v2`. The additional paired action
is 0058. Replace the old observer-root spelling consistently in the dispatcher,
controller, target, source manifest, sole required Import overlay, materialization
plan, support paths, authority and literal. This same-length path substitution changes
no compiler control, project metadata, selected product source or restore bytes. The
33 original product blobs remain unchanged; the sole Import remains mandatory.
Keep the accepted product commit/tree, SDK/runtime/package pins, three Csc contexts,
Windows guard/Job Object, physical predicates and stop-before-ILC/linker boundary.

The original indented 211,842-byte handoff retains its exact hash, strict JSON and
semantic checks. Do not rewrite it or fabricate an absent 0057 receipt/directory.
For compiler mode only, the two Windows action-directory lists must equal 0001–0056
before reservation and 0001–0056 plus 0058 at the second checkpoint. Any 0057 entry,
extra entry, missing entry or unmatched pair rejects continuation before its content
is read. Preserve the existing fixed historical reads and disposed-0054/0056 checks;
the second disposed-0054 checkpoint binds reserved 0058. This grants no 0057 leaf,
old observer-root or old-process inspection. Other history modes are unchanged.

The existing history-input authority uses compiler schema v2 and binds its exact
`priorCapacity` projection. The paired history still yields 87 build/test units,
including the existing fixture once, and 48 synthetic scenarios. Add original 0057's
unavailable unit and the independently accepted systemd batch's one build/test and
four synthetic units: current global occupancy is 89/120 and 52/80. Reference the
accepted systemd reservation/result and PR #180 observations during exact admission.
The additional diagnostic consumes one more build/test unit: 90/120 and 52/80.
Transfer one prospective unit from Linux ceiling 78 to 77 and aggregate Windows
ceiling 50 to 51; ordinary Windows capacity remains exhausted at 48. Retain the global
120 ceiling, preparation/publication/download limits and twelve protected final CLI
cases. `started.json` and original-result validation bind the additional capacity
projection without changing historical `priorCounters` or inventing old events.

### Linux Verification Helpers

Only compiler-mode `public_read` uses the installed systemd user manager. The complete
admitted caller makes five immutable local Git queries and three exact fork-ref GETs;
the latter occur after initial history binding, immediately before reservation and
after the original-result/history join. Permit at most eight calls in that sequence,
with a permanent failure latch and no retry. Do not supervise the dispatcher, Windows
proxy, controller, compiler or Job Object within these Linux units.

Bind the installed systemd-run, env, Python and manager file hashes to the accepted
supervision batch and the new source's exact sizes. These installed-byte checks do
not identify every loaded manager/library byte. Retain the existing pinned GitHub
CLI verification. Use a minimal client/bootstrap environment, user bus and unique
unit names, with no installation, manager repair, host configuration or service
persistence. Each transient service retains `--no-ask-password`, `--quiet`, `--wait`,
`--pipe`, `--collect`, `--expand-environment=no`, `--job-mode=fail`, Type=exec,
ExitType=cgroup, KillMode=control-group, SendSIGKILL=yes and Restart=no.

A fixed, uninterpolated Python leaf string is part of the exact history source.
Invoke it with the pinned Python and `-I -B -S -c`, passing identity path/unit as
separate arguments. Inspect its decoded AST without executing it during review.
Its source is public code, never an environment or credential carrier. It publishes
its own PID, start ticks and unique-unit cgroup identity before reading a bounded
stdin payload. The payload contains only the fixed query vector, the existing
filtered child environment and an absolute latest-exec time. It is at most 128 KiB,
is sent nonblockingly alongside output observation and is never retained, hashed,
printed, or placed in argv or unit properties. Restore the previous cwd/environment
semantics; before execve, replace stdin with /dev/null and restore the subprocess
signal defaults. No shell or additional worker process is used.

Each call shares `E = min(original outer deadline, call start + 30 seconds)` across
hashing, preparation, handoff, output, observation and final acceptance. Keep the sole
original 900-second dispatcher clock. Select runtime at most twenty seconds from the
remaining budget after a nine-second reserve; job/start/stop limits are two seconds
each. Immediately before Popen, require at least runtime plus eight seconds remaining.
The leaf checks `E - runtime - four seconds` immediately before execve, rejecting late
Git/GET starts. JobTimeoutSec limits the queued job; it does not stop an already-started
unit. The source basis is the same immutable systemd v259 documentation plus
[unit job timeouts](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/man/systemd.unit.xml#L1140-L1160).

The thirty-second boundary is the call's acceptance and observation deadline. Manager
limits are separate finite fallback supervision, not proof that scheduler, manager
or filesystem delay cannot outlive that boundary. If required exit evidence is
unavailable by E, preserve uncertainty and stop all later helpers and dependent work.
Do not extend the original clock, retry the helper, signal a recovered PID, or issue
manager cleanup commands. Only the retained local systemd-run Popen may be killed and
reaped; its unit retains independent manager termination limits after client loss.

Keep stdout byte-for-byte and stderr separate with the original combined 8 MiB
ceiling. At most one returned overflow byte is inspected; overflow closes output
pipes and fails the invocation. Success requires the original client exit zero,
complete payload transfer, both pipe EOFs, and the bound unique cgroup observed empty
or removed. Neither EOF, client exit, job timeout nor a historical test alone proves
completion. Cancellation and all failures retain the permanent failure latch.

### Additional Local Effects and Result Acceptance

The fixed Linux helper root is
`/var/tmp/azureauth-compiler-verifiers-108-0058`. Create it exclusively, retain it,
and reject reuse. Its first durable marker records the same diagnostic's one charge;
it is not a second charge beyond the paired action or a replacement historical
ledger. A failure before paired reservation still consumes the additional diagnostic.
The root has one marker and at most eight numbered call directories. Each call has
started, identity and provisional result files; the identity writer briefly owns a
pending name and exchanges it by hard link before removing only that pending name.
At most nine directories, twenty-five retained files and eight temporary names are
created. No original experiment root is used for helper evidence. Preserve all new
state, including partial failed starts; no retry or speculative cleanup follows.

Each call permits at most 1,200 pump iterations, each with at most one stdin write
and two output reads. Each write/read request is at most 8 KiB; actual output bytes
remain bounded by the combined limit plus the one overflow byte. Identity content is
read once per call with a 4 KiB cap. Cgroup status is at most 4 KiB plus one rejection
byte per pump; presence checks and observations share the same iteration and absolute
time limits. Exact admission must join these finite additions to the existing input,
history, materialization, bootstrap and Windows evidence budgets without resetting
any allowance. Original fixed metadata copies and recoveries remain consumed.

Call result files are provisional observations. Their elapsed field excludes their
own final persistence, and a later cancellation/deadline check can reject the caller.
Accept neither these files nor a paired Windows receipt without the original outer
tool completion and the existing independent source, authority, literal, original
transport, history, Windows completion and semantic-observation joins. Refresh all
changed descriptors/review roles and actual source-materialization acceptance before
execution. A successful corrected diagnostic only supplies its bounded compiler/native
input evidence; dependent compilation and final CLI scenarios keep separate exact
admissions. Any new ownership or termination uncertainty stops further execution.

### Original 0058 Failed Outcome

The sole corrected invocation ran under accepted protocol/source revision
`3fbcea11f2f675b7a86ce43104c2a58158043370`, tree
`42eace86a48e208c713666e362e3ea0fb577fb0c`. It used the independently accepted
four-file materialization, completed authority and exact original literal. The
selected product remained commit `503360753accd0829801953823b1b57a4f852440`,
with the existing SDK, runtime and dependency pins. This observation changes none
of those identities or the existing credential-free WSL/Windows effects boundary.

The original tool returned exit code 1, complete output and no running session.
Its sole intentional dispatcher frame used schema
`compiler-native-inputs-dispatcher-failure-v1`, stage `history-reservation`,
exception type `ValueError` and outcome `incomplete`. The canonical frame is
140 bytes with SHA-256
`3f01147d48a157c7cc10b54942d6a178a19a1ed189eb2b91264c2aeb050f8c1c`.
The complete private original transport is 1,070 bytes with SHA-256
`4e445f551d2c602e96b53782c49e6338019653170b25088ad217fa5780c20eb6`.
Independent failed-outcome acceptance binds that transport to the admitted literal;
its 9,232-byte carrier has SHA-256
`1517bd9ced5bd1791b6da9a02b9032029ca54a95dd7fc25ec8606d43a4d9fb08`.
Only the sanitized classification and evidence identities are public.

This is a runtime failure observation at a coarse dispatcher stage. The specific
first failing check, reached reservation effects, helper launches and completion,
Windows launch, persistent partial state and quiescence remain unestablished.
Short elapsed time is not evidence that no work started. Static review of the
frozen authority/history configuration found no mismatch in the checked canonical
JSON, source descriptors, schema, product, prior capacity or accepted revision
bindings; that source/data finding does not identify the actual exception site.
No compiler, native-input, graph, artifact or scenario success follows from this
invocation. No account operation or human interaction was selected by its protocol.

The additional diagnostic is consumed, including its failed start. Current global
occupancy is 90/120 build/test units and 52/80 synthetic scenarios. Keep the twelve
protected final CLI scenarios and sixteen unallocated synthetic scenarios; no unit
is refunded. Preserve the original result and any partial state without cleanup.
The normal-result collector is ineligible, the old 0057 recovery remains consumed,
and no retry, additional diagnostic, new recovery or dependent execution is admitted
by this failed-outcome record. The accepted historical 0057 risk disposition does
not establish or waive any new 0058 lifetime uncertainty.

### One Fixed 0058 Failure-Receipt Recovery

Within the existing credential-free evidence boundary, permit one separately
admitted read-only collection of fixed receipts from the failed 0058 invocation.
This is evidence recovery only. It does not repeat a compiler diagnostic, reuse
the consumed 0057 recovery, accept new lifetime risk or lift any dependent stop.
No Windows-root access, process or cgroup query, manager operation, installation,
account access, network call, subject launch or cleanup is selected.

The [inactive collector](../../../tools/validation/collect_windows_compiler_0058_failure.py)
selects only these 28 possible regular files:

| Exact parent | Fixed leaves | Collector rejection limits |
| --- | --- | --- |
| `/var/tmp/azureauth-windows-slice-108/windows-actions/0058` | `started.json`, `reservation-failure.json`, `result.json` | 8,192; 4,096; 65,536 bytes respectively |
| `/var/tmp/azureauth-compiler-verifiers-108-0058` | `started.json` | 4,096 bytes |
| Each literal child `01` through `08` of that helper root | `started.json`, `identity.json`, `result.json` | 4,096; 4,096; 8,192 bytes respectively |

These are new collector rejection limits, not claims that every original producer
enforced those sizes. Content totals at most 212,992 bytes. Never enumerate a
directory, follow a path from receipt content, read a pending name or inspect an
unlisted leaf. Receipt bytes remain uninterpreted private evidence during copying;
later independent interpretation must distinguish provisional helper files from
original completion. Presence and absence do not establish helper termination or
quiescence, and a partial snapshot cannot authorize another diagnostic.

Reach the existing WSL root and windows-actions parent through component-wise,
descriptor-relative no-follow directory opens. Keep the original root and parent
mandatory; an error there is not absence. The exact 0058 action directory, helper
root, eight fixed helper children and each receipt may be absent. Record absence
only from the corresponding no-follow lookup, then recheck that same leaf once.
When the helper root is absent, record its eight children as ancestor-absent
without probing them. Missing, linked, inaccessible, non-directory, nonregular,
oversized or changing inputs otherwise fail closed. Compare opened and named file
and selected-directory identities using device, inode, mode, size and nanosecond
mtime/ctime. Bind the mandatory parent directory identities again at finalization;
unrelated `/var/tmp` entries may change, so its continuity uses device/inode/mode.
These are checkpoint observations under the existing cooperating-filesystem
premise, not a snapshot lease or evidence that a writer has permanently stopped.

Open only the existing `/var/tmp/azureauth-windows-slice-108/action.lock`, read-only
and no-follow as a regular file, and attempt its exclusive lock once nonblockingly.
Do not read, create or change lock content. Bind the held and named lock before
and after collection, and release it during finalization. No contention retry,
concurrent experiment, signaling or process-lifetime claim follows from this lease.

After all initial observations pass, create only
`/tmp/windows-compiler-0058-failure-offline-root-v1`, exclusively at mode 0700.
Copy present leaves into the 28 statically derived flat role names in the source,
with initial mode 0600 and final mode 0444. Use complete bounded writes, fsync,
exact copy readback and one later identical original-content/identity reread.
Missing leaves get no file. Retain at most 29 files, including one canonical
ASCII compact-JSON inventory of at most 65,536 bytes. Fsync the output directory
and parent, verify held/named output identity, and preserve all partial outputs
on failure. There is no overwrite, repair, deletion or second attempt.

The exact admission input is at most 16,384 bytes and binds the accepted target,
source/runtime review and the failed original transport. Its one content read,
the 28 possible original reads, 28 continuity rereads, 28 private-copy readbacks
and one inventory readback total at most 86 content reads. Use at most 184 read
calls, 720,982 requested bytes, 720,896 returned bytes, 278,528 written bytes,
35 complete write calls and 4,096 path operations. Each content chunk is at most
16,384 bytes; each read includes its charged one-byte EOF/rejection probe.
Counters are distinct, finite rejection bounds; short reads or writes gain no
retry or expanded allowance. Trusted interpreter startup is not a complete
system-I/O trace within those counters.

Use one nonresetting 90-second source deadline with cancellation checks around
reads, path operations, writes, seals, syncs and finalization. The separately
accepted exact literal uses the retained Python 3.14 isolated/no-site/no-bytecode
runtime and GNU timeout at 95 seconds with a two-second KILL grace. Its closed
transport frame reports only completion, stage/role, exception class, inventory
descriptor and counters. Preserve the original tool transport and normal final
exit; any same-session empty wait remains at most 60 seconds. The frame and
inventory are provisional until that original outcome is independently accepted.

Keep the tracked source inactive. After this protocol merges, independently
accept exact source activation, materialization, runtime, authority and literal
before the sole invocation. Materialize the sole `ACTIVE = False` to
`ACTIVE = True` substitution in the captured inline Python source of that literal;
bind its exact UTF-8 bytes/hash and reverse recovery to the accepted tracked bytes.
Create no activated source file or extra writer invocation. Accept its original result before interpreting copied
receipts. Any failed start, timeout, cancellation, input change or incomplete
original collection consumes this recovery and stops further collection without
cleanup. This read-only copy adds no build/test or synthetic execution; retain
90/120 and 52/80, including the consumed failed diagnostic. A successful recovery
does not itself establish a failure cause, quiescence, graph/artifact acceptance
or authority for later execution.

### Accepted 0058 Failure-Receipt Recovery Outcome

The sole fixed recovery ran under accepted protocol/source revision
`c4380fc1c3e559d9039afffd0891c47672ce8c5d`, tree
`7327cf1b8428ab6f780fa1d5d5022ed51d41b076`. Independent admission bound the
inactive collector to its exact inline activation, retained runtime identities,
closed admission data and complete original command. The original tool returned
normal exit 0, complete output and no running session. Its canonical 389-byte
transport frame has SHA-256
`23000dec78e27cd22b8e169677eb0afe3371075df52cf27e063946bba7fcdbf4`;
the complete private original transport is 23,892 bytes with SHA-256
`116403a2a00e3b03b96ab128046c6cc5771eaed25d85d2fcf66aa7b994bdbe96`.

The sealed 7,533-byte inventory has SHA-256
`877841dad845cfb21cd79a51e08b9d9270b611076254983dab1ca3a70dbc6a3b`.
It binds three copied receipts totaling 702 bytes: the helper-root start marker
and helper 01's start and result. The action 0058 directory, helper directories
02 through 08, and helper 01's identity leaf were absent at the selected initial
and final checkpoints. These are fixed checkpoint observations, not evidence
of permanent absence or an atomic snapshot. No Windows-root observation was made.

Independent original-outcome and opaque-copy acceptance passed before receipt
interpretation. Its 11,030-byte carrier has SHA-256
`5a9fe1ec54b5494eb4c5ee4e7f988e3658442ededfa8725cf6326b6276b77059`.
All seven reported counters reconcile with the exact selection: 11 content reads,
22 read calls, 10,317 requested bytes, 10,306 returned bytes, 8,235 output bytes,
four complete writes and 130 source-defined path operations. These counters do
not measure every interpreter or operating-system startup operation.

The helper-root marker records prior capacity 89 build/test and 52 synthetic
units, with the same original diagnostic charge of one build/test and zero
synthetic units. It does not add another diagnostic charge. Helper 01's start
selects 20,000 milliseconds of runtime and 2,000 milliseconds each for job,
start and stop bounds. Its result records:

| Field | Recorded value | Evidence limit |
| --- | --- | --- |
| Client exit | `1` | The verifier's client exited unsuccessfully; this is not a service-completion observation. |
| Standard-output and standard-error EOF | Both `true` | The original client pipes reached EOF; neither field supplies their content. |
| Failure | `IdentityUnavailable` | No acceptable helper identity was available when the source selected this failure. |
| Completed | `false` | The helper's complete acceptance condition was not established. |
| Group empty | `false` | The source initializes this field to false and checks the group only after obtaining identity; this is not an observation of a populated group. |
| Elapsed milliseconds | `65` | A source measurement before result persistence, not an outer completion or lifetime bound. |

Independent offline interpretation uses the accepted private copies and the
original accepted inactive source. Its 6,870-byte carrier has SHA-256
`8cb6e7acc28532fa5613ed912c07f5d83f0df86124aadff44eb44a6e56b542d9`.
Source review of `compiler_verifier_read`, `load_core_csc_history` and
`verify_revision` in the [history adapter](../../../tools/validation/final_publish_contracts.py)
joins `IdentityUnavailable` to the branch where the client has
exited, both pipes have reached EOF and the identity remains unavailable. The
subsequent failure gate refuses to return verifier output or enable another
helper. This is consistent with the original dispatcher's
`history-reservation` / `ValueError` failure. Conditional on the accepted source
and input bindings, call 01 is the first immutable Git query for the accepted
commit's tree. The receipts do not independently record its argument vector or
establish that the query executed or completed.

The underlying startup error remains unknown. The accepted helper counts any
standard-error bytes against its combined output limit but does not retain them;
the result records no separate standard-error content or length. EOF therefore
does not establish that standard error was nonempty. No specific systemd
rejection, service-never-started conclusion, original first-exception instruction,
absence of partial Windows effects or process quiescence follows from these data.
All raw receipts and local identities remain private.

This recovery is consumed, with no retry, replacement copy or cleanup. Capacity
remains 90/120 build/test and 52/80 synthetic units; preserve the twelve protected
final CLI scenarios and sixteen unallocated synthetic scenarios. The original
0058 diagnostic remains failed, with direct completion evidence unavailable.
The source/contract reassessment below distinguishes that evidence gap from loss
of manager supervision; it does not rely on the historical 0057 risk exception.
Keep dependent diagnostics, compilation, graph, artifact and scenario acceptance
stopped pending their separate authorization and admission. This outcome grants
no new invocation, process query or owner risk acceptance.

### 0058 Manager-Supervision Reassessment

This is a source/contract inference about the original accepted launch, not a new
runtime observation. Apply the existing experiment-safety instruction to rely on
documented process contracts within the workstation threat model. The immutable
systemd v259 source at `9ca433482f2281d71718718705ca8cd3bf562ad6`
supports the following distinction:

- The manager [sets transient properties before queuing the start job](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/core/dbus-manager.c#L1021-L1157).
  Rejection before that queue does not start this service. After submission,
  [client reply parsing or observation may fail](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/run/run.c#L2580-L2668)
  without removing the service's manager-owned limits. Client exit 1 and missing
  leaf identity do not identify which branch occurred.
- The selected Type=exec service has a two-second startup limit, at most twenty
  seconds of active runtime and a two-second stop limit, with ExitType=cgroup,
  KillMode=control-group, SendSIGKILL=yes and Restart=no. The documented
  [startup and stop deadlines](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/man/systemd.service.xml#L619-L674),
  [running timer](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/core/service.c#L2398-L2412)
  and [timeout transitions through forced termination](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/core/service.c#L4520-L4600)
  belong to the manager. Group signaling uses the
  [manager's own cgroup path](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/core/unit.c#L4962-L4976),
  independently of the leaf's private identity file. The separate job timeout
  bounds queuing and does not replace these service controls.

Missing identity therefore does not establish a new unsupervised lifetime or,
by itself, require a new owner risk exception. Under the accepted installed-OS
and configured-service premises, the documented finite manager supervision and
termination procedure still applies. This does not reattest effective host state,
prove that the selected Git command ran, recover the startup cause, or establish
observed quiescence. In particular, the cited stop implementation can continue
after processes remain following SIGKILL; finite supervision is not a guarantee
of quiescence within an exact wall-clock interval. Preserve the original failure
and its stricter success predicate rather than retroactively accepting it.

This correction adds no policy exception or execution grant. The one corrected
diagnostic and its recovery remain consumed; capacity remains 90/120 build/test
and 52/80 synthetic. Another diagnostic requires its own accepted authorization,
protocol and exact admission. No query or cleanup follows from this reassessment.

### Inactive Verifier Evidence Correction

The current inactive [history adapter](../../../tools/validation/final_publish_contracts.py)
uses future receipt schema `compiler-verifier-result-v2`. This is a source-only
correction; original 0058 used its recorded earlier source and receipt shape.
No original receipt, source binding, consumed recovery or observed result changes.

Within the existing combined output limit, retain at most the first 16,384 stderr
bytes already read by the pump. Encode that exact private prefix as base64 in the
existing provisional `result.json`, with observed and retained byte counts.
`stderrComplete` requires stderr EOF and equal observed/retained counts. A short
prefix without EOF is incomplete; more observed than retained bytes means truncation.
Count the possible single overflow byte as observed before the existing output-limit
failure. Never make an extra read, enlarge the combined output allowance, repeat a
helper, or expose the raw prefix in public evidence. Base64 is a byte representation,
not sanitization; the existing private receipt permissions and retention apply.

The future result is bounded to 32 KiB, including at most 21,848 base64 characters.
This adds no file or directory to the existing twenty-five-file/nine-directory
maximum. It does not enlarge the consumed recovery's 8 KiB helper-result slot or
permit recollection. `groupEmpty` is null until the existing bound-group predicate
returns a boolean; false then means that predicate did not establish emptiness.
The original receipt's false value retains its separately recorded unobserved meaning.
The success condition, failure latch, clocks, calls, pump limits and manager settings
are unchanged. A provisional result still requires original outer completion and
independent interpretation; its persistence is not included in its elapsed field.

This code remains disabled and supplies no new invocation. A future proposal must
bind its changed source and receipt shape, a fresh evidence location, then-current
capacity, and separate exact admission under an accepted execution grant. It must
not reuse the consumed 0058 root or its earlier source/capacity bindings. No additional
startup error, cause or successful platform behavior has been observed by this edit.

## One Additional Compile-Through Diagnostic 0059

This supplement implements the current Wave's additional compiler-input diagnostic
as one credential-free invocation numbered 0059. It inherits the selected source,
three Csc contexts, native-input cutoff, finite execution, original-result and
independent admission requirements of the two preceding compile-through supplements,
with only the changes below. Original 0057, original 0058 and their recoveries remain
failed or consumed as recorded. The accepted manager-supervision reassessment is a
contract inference, not observed quiescence or a new lifetime-risk exception.

### Fresh Source, History and Capacity

Use the four existing inactive sources with a fresh Windows observer root ending
`compiler-native-inputs-5033607-v3` and Linux helper root
`/var/tmp/azureauth-compiler-verifiers-108-0059`. Bind the new root spellings in every
source, Import overlay, DATA descriptor, materialization plan, authority and literal.
Use helper marker schema `compiler-0059-verifiers-start-v1` and unique service names
beginning `azureauth-compiler-0059-`. Root creation remains exclusive and all partial
state is retained. Keep all tracked execution gates disabled; source activation and
materialization still need their separate independent exact admission.

The 33 product payloads, original restore bytes, selected product commit/tree,
SDK/runtime/packages, installed helper pins and required Import semantics do not
change. Neither do compiler controls, Windows guard/Job Object, physical predicates,
output/evidence limits or the stop before ILC and the linker. Preserve the original
900-second dispatcher clock, at most eight verification calls with permanent failure
latch, each call's 30-second acceptance window, at most 20-second manager runtime,
two-second job/start/stop limits, minimal environments and exact command sequence.
The previously accepted stderr-prefix correction and nullable `groupEmpty` field
apply to the new 32 KiB provisional helper-result slots, without extra reads or an
increase to the combined 8 MiB helper-output limit.

Keep the exact indented 211,842-byte handoff unchanged. Compiler-mode action lists
must equal 0001–0056 before reservation and 0001–0056 plus 0059 after original
completion; 0057 or 0058 entries, missing or extra entries reject before their
contents are read. The second disposed-0054 checkpoint binds reserved 0059.
Preserve existing fixed historical reads and disposed-0054/0056 validation, without
reading any original 0057/0058 action/helper leaf or old observer root. Other history
modes are unchanged. The existing shared parents, owner markers and action lock
remain covered by the preceding history/reservation requirements.

The exact `priorCapacity` projection now adds `original0058FailedBuildTest: 1`.
Historical paired counters remain 87 build/test and 48 synthetic, including their
fixture once. Original 0057 adds one unavailable build/test unit, failed original
0058 adds one, and the accepted systemd batch adds one build/test and four synthetic.
Prior occupancy is therefore 90/120 and 52/80. The helper-root first-start marker
binds those totals and charges this same single diagnostic even if paired reservation
is never reached. Successful paired reservation does not charge it twice.
The additional unit produces at most 91/120 and 52/80. Transfer one prospective
unit from Linux ceiling 77 to 76 and aggregate Windows ceiling 51 to 52; ordinary
Windows capacity remains exhausted at 48. Keep preparation, publication and download
limits and the twelve protected final CLI cases plus sixteen unallocated synthetic
cases. No startup scenario, retry or refund is granted.

Require current target/protocol/Wave bindings and refreshed exact DATA, source,
runtime, materialization, history, capacity, authority and invocation reviews before
execution. Preserve the unchanged selected product, guard and other evidence only
within their original review scopes. Original tool completion and independent
outcome acceptance remain required before any receipt is interpreted. A successful
0059 supplies only its accepted compiler/native-input observations; final Native AOT
publication, artifact validation and scenario execution retain separate admission.

### Conditional Fixed 0059 Failure-Receipt Collection

If and only if the original 0059 tool outcome is independently accepted as failed,
permit at most one separately admitted fixed receipt collection. This is part of
accepting that diagnostic's outcome, with no new build/test or synthetic charge.
Do not use it after a successful or unresolved original invocation. A failed start,
timeout, cancellation or incomplete collection consumes this sole collection.
No retry, subject launch, process/cgroup query, manager operation, Windows-root
access, network call, installation, account access or cleanup is included.

Reuse the existing inactive
[0058 collector template](../../../tools/validation/collect_windows_compiler_0058_failure.py),
19,604 bytes with SHA-256
`0274f8f0e0d08d5cf26af73f506815bdc30ff1f362fdb185ca7f5f5970eb070d`.
Keep that tracked historical template unchanged. Independently review these exact
transformations in a captured inline literal after the failed outcome is accepted:

- Replace exactly ten ASCII `0058` occurrences with `0059`; these bind the fixed
  action/helper roots, output/admission paths, role/schema labels and docstring.
- Replace only the unique helper tuple `('result', 'result.json', 8192)` with
  `('result', 'result.json', 32768)`. The action-start slot stays 8,192 bytes.
- Replace the unique `TRANSPORT` assignment with the independently accepted
  original 0059 transport's exact byte count and SHA-256.
- Replace the unique `LIMITS` assignment with the finite bounds below.
- Change the sole `ACTIVE = False` to `ACTIVE = True` only in the captured literal.

Bind the accepted template, every exact substitution, derived source bytes/hash,
reverse recovery and decoded AST, isolated runtime, actual original transport and
exact literal. Create no activated source file, duplicate collector or extra writer.
The collector validates admission shape and transport equality; external independent
admission must bind the actual source/runtime/accepted target artifacts. Its fixed
`originalOutcome: failed` remains unchanged, which is why this is failure-only.

The same 28 fixed slots now select only the 0059 action and helper roots. The action
slots retain limits 8,192, 4,096 and 65,536 bytes; the helper-root start slot remains
4,096; each of eight fixed children has start/identity/result limits 4,096, 4,096 and
32,768. Selected content totals at most 409,600 bytes. The v2 helper JSON is copied
as opaque private bytes, including base64 stderr; encoding is not sanitization.
Do not inspect original 0057/0058 roots, follow receipt-selected paths, enumerate
unlisted leaves or interpret copied output before original collection acceptance.

Retain the preceding fixed collector's component-wise descriptor-relative no-follow
opens, mandatory shared WSL root and windows-actions parent, identity/absence
checkpoints, read-only existing `action.lock` and one nonblocking exclusive lock,
fixed flat roles, private modes, complete writes, fsyncs, copy readbacks and later
original rereads. Do not read or mutate lock content. Create only
`/tmp/windows-compiler-0059-failure-offline-root-v1` exclusively, with at most 29
files including a 65,536-byte inventory, and intentionally retain partial output.
The admission input is
`/tmp/windows-compiler-0059-failure-recovery-admission-root-v1.json`, at most 16,384
bytes. Parent access does not authorize another action directory or old helper root.

Use at most 86 content reads, 208 read calls, 1,310,806 requested bytes, 1,310,720
returned bytes, 475,136 output bytes, 43 write calls and 4,096 path operations.
The 16,384-byte chunks, charged EOF probes, separate counters and fail-closed
short-read/write behavior stay unchanged. These are rejection ceilings, not extra
retry allowances. Keep the nonresetting 90-second source deadline and isolated
Python 3.14 runtime, with GNU timeout at 95 seconds and two-second KILL grace.
The closed transport frame, final original exit, at most 60-second same-session
waits and independent outcome/interpretation requirements remain unchanged.
Neither a copied provisional receipt nor absence proves termination or quiescence.
Any new ownership or termination uncertainty retains ordinary stop conditions;
this collection cannot authorize another diagnostic or dependent execution.

### Original 0059 Failed Outcome and Fixed Collection

The sole invocation ran under accepted protocol/source commit
`93c1d2a1a89e71ff9ab5448b4b390b3f00e1454b`, tree
`07899ecea196648fae8d3117f14e677382d421ac`, after independent DATA, source,
materialization, authority and exact-literal admission. The selected product remained
`503360753accd0829801953823b1b57a4f852440`; the existing Windows/WSL environments,
SDK/runtime/package pins and credential-free effects boundary were unchanged.
No account operation or human interaction was selected.

The original tool completed with exit code 1 and no running session. Its complete
dispatcher frame reported `history-reservation`, `ValueError` and `incomplete`.
The private original transport is 284 bytes with SHA-256
`4480305c48fd9aca66e328070975e9f85042d5f1afaea5a99f80fe5bc84de666`.
Independent original-outcome acceptance established failure before the separately
admitted conditional collection ran. Short execution time and the coarse failure
stage do not establish absent partial effects or quiescence.

The sole fixed collection completed with exit code 0, no running session and a
complete normal-completion frame. Its private original transport is 553 bytes with
SHA-256 `cf9857d84e3543f18bd570cac9445591c7b75e7f3028ab160f3ae11c24c92ee4`.
Independent outcome/copy acceptance verified all 28 slots, the 7,542-byte inventory
with SHA-256 `9d38709c842b2bf3aa3c381bc2bc3972e1ed406eeafb06fced8e96edbb023cb0`,
and three copied files totaling 1,050 bytes: the helper-root marker and first helper's
start and result. The first identity leaf was absent. The action directory and
helper directories 02 through 08 were absent at the collection checkpoints only.
The collector used 11 content reads, 22 read calls, 11,369 requested bytes, 11,358
returned bytes, 8,592 output bytes, four writes and 130 path operations. No additional
original-root inspection, manager query, Windows access or cleanup followed.

The first helper result reported client exit 1, `completed: false`,
`failure: IdentityUnavailable` and `groupEmpty: null`. Both output streams reached
EOF; stderr observed, retained and decoded lengths were all 159 bytes, and
`stderrComplete` was true. The complete private stderr contains this sanitized
startup-rejection sentence:

> Failed to start transient service unit: Cannot set property JobTimeoutUSec, or unknown property.

This directly identifies the rejected property and explains why the helper did not
supply an accepted identity. It does not independently establish the loaded manager's
source revision, absence of every partial service-definition effect, termination or
quiescence. No successful Git verification, Windows compilation, native-input graph,
AOT artifact or CLI scenario is accepted from this attempt.

The diagnostic and its sole collection are consumed, with no retries or refunds.
Capacity is 91/120 build/test units and 52/80 synthetic scenarios; preserve the twelve
protected final CLI scenarios and sixteen unallocated synthetic scenarios. Retain all
partial state and private copies. Original 0057/0058 dispositions remain unchanged;
the new stderr cannot retrospectively identify original 0058's missing stderr.

### Public-Source Finding and Inactive Verifier Correction

The immutable official systemd v259 source at
`9ca433482f2281d71718718705ca8cd3bf562ad6` provides a source-level explanation
consistent with the observed error. The [CLI property conversion](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/shared/bus-unit-util.c#L2771-L2772)
maps `JobTimeoutSec` to `JobTimeoutUSec`. The [transient-property setter](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/core/dbus-unit.c#L2378-L2389)
handles that property but omits `return r;`, eventually returning zero. The
[outer property dispatcher](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/core/dbus-unit.c#L2673-L2682)
then emits the observed rejection. The adjacent `JobRunningTimeoutUSec` branch
returns its result correctly. These are public-source facts, not proof that the
installed package or loaded user manager has identical bytes. The successful
earlier supervision batch did not include `JobTimeoutSec`; it did not validate
this additional property in the diagnostic command.

The current inactive history adapter replaces only that timer setting with
`JobRunningTimeoutSec=2s` and makes the existing absolute query deadline an explicit
bootstrap argument. Its first deadline check occurs after importing only `sys` and
`time`, before identity/proc reads, identity writes or stdin consumption. An expired
bootstrap exits 125. The payload must carry exactly the same integer deadline;
retain its existing post-payload and immediate pre-`execve` deadline checks. The
deadline derives once from the existing `latest_exec` calculation, without extension
or a new clock. Preserve the maximum eight calls, permanent failure latch, original
30-second acceptance window, 900-second outer clock, pre-spawn reserve and source
output/read bounds. `TimeoutStartSec=2s`, `RuntimeMaxSec` at most 20 seconds and
`TimeoutStopSec=2s` remain unchanged.

This correction deliberately changes the queue-time claim. [Official job-timeout
semantics](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/man/systemd.unit.xml#L1140-L1160)
and the [timer implementation](https://github.com/systemd/systemd/blob/9ca433482f2281d71718718705ca8cd3bf562ad6/src/core/job.c#L1140-L1172)
distinguish time since queuing from time since a job starts running. The new setting
bounds the latter only. The start receipt therefore uses `jobRunningMilliseconds`
and `queueTimeoutConfigured: false`, replacing the ambiguous `jobMilliseconds`.
Do not claim a two-second queue-residence bound or that all possible future bootstrap
processes cease within the outer observation window.

A future separately admitted invocation must explicitly retain up to eight unique
transient definitions/jobs if still queued. They are pending manager work, not already
running Git or API-query processes. If started after the absolute query deadline, the
bootstrap rejects before query-specific effects; ordinary executable/interpreter
startup still occurs under the declared service timers. This is bounded-count
retention with expired-query rejection, not a bound on queue residence or proof of
zero later effects. It requires no extra service, query, host upgrade, unit-file
installation or cleanup. Ordinary manager-contract trust does not establish
unconditional wall-clock termination; new actual ownership or termination uncertainty
still triggers the existing stop conditions. No new lifetime-risk exception is added.

All tracked execution gates remain inactive. This source/protocol correction records
the failure and prepares a corrected mechanism only. It does not admit another
diagnostic, replay a consumed supervision batch, validate the new setting at runtime,
or lift Native AOT and scenario prerequisites. Another invocation requires its own
accepted Wave/protocol grant, fresh roots and refreshed source, runtime, DATA,
materialization, capacity, authority and exact-literal admission. The original 0059
command and its earlier timer settings remain its historical execution identity.

## One Additional Compile-Through Diagnostic 0060

This supplement implements the accepted Wave's one additional credential-free
compiler-input diagnostic, numbered 0060. It follows the accepted 0059 failure and
inactive verifier correction above. Inherit the preceding compile-through protocols'
selected product, three Csc contexts, native-input cutoff, finite effects, original
completion and independent exact-admission requirements, with the changes below.
Original 0057, 0058 and 0059 and their recoveries remain failed or consumed; none
may be replayed. This supplement neither accepts new lifetime risk nor establishes
that the corrected manager setting works on the designated host.

### Fresh Bindings and Preserved Consumption

Use the same four inactive sources, with Windows observer root ending
`compiler-native-inputs-5033607-v4` and Linux helper root
`/var/tmp/azureauth-compiler-verifiers-108-0060`. Bind these spellings in the sources,
sole required Import overlay, DATA, source manifest, materialization plan, support
paths, authority and literal. The paired action is 0060, helper marker schema is
`compiler-0060-verifiers-start-v1`, and unique service names begin
`azureauth-compiler-0060-`. Creation remains exclusive; retain all partial state.
Keep every tracked execution gate disabled. Independently accept exact activation,
materialization and its original outcome before admitting the diagnostic.

Preserve the 33 product blobs, original restore bytes, selected product commit/tree,
SDK/runtime/package and installed-helper pins, compiler controls, Windows guard/Job
Object, physical predicates and stop before ILC/linker execution. The same-length
Import-path substitution changes no product or project-reference semantics. The
original indented 211,842-byte handoff, its exact hash and semantic checks, fixed
historical reads and paired counters remain unchanged.

Compiler-mode action lists must equal 0001–0056 before reservation and 0001–0056
plus 0060 after original completion. Any 0057, 0058 or 0059 entry, extra entry,
missing entry or unmatched pair rejects before its content is read. The second
disposed-0054 checkpoint binds reserved 0060. Preserve disposed-0054/0056 validation
and the shared parent, owner-marker and action-lock requirements. Do not inspect
original 0057/0058/0059 action/helper leaves or old observer roots. Other history
modes remain unchanged.

Add `original0059FailedBuildTest: 1` to the exact `priorCapacity` projection.
Historical paired counters remain 87 build/test and 48 synthetic, including the
fixture once. Original 0057, failed 0058, failed 0059 and the accepted systemd batch
add one build/test unit each; the batch also adds four synthetic units. Prior global
occupancy is 91/120 and 52/80. The helper-root first-start marker binds these totals
and charges this same diagnostic if paired reservation is never reached; paired
reservation does not charge it twice. The new unit produces at most 92/120 and
52/80. Transfer one prospective unit from Linux ceiling 76 to 75 and aggregate
Windows ceiling 52 to 53; ordinary Windows capacity stays exhausted at 48. Preserve
all other preparation/publication/download limits, the twelve protected final CLI
cases and sixteen unallocated synthetic cases. Failed start consumes this sole
invocation; no retry, separate startup scenario or refund is granted.

### Corrected Timer and Queued-Work Retention

Use the accepted `JobRunningTimeoutSec=2s` correction and initial absolute-deadline
check, not the failed original's `JobTimeoutSec` setting. Carry the single existing
`latest_exec` integer in bootstrap argv and require equality with the stdin payload.
After importing only `sys` and `time`, an expired bootstrap exits 125 before identity
reads/writes or query-input consumption. Preserve the post-payload and immediate
pre-`execve` checks, 30-second acceptance window, original 900-second dispatcher
clock, pre-spawn reserves, runtime at most 20 seconds, two-second running-job/start/
stop timers, at most eight calls, permanent failure latch and no retries.

The start receipt binds `jobRunningMilliseconds: 2000` and
`queueTimeoutConfigured: false`. Explicitly retain up to eight unique transient
definitions/jobs if still queued. There is no queue-residence deadline. A late
bootstrap may undergo ordinary executable/interpreter startup, but rejects expired
query work before query-specific effects. This bounded-count retention is neither
zero future effects nor unconditional wall-clock termination. Preserve independent
manager supervision, all original success evidence and stop conditions; new actual
ownership or termination uncertainty stops further work. No manager command,
cleanup, installation, host upgrade or broader risk exception is authorized.

All remaining helper I/O, 32 KiB provisional result slots, stderr completeness
fields, nullable `groupEmpty`, fixed query order and finite source bounds are
unchanged. Require refreshed source, DATA, runtime, history, capacity, authority,
materialization, review-role and exact-literal admission against the accepted
protocol/Wave. Accept original tool completion independently before interpreting
receipts. Success supplies only bounded compiler/native-input evidence; final AOT
publication, artifact validation and CLI scenarios retain separate admissions.

### Conditional Fixed 0060 Failure-Receipt Collection

Only after independent acceptance of the original 0060 tool outcome as failed,
permit one separately admitted fixed receipt collection. Inherit all finite limits,
28 fixed roles, file/parent/lock identity checks, no-follow traversal, sealed copies,
original completion and interpretation requirements of the conditional 0059
collection above. Retain 92/120 build/test and 52/80 synthetic consumption; this
read-only collection adds no subject execution or separate scenario charge.

Derive the captured inline source directly from the unchanged 19,604-byte inactive
0058 collector template with SHA-256
`0274f8f0e0d08d5cf26af73f506815bdc30ff1f362fdb185ca7f5f5970eb070d`.
Apply the preceding collection's five exact transformations, except replace the
ten ASCII `0058` occurrences with `0060` and bind the unique `TRANSPORT` assignment
to the independently accepted original 0060 transport's byte count and SHA-256.
The helper-result limit remains 32,768 bytes and the same finite `LIMITS` assignment
applies. Independently bind reverse recovery, decoded AST, exact source/runtime,
accepted target, original failed transport and invocation before execution. Activate
only the captured inline literal; create no active source file or writer invocation.

The selected roots are only action 0060 and helper root 0060. Create only
`/tmp/windows-compiler-0060-failure-offline-root-v1`, exclusively, with the existing
at-most-29-file bound. The admission input is
`/tmp/windows-compiler-0060-failure-recovery-admission-root-v1.json`, at most 16,384
bytes. Preserve all partial output; never reuse a consumed collector or inspect an
old action/helper root. The existing 90-second source deadline, 95-second external
timeout, two-second KILL grace and at-most-60-second same-session waits remain.
An unresolved or successful original invocation makes this collection ineligible.
Any failed start, timeout, cancellation or incomplete collection consumes it. No
retry, process/cgroup query, manager operation, Windows-root access, network call,
account access, installation or cleanup is included. Snapshot absence and copied
provisional receipts establish neither termination nor quiescence and cannot lift
a dependent gate or authorize another diagnostic.

## Fixed Compiler and Task-Host Metadata Copy

This supplement permits preparation of one separately admitted raw-data copy,
METADATA12, for the remaining finite compiler-extension selection and NET task-host
configuration inputs of the compile-through native-input diagnostic. Reuse the
accepted SDK19, HOST14, restore, compiler and public-source evidence within their
scopes. Those consumed operations cannot be replayed. This copy has ten required
content slots and two conditional presence/content slots. It does not establish
current compiler selection, a successful task-host launch, complete dependency closure,
Native AOT publication or Slice acceptance.

Use the existing WSL Linux review environment and public Windows SDK 10.0.401/runtime
10.0.12 installation and dedicated public-package location. Selected DLL/EXE bytes
remain inert data: do not load, invoke or execute them. This operation performs no
Windows invocation, network request, dependency download, installation, SDK/MSBuild
evaluation, restore, build, test, compilation, publish, product execution, account
enumeration, token acquisition, WAM, UI, consent or authentication-cache operation.
It does not materialize diagnostic/product source or rewrite restore inputs.

### Twelve Literal Slots

The inactive collector fixes the corresponding twelve `/mnt/c/` paths and flat output
labels. Accept no argument-supplied path, wildcard, directory enumeration, recursive
walk, alternate SDK or metadata-directed follow-up. Existing identity evidence for
FrameworkList.xml and ILLink.Tasks.deps.json supplies exact initial length/hash
predicates, not their missing contents. All other present slots receive one initial
observed length/hash, then require its exact continuity and raw-copy readback. A first
capture is not independent public provenance or installed-source correspondence.

| Slot | Exact Windows path | Outcome required | Maximum bytes |
| --- | --- | --- | ---: |
| pack-01 | `C:\Program Files\dotnet\packs\Microsoft.NETCore.App.Ref\10.0.12\data\FrameworkList.xml` | Required content | 36,320 |
| task-01 | `C:\Temp\azureauth-windows-slice-108\packages\microsoft.net.illink.tasks\10.0.12\tools\net\ILLink.Tasks.deps.json` | Required content | 2,451 |
| msbuild-01 | `C:\Program Files\dotnet\sdk\10.0.401\MSBuild.runtimeconfig.json` | Required content | 65,536 |
| msbuild-02 | `C:\Program Files\dotnet\sdk\10.0.401\MSBuild.deps.json` | Required content | 1,048,576 |
| analyzer-01 | `C:\Program Files\dotnet\sdk\10.0.401\Sdks\Microsoft.NET.Sdk\analyzers\Microsoft.CodeAnalysis.NetAnalyzers.dll` | Required content | 16,777,216 |
| analyzer-02 | `C:\Program Files\dotnet\sdk\10.0.401\Sdks\Microsoft.NET.Sdk\analyzers\Microsoft.CodeAnalysis.CSharp.NetAnalyzers.dll` | Required content | 16,777,216 |
| msbuild-03 | `C:\Program Files\dotnet\sdk\10.0.401\MSBuild.exe` | Content or exact leaf absence | 1,048,576 |
| msbuild-04 | `C:\Program Files\dotnet\sdk\10.0.401\MSBuild.runtimeconfig.dev.json` | Content or exact leaf absence | 65,536 |
| config-01 | `C:\Program Files\dotnet\sdk\10.0.401\Sdks\Microsoft.NET.Sdk\analyzers\build\Microsoft.CodeAnalysis.NetAnalyzers.props` | Required content | 1,048,576 |
| config-02 | `C:\Program Files\dotnet\sdk\10.0.401\Sdks\Microsoft.NET.Sdk\analyzers\build\Microsoft.CodeAnalysis.NetAnalyzers.targets` | Required content | 1,048,576 |
| config-03 | `C:\Program Files\dotnet\sdk\10.0.401\Sdks\Microsoft.NET.Sdk\codestyle\cs\build\Microsoft.CodeAnalysis.CSharp.CodeStyle.targets` | Required content | 1,048,576 |
| config-04 | `C:\Program Files\dotnet\sdk\10.0.401\Sdks\Microsoft.NET.Sdk\analyzers\build\config\analysislevel_10_default.globalconfig` | Required content | 1,048,576 |

The first two required slots must have their exact listed lengths and these hashes on
the initial read:

| Slot | Historical SHA-256 |
| --- | --- |
| pack-01 | `51955f4e8836b9d4ba57d32c0f0d0b865666bc918d6494a45d80dc65737be35b` |
| task-01 | `518f0256eb3699c88d7c798cbb1f8cfd42845754f4cba8726b499a25d20da6eb` |

For either optional slot, accept absence only at the exact leaf under an existing
no-follow directory chain. Missing parents, inaccessible paths, symlinks, nonregular
leaves and other errors fail the invocation. Recheck each initially absent leaf once
after copying under its unchanged parent identity. Presence or identity change fails;
never create a placeholder or discover an alternate path. These are bounded absence
observations, not an atomic or continuing filesystem guarantee. Present optional
files receive the same stable content checks as required files.

FrameworkList supplies pack analyzer metadata; the two SDK analyzer copies supply
missing selected-candidate identities. They do not by themselves prove the eventual
ordered Csc analyzer vector. ILLink's component dependency manifest and the separate
MSBuild application configuration/manifests supply task-host resolution inputs.
MSBuild.exe and its development config are conditional startup discriminators. Their
presence does not automatically admit an apphost or additional probing path. A present
apphost requires separately accepted offline target/bundle/root interpretation before
that branch is selected. An absent branch may retain the original diagnostic's exact
physical-absence predicates. Do not recollect Csc, acquire ILLink.Tasks.dll, or replace
the accepted task-runtime source inference with a broader binary inventory.

The three analyzer declaration files bind the generated imports' actual bytes before
joining their property/item producers to the prospective compiler contexts. The
pinned SDK
[NetAnalyzers configuration generator](https://github.com/dotnet/sdk/blob/32593ca81f8aae7b0d41c1a7198529c3365106b8/src/Microsoft.CodeAnalysis.NetAnalyzers/tools/GenerateDocumentationAndConfigFiles/Program.cs#L1387-L1480)
emits the default selection formula: effective level 10.0 becomes rules version 10,
with Default mode and no true CodeAnalysisTreatWarningsAsErrors value selecting
analysislevel_10_default.globalconfig. Product TreatWarningsAsErrors does not itself
set CodeAnalysisTreatWarningsAsErrors. This source inference motivates config-04;
actual generated-declaration correspondence and selection remain separate gates.
The selected configuration is a pre-existing SDK input, not a file newly generated by
0057. Its descriptor is required before compiler use; no blanket audit of rule-severity
contents is required. No alternate/category/CodeStyle configuration content slot is
admitted by this copy. An unexpected later selector fails the proposed branch rather
than authorizing another original read.

### One Invocation and Bounded Raw I/O

METADATA12 has exactly one invocation. Recover current accepted Wave/protocol and prior
dispositions, finish active observer/source operations, and record its start before
launch. Failed start, inactive-source rejection, lock contention, output collision,
content/identity error, interruption, timeout, incomplete transport or nonzero exit
consumes it. No retry, repair, resume, alternate root or expanded selection is allowed.
Existing counters remain Linux [8,37,0,0], Windows [7,49,0,48], combined 87/120 with
the original fixture once, preparation 15/16, publish 0/12 and synthetic 48/60.
This review copy charges no restore/build/test/publish/synthetic action, reserves no
0057 slot and resets no historical capacity.

Retain the SDK19 mechanism for the existing
`/var/tmp/azureauth-windows-slice-108/action.lock`: no-follow traversal, read-only
regular-file open, nonblocking exclusive lock, held/path identity checks before and
after collection, and release/close in finalization. Do not create the lock, read or
write its contents, wait or retry. No concurrent experiment/observer is permitted.
No original-root access beyond this lock and the twelve literal inputs is admitted.

Each logical content read uses exactly one direct `os.read(fd, observed_size + 1)`
after validating the file's size and applicable row bound. Reject a short read,
overflow byte or identity/content change without refill or retry. This applies to
initial originals, their continuity rereads, new raw copies and inventory readback.
Charge requested bytes before the call and returned bytes afterward against separate
cumulative limits, including a rejected call; a logical-read counter alone cannot
bound hidden buffered refill calls. Preserve stable device/inode/length/mtime/ctime,
regular-file and final no-follow leaf identity checks. Original continuity requires
the first-read identity, length, hash and raw-byte equality. Final stdout reports
the enforced path-operation counter after final lock verification and resource
cleanup; the inventory's observedBeforeInventory counters remain preliminary.

| Bound | Maximum |
| --- | ---: |
| Literal input slots / required present files | 12 / 10 |
| Optional leaf observations, including absent rechecks | 4 |
| Aggregate original content | 41,943,040 bytes (40 MiB) |
| Logical content reads / direct content read calls | 37 / 37 |
| Aggregate returned content bytes | 125,894,656 bytes (120 MiB + 64 KiB) |
| Aggregate requested content bytes | 125,894,693 bytes |
| New output bytes, including inventory | 42,008,576 bytes (40 MiB + 64 KiB) |
| Canonical inventory bytes | 65,536 bytes |
| Counted path operations | 4,096 |
| Write chunk | 65,536 bytes |
| Original collector clock | 90,000 milliseconds |
| Outer TERM deadline, including interpreter startup | 95 seconds |
| Nonresetting KILL grace | 2 seconds |
| Complete original combined tool capture retained for acceptance | 16 KiB |

With P present files totaling S bytes and inventory length I, successful completion
uses `3 * P + 1` direct/logical reads, returns `3 * S + I` bytes, requests
`3 * S + I + 3 * P + 1` bytes and writes `S + I` bytes. Row maxima sum to
40,015,731 bytes. With twelve present slots and the full inventory allowance, maximum
normal returned bytes are 120,112,729, requested bytes 120,112,766 and output bytes
40,081,267, below the conservative ceilings. Missing leaves are not content reads.
These bounds cover intentional collector data/path operations. Ordinary Linux
interpreter, standard-library, ELF loader and watchdog startup retain their separate
runtime review; no system-wide I/O total is claimed.

Keep one monotonic clock starting in main and latched cancellation. Check both before
and after bounded I/O, sync, output validation, resource finalization and final stdout
flush. The watchdog includes startup and cannot make a late source result acceptable.
These controls retain the accepted OS assumptions and do not claim protection from an
uninterruptible kernel/filesystem stall or global process quiescence.

### Source, Output and Exact Admission

Create only `/tmp/windows-compiler-inputs-metadata12-offline-v1`, mode 0700, exclusively
and without following links, after all initial content/absence checks pass. Reject an
existing root. Use only the twelve admitted flat labels and inventory.json; absent
leaves have inventory entries and no raw file. Do not enumerate output. Create each
file exclusively at 0600, write/sync complete bytes, seal 0444, sync again and sync
the held output directory. Preserve its held/final path identity. Read back every
raw copy and the canonical ASCII, sorted-key, compact JSON inventory with one final LF.
Retain complete or partial output and original start/transport evidence on all outcomes.
Never delete, rewrite or accept partial transport as successful collection.

The exact inactive collector, predicted one-toggle activation, procedure and runtime
bindings must receive independent source review before materialization. Preparing
this supplement grants no original-root read or execution. Bind the then-current
accepted protocol and Wave separately from the source's preparation provenance.
The prepared inactive collector is 27,278 bytes with SHA-256
`8524388e958898a8a378ebd1c97c548370539656954011b804e26decd7abdcf7`.
Its procedure is 22,440 bytes with SHA-256
`f6480fe7f78542628a454ce75d7e7a50dab5325ed05115dcfbd7f4320d415973`.
Activation may change only `ACTIVE = False` to `ACTIVE = True`, producing the
predicted 27,277 bytes with SHA-256
`0f6401761989c8706d6c09e3ccd893516e18a59eb97840b1638fe1ee908a74ee`
at `/tmp/collect_windows_compiler_inputs_metadata12.accepted.py`. Preparation has
not materialized or executed those predicted bytes.

Use the same reviewed Linux bash, GNU watchdog and Python 3.14 identities as SDK19,
with fresh identity/startup-context acceptance. The exact literal in the separately
prepared accepted checkout `/tmp/azureauth-windows-compiler-inputs-metadata-accepted-108`
uses nonlogin `/usr/bin/bash`, no TTY, pipeline or status wrapper, and complete original
capture:

```sh
exec /usr/bin/gnutimeout --signal=TERM --kill-after=2s 95s /usr/bin/python3.14 -I -B -S /tmp/collect_windows_compiler_inputs_metadata12.accepted.py
```

Require isolated, no-bytecode, no-site, nonoptimized Python and the accepted
shell/loader/startup-injection boundary. Do not substitute another timeout program,
add `--foreground` or `--preserve-status`, inject code or execute candidate modules
for testing. Independently accept exact source, runtime, literal, cwd, output and
one-time capacity before any execution-oriented parsing, import, materialization or
launch. No owner input or desktop attendance is selected.

Independently accept the original normal zero exit, complete transport, exact copy and
inventory bytes, optional classifications, all finite counters, continuity and
finalization before using the raw outcome. Subsequent JSON/XML or optional PE
interpretation requires its own exact offline source/input/lifetime admission and
must not follow metadata into new originals. Keep graphAccepted, artifactAccepted,
continuation_allowed and new SDK provenance/historical-continuity claims false.
The separately admitted 0057 action still requires its finite prospective selection,
effects, physical inputs, history, guard and literal bindings; only its own current
checks can establish physical predicates at execution. Its successful original
Csc/response/native evidence remains a result obligation, not a prerequisite requiring
that diagnostic to have already succeeded.

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

A later complete final caller must check the same original deadline and latched
cancellation after durable final receipt persistence and relevant context
finalization, before normal return. A late or cancelled original invocation fails
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
| dispatcher | [`run_windows_final_guard_prepare.py`](../../../tools/validation/run_windows_final_guard_prepare.py) | `419ef046bddea192a9b63fd4e9da705265b7c2556de94bf477505ad79f9ce4c4` |
| controller | [`Invoke-WindowsFinalGuardPrepare.ps1`](../../../tools/validation/Invoke-WindowsFinalGuardPrepare.ps1) | `ea93b4eecfea6eed623a3149b648e93686db4f8bafa81561ff28ad0379e4ebae` |
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

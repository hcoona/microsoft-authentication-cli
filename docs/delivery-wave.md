# Current Delivery Wave

This record is the sole positive work-authorization authority. An entry is authorized
only as accepted on `main-v2`. An Issue, Milestone, branch, pull request, comment, label,
or unmerged edit cannot add to or enlarge this record.

Adding or changing an entry through merge grants or changes its bounded authorization.
Deleting an entry through merge ends that authorization. Git and the proposing pull
request retain the reason and history; this record contains no progress or historical
status.

Preparing and reviewing an explicitly repository-owner-approved pull request whose sole
substantive purpose is to change this record is permitted without an existing entry. The
proposal does not authorize any work it would add before merge.

## Authorized Advancements

### Windows Native AOT Implementation Readiness

**Accepted inputs:** [V2-REQ-055](product/requirements/quality-build-and-validation.md#v2-req-055-native-aot-publishing),
the [Windows Slice design](designs/windows-ado-authentication.md), its
[protocol schemas](../contracts/v1/request.schema.json), the
[public dependency assessment](research/v1-public-contract-baseline.md#windows-native-aot-assessment),
the [accepted original observations](research/experiments/windows-native-aot.md#retained-native-artifact-runtime-results)
and [stopped readiness supplement](research/experiments/windows-native-aot.md#readiness-results),
the [validation basis](validation/strategy.md#native-aot-publishing), and
[experiment safety](research/experiment-safety.md). The repository owner directed
completion of the remaining AOT evidence and publishing design, stopping before
implementation of the minimal Windows CLI.

**Bounded advancement and outcome:** Resolve the remaining preimplementation Native
AOT compatibility questions for the existing .NET 10, Windows x64, small Win32 host
design and unchanged MSAL/Broker 4.83.1 and NativeInterop 0.20.3 pins. Use public source
and API evidence first. Independently accept an amendment to the existing synthetic
protocol and narrowly scoped probe/controller changes before new execution. Supplement
the successful allocation/loading/search evidence with retained publish diagnostics,
an explicit AOT/trim-warning and native-dependency disposition, native cleanup evidence,
and wrong-architecture rejection. Preserve the original thirteen attempts, all exhausted
limits, artifacts, and attempt 10's unknown stop origin and missing historical warnings.
New evidence must not retrospectively change that history or claim a clean public restore
from reused packages.

Authorize the distinct [readiness recovery](research/experiments/windows-native-aot.md#readiness-recovery)
using a new dedicated root; neither earlier sequence may resume. Preserve all prior
attempts, the supplemental stop, missing diagnostics, artifact identities and consumed
capacity. The recovery may use at most one local-feed restore (180 seconds), one Native
AOT publish (600 seconds), four synthetic runtimes (30 seconds each), and six standalone
guard compilations (30 seconds each). Together with the accepted stopped supplement,
maxima remain two restores, two publishes, four runtimes and eight guards. Reserve every
attempt before starting it, including failed starts. No protocol revision resets totals.

The independently accepted exact recovery may charge a two-second normal Job drain
window to the existing action limit, with at most 100 milliseconds of scheduling tolerance.
It may disable debug-symbol generation for the synthetic probe while preserving its
rooted provider surface, AOT/trim diagnostics, and strict zero-process normal completion.
It may not accept or terminate a surviving helper as expected successful completion.
Failed termination, incomplete/suppressed output, unexpected effects or a new safety
stop end recovery. This prospective rule does not reclassify either historical stop or
permit unreviewed retries. Retain screened diagnostics after owned termination on
completed-capture failure paths, preserving failure and stop evidence.

Reuse only hash-verified public archives from the original experiment. No new package,
SDK, compiler, debugger or tool installation is authorized. The exact protocol bounds
source/artifact provenance, replacement environments, diagnostic capture, process identity,
controller/emergency termination, cumulative effects and sequential continuation.

Accept the resulting observations and reviewed dependency/diagnostic conclusions in the
existing research authority, then update the existing Windows design and validation
consumers atomically where their premises change. Select Native AOT for the designed
target only when the preimplementation premise is supported; do not substitute a
non-AOT exception, suppress warnings broadly, or weaken requirements. Review and render
the affected standard UML/C4 views. Keep later complete-application, WAM/UI, account,
Profile, performance, release, and support validation distinct from design readiness.
Coordinate this multi-PR advancement through
[Issue #92](https://github.com/hcoona/microsoft-authentication-cli/issues/92); it is not
an authorization source.
Remove this grant after acceptance of the bounded design outcome. An unresolved
compatibility blocker remains explicit and requires owner disposition rather than a
fabricated readiness claim.

**Permitted external effects and owner disposition:** The owner's continuation request
covers public documentation/source reads, read-only inspection of the designated WSL 2
Linux x64 and existing Windows 11 x64 host and retained public experiment artifacts,
and use of the already pinned Windows SDK/native compiler and PowerShell process guard.
Permit dedicated source/feed/cache/build/case files and sanitized receipts under
`C:\Temp\azureauth-native-aot-readiness-recovery`; both prior roots remain read-only. Permit bounded configuration allocation/release
and native-loader tests in owned Windows child processes through WSL. This intentionally
retains experiment-owned files on the existing host; no authentication or credential
state is used. Preserve replacement child environments, telemetry controls, process
ownership, bounded termination, and evidence screening. No host-wide process discovery,
command-line/environment/token inspection, or termination of shared servers is permitted.
Executions within this accepted
entry and its exact accepted protocol require no repeated owner approval.

**Exclusions:** Product CLI or library implementation, product MSBuild scaffolding,
account discovery, token acquisition, WAM/session/cache operations, authentication or
consent UI, credential-store access, resource requests, private dependencies/source,
network telemetry, registry/firewall or unrelated installation changes, shared broker
termination, historical experiment replay or cleanup, Profile activation/distribution,
packaging/release, support promises, performance experiments, and governance-policy
changes. Stop before implementing the minimal Windows CLI.

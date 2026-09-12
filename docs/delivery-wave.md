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
the [accepted synthetic observations](research/experiments/windows-native-aot.md#retained-native-artifact-runtime-results),
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

The amendment may add, cumulatively, at most two local-feed restore attempts, two Native
AOT publish attempts, four synthetic runtime attempts, and eight standalone guard
compilations. Reserve every attempted action before starting it, including failed starts.
Use a separate dedicated experiment directory; do not reset or mutate the original root.
Each restore is limited to 180 seconds, each publish to 600 seconds, each synthetic
runtime to 30 seconds, and each guard compilation to 30 seconds. The exact accepted
protocol must additionally bound controller termination, diagnostic capture, total
effects, artifact provenance, and sequential continuation. A safety stop or unproved
quiescence ends execution; an unused limit is not authority to retry that stop.
Reuse only hash-verified public archives from the accepted experiment, copied into the
new dedicated feed. No new package, SDK, compiler, debugger, or tool installation is
authorized. Ordinary source/documentation reads are not package acquisition.

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
`C:\Temp\azureauth-native-aot-readiness`, and bounded configuration allocation/release
and native-loader tests in owned Windows child processes through WSL. This intentionally
retains experiment-owned files on the existing host; no authentication or credential
state is used. Preserve replacement child environments, telemetry controls, process
ownership, bounded termination, and evidence screening. Executions within this accepted
entry and its exact accepted protocol require no repeated owner approval.

**Exclusions:** Product CLI or library implementation, product MSBuild scaffolding,
account discovery, token acquisition, WAM/session/cache operations, authentication or
consent UI, credential-store access, resource requests, private dependencies/source,
network telemetry, registry/firewall or unrelated installation changes, shared broker
termination, historical experiment replay or cleanup, Profile activation/distribution,
packaging/release, support promises, performance experiments, and governance-policy
changes. Stop before implementing the minimal Windows CLI.

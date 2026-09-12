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

### Windows Native AOT Synthetic Compatibility Experiment

**Accepted inputs:** [V2-REQ-055](product/requirements/quality-build-and-validation.md#v2-req-055-native-aot-publishing),
the [Windows Native AOT candidate](designs/windows-ado-authentication.md#native-aot-target-disposition),
the [public dependency assessment](research/v1-public-contract-baseline.md#windows-native-aot-assessment),
the [validation strategy](validation/strategy.md), and the
[experiment policy](research/experiment-safety.md). The repository owner requested an
experiment to resolve the remaining publishing and loading uncertainty.
[Issue #76](https://github.com/hcoona/microsoft-authentication-cli/issues/76) coordinates
the protocol, execution, and evidence changes without granting authorization.

**Bounded advancement and outcome:** Prepare and independently review an exact synthetic
experiment protocol and minimal probe, accept them on `main-v2`, then execute the bounded
Windows x64 .NET 10 restore, Native AOT publish, and native-loading investigation. Retain
SDK 10.0.401, runtime 10.0.12, MSAL and Broker 4.83.1, NativeInterop 0.20.3,
`net10.0-windows`, and `win-x64` as the initial subject. Pin the existing Windows compiler,
linker, Windows SDK, public package closure, source, and publish properties in the
protocol before execution. Use a separate probe; preserve the historical .NET 8 probe
and its exhausted execution limits.

Determine whether the upstream managed/native loading path works under Native AOT with
DLL search restricted to the application directory and System32. Include finite positive
and missing-library/search-path negative cases where they can execute without account or
broker-session operations. Public source and artifact inspection may identify the exact
loading entry point and establish whether it can be exercised inside this boundary.
If the upstream path cannot be safely separated from authentication state or telemetry,
record that limit rather than invoking it. A raw OS DLL-load result alone cannot establish
upstream-loader compatibility.

Record sanitized observations, consumed capacity, artifact identities, warnings, precise
blockers, and untested behavior. Investigate supported source-level remedies or public
dependency/host alternatives for a demonstrated blocker; execution of changed subjects
requires an accepted exact protocol amendment within the same cumulative limits. Update
the canonical research, Windows design, and validation obligations together where the
evidence changes a premise. A synthetic success does not establish actual WAM, account,
UI, cancellation, or production support. Keep any remaining publishing gap explicit;
no non-AOT exception is granted. Completion is an accepted bounded conclusion, including
an evidenced blocker if the permitted investigation cannot resolve compatibility.

**Permitted external effects:** Public documentation, source, and NuGet downloads;
read-only inventory and use of the existing owner-designated Windows host's .NET 10,
Visual Studio C++ tools, and Windows SDK through WSL interoperability; dedicated probe
source copies, package caches, build outputs, sanitized logs, and local attempt records;
child-process restore/publish and synthetic execution within exact protocol time and
attempt limits. Downloads use public sources without inherited package credentials.
Disable documented tool telemetry and first-run installation effects. Retain only
identified experiment-owned files for reproducibility; no machine-wide installation or
configuration changes. The protocol must bound owned processes, cross-host termination,
network operations, and cleanup. Every covered execution still requires the accepted
protocol and current grant; repeated executions inside both require no new owner approval.

**Exclusions:** Real account discovery, token acquisition, WAM/session/cache operations,
authentication or consent UI, credential-store access, resource requests, private feeds or
source, global tool/compiler installation, registry or firewall changes, shared broker
termination, historical experiment replay, product implementation, Profile activation,
release or packaging, support claims, and changes to experiment authorization policy.
New record routing needed for this exact protocol must receive the existing governance
review; this entry does not waive it.

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

### Windows Native AOT Restore Diagnosis and Synthetic Continuation

**Accepted inputs:** [V2-REQ-055](product/requirements/quality-build-and-validation.md#v2-req-055-native-aot-publishing),
the [Windows target disposition](designs/windows-ado-authentication.md#native-aot-target-disposition),
the [public dependency assessment](research/v1-public-contract-baseline.md#windows-native-aot-assessment),
the [existing experiment and observations](research/experiments/windows-native-aot.md),
the [validation strategy](validation/strategy.md#native-aot-publishing), and the
[experiment policy](research/experiment-safety.md). The repository owner requested
continued diagnosis of the unresolved restore failure.
[Issue #76](https://github.com/hcoona/microsoft-authentication-cli/issues/76) coordinates
this continuation without granting authorization.

**Bounded advancement and outcome:** Amend and independently accept the exact existing
protocol and controller to retain useful, bounded, sanitized SDK diagnostics. First
repeat the same restore subject with corrected diagnostic retention. Identify the
failing component and distinguish package availability, network/access, command,
configuration, and toolchain/environment causes from evidence. Do not infer a cause
from output length or missing diagnostic codes.

Investigate and apply minimal evidenced remedies within the existing Windows x64
.NET 10 subject and effects boundary. Retain SDK 10.0.401, runtime 10.0.12, MSAL and
Broker 4.83.1, NativeInterop 0.20.3, `net10.0-windows`, and `win-x64`. Changed commands,
environment, dependency closure, or executable source require an independently accepted
exact protocol amendment before execution. Public source/artifact inspection and
read-only existing toolchain inventory may establish the remedy. No speculative retry
without a diagnostic or reviewable reason is authorized.

After successful restore and closure inspection, continue the existing Native AOT
publish and upstream configuration-allocation/loading cases. Preserve the original
experiment root, source provenance, and all prior receipts. Extend cumulative restore
capacity from two to six actions; retain the existing two-publish and one-per-case
ceilings. Bound guard compilation to eleven cumulative actions. Permit at most one
additional public-fetch batch, twelve additional exact archives, and 256 MiB of
additional download data, only for an evidenced missing public dependency and after
its exact manifest/protocol is accepted. The amended protocol must bind finite per-action
timeouts, output bounds, and the prior consumption; no amendment resets capacity.

Completion is accepted evidence identifying the restore cause and disposition, followed
by the permitted synthetic result or a precise remaining blocker. An unexplained exit
alone is insufficient while useful authorized diagnostic capacity remains. Update the
canonical experiment, assessment, Windows design, and validation obligations together
where evidence changes their premises. Synthetic success does not establish actual WAM
or production support; no non-AOT exception is granted.

**Permitted external effects:** Public documentation/source reads and the bounded public
package downloads above without inherited credentials; read-only inventory and use of
the existing owner-designated Windows .NET/Visual Studio C++/Windows SDK installations
through WSL interoperability; dedicated source copies, package caches, build outputs,
sanitized diagnostics, and sequential attempt records in the existing experiment root;
bounded child-process restore, publish, and synthetic execution. Preserve documented
telemetry and first-run installation controls, process ownership, termination, and
intentional retention. Do not erase the recorded uncertainty about the first restore's
earlier Windows trust path. Repeated execution within the accepted Wave and exact
protocol needs no additional owner approval.

**Exclusions:** Account discovery, token acquisition, WAM/session/cache operations,
authentication or consent UI, credential-store access, resource requests, private feeds
or source, global installation, registry/firewall or unrelated host changes, shared
broker termination, replay of other historical experiments, product implementation,
Profile activation, release/packaging, support claims, and experiment-policy changes.

# Experiment Safety Protocol

## Scope

This policy applies before running an upstream or v2 authentication binary, restore,
build, cache, installer, or migration experiment.

Experiments may use repository-owner-designated existing machines and authorized account
state. They must keep effects within the accepted experiment boundary, protect unrelated
state, and publish only sanitized evidence. Disposable accounts, operating-system users,
VMs, and a fresh-state environment are not general prerequisites.

The historical [Issue #1 public-build record](#phase-1-public-build-record) retains its
specific isolation, execution, and evidence rules. The general policy below does not
relax those rules or authorize replay of that experiment.

## Experiment Authorization

Before any experiment covered by this policy runs:

- the target branch's accepted Delivery Wave entry must authorize the
  decision-relevant question, environment, maximum external effects, and bounded
  outcome;
- a Git-tracked protocol defining the exact subject, source and dependency versions,
  environment and account-state boundaries, expected observations and interaction,
  evidence limits, finite attempt/time/cumulative-effect bounds, stop conditions, and
  cleanup or intentional retention must be independently reviewed and accepted on
  `main-v2`;
- execution and preflight must bind the exact accepted protocol revision; and
- every applicable contextual review and mechanical precondition must be satisfied.

The Delivery Wave entry must include an explicit repository-owner risk decision before
first crossing or expanding a boundary involving non-disposable identities or tenants,
credential-bearing state, persistent host, account, cache, or installation state,
remote mutation, or another material external effect. No separate owner approval is
required for each execution that remains within the accepted entry and protocol.

An accepted protocol may permit repeated executions only within its finite bounds. Count
manual and automated attempts, including failed starts and interrupted runs. Before each
attempt, recover prior consumption from retained sanitized execution evidence and record
that the attempt has started before invoking the subject. A protocol involving persistent
state or cumulative external effects must define measurable units and prohibit concurrent
execution unless it defines safe capacity reservation. A simple sequential attempt record
is sufficient; a general runner or reservation service is not required.

Protocol revisions and machine switches do not reset consumed capacity. Record prior
attempts and remaining limits, and fail closed when remaining capacity cannot be
established. Deleting or narrowing the Delivery Wave entry ends or narrows authority for
subsequent execution.

An Issue, Milestone, branch, pull request, comment, protocol, or unmerged Delivery Wave
change cannot grant experiment authority. Non-executing planning and review must not
invoke the binary or tool under study, resolve dependencies, access a credential or
account store, or create another planned side effect.

## Environment and Effects

### Source and Build

- Pin source-built subjects to a recorded commit in a detached checkout; record the
  dependency versions and any probe changes. For a released binary, record its public
  provenance, version, and artifact identity.
- A claim that public restore works requires an empty package cache and no inherited
  package-source credentials. Do not use a cached private package to support that claim.
- For other experiment preparation, declare public dependency sources, existing cache
  use, toolchain and artifact locations, and their evidence limits in the protocol.
  Do not silently use ambient credentials or infer a clean restore from a warm cache.
- Keep build output and experiment package caches outside production install paths.
- Record publicly reviewable nonpublic-dependency blockers without accessing private
  feeds, packages, service connections, or signing identities.

### User and Credential State

- The protocol identifies the owner-designated machine, host/session, selected account
  roles, relevant existing state, and permitted observations and updates. Public records
  use sanitized roles and state descriptions, not account, tenant, or machine identifiers.
  The operator supplies actual account selectors locally without putting them in logs or
  committed records.
- Existing OS accounts, broker sessions, and secure caches may be used when the accepted
  Wave and protocol cover that state and its ordinary authentication updates. Describe
  relevant initial state and what is unknown; do not assume an existing environment is
  clean or clear unrelated state to simulate first use.
- Use documented account and authentication APIs. A protocol may permit in-memory
  account enumeration needed for selection, while prohibiting acquisition as an
  unrelated account. Do not dump broker contents or copy refresh-token caches into the
  repository, agent traces, or session artifacts.
- Application-owned experiment files should have dedicated locations. That separation
  does not isolate an OS broker or change its account scope. Declare any intentional
  access to an existing application cache, keychain, keyring, registry value, or
  installation, including whether access is read-only or allows normal authentication
  updates. Never modify an unrelated store or installation.
- Native and cross-host execution must identify both the initiating environment and the
  host that owns the account state and interaction. WSL invocation of a Windows helper
  requires explicit protocol coverage of the Windows-side broker, storage, transport,
  UI, and termination boundaries and the applicable rechecks.
- The owner may operate steps or switch among protocol-covered machines. A machine,
  account-state context, or effects boundary outside that coverage requires protocol
  amendment and, if it expands the Wave's effects, a new accepted owner decision.

### Interaction and Telemetry

- Disable upstream-product and experiment-tool telemetry through documented controls.
  Issue #1 commands set `DOTNET_CLI_TELEMETRY_OPTOUT=1`.
- Disable .NET first-run development-certificate generation, global-tool PATH
  registration, and workload-advertising downloads for Issue #1 commands.
- When the behavior of a telemetry switch is under test, isolate network access and
  record only sanitized endpoint and field observations.
- Record the expected interactive surface before execution. Keep sign-in, account
  choice, user consent, and any state-unlock interaction under operator control.
- Ensure the operator can identify and close prompts created by the test. Authentication
  secrets and device codes may appear only on the intended operator surface, not in
  captured output, agent traces, screenshots, or committed evidence.
- Require operator attendance when an accepted action needs human input, a choice,
  or state unlock. Finish preparation and verify the actual
  waiting action before requesting a fresh readiness response. Do not run those
  actions in CI or unattended sessions. Manual assistance must use the accepted
  procedure and counts toward the same attempt limits.
- Fully automated, credential-free synthetic window tests do not require operator
  attendance solely because a window is visible. Their accepted protocol and exact
  admission must cover the automation, owned surfaces, required observations, and
  bounded termination on the designated host/session. Keep sign-in, account choice,
  consent, and state unlock under operator control. Unexpected human interaction
  follows the protocol's stop procedure; it is not permission to automate it.
- Do not request desktop attendance solely to watch automated work. Use admitted
  automation for observations; if it cannot establish a required observation,
  leave that claim unvalidated until suitable evidence is admitted.

### Network and Resource Effects

- Declare identity endpoints, client registration, authority class, scopes, and any
  read-only resource probe. Bound required public dependency downloads separately.
- Prefer token acquisition and read-only resource probes. Ordinary authentication may
  update the selected account's sessions and secure reusable state when authorized.
- Do not create, delete, push, publish, revoke, or mutate remote resources unless that
  side effect is the explicit subject and lies within the accepted Wave and protocol.
- Do not create PATs as an incidental fallback or automate administrator consent.
- Bound every operation with a documented timeout and termination procedure.

### Termination and Retention

The protocol identifies experiment-controlled processes, listeners, prompts, and files,
and how to stop or retain them. Rely on documented process, broker, and storage contracts
within the workstation threat model. Do not require proof of all internal OS or provider
activity, terminate a shared broker, or repair unrelated account state.

On timeout or cancellation, end the attempt and terminate experiment-controlled work
using the declared bounded procedure. Further attempts require that the protocol's stop
conditions permit continuation and its remaining capacity is known. An unexpected effect
stops further attempts. Record any uncertainty; if safe termination or file ownership
cannot be established, preserve the affected state and do not perform speculative cleanup
or continue the experiment.

This exception addresses only the unresolved lifetime of the preceding immutable
Git verification helpers and possible descendants from original Issue #108
invocation 0057. With the accepted Wave risk decision and applicable independently
accepted exact protocols, that historical uncertainty alone need not block
credential-free Windows Slice validation within the scope and ceilings accepted
with that decision. The original attempt remains failed and stopped. This
exception does not establish termination, authorize old-process cleanup or weaken
future work's ownership, termination, evidence or capacity requirements. It does
not apply to other unknown processes or historical Issue #1. The exception ends
when that Wave grant closes; it does not transfer to a successor grant. The finite renewed credential-free capacity and the separately stated
retained-launcher and supplemental managed/caller allocations below are its explicit
extensions beyond the original ceilings and effects. Other later boundary changes do not
automatically expand it.
All new ownership or termination uncertainty
retains the ordinary stop conditions.

Separately, the accepted Wave risk decision for original Issue #108 Windows
final publication 0064 permits credential-free Windows Slice validation despite
the unresolved identity and later lifetime of that original Job's remaining
process. Apply only that decision's existing environments, effects and cumulative
ceilings, after the corresponding independently accepted protocol amendment.
Preserve the original failure, charge and evidence. This exception establishes
neither termination nor artifact acceptance and permits no old-process cleanup,
automatic retry or capacity refund. It ends with that Wave grant and cannot
transfer to a successor grant. The finite renewed credential-free capacity and the separately stated
retained-launcher and supplemental managed/caller allocations below are its explicit
extensions beyond the original ceilings and effects. Other later boundary changes do not
automatically expand it. It does not cover other unknown processes. Future
publication supervision must meet the Wave's named-Job requirement and the exact
protocol's identity, audit and authorized-operation rules before execution;
all new ownership or termination uncertainty retains the ordinary stop conditions.

The current Wave's renewed credential-free capacity expressly extends the
original 0057, 0064 and 0068 dispositions to that finite allocation's cumulative
ceilings of 28/130/30/180,
on the same hosts and within the same credential-free effects. Accept the Wave,
this policy and the corresponding Windows protocol allocation together. Preserve
original failures, charges and evidence; require ordinary exact source, artifact,
protocol and call admission for each new action. This extension does not permit
old-process cleanup, infer termination, authorize automatic retries, excuse new
uncertainty or transfer to another grant. The Wave's future real-effects capacity
reservation does not extend these exceptions to private identities, credentials,
account/cache/consent effects or real WAM interaction. Those effects retain their
separate concrete owner risk decision and exact protocol requirements.

Separately, the accepted Wave decision for original Issue #108 named-Job fixture
0068 permits continued credential-free Windows Slice validation despite the
unresolved lifetime of its controller or experiment-controlled descendants and
their possible interference. Apply only that decision's existing hosts, effects
and fixed cumulative ceilings, after the matching protocol amendment is accepted.
Preserve the original failure, full charge and both spent file observations.
This exception supplies no termination evidence, old-state scan or cleanup,
original replay or recovery, quota increase or refund, or fixture/artifact
acceptance. It ends with the current grant and cannot transfer to a successor
or automatically expand with later quota or effects changes. Only the current Wave's renewed credential-free capacity and its separately stated
retained-launcher and supplemental managed/caller allocations expressly extend its
prior ceiling and exact effects.
The 0057 and 0064
exceptions remain separate. Require corrected creation-time controller
containment, bounded startup/failure diagnostics and named, auditable, operable
Windows Jobs before another fixture launch, with ordinary independent exact
source, artifact, protocol and call admissions. All new ownership or termination
uncertainty retains the ordinary stop conditions. This exception does not cover
account or credential effects, real WAM interaction, installation or release.

Separately, the accepted Wave decision for original Issue #108 final publication
0093 permits continued credential-free Windows Slice validation despite the
unresolved launch state and lifetime of its associated WSL or Windows processes
and descendants, and their possible interference. Apply only to original 0093
on the same hosts within ceilings of 28 preparation, 130 build/test,
30 publication and 180 synthetic actions, after the matching protocol amendment
is accepted. Preserve its failed result, full charge and retained evidence;
this exception establishes neither termination nor publication or artifact
acceptance. It permits no original replay, further observation, process or
shared-service operation, cleanup or refund. New actions retain their ordinary
independent protocol, source, artifact and exact-call admissions. The exception
ends with the current grant, does not transfer or automatically expand, and
does not cover future uncertainty, account effects, installation or release.
Historical 0057/0064/0068 exceptions remain separate.

Separately, the accepted Wave decision for original Issue #108 final publication
0107 permits credential-free Windows Slice validation despite the unresolved
later lifetime of that original invocation's associated WSL or Windows processes
and descendants, and their possible interference. Apply only to original 0107
on the same hosts within ceilings of 28 preparation, 130 build/test,
30 publication and 180 synthetic actions, after the matching protocol amendment
is accepted. Preserve the failed result, full charge and sole spent passive
observation. This exception establishes neither termination nor publication or
artifact acceptance; it permits no replay, further old-state observation,
old-process or shared-service operation, cleanup or refund. The Wave's bootstrap
and controller pre-candidate diagnostic and clock-handoff prerequisites apply
before successor publication;
every new action retains independent finite allocation and exact admission.
This exception ends with the current grant, does not transfer or automatically
expand, and does not cover future uncertainty, account effects, installation
or release. Historical 0057/0064/0068/0093 exceptions remain separate.

Separately, the accepted Wave decision for original Issue #108 final publication
0110 permits one independently admitted Linux-only passive retained-candidate
observation and the existing separately admitted credential-free scenarios despite
possible interference from that invocation's unresolved work. Apply only on the
same hosts within unchanged ceilings 28/130/30/180, after the matching protocol
is accepted. Preserve the failed publication, full charge, spent failure snapshot,
and original success collector's ineligibility. This exception establishes no
historical or current quiescence and does not resume the original interval.

The separate artifact basis must establish the necessary source, dependency,
tool, response, diagnostic, artifact, asset, and symbol/provenance relationships.
Apply the ordinary workstation threat model. Current hashes cannot establish
original clock or held-handle continuity, natural Job drain, or execution of
skipped postconditions. Classify each original obligation against the new limited
claim, with an independent rationale for any unnecessary historical condition;
necessary missing, unstable, or insufficient evidence blocks artifact acceptance.
Risk acceptance cannot supply that evidence. Freeze accepted candidate bytes in
the new snapshot; later materialization and scenario use retain separate admission.

The exact protocol owns the single observation's literal leaves, destination,
source/runtime/call bindings, finite operations, byte and time limits, zero-unit
accounting, and failure retention. A failed or partial start spends it. No retry,
alternate destination, quota increase, automatic fallback publication, recompilation,
original recovery/replay, broader old-state observation, old-process/Job/shared-service
operation, cleanup, refund, account effect, installation, signing, or release is
permitted by this exception. It ends with the current grant and cannot transfer or
expand automatically. Historical exceptions remain separate; every new ownership
or termination uncertainty retains ordinary stop conditions.


The current Wave's retained-launcher allocation explicitly extends the distinct
original Issue #108 0057, 0064, 0068, 0093, 0107 and 0110 historical lifetime and
interference dispositions to credential-free work on the same hosts within
35/141/30/277 and its exact accepted effects. This finite explicit extension is
not an automatic expansion. Preserve failures, charges, spent observations and
`noExperimentLive=false`. It grants no termination claim, old-state survey/cleanup,
replay, refund or real-account effect, ends with the grant and excuses no new
uncertainty.

For that allocation, apply the concrete owner decision to transient unrelated
private command-line, image and user-SID data in the bounded private ETW consumer
and possible persistence of its owned trace session after failed stop/drain or
forced exit. Require fresh ownership, PROCESS|NO_SYSCONFIG selection, finite
buffers/payload/callback/join bounds, no raw unrelated retention and at most eight
session-creation attempts. Actual observation attempts remain sequential, with
independent outcome review before another attempt; residual owned kernel sessions
and buffers may overlap later admitted attempts.

The owner's narrow disposition permits later bounded validation within existing
unused allocations when persistence of an originally owned session or its buffers
is the sole remaining issue. It requires no additional owner risk request solely
for that persistence and supplies no empirical no-business-impact claim. Preserve
original session ownership/identity, failed results, full charges and required
evidence. An independently accepted failure disposition is not successful
calibration or observation evidence. Exact passing-result gates, including complete
consumer drain and zero loss, remain unchanged. Unknown ownership, native-process,
gate, consumer, pending OVERLAPPED or other evidence uncertainty still stops work;
no additional cleanup, repeated stop, elevation, foreign-session operation,
automatic retry or automatic recovery is implied. Process, Job or cgroup exit alone
proves neither trace closure nor direct-native-product termination. The exception
ends with this finite Wave allocation and grants no additional session creation.
Keep the explicit inherited direct Windows relay premise and the distinction
between Linux preclosed stdin and native precreation EOF. Only the separately
bounded fresh public dependency-cache copy and complete-cache offline restore are
included; no account, credential, application or broker cache, WAM or release effect
is granted.

The Wave's supplemental managed/caller allocation separately adds exactly
1/6/0/25 preparation/build-test/publication/synthetic capacity, initially giving aggregate
ceilings 36/147/30/302 with preparation host ceilings 18 Linux and 18 Windows.
It explicitly extends each separate original 0057, 0064, 0068, 0093, 0107 and 0110
lifetime/interference disposition only to that finite increment on the same hosts
and within the same credential-free effects. Preserve every prior failure, charge,
spent observation, protected reservation and unresolved lifetime status. No old
restore/build slot is reopened or transferred; all twelve later-product build/test
planning slots remain protected. The increment supplies no correction buffer,
automatic retry, refund, old-state recovery, quiescence claim or broader exception.

The three added D0/D1/D2 ETW creation attempts raise the aggregate maximum to eleven
without changing the original eight reservations or consumption. Extend the bounded
private-memory/transient-data effects and the sole-owned-session/buffer persistence
disposition above only to these three attempts. Actual observations remain sequential,
with independent outcome review; all other process, ownership, consumer, cancellation,
loss and evidence stop conditions remain. Preserve passing calibration and exact-source
correspondence before a dependent direct observation. No new helper kind, foreign
session operation, repeated stop, cleanup or elevation is permitted.

This finite extension requires the matching owner decision in the accepted Wave and
the independently accepted protocol amendment before execution. Each reserved row still
requires its exact protocol, source/artifact/current-input/checkpoint/call admission
and outcome review; the controlled caller rows cannot execute before their exact
protocol and source/tool integration are accepted. Failed or partial starts consume
their declared attempts. Existing account and external-effects exclusions and future
real-effects gates remain unchanged. The historical dispositions and the ETW exception
end with the current grant and never transfer or expand automatically.

The separate managed and controlled correction pool adds 3/19/0/76, initially giving
aggregate ceilings 39/166/30/378 and preparation host ceilings 18 Linux / 21 Windows.
It provides the missing managed build plus three complete correction cycles' equivalent
capacity, shared only among the exact managed and controlled operations in the protocol.
At most three restores, nineteen build/test originals, 76 synthetic units and nine
additional D0/D1/D2 ETW creation attempts belong to this new pool. Preserve every old
charge and protected slot, including blocked paired builds, the existing controlled
sequence and twelve later-product build/test slots. No old allocation transfers.

A failed or partial original stops and remains fully charged. A separately numbered
corrected original needs independent cause/lifetime disposition, accepted source and
protocol repair, exact inputs/artifacts, current accounting and literal-call acceptance.
Within this finite grant, an independently accepted correction does not by itself need
another owner capacity approval. Preserve the accepted remaining success-path capacity;
no blind replay, output overwrite, refund, clock reset, cleanup or new uncertainty follows.
The first managed build retains accepted 0120 inputs and the independently disposed
0121 pre-dispatch failure. A build that may have written obj/bin normally needs a fresh
charged restore; any exception must establish permitted non-overwrite semantics and
unchanged valid input lineage from already authorized evidence.

Extend the six separate 0057, 0064, 0068, 0093, 0107 and 0110 dispositions only to this
finite increment and its declared passive work on the same hosts. Preserve their original
failures, observations and unresolved status, including noExperimentLive=false. Extend
the same bounded private-memory/transient-data and sole-owned-session/buffer-persistence
ETW disposition to nine added attempts, for twenty aggregate. Existing sequential
observation, successful exact-artifact calibration, scoped outcome review and all other
ownership, process, consumer, loss and evidence stops remain. No new owner risk request
is required solely for the already accepted narrow persistence case.

The matching grouped owner Wave decision permits only the listed incidental OS
console-host roles for the existing controlled compile, N1/N2/N3 native batch and
D0/D1/D2 direct synthetic paths. Preserve the normal launcher, compiled fixtures,
creation flags and nested Job limits. Invoke no console host directly and add no
authored helper. The source-derived models do not establish individual historical
identities, installed-source equality or universal platform behavior.

Only the initial WSL interop console hosts are covered by the specific outside-Job
lifetime decision. They precede the later experimental Jobs. Rely on ordinary
platform console lifecycle and the accepted WSL requested-process completion basis,
while explicitly retaining each such host's unmeasured identity, exit and bounded
termination. The owner accepts possible persistence or interference only for these
finite roles within this credential-free grant. This is not a general exception for
unowned descendants. Explicitly launched application, owned-Job and Linux completion,
complete captures, zero active owned-Job members and all ordinary stop conditions
remain required. No host survey, additional ETW diagnostic, foreign-service operation,
containment redesign or cleanup is required or authorized by this decision.

Apply the Wave's grouped maxima, initially four future originals per operation,
twenty total originals, 28 initial outside-Job hosts and 28 inside-Job hosts,
intersected with the stricter
remaining correction pool, protected success path, unused stages, immutable lineages,
ETW limits and exact admissions. These are not jointly funded reservations or retries.
The matching protocol charges compile 0/1/0/7, native 0/1/0/15 and each D0/D1/D2
0/1/0/5; its required remaining path uses the protected 0/4/0/22 plus eight unused
correction-pool synthetic units. Preserve all other allocations and twelve later-product
build/test slots. No quota increases, refunds, clock resets or new passive passes follow.

Extend each of the six separate historical interference dispositions only to these
newly bounded OS-host roles. Preserve all original uncertainty, failed outcomes,
charges, spent observations and noExperimentLive=false, including 0129's failed
0/1/0/1 outcome and 0130's original 0/1/0/6 charge. Do not reprice, identify hosts or
reobserve either original. This decision does not accept a new application/Job/Linux
lifetime uncertainty. Both the narrow host decision and historical extensions end
with this grant. Other managed builds, publication, future real-account acceptance,
launcher replacement and account, cache, credential or installation effects remain
outside this exception. Independently accept matching source/protocol and current
input/artifact/checkpoint/finite-accounting/call gates before dependent execution.

The Wave's controlled diagnostic continuation buffer separately adds 0/0/0/76,
giving current aggregate ceilings 39/166/30/454. Only the existing four-target
compile and N1/N2/N3 native operations may spend the added synthetic units. Together
with twelve unused pool units and eight existing build/test slots, this supplies one
compile/native pair and three contingency pairs. Preserve the existing protected
direct path and every other reservation; stop when the needed evidence is sufficient.

For the grouped bounds above, replace only the compile maximum four with six, native
maximum four with seven, and inside-Job host-role maximum 28 with 44. Keep total
twenty, outside-Job 28 and direct per-operation four as simultaneous stricter limits.
Explicitly extend the six separate historical lifetime/interference dispositions and
the narrow initial-interop OS-host disposition only to this additional finite envelope
on the same hosts. Preserve noExperimentLive=false and all application, owned-Job and
Linux completion requirements. These extensions end with the grant.

Require the owner-approved matching Wave and independently accepted protocol before
execution. Keep every full failed charge, exact admission, finite stage and passive
limit, twenty-attempt ETW ceiling, and twelve later-product build/test reservations.
No other category, helper, target, topology, account or external-effect boundary grows;
no replay, refund, observation reset, baseline refresh, clock renewal or cleanup follows.

For at most 27 new intended-operation lineages, permit at most four separately admitted
metadata passes per immutable lineage and four fixed-selection collectors per fresh
terminated original. Source, nonce, action or inventory revisions do not reset the limit.
The exact protocol preserves each recipe's stricter bounds and caps this at 108 metadata
passes, 1.6875 GiB retained metadata and 6,480 seconds, and 108 collector passes,
216 GiB collected payload and 32,400 seconds. These are cumulative maximum allowances,
not expected usage or a replacement for per-pass arithmetic. Passive operations must
remain independently classified at zero experiment units; no new process or tool runs.
Retain prior and partial snapshots without overwrite, selection expansion, predicate
weakening or baseline refresh. No historical collector or output is reopened.

The Wave's separate public-cache prospective identity admission after original 0124
permits one bounded exception to that baseline-refresh prohibition. It covers only the
same 1,764 admitted public dependency-cache leaves for a fresh managed restore. A fixed,
payload-free metadata pass may supply prospective ctime observations, provided every
other identity field equals the original descriptor. Preserve the original descriptors,
failures and content expectations; metadata alone establishes no content or restore
success. Independently accept the exact manifest, source, finite observation and new
prospective inventory. The first accepted snapshot fixes the sole new baseline; every
later ordinary input read retains strict full9, exact length and SHA-256 checks.

Keep this exception within the existing intended-operation lineage, passive-attempt
limits and charged correction capacity. It adds no survey, payload read during metadata
collection, cache repair, download, runtime-predicate relaxation or counter reset.
Source inputs, installed tools, the launcher, historical restored trees and outputs are
excluded. No later pass may replace the accepted baseline or supersede a contradictory
observation. Require the owner-approved Wave and exact protocol amendment before this
observation; all other evidence, lifetime and effects boundaries remain unchanged.

The Wave's controlled-compilation reuse extension permits only the exact two
same-path public runtime configuration descriptors already carried by accepted
restore 0126 from that first baseline. Their exact protocol join to original
controlled inputs 168/169 is required before successor input acceptance in the
existing controlled-compile lineage. This reuses the sole baseline unchanged;
it authorizes no new metadata, cache leaf, baseline, quota, effects, comparison
relaxation or lineage reset. Preserve full9/content checks, original descriptors,
failures and the unknown cause of the earlier ctime differences. Any further
contradictory observation remains a stop without replacement or readmission.
Require the matching Wave and protocol amendments before dependent admission.

The Wave's created-native-fixture decision permits only the one exclusively created
public synthetic fixture admission in an independently admitted remaining fresh stage
to qualify change time between write closure and separate Linux reads. Preserve the
original write-closed identity, exact admitted content, the other eight identity fields,
and full9 stability within each read. Keep every sampled full9 and the precise comparison
outcomes; do not replace a baseline or use the broader compile-copy read qualification.
Native held Windows checks and every other ordinary control remain unchanged.

This accepts only the loss of that historical change-time rejection signal, not a
benign cause or uninterrupted metadata integrity. Apply the exact
[fixture-control protocol](experiments/windows-slice-validation.md#created-fixture-between-read-identity-qualification)
and independently accepted source, finite evidence bounds and ordinary exact gates.
No additional observation, settling pass, occupied-control reuse, overwrite, cleanup,
quota or process uncertainty is included. Preserve historical failures and charges;
the exception ends with the current grant and cannot expand or transfer automatically.

The Wave's separate synthetic-native-catalog decision permits only cross-role Windows
ChangeTime inequality for its fixed 202-leaf N1/N2/N3 catalog. Preserve strict complete
local pin/read/held/named stability, exact admitted content, and every other cross-role
path/object predicate. Authenticate and retain the driver's original map/digest through
all descendant bindings; neither original nor local snapshots may be refreshed or
replaced. This accepts the loss of an intervening metadata-change signal, not a benign
cause or continuous metadata integrity. Apply the exact
[native catalog protocol](experiments/windows-slice-validation.md#native-catalog-cross-role-changetime-qualification)
only after owner acceptance and independent source/protocol review. Direct synthetic
and real/product admission, Linux controls and unrelated inputs remain unchanged.
No quota, process role, observer, ETW session, clock extension, cleanup or new process
uncertainty is granted. The qualification ends with this grant.

The Wave's separate synthetic-direct decision permits Linux ctime-only inequality
within and between reads and held-input comparisons for only the fixed 200 deployed
synthetic leaves. It also permits one non-overwrite completion of the occupied v4
tree, retaining its 194 leaves and exclusively creating the remaining six. For that
completion and the remaining already-funded direct originals expressly covered by
the Wave, also qualify ctime within and between Linux reads of only the
four fixed original SyntheticSubject artifact donors. Apply the
[direct donor completion protocol](experiments/windows-slice-validation.md#direct-four-donor-and-194-leaf-completion)
after the owner decision and matching amendments merge, and after exact source review.
Preserve original descriptors, all actual ctime observations, exact admitted bytes and
the other eight Linux identity fields. Retain the four donors' original compile
lineage. The two Python donors and all other original donors, tools, external controls,
private/account inputs, unrelated files and Windows predicates receive no exception.

The owner decision accepts the lost ctime-only metadata/history signal and the lack of
continuously held historical handles. The failed 24th leaf's original creation-object
check passed, but only its first-read snapshots/content remain; do not reconstruct its
missing creation/write-closed snapshots. Neither matching content nor the exception
establishes a benign cause or uninterrupted integrity. Any other mismatch stops without
repair. Keep both failed preparations' charges, partial tree and original observations;
add no settling pass, survey, overwrite, cleanup, quota or process uncertainty. The completion is
single-use; comparison authority expires with the grant and cannot transfer to real
inputs or later work automatically.

The Wave's v6 completion decision separately permits one non-overwrite completion
of the 194 leaves retained by failed preparation 0149, exclusively creating its six
remaining leaves. Apply the [exact v6 protocol](experiments/windows-slice-validation.md#direct-v6-completion-after-0149).
Preserve original copy/readback lineage and content; the same synthetic destination
qualification and exact four-donor qualification apply, with every other predicate
unchanged. Local recovered artifact copies and the two Python donors remain strict.
The owner accepts the same limited loss of a ctime-only history signal and absence
of continuously held historical handles. No baseline is refreshed and no benign
cause or successful outcome is inferred. Keep the failed charge, partial tree and
observations; one newly charged D0 allocation funds the sole completion. Existing
compilation and native evidence may be reused without another experiment. This adds
no capacity, process role, account effect, cleanup or lifetime exception. Further
occupied-tree adoption is excluded; the donor qualification ends with this grant.

This grant permits independently reviewed narrow source/protocol corrections and its
finite fresh owned stage versions within unchanged topology/effects; it creates no
generic execution or discovery mechanism. Matching owner Wave acceptance and protocol
review precede execution. Source-only review requires no experiment allocation. No new
publication, helper/target, download, toolchain, account, WAM, credential, application or
broker cache, installation, cleanup, signing or release effect is granted. Exhaustion or
an expanded boundary requires a new decision; all dispositions end with this grant.



Delete only identified experiment-owned artifacts when cleanup is safe. Retain normal
selected-account session or secure-cache updates when the protocol declares that outcome.
Deleting local files does not reverse provider-side authentication, consent, or session
changes. Do not sign out, revoke consent, erase caches, or promise automatic rollback of
existing account state as incidental cleanup.

## Authentication Experiment Records

Every committed authentication-experiment result must state the applicable fields below
and explicitly mark nonapplicable context when omission could change interpretation:

- accepted protocol revision and actual subject/source or artifact identity;
- v2 commit, if applicable;
- MSAL and native-broker versions;
- operating system, architecture, WSL version, and initiating/interaction host types;
- sanitized account-state shape and relevant prior-use or unknown-state limitations;
- client profile, authority class, scopes, and requested policy;
- application-file separation and declared existing account/cache/configuration access;
- telemetry, network, and sensitive-output controls;
- expected UI and typed result;
- observed UI, result, and state effects, including operator-assisted observations;
- manual steps, failed starts, interruption, and termination outcomes;
- cleanup performed or state intentionally retained, without claiming remote rollback;
- attempt history, prior consumption, remaining capacity, and known variability;
- whether the record is a source finding, runtime observation, inference, or hypothesis.

Record decision-relevant sanitized outcomes such as account-match status and metadata
availability rather than identities, token contents, or raw broker diagnostics. Manual
observations have the same protocol, provenance, and review requirements as automated
ones. Existing-state success cannot establish fresh-state behavior, another host's
behavior, or broader platform/Profile support.

### Phase 1 Public-Build Record

This historical heading is retained because the recorded singleton and its schema bind
this exact policy anchor. It does not define a current project phase.

Issue #1 uses the fixed source baseline, Lasso reference manifest, and singleton strict-JSON
bundle linked from the research catalog. The source records own the audited source facts.
This policy owns outcome-level safety and evidence rules. The singleton bundle owns the
exact instance inputs, including commands, source-mode paths and configuration, expected
observations, selected bounds, SDK and mise configuration, component hashes, and
limitations. The schema owns strict shape, lifecycle, types, authorized ceilings, and the
six runtime semantic carriers; it does not define a second literal command protocol.

#### Authorization History and Lifecycle

The recorded run was executed under the former work-authorization model and the Issue #1
owner decisions retained in GitHub history. Those historical decisions do not authorize
another run. The recorded singleton is evidence rather than an executable protocol. A
future public-build execution requires a current accepted Wave entry and a new accepted
planned protocol. Non-executing review may inspect repository records and host metadata,
but it must not invoke .NET or NuGet, resolve packages, access feeds, or mutate source or
user state.

The current tree has exactly one semantic bundle at
`docs/research/experiments/public-build-wsl2-linux-x64-dotnet-8-0-424.json`, with a
matching filename and ID. Git history, PR #6, and Issue #1 retain the retired numbered
preflight receipt; it is not a current executable protocol or runtime-evidence carrier. A
planned bundle contains no runtime evidence. A recorded bundle contains runner-produced
evidence with distinct `command_outcomes`, `canonical_termination`,
`all_exit_quiescence`, `ownership_conditioned_cleanup`, `receipt_binding`, and
`bounded_conclusions` carriers.

Trusted-base inspection, existing experiment-root rejection, and the other checks that
precede experiment-owned state are preflight. A preflight rejection exits nonzero and
preserves the canonical planned bundle's bytes, inode, and status without creating a
recording candidate or publishing assets. Preflight may create missing trusted-base
components as mode `0700` operational host infrastructure and retain them after rejection;
those directories are not experiment-owned runtime state. The fixed topology creates its
roots before any child process, so canonical runtime recording begins when the runner
creates the first experiment root. A failure after that boundary, including root-marker
initialization failure, remains durable evidence. The runner must atomically fail closed
when recording the reviewed singleton; a partial or concurrently changed replacement
must not become current.

For the recorded run, the repository owner approved
`defer_to_first_production_run`. That decision meant review and hk did not install the
SDK; the first WSL2 Linux x64 production run exclusively created its dedicated toolchain
root and installed the bundle's locked SDK archive through the reviewed mise descriptor
before any .NET metadata or experiment command ran. The `http:dotnet-sdk` tool remains
disabled for ordinary mise installation, automation, and hk. The acquisition timing and
WSL2 host decisions for that recorded run remain in Issue #1:
[SDK acquisition](https://github.com/hcoona/microsoft-authentication-cli/issues/1#issuecomment-5471951604)
and
[WSL2 host](https://github.com/hcoona/microsoft-authentication-cli/issues/1#issuecomment-5483552767).
The recorded run's trusted-base provisioning boundary remains in its
[owner disposition](https://github.com/hcoona/microsoft-authentication-cli/issues/1#issuecomment-5486463259).

#### Isolation and Execution Outcomes

The runner must fail closed before creating a root or spawning a child unless the host is
WSL2 Linux x64. Every child receives a complete direct replacement environment and no
shell interpretation. The child environments omit WSL-specific variables and Windows
PATH entries, and the fixed mise, Git, and .NET executable selections are Linux paths and
identities. The protocol does not invoke a Windows executable, helper, broker, credential
provider, account state, or cache through WSL interoperability. An observed Windows-side
interaction is a stop condition. This boundary constrains the reviewed execution; it is
not a hostile-build-input sandbox or a claim that WSL interoperability is disabled for
unrelated processes.

The two reviewed source modes use disjoint experiment-owned checkout, home, cache,
temporary, output, selection, and toolchain paths. No ambient credentials, package
configuration, caches, startup hooks, or toolchain selection may affect an outcome.
Existing, linked, replaced, or identity-unverified roots are not reusable.
`/var/tmp` must remain root-owned mode `1777`. Each existing trusted production-base
component below it must be opened without following links, owned by the current Linux
user, grant owner read/write/search permission, and grant no group or other write
permission. This protects identity and mutation integrity, not ancestor-name
confidentiality. Experiment roots remain exact mode `0700`, and their markers remain
exact mode `0600`.

The bundle records exactly the source-faithful and public-only modes and their sixteen
restore, build, filtered-test, and non-publishing package commands. Each command has one
attempt and a finite timeout. Downstream commands cannot restore implicitly and run only
after their mode's recorded restore passes. PCACache remains excluded and the limitation
must state that the evidence does not cover an unfiltered suite or platform persistence.
The validator independently checks the fixed Issue, source authorities, host and toolchain
identities, modes and endpoints, baseline stages and targets, one-attempt and dependency
relationships, non-publishing behavior, trusted path structure, authorized ceilings, and
internal consistency. The shared implementation contract owns the complete ordered
command-ID sequence and deterministically reconstructs each command vector. The validator
requires exact equality for both the full order-sensitive ID sequence and every command
field and argument; stage coverage or dependency equivalence cannot make a reordered
protocol acceptable.

Preparation and command outcomes retain primitive attempts and failure origins. One
implementation-only preparation topology supplies subject metadata and the required
recorded order, which validator and conformance checks enforce. A shared narrow reducer
determines global and mode blockers and the canonical cause. Unproved quiescence
has strongest precedence, followed by late root-identity failure, the first global safety
stop, ordinary global preparation failure, any command or mode failure, and completion.
Ordinary mode-local failure must not stop the independent mode. Cancellation, sensitive
output, failed capture, source-integrity change, unproved quiescence, and unsafe root state
stop globally. A nonpassed restore blocks its own downstream commands with the restore
relationship preserved.

Every spawned subject must be bound to its process identity and brought to all-exit
quiescence, including surviving descendants, before evidence is finalized or cleanup is
considered. Cancellation must remain event-driven and cannot bypass descendant discovery,
termination, reap, or evidence finalization. If all-exit quiescence cannot be proved, the
runner must record that uncertainty, stop globally, retain created roots, and perform no
unsafe cleanup, root release, or asset access.

Created selection and toolchain roots are retain-always, including partial roots. No later
process may resume the run, infer ownership from a name or absence, release a root, or
delete it. The lifecycle carrier records only whether each root was created and whether
its current identity was verified; retention and cleanup conclusions are derived from this
policy and the primitive evidence. After command execution, successful selection-root
verification retains that exact directory descriptor through dependency inspection and
recording. Dependency asset traversal is descriptor-relative and no-follow; pathname
existence or type probes are not authority. Immediately before every bundle commit
attempt, the canonical selection-root pathname and marker must still bind that retained
identity. A late mismatch rolls back only matching invocation assets and records
root-identity-unverified with dependency inspection blocked.

#### Bounded Evidence and Source Integrity

Source-faithful experiment-command output must be drained through bounded in-memory
screening and recorded only as a fixed suppression disposition; no stdout or stderr
content, excerpt, hash, path, or byte count may be persisted. Other child output must be
streamed into bounded sanitized captures under the selection root. Only sanitized,
identity-verified bytes and bounded excerpts may be recorded. Output beyond the bound
terminates the command and blocks its mode. A later sensitive or capture failure supersedes
that mode-local overflow and stops globally; replaced or unverifiable output also stops
globally and cannot become evidence. A failed retained-capture identity check records only
the fixed `capture-unverifiable` no-content disposition for both streams. That later
verification failure preserves an already selected cancellation, unproved quiescence,
sensitive-output, source-integrity, root-identity, or capture-failed global safety
termination; otherwise the reducer selects the later capture-failed event over completion
or a mode-local timeout or output-limit result.
The runner retains capture identity handles through recording and verifies the canonical
selection root, capture parent, leaf identity, type, size, and hash before and after the
bundle exchange while the displaced plan remains recoverable. A safe mismatch invalidates
the affected attempt symmetrically, and a failed selection-root identity invalidates every
retained capture reference under that root.

Before root creation, the runner recomputes both canonical authority payload hashes,
retains the validated source-baseline snapshot for dependency extraction, and takes one
bounded no-follow snapshot of the experiment lock after verifying its component hash and
exact one-tool projection. The generated `mise.lock` must use and match those retained
bytes rather than reopening the repository path. Runtime evidence records the reviewed
mise digest, a safe normalized executable mode, and successful owner verification, plus
the selected Git executable digest, but not ambient executable paths or the numeric
operating-system user ID.

After each Git initialization, the runner must retain a no-follow descriptor and
device/inode identity for that mode's checkout through all remaining preparation,
experiment, inspection, and recording work. Checkout-related child working directories
and checkout-contained runtime arguments are descriptor-bound while the reviewed bundle
continues to retain the canonical command vectors. The canonical checkout pathname must
still resolve to the retained identity at baseline and command boundaries. Fingerprints
must traverse a duplicate of the retained descriptor rather than reopening that pathname.
The source-faithful `nuget.config` runtime token is relative to the descriptor-bound
working directory so NuGet records the canonical checkout path rather than a procfs
descriptor spelling in replayed restore metadata.
After checkout preparation and after each executed experiment command, the runner must
compute one bounded, no-follow aggregate source fingerprint. It binds the detached audited
HEAD, the Git index, and every worktree entry outside `.git`, including relative path,
type, normalized executable mode, regular-file content, symbolic-link target, and
directory presence. Path replacement, unsupported types, races, ceiling violations, or a
mismatch stop globally and cannot leave the affected command acceptable. Exact HEAD
verification remains independent. The bundle selects bounds within the schema and
contract ceilings; policy does not duplicate their numeric values.

Dependency evidence is nested by source mode and target. Target containment supplies mode
and target identity. A valid target retains the exact asset path, hash, full
current-extractor projection, and target-level provenance bound to the corresponding
restore outcome and initial-cache observation. Missing or invalid targets retain their reason and every applicable unresolved
direct package declaration with failure references. Mode completeness is derived from the
valid target set; unknown transitive scope follows from partial or unavailable evidence.
The fixed Linux x64 applicable package-backed-assembly set must be empty. A future source
baseline that makes such a declaration applicable requires an atomic runtime-contract
expansion before execution.

Raw `project.assets.json` evidence must be safety-screened, bounded, exact-byte retained,
hash-bound, and replay exactly through the live reviewed extractor. Asset access and
publication require proved all-exit quiescence, verified root identity, unchanged source,
and no global preparation or safety stop. Pre-commit failure may remove only an
invocation-owned asset whose identity still matches; committed or replaced assets must not
be unlinked. Cleanup of runner-owned published-asset leaves, asset staging names, and
bundle candidate or displaced names must use one directory-descriptor-relative Linux
quarantine operation. A no-replace atomic move to a cryptographically unpredictable name
is the ownership linearization point. The moved object must match the captured device,
inode, and hash when available before deletion. An unexpected object is never unlinked:
it is restored with no-replace semantics when safe, otherwise preserved in quarantine and
reported as indeterminate. The final bundle compare-and-swap owns the complete
published-asset identity set. It verifies every asset before exchange and again while the
displaced planned bundle is retained. A post-exchange asset or root mismatch permits
reversal only while both bundle leaf identities remain exact; reversal must restore and
durably verify the original plan before matching invocation assets are rolled back. Once
the displaced plan is deleted, asset rollback is forbidden. A post-exchange displaced
leaf that is not the exact original plan is observationally ambiguous and must preserve
the canonical candidate, unexpected displaced state, and published assets as a committed
or indeterminate recording error. Indeterminate cleanup,
reversal, restoration, or durability is a committed or indeterminate recording error,
never a claimed safe rollback. This quarantine rule is limited to runner-owned named
leaves and does not establish broader same-user or filesystem hardening. Provenance
references establish reviewable carrier relationships, not causal sufficiency.
Immediately after each restore reaches proved quiescence, the runner takes a bounded,
no-follow in-memory presence and SHA-256 snapshot of every expected target asset. Final
inspection and publication require the current bytes to match that restore-time snapshot;
changed, deleted, or newly appearing bytes remain invalid and unresolved.

Planned and recorded validation require every hash-bound runner, validator, contract,
schema, extractor, NuGet helper, and experiment-lock component to match the live
repository file, and recorded projection replay uses the current extractor. After a
recorded bundle exists, the first proposed change to any of those hash-bound components
must atomically choose and implement either historical replay or record migration, with
independent research-evidence review. Until that trigger fires, history-wide component
search and recovered historical Python execution are prohibited.

The embedded receipt binds the complete recorded strict-JSON bundle except its own digest.
The runner, CLI validator, and repository checker share shape and semantic validation;
repository checks delegate rather than maintain a second positive plan. Mechanical checks
establish consistency, not evidence sufficiency or public causality.

#### Conclusions and Boundaries

Conclusions must remain bounded to the recorded host, audited commit, source mode,
commands, reproduction count, retained evidence, and limitations. Complete, partial, and
unavailable dependency states are observations, not support promises. A shared failure
does not by itself prove a public-dependency cause, and one run does not establish
variability or service reliability. The Lasso manifest remains the source-usage authority;
Issue #1 may map responsibilities and bounded candidates but cannot select or implement a
replacement.

This protocol does not define publish parity, a generic experiment framework, product or
support contracts, release readiness, or a second narrative copy of command and dependency
results.

## Stop Conditions

Stop the experiment if:

- a real token, code, credential, or private account detail would enter captured or
  retained evidence;
- a prompt appears outside the declared interaction policy or in an unexpected session,
  or cannot be identified by the operator;
- account acquisition, cache/store access, host execution, or network effects exceed
  the accepted protocol;
- a public-restore claim would depend on inherited credentials or cached private
  packages;
- native or cross-host execution accesses an environment not covered by the protocol;
- remaining authorized attempts or cumulative capacity cannot be established;
- experiment-controlled work cannot be stopped within the declared bounds, or safe
  ownership cannot be established for cleanup, except for the case-specific original
  Issue #108 invocation 0057, publications 0064, 0093, 0107 and 0110, fixture 0068,
  and the retained-launcher allocation's sole-owned-ETW-persistence exception in
  Termination and Retention, each within its exact accepted scope;
- the subject's source or artifact identity no longer matches the accepted protocol; or
- continuing would mutate an unrelated account, installation, or remote resource.

The historical Issue #1 rules additionally retain their unconditional WSL-to-Windows
prohibition, source-integrity checks, and proved all-exit quiescence before cleanup or
asset access. Those specialized rules are not a general experiment framework.

## Direct Observer Diagnostic Continuation

The Wave's direct observer diagnostic continuation adds only 0/7/0/43, giving current
aggregate ceilings 39/173/30/497. It funds at most four separately admitted four-target
compile/D0 pairs, one necessary and three contingency pairs, while retaining protected
D1/D2 and later-product work. Each pair costs 0/2/0/12. Stop after sufficient evidence;
failed starts retain their complete charge and ordinary independent failure disposition.

The same seven added build/test originals replace the pool build/test ceiling 19 with
26, the pool original maximum 22 with 29, and the total path maximum 27 with 34.
Preserve the three-restore ceiling, all spent counts and the separate 27 immutable
passive-lineage/108-pass limits. This adds no allocation beyond 0/7/0/43.

Retain native evidence when its source, artifacts and exercised behavior are unchanged.
Direct diagnostics use only fixed numeric source locations and input ordinals within
the existing pipe/final-record caps. No private values, exception text, raw traces,
new process roles, broader identity qualification or additional telemetry is included
in that diagnostic decision. The separate direct comparison decision below is the
only added Windows qualification for the direct synthetic catalog.
A new observer requires its own exact artifact acceptance and D0 calibration.

Apply grouped maxima compile ten, native seven, D0 seven, D1/D2 four each, total 25,
inside-Job console hosts 62 and outside hosts 28, together with all stricter limits.
Fresh compile stages v16-v19 and direct deployments v5-v8 remain within dedicated
experiment roots; occupied roots are retained. Passive lineage/pass, per-original
clock, ETW twenty-session and all other effects limits remain unchanged.

Extend only the same six historical and already accepted platform-host/sole-owned-ETW
persistence dispositions to this finite scope. Preserve noExperimentLive=false and all
historical charges and uncertainty. No new application, Job or Linux lifetime exception
is granted. Source/control/protocol and exact-call review remain required; this section
alone does not activate a source or authorize a retry.

## Synthetic Direct Cross-Role ChangeTime Qualification

The Wave's separate direct-catalog decision permits only cross-role Windows
ChangeTime inequality between supervisor and worker for the fixed 200-leaf D0/D1/D2
synthetic catalog. This supersedes the diagnostic continuation's full cross-role
baseline-equality requirement only within that scope. Preserve strict complete local
pin/read/held/named identity stability, including ChangeTime; all other header,
ordered-path, object and exact admitted content comparisons remain mandatory.
Retain both local baselines and use the supervisor's original digest for downstream
record binding only after every required projection agrees. No baseline is refreshed.

The owner accepts the loss of the intervening metadata-change rejection signal,
not a benign cause, continuous metadata integrity or successful calibration.
Apply the [direct comparison protocol](experiments/windows-slice-validation.md#direct-catalog-cross-role-changetime-qualification)
only after the specific owner decision and matching record acceptance. Native
pinning, real/product admission, Linux controls and unrelated inputs are unchanged;
this exception cannot transfer automatically. Use existing finite correction capacity,
fresh stages, independent source/artifact/call gates and new D0 acceptance for changed
observer bytes. Preserve all failed charges, protected work, historical uncertainty
and containment. Add no observation allowance, process role, helper, clock
extension, cleanup, occupied-tree reuse or new process uncertainty. Existing
per-original observations and ETW reservations remain charged. The
qualification ends with the current grant.

## Synthetic Direct v7 Completion and Public Donor History

The Wave's single-use v7 completion permits one retained leaf and 199 exclusive
creations, reusing the accepted observer without another compile. Apply the
[exact v7 protocol](experiments/windows-slice-validation.md#direct-v7-completion-and-public-donor-history)
only after matching record acceptance and independent source/input/call review.
The fixed 196 NTFS public original donors may differ only in ctime between their
historical expected and current opened identities. Require the original ordered
role/path/descriptor, the other eight fields and a new exact length/hash/EOF read.
For the 194 runtime/host/observer donors, retain strict full9 within each read;
the two SyntheticSubject donors retain their separate existing qualification.
Four local donors, external controls, infrastructure and unrelated inputs stay strict.

The owner accepts loss of that historical ctime signal and reuse without continuously
held historical handles. Matching content does not establish a benign cause or
continuous metadata integrity. Preserve original baselines and actual observations;
prior hashes cannot replace the new read. The donor qualification applies only to
this completion and ends with the grant. Existing deployed-catalog rules remain.
Use one already funded 0/1/0/5 allocation, with only D0's submaximum raised to eight;
add no aggregate quota or observation allowance. Preserve failed charges, protected
work, all six historical unknowns, `noExperimentLive=false`, named Jobs/cgroups and
existing ETW dispositions. No overwrite, repair, extra survey, clock extension,
new process uncertainty or account effect is included. Failure cannot renew adoption.

## Direct ETW Failure Diagnostics and Finite Continuation

The corresponding Wave increment adds only 0/8/0/46, producing aggregate ceilings
39/181/30/543 and, with two previously unspent synthetic units, four compile/D0
pairs at 0/2/0/12 each. One pair supplies the instrumented observation; three are
contingent correction capacity. Stop after sufficient evidence. Each failure
retains its full charge and needs independent disposition and a concrete repair
before another original. Old protected work, D1/D2 and twelve later-product slots
cannot be transferred into this pool.

For the same increment, shared build/test, shared total and path-original maxima
become 34, 37 and 42. Grouped compile/D0/total maxima become 13/12/33; outside and
inside console-host roles become 35/79. Native seven, D1/D2 four each, ETW twenty,
passive 27 immutable lineages/108 passes, and stricter local limits remain. Use only
exclusively fresh compile v19-v22 and direct v8-v11 stages. Admission must prove
remaining lineage/pass capacity, not infer it from the larger execution allowance.

Synthetic failures may preserve a numeric first-source location, UInt32 native
status and creation/stop/drain bits within the existing 40-byte pipe and 4,096-byte
record. Latch the first cause before cleanup, including callback-thread failures;
keep later cleanup outcomes separate. Missing facts remain unknown. This adds no
platform query, trace, helper, snapshot, raw payload, exception text or private
value. Successful frames, strict acceptance and real-role diagnostics stay unchanged.

Preserve accepted native and SyntheticSubject dependencies. Carry the accepted
historical ctime/content qualification forward for the 196 fixed donor roles.
Rows 1-190 and 195-196 retain original paths/descriptors; observer rows 191-194
use the newly accepted corresponding compile-stage artifact descriptors. No other
descriptor is refreshed. Fresh hashes, lengths,
EOF and all other required identity fields remain mandatory; runtime/host/observer
within-read full9 and local/control inputs stay strict. The two SyntheticSubject
donors and deployed catalog retain their existing narrowly scoped qualifications.
No occupied stage or deployment is reopened.

Existing historical process and platform-host/sole-owned-ETW risk dispositions
continue within this finite credential-free scope on the same hosts. Keep all
spent charges, `noExperimentLive=false`, creation-time named Jobs/cgroups and
original clocks. No new application/Job/Linux lifetime exception, permission
change, account effect, download, restore or publication follows. Ordinary exact
source, artifact, input, call and outcome gates precede dependent execution.

## Compile Public-Donor Historical ctime Qualification

The matching Wave applies the existing content/ctime decision to only the closed
365 original public compile donors: 167 references, 197 toolchain leaves and one
apphost template. Preserve their original paths/descriptors and exact accepted
catalog/inventory linkage. A fresh read must establish exact length, SHA-256, EOF
and all eight non-ctime identity fields against that original descriptor. Only the
historical ctime comparison may differ; retain both operands without refreshing
the baseline. All nine fields must still agree within each read. This loses only
the historical ctime-change signal and establishes no benign cause or continuous
integrity. Generic pinning, 48 local source/control inputs, infrastructure, Windows
held-object checks, native and real/product rules remain unchanged.

Use the existing finite continuation pool, remaining fresh compile v20-v22 stages
and unused direct v8-v11 roots after the ordinary independent gates. Preserve full
failed charges and occupied trees. No new capacity, observation, helper, metadata
pass, retry, overwrite or cleanup is added; this qualification expires with the
current Wave grant.

## Retained Elevation Entry for Synthetic Direct Diagnostics

The matching Wave permits a single temporary administrator entry for D0/D1/D2 on
the same designated Windows host. The owner accepts its retained privilege during
analysis, correction and independent review. Apply the
[entry protocol](experiments/windows-slice-validation.md#retained-elevation-entry-for-synthetic-direct-diagnostics)
and source/artifact/call gates before execution. Complete launch and automatic
shutdown preparation before requesting fresh readiness for the UAC/manual handoff.
The owner can leave after the actual elevated relay and its bounded ownership are
confirmed; watching automated work is not required.

Only the entry infrastructure may remain between attempts, up to 86,400 seconds
from successful elevated entry start, including idle/review time. No deadline
renewal, automatic relaunch or open-ended privileged command service is permitted.
This is the sole exception to the current synthetic allocation's no-elevation and
no-live-process-waiting-for-review rules. Actual test processes, their owned ETW
sessions and all observations retain their original shorter bounds and separate
outcome gates. A failed D0 still blocks D1/D2.

Require creation-time named Job ownership for the Windows entry child, a named
Linux scope for its holder, and an actual fixed child-token check through the new
relay. Preserve the distinction between Windows Job membership, Linux containment,
relay lifetime and ETW closure. End the entry on completion, owner stop, deadline,
or inability to continue within the accepted scope. Observe its owned termination;
closing a window is insufficient. Keep shared WSL infrastructure under the existing
workstation/platform-host premise; do not stop a shared service or the distribution.
No new unknown application, Job, Linux or elevated-relay lifetime is accepted.

Use existing correction capacity for the one compilation and activation. The
permission covers only the fixed validation harness and credential-free synthetic
subjects. No persistent privilege/group/ACL/policy/registry/service/task change,
real account access, product elevation, download, installation or old-session
cleanup follows. Retained artifacts and existing historical risk decisions remain
unchanged; elevation success does not establish ETW or scenario success.

## Pre-UAC Input-Check Continuation

The matching Wave permits ten bounded Linux compilation/native input-check pairs
and one replacement retained entry after the failed first activation. The owner
accepts the finite increment 10/11/0/26 and aggregate ceilings 49/192/30/569;
Linux/Windows preparation ceilings become 29/20 and outside/inside console-host
ceilings 46/80. Preserve the entire old correction balance 0/4/0/23 and all
protected work. Entry-specific maxima are eleven compilations including the spent
first one, ten input checks and two activations including the failed first one.
Other original, grouped scenario, ETW and passive limits do not increase.

Apply the [exact continuation protocol](experiments/windows-slice-validation.md#pre-uac-input-check-continuation)
and ordinary independent gates before any compile or check. A check runs only the
same pre-UAC input-admission path used by launch, with finite numeric statuses, and exits before
Launch. It has no UAC, child, Job, relay, account, credential or ETW operation. Its
thirty-second external interval includes termination. The Linux controller and
normal native return require scoped evidence; killing an interop proxy, complete
streams alone or a timed-out call cannot establish native completion. Any new
unresolved application lifetime stops continuation. The already accepted initial
interop-host limitation remains distinct from application completion.

Carry the six existing historical process/interference dispositions and the
platform-host/sole-owned-ETW persistence decisions into only this finite allocation
on the same hosts. Preserve unresolved status, full failed charges and
`noExperimentLive=false`; no new application, Job, Linux or elevated-relay uncertainty
is accepted. A check creates no ETW, and the retained entry does not itself grant a
D0 attempt. This extension expires with the current Wave and cannot transfer.

Use fresh dedicated check/compilation evidence roots. Do not reopen old outputs,
repair occupied payloads or refresh input baselines. A successful check must bind
the exact unchanged four-file activation payload; it writes no activation marker.
A failed pair needs independent outcome and scoped-completion acceptance plus a
concrete correction before another pair. Stop after sufficient evidence.
Only after accepted actual input-check success and complete launch/shutdown
preparation may the one replacement activation request fresh readiness. Its full
charge is spent even on failure; no further prompt or deadline renewal follows.
The original retained-entry 86,400-second absolute cap, owned closure, synthetic-only
permission and all individual test clocks remain unchanged. No persistent permission
or account changes, restore, download, installation, publication or release follow.

## Complete Retained-Entry Recovery and Continuation

The matching Wave authorizes one complete credential-free recovery sequence under
[its protocol](experiments/windows-slice-validation.md#complete-retained-entry-recovery-and-continuation).
This adds a bounded observation path for original 0179's two recorded native
incarnations and exact relay, not permission to ignore uncertain ownership. Before
other experimental continuation, independently accept their current closure: neither
original native incarnation remains active and the exact relay is absent. Preserve
unobserved original exits/timing and all historical dispositions. Current reconciliation
does not reconstruct past completion or diagnose the failed context predicate.

One fixed non-elevated observer may query each of the two literal PIDs once with
limited-query and synchronize rights, sample creation and held-handle exit state,
and return normally within thirty seconds including transport termination. One Linux
no-follow metadata sample covers only the recorded relay. Distinguish PID absence,
reuse, matching exited/live incarnation and access/query failure. A present, changed
or inaccessible relay does not pass. No process survey, extra rights, image/token/
account inspection, relay connection, termination, shared-service action or UAC is
part of reconciliation. The observer's own native completion and transport scope
must be established; timeout or killed proxy is insufficient. An unresolved result
stops dependent execution without replay or inferred risk acceptance.

Fund at most 2/3/0/10 and five passive passes totaling at most 210 seconds/32 MiB
from existing capacity, preserving protected work and the old 0/4/0/23 reserve.
Only the accepted reconciliation may execute while closure is unresolved; inert
source/diagnostic/corrective preparation remains permitted. All source, artifact,
input, exact-call and outcome gates remain. Code fixes require supported findings;
generic failure records do not justify guessed causes or arbitrary relaxed predicates.

The single additional retained entry raises only its activation submaximum to three.
It must preserve original 0179's absolute deadline rather than restart a 24-hour clock.
Bind that deadline before input validation and UAC; refuse admission when insufficient
time remains for startup and bounded closure. Fresh attendance follows completed
preparation. A failed activation consumes its full charge without another prompt.
Apply existing ordinary D0/D1/D2 clocks, ETW controls and outcome dependencies.

No additional owner approval is needed for each technical step inside this complete
accepted sequence. Separate owner decisions remain necessary for actual expansion
of its effects/capacity or disposition of uncertainty beyond the declared current
reconciliation. Standing historical ctime acceptance remains unchanged.

### Standing Historical ctime Qualification

The matching Wave records the owner's standing acceptance of historical Linux
ctime drift for already admitted input roles in the current finite credential-free
grant. Another admitted file with that same drift does not require another owner
risk decision. This replaces per-input risk escalation for this historical signal;
new input/effect/attempt authority still requires its ordinary accepted records.

Preserve original descriptors, all other historical identity fields and fresh
exact admitted length/SHA-256/EOF validation. Existing within-read checks retain
their separate accepted rules; this standing decision adds no within-read
relaxation. Retain original and actual observations without baseline replacement.
Do not infer a benign cause, continuous integrity or current content agreement
from a ctime mismatch alone. Exact historical comparison points remain defined
and independently reviewed in the applicable protocol and source.

For the retained-entry payload, apply the
[closed qualification protocol](experiments/windows-slice-validation.md#entry-payload-historical-ctime-qualification)
to the original successful check 0164's four files before replacement 0179. This
qualifies only their historical ctime comparison in the preceding unchanged-payload
requirement; all other correspondence and full9 within-read stability remain.
Allow at most one separately admitted local-control qualification readback,
0/0/0/0 and thirty seconds including termination, after accepted failure/triage
and matching canonical/source/call gates. Failure grants no further readback or
readiness. Actual source/artifact/input correction still requires a new charged
successful check. No compile, metadata survey, Windows start or quota is added.
All lifetime, evidence, readiness and closure rules remain. The standing decision
expires with the current grant; this readback is limited to this replacement.

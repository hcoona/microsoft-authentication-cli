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
- Do not run interactive experiments in CI or unattended sessions. Manual assistance
  must use the accepted procedure and counts toward the same attempt limits.

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
  ownership cannot be established for cleanup;
- the subject's source or artifact identity no longer matches the accepted protocol; or
- continuing would mutate an unrelated account, installation, or remote resource.

The historical Issue #1 rules additionally retain their unconditional WSL-to-Windows
prohibition, source-integrity checks, and proved all-exit quiescence before cleanup or
asset access. Those specialized rules are not a general experiment framework.

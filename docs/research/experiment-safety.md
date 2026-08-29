# Experiment Safety Protocol

## Scope

This protocol applies before running an upstream or v2 authentication binary, restore,
build, cache, installer, or migration experiment.

Phase 1 experiments may observe real platform behavior, but they must not contaminate
personal production state, rely silently on private credentials, or publish sensitive
evidence.

## Required Isolation

### Source and Build

- Use a detached checkout pinned to the recorded upstream commit or tag.
- Record the exact source commit and dependency versions.
- Test public restore with an empty package cache and no inherited package-source
  credentials.
- Do not use a cached private package to claim that a public build works.
- Keep build output and package caches outside upstream or v2 production install paths.
- Record every nonpublic feed, package, service connection, or signing dependency found.

### User and Credential State

- Use dedicated, authorized test identities and tenants.
- Do not embed personal account names, tenant details, screenshots, tokens, or policy
  output in committed evidence.
- For WAM, OS-account, Windows-helper, or other broker experiments, use a disposable
  operating-system user or VM whose broker contains only the dedicated test identities.
  If that environment is unavailable, do not run the broker experiment.
- An isolated home, cache, or configuration root is sufficient only for a non-broker
  experiment that cannot enumerate or use operating-system account state.
- WSL invocation of a Windows helper inherits the Windows-side broker boundary and
  therefore requires the same disposable Windows user or VM.
- Never point an experiment at an upstream production cache, keychain, keyring, registry
  value, PAT store, or installation path unless the experiment explicitly studies that
  store and has a read-only plan.
- Never copy refresh-token caches into the repository or session artifacts.

### Interaction and Telemetry

- Disable upstream remote telemetry through its documented controls before execution.
- When the behavior of the telemetry switch itself is under test, isolate network access
  and record only sanitized endpoint and field observations.
- Record which interactive surface is expected before running the experiment.
- Ensure the operator can identify and close WAM, browser, device-code, or terminal
  prompts created by the test.
- Do not run interactive experiments in CI or unattended sessions.

### Network and Resource Effects

- Prefer token acquisition and read-only resource probes.
- Do not create, delete, push, publish, revoke, or mutate remote resources unless that
  side effect is the explicit experiment subject.
- Do not create PATs as an incidental fallback.
- Bound every operation with a documented timeout and cleanup procedure.

## Authentication Experiment Records

Every committed authentication-experiment result must state the applicable fields below
and explicitly mark nonapplicable context when omission could change interpretation:

- source commit;
- v2 commit, if applicable;
- MSAL and native-broker versions;
- operating system, architecture, WSL version, and host type;
- sanitized account-state shape;
- client profile, authority class, scopes, and requested policy;
- cache and configuration isolation;
- telemetry and network controls;
- expected UI and typed result;
- observed UI and result;
- cleanup performed;
- reproduction count and known variability;
- whether the record is a source finding, runtime observation, inference, or hypothesis.

### Phase 1 Public-Build Record

Issue #1 public-build experiments use the YAML contract in
[`public-build-experiment-bundle.schema.json`](../../schemas/research/public-build-experiment-bundle.schema.json).
A narrow read-only preflight may capture the operating system, architecture,
`dotnet --info`, NuGet version, build entry point, and configuration before bundle
activation. It must not restore or resolve dependencies, access configured feeds, build,
test, package, or mutate source or user state.

After that preflight, create the first `planned` bundle under
`docs/research/experiments/` and validate its protocol before running any other issue #1
command. The same bundle carries the approved protocol, command-result matrix, observed
dependency inventory, conclusions, and limitations as the work progresses.

Use the bundle states as follows:

- `planned` contains the reviewed protocol and no command results;
- `in-progress` begins immediately before the first experiment command and records each
  bounded outcome without discarding failures;
- `aborted` preserves any partial results and records the triggered stop condition,
  cleanup outcome, reason, and sanitized evidence;
- `completed` contains the two restore modes, every required stage outcome, dependency
  inventory, conclusions, and explicit overall public-build outcome.

Each protocol command records a direct executable and ordered argument list and is run
without a shell wrapper. Restore commands have no command dependency. Each build, test, or
package command depends only on the restore for the same source mode and passes
`--no-restore` directly to the matching `dotnet` verb.

A `blocked` downstream command result identifies exactly the same-mode restore result that
blocked it. When a restore does not pass, every applicable downstream stage for that
source mode is blocked by that restore. Use `not-applicable` only when the target or stage
does not exist. Both statuses represent commands that were not executed and therefore
record a null exit code and zero reproductions.

Each resolved or unresolved dependency observation names the restore result, exact
retrieval source, access mode, and cache state that produced it. Treat a dependency as
publicly retrievable only when its public-only observation records anonymous access and
an empty cache. A `publicly-reproducible` outcome requires passing or not-applicable
public-only stage results, public-only resolved observations for every resolved and
source-declared dependency, and no unresolved edge in the public-only attempted graph. A
`not-publicly-reproducible` outcome requires an observed failed public-only stage or
unresolved public-only edge. An `inconclusive` outcome identifies the evidence
limitation; the contract does not mechanically decide whether contextual evidence is
sufficient.

The contract is limited to the public restore, build, test, and non-publishing package
work authorized by issue #1. It does not define a generic authentication-experiment
format, release SBOM, or v2 product protocol. Its dependency inventory records
issue-specific source and runtime observations, including unresolved edges that a release
SBOM cannot yet assert. Narrative research may synthesize the structured bundle but must
not maintain a second copy of its command results or dependency inventory.

## Stop Conditions

Stop the experiment if:

- a real token, code, credential, or private account detail would be recorded;
- a prompt appears in an unexpected session or cannot be identified;
- the process accesses an unplanned cache, keychain, keyring, registry path, or
  installation;
- a restore succeeds only because inherited credentials or package caches are present;
- cleanup ownership is unclear;
- continuing would mutate an unrelated remote resource.

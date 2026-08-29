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

- `planned` contains the reviewed protocol and audited source manifest, but no command
  results, runtime-observation conclusions, or restore graphs;
- `in-progress` begins immediately before the first experiment command and records each
  bounded outcome without discarding failures;
- `aborted` preserves any partial results and records the triggered stop condition,
  cleanup outcome, reason, and sanitized evidence;
- `completed` contains the two restore modes, every required stage outcome, dependency
  inventory, conclusions, and explicit overall public-build outcome.

The protocol declares build, test, and package applicability once for both source modes.
An inapplicable stage requires a reason and evidence reference; both mode results then use
`not-applicable`. An applicable stage cannot use that status.

The bundle records one typed Issue #1 isolation profile. It names canonical absolute
checkout, home, global-package, HTTP-cache, plugin-cache, and scratch roots; keeps every
isolation root outside the detached checkout; disables inherited user and machine NuGet
configuration, package-source credentials, credential providers, and credential-bearing
environment variables; and starts every cache empty. Each restore result records whether
those boundaries were verified. Detection of inherited configuration, credentials,
credential-provider execution, or a populated or unknown initial cache invalidates the
experiment and requires an `aborted` bundle rather than a completion conclusion.

Each protocol command records a direct executable and canonical ordered argument list and
is run without a shell wrapper. The list begins with the matching `dotnet` verb and the
audited `AzureAuth.sln` entry point. All commands run with the detached checkout root as
their working directory. Restore commands have no command dependency and use exactly the
configuration recorded for their source mode. Build, test, and package commands depend
only on the restore for the same mode, pass `--no-restore`, and use the recorded build
configuration.

The protocol records exactly two restore configurations. The source-faithful
configuration identifies the audited checkout's unmodified `nuget.config`; the
public-only configuration identifies the isolated generated file. Each record includes a
verified canonical path, symlink status, content hash, and the exact source identifiers it
contains. The source-faithful record is bound to the audited file hash and Office feed.
The public-only file must be outside the checkout, inside the isolated scratch root, and
byte-identical to the schema-defined configuration that clears inherited sources and
selects only the canonical NuGet.org v3 endpoint. Dependency graph nodes cite only the
source declared by the configuration used for their restore result.

A `blocked` downstream command result identifies exactly the same-mode restore result that
blocked it. When a restore does not pass, every applicable downstream stage for that
source mode is blocked by that restore. Use `not-applicable` only when the target or stage
does not exist. Both statuses represent commands that were not executed and therefore
record a null exit code and zero reproductions.

The protocol lists every solution project, target framework, SDK, and internal project
edge in the attempted target manifest. The dependency inventory lists all 38 external
package declarations at the audited commit, including the one environment-conditional
declaration. The checker canonicalizes those records and requires their manifest hash to
match the audited source.

Each executed restore records one normalized dependency graph per attempted project and
target framework. A graph binds the restore result and target to the source
`project.assets.json` hash, a canonical normalized-graph hash, every observed package
node, every resolved parent edge, every unresolved edge, and sanitized evidence. Root
edges cite their source declarations. Transitive edges cite their parent nodes. Every
node records its exact version, retrieval source, anonymous or credentialed access, and
initial cache state. A passing restore requires a complete graph with no unresolved edge.
The checker rejects missing target graphs, orphan nodes, incompatible direct versions,
and direct declarations without a resolved or unresolved root edge in either restore
mode.

A `publicly-reproducible` outcome requires passing or not-applicable public-only stage
results, a complete NuGet.org graph for every attempted target, anonymous empty-cache
provenance for every graph node, resolved root edges for every applicable source
declaration, and no unresolved public edge. A `not-publicly-reproducible` outcome requires
an observed failed public-only stage or unresolved public-only edge. An `inconclusive`
outcome identifies the evidence limitation; the contract does not mechanically decide
whether contextual evidence is sufficient.

A completed bundle also maps every audited public `Microsoft.Office.Lasso` source
reference to an apparent responsibility and supporting public evidence. The union of
those references must match the fixed audited reference-manifest hash. The analysis
records evidence gaps and bounded removal or replacement candidates, or an explicit
evidence-supported statement that no candidate is currently supported, without selecting
or implementing an option.

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

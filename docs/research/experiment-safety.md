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

- Disable upstream-product and experiment-tool telemetry through documented controls.
  Issue #1 commands set `DOTNET_CLI_TELEMETRY_OPTOUT=1`.
- Disable .NET first-run development-certificate generation, global-tool PATH
  registration, and workload-advertising downloads for Issue #1 commands.
- When the behavior of a telemetry switch is under test, isolate network access and
  record only sanitized endpoint and field observations.
- Record the expected interactive surface before execution.
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

Issue #1 public-build work uses the fixed strict-JSON authorities
[`public-build-source-baseline.json`](public-build-source-baseline.json) and
[`public-build-lasso-reference-manifest.json`](public-build-lasso-reference-manifest.json).
Their content hashes bind the audited payloads; their schemas and the repository checker
bind source identity independently. The repository owner's
[Issue #2 disposition](https://github.com/hcoona/microsoft-authentication-cli/issues/2#issuecomment-5463764986)
authorizes preparing those immutable public-source audits, their schemas, deterministic
checks, the planned-bundle contract, and synthetic fixtures during the governance
migration. It does not activate runtime Issue #1 work.

#### Runtime Activation Prerequisites

No Issue #1 restore, dependency-resolution, build, test, or package command may run until
all three prerequisites are recorded:

1. the Issue #2 governance change has merged into `main-v2`;
2. the repository owner has recorded that the Record-System Gate passed; and
3. the target branch's accepted `docs/project-state.md` authorizes Issue #1 runtime
   execution.

A narrow non-executing discovery step may inspect the operating system, architecture,
available .NET host and SDK files, NuGet version metadata, build entry point, and
configuration before activation. It must not invoke `dotnet` or NuGet, restore or resolve
dependencies, access configured feeds, build, test, package, or mutate source or user
state.

#### Planned Bundle

Before activation, the YAML schema
[`public-build-experiment-bundle.schema.json`](../../schemas/research/public-build-experiment-bundle.schema.json)
defines only a reviewed `planned` bundle. It records:

- bundle identity;
- Issue #1 plus the fixed source-baseline and Lasso-manifest hashes;
- the planned host and runtime identifier;
- one exact .NET 8 SDK identity and one exact repository runner identity;
- intended selection, checkout, mise data, and .NET installation roots;
- replacement-environment and exclusive, no-follow root-creation principles;
- the two source modes and the bounded restore, build, filtered-test, and selected-library
  package command topology;
- one attempt and a finite timeout for every command;
- retained raw-assets, strict parsing, extractor replay, provenance, and limitation
  requirements;
- exact identities for the extractor entry point and its repository-local NuGet-version
  component;
- the PCACache exclusion and its required limitation; and
- this policy reference.

The planned schema does not define command results, guards, runtime observations,
termination or stop-cause matrices, cleanup outcomes, receipts, dependency conclusions,
or completion conclusions. Those fields require a real runner and evidence carrier.

#### Runtime Activation Acceptance Criteria

The activation change must:

- pin one reviewed exact stable .NET 8 SDK in `mise.toml` and install it under a dedicated
  mise data root that is not reused by another bundle;
- add the repository-owned LF-normalized runner, use direct process creation without a
  shell, replace rather than inherit the child environment, enforce one attempt and the
  reviewed timeout, and keep occupied selection roots disjoint from every other occupied
  selection or toolchain root;
- expand or replace the planned-only schema with the runner-produced runtime evidence
  contract, set its machine-readable contract marker to `runtime`, bind each required
  runtime-semantic marker to a concrete schema location, and activate the bundle family
  and evidence control in the same change;
- require build, test, and package commands to use `--no-restore` after the corresponding
  recorded restore succeeds;
- define independent resolved or unresolved evidence for each applicable
  `package-backed-assembly` declaration, binding its declaration ID, condition, resolved
  package and version, evaluated property and `HintPath`, assembly-path existence, and
  reference-resolution result;
- select one canonical termination cause with optional structured detail instead of
  parallel stop-condition fields, and define the minimum receipt hash only after choosing
  whether the raw or embedded receipt is authoritative;
- prove process-tree quiescence on every normal, failed, cancelled, and timed-out exit;
  if quiescence cannot be proved, abort without destructive cleanup or releasing the
  selection root; and
- add blocking runner-conformance fixtures at local-fast and CI, including a case where
  the parent process exits normally while a grandchild remains alive.

The activation review must also choose how the runner records command results,
all-exit observations, cleanup evidence, and conclusions. The current planned contract
does not pre-authorize or mechanically close those semantics.

#### Bounded Command and Isolation Plan

The two source modes are:

- `source-faithful`, using the audited checkout's source configuration; and
- `public-only`, using an isolated configuration that clears inherited sources and
  selects only the canonical NuGet.org v3 endpoint.

Each mode plans one solution restore, one solution build depending on that restore, one
filtered solution test depending on that restore, and package commands for
`src/AdoPat/AdoPat.csproj`, `src/AzureAuth/AzureAuth.csproj`, and
`src/MSALWrapper.Benchmark/MSALWrapper.Benchmark.csproj`,
`src/MSALWrapper/MSALWrapper.csproj`, and `src/TestHelper/TestHelper.csproj`, each
depending on that restore. These are the five SDK projects in the fixed solution that do
not disable packing. The AzureAuth package attempt records the fixed source's missing
`AzureAuth.nuspec` as a failure if the file remains absent; it does not claim publish or
archive parity. Every downstream command uses `--no-restore`, one attempt, and a bounded
timeout. Tests exclude
`Microsoft.Authentication.MSALWrapper.Test.PCACacheTest`; therefore the evidence cannot
establish an unfiltered upstream test-suite pass or PCACache, keyring, Keychain, or DPAPI
behavior.

The replacement environment must not inherit ambient package credentials, caches,
proxies, startup hooks, MSBuild imports, or toolchain selection. The selection root is
created with exclusive, no-follow operations and contains the detached checkout and
isolated mutable state. The dedicated mise data and .NET installation roots remain
outside the selection root. Their final exact environment allowlist and command arguments
belong to the activation change and real runner contract.

One execution is one uninterrupted runner invocation. A later process must not resume
commands, delete the selection root, or release its reservation. The same invocation may
release the root only when it can prove either that the root was never successfully
created, or that its process tree is quiescent on the applicable exit path and current
ownership has been verified. Path absence observed by a later process is not transferable
cleanup authority.

#### Raw Assets, Extraction, and Provenance

A runtime restore conclusion that uses `project.assets.json` must retain the sanitized
file as exact bytes under `docs/research/experiments/assets/`. JSON parsing rejects
duplicate object keys. The retained file must pass its schema, match its recorded
SHA-256, and replay exactly through
`tools/extract_public_build_assets.py`.

The extractor is the sole authority for the resolved projection. The checker compares
the replayed output as a whole; it does not reimplement projection node identifiers,
edge identifiers, ordering, or constraint construction. The extractor continues to
validate the selected source project, target framework, applicable direct
`PackageReference` declarations, project references, resolved dependency topology, and
the bounded NuGet version and range grammar needed by the synthetic fixtures. Its
content identity includes both the extractor entry point and its repository-local
NuGet-version component, with LF-normalized checkout bytes.

Runtime provenance remains distinct from topology. Activation must bind each retained
raw asset to its command result and source mode, and bind each projected package to
sanitized retrieval-source, access, and initial-cache evidence. Exact extractor replay
does not prove network access, cache emptiness, credential-provider absence, or causal
attribution. It also does not prove that an MSBuild property and `HintPath` selected a
package-backed assembly. That declaration requires the separate activation-time evidence
defined above; `project.assets.json` may support its package and file observations but is
not the sole authority for reference resolution. The first real unsupported NuGet
constraint, or the first conclusion that
requires broader range evaluation, requires the Research maintainer and an independent
evidence reviewer to choose official NuGet semantics or an explicit bounded grammar. The
fallback is a partial limitation and no causal conclusion.

#### Conclusions and Lasso Analysis

Any eventual conclusion is bounded to the recorded host, source commit, toolchain,
source mode, commands, attempts, and sanitized evidence. A failure shared by both source
modes does not establish that public dependency resolution caused it. A transient or
unsupported condition remains inconclusive unless independent evidence supports a
stronger statement.

The fixed symbol-aware Lasso manifest remains the source-usage authority. Runtime work
must map its references to apparent responsibilities and public evidence before proposing
removal or replacement. That analysis may identify candidates but does not select or
implement one.

#### Non-Goals

This protocol does not define AzureAuth publish/archive release parity, a generic
authentication-experiment format, a release SBOM, a public product contract, or support
and compatibility commitments. Narrative research may synthesize future structured
evidence but must not maintain a second copy of command results or dependency inventory.

## Stop Conditions

Stop the experiment if:

- a real token, code, credential, or private account detail would be recorded;
- a prompt appears in an unexpected session or cannot be identified;
- the process accesses an unplanned cache, keychain, keyring, registry path, or
  installation;
- a restore succeeds only because inherited credentials or package caches are present;
- ownership or process-tree quiescence cannot be proved before cleanup;
- continuing would mutate an unrelated remote resource.

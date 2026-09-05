# AzureAuth V1 Public Contract Baseline

## Purpose and authority

This record is the public-source research authority for the caller-visible AzureAuth V1
baseline used by [Issue #25](https://github.com/hcoona/microsoft-authentication-cli/issues/25).
It preserves material promises, source behavior, defects, inferences, and unresolved
limits without converting V1 behavior into a V2 compatibility, support, architecture, or
release commitment.

The governing target-branch authority is `main-v2` commit
[`d09d357c3fee953740d4a7470f57c57da56bbf5d`](https://github.com/hcoona/microsoft-authentication-cli/commit/d09d357c3fee953740d4a7470f57c57da56bbf5d).
Its accepted
[Delivery Wave](https://github.com/hcoona/microsoft-authentication-cli/blob/d09d357c3fee953740d4a7470f57c57da56bbf5d/docs/delivery-wave.md#L18-L79)
authorizes fixed-scope V1 research, the three fired public-source rechecks, and
reconciliation of the canonical V2 requirements.

This record is evidence rather than product policy:

- required product behavior remains owned by the
  [V2 requirements](../product/requirements/);
- compatibility remains owned by the
  [compatibility and migration policy](../product/compatibility-and-migration.md);
- architecture selection remains owned by architecture and decision records; and
- evidence required before claiming support remains owned by the
  [validation strategy](../validation/strategy.md).

## Evidence boundary

### Fixed V1 source scope

The immutable V1 inputs are:

- audited upstream commit
  [`de20930c34b3b86c8a0ed7bbdeeca3f662dae918`](https://github.com/AzureAD/microsoft-authentication-cli/commit/de20930c34b3b86c8a0ed7bbdeeca3f662dae918);
- tag
  [`0.9.5`](https://github.com/AzureAD/microsoft-authentication-cli/tree/21258ff3a2cbb01d6891243114a55abe9ae3587e),
  commit `21258ff3a2cbb01d6891243114a55abe9ae3587e`;
- tag
  [`0.9.6`](https://github.com/AzureAD/microsoft-authentication-cli/tree/8ef1b8b00782bf20a51de078289819a79c3cba70),
  commit `8ef1b8b00782bf20a51de078289819a79c3cba70`;
- their public README, usage documentation, changelog, support material, command
  definitions, implementation, tests, installers, and release definitions; and
- the accepted V2 product, compatibility, architecture, validation, research, and
  governance records.

Fixed-source tests are source corroboration only. Mocked account, broker, cache, browser,
device-code, IWA, and platform tests do not establish real service or operating-system
behavior.

### Fired current-source scope

Current mutable evidence is limited to the sources named by the accepted
[recheck registry](rechecks.yaml):

- [`RECHECK-001`: AzureAuth issue #464](https://github.com/AzureAD/microsoft-authentication-cli/issues/464);
- [`RECHECK-002`: AzureAuth issue #465](https://github.com/AzureAD/microsoft-authentication-cli/issues/465); and
- [`RECHECK-007`: Microsoft Learn Azure DevOps Entra OAuth guidance](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/entra-oauth?view=azure-devops).

The recheck evaluation occurred on **2026-09-04 UTC**. At retrieval:

- issue #464 was open, unanswered, and had zero comments;
- issue #465 was open, unanswered, and had zero comments; and
- the Microsoft Learn page returned revision
  `f7bd73fbf08aed577f62dceb04fa31aa16643c19`, with
  `Last-Modified: 2026-05-08T17:05:00Z`.

These mutable facts are bounded to that evaluation time.

### Exclusions

There are no new runtime observations in this record. It makes no claim based on
executing AzureAuth, MSAL, broker, browser, device code, IWA, cache, installers,
migration, restore, build, tests, packaging, telemetry, or account access.

This record does not:

- freeze a V2 request, result, process, or wire contract;
- select an implementation Slice, platform matrix, mechanism, cache technology, or
  telemetry backend;
- implement or import upstream code;
- authorize a compatibility adapter, package, release, or experiment;
- claim current platform or account support; or
- expand the authentication core into PAT lifecycle, Git credential protocols, host
  adapters, confidential clients, service principals, managed identities, or workload
  identities.

## Evidence categories

Material statements are classified as:

- **Explicit public promise:** caller-facing documentation, command help, changelog,
  release, or support language.
- **Source finding:** behavior directly recoverable from the authorized source.
- **Inference:** a bounded interpretation needed to explain source composition, without
  treating intent as an enforced promise.
- **Known defect or workaround:** a contradiction, unsafe widening, lossy boundary, or
  source path that does not enforce its stated intent.
- **Unresolved empirical question:** behavior that authorized desk evidence cannot
  establish.

Confidence is high for direct fixed-source findings and documented public text.
Confidence in real provider, broker, host, secure-store, installer, or network effects is
not inferred from those materials.

## Executive conclusion

AzureAuth V1 publicly presents a cross-platform command-line wrapper around MSAL for
delegated public-client token acquisition and recommends subprocess integration as a
credential-provider boundary. Its caller surface includes:

- generic `aad` acquisition;
- Azure DevOps token and PAT commands;
- command-line, alias, and environment inputs;
- cache persistence and clearing;
- multiple acquisition mechanisms;
- raw-token, status, and JSON output;
- diagnostics and telemetry configuration;
- platform-specific installers and packages; and
- upstream support and operational identities.

The fixed source contains useful mechanism integrations and platform knowledge, but does
not define the deterministic machine contract required by V2:

- domain-based account selection is advisory rather than strict;
- caller acquisition order is discarded;
- broker silent and interactive work are combined;
- no-interaction policy is ambient and not independently enforced;
- fallback is driven by broad failure rather than typed retryability;
- claims retry loses the selected account;
- lock waiting, acquisition timeout, and cancellation do not form one lifecycle;
- authoritative provider result metadata is discarded;
- access-token claims are used to reconstruct identity;
- output and failures are unversioned and lossy;
- secure-cache failure may silently select plaintext or process-local state; and
- upstream telemetry, build dependencies, installation identities, and Azure DevOps PAT
  behavior cannot be inherited by the unofficial V2 product.

`RECHECK-001` and `RECHECK-002` confirm that current upstream public evidence does not
weaken the accepted V2 interaction or account requirements. `RECHECK-007` records current
guidance but does not satisfy the prerequisite for selecting or distributing the
Microsoft-owned Azure DevOps profile.

## Caller-visible V1 surface

This inventory establishes coverage of Issue #25 without creating a universal
traceability database.

### Commands

The fixed command hierarchy is:

- `azureauth`, a help-only root;
- `azureauth aad`, generic delegated public-client acquisition and cache clearing;
- `azureauth ado`, a help-only grouping command;
- `azureauth ado token`, Azure DevOps token or PAT selection and formatting;
- `azureauth ado pat`, PAT creation, caching, and reuse;
- `azureauth ado pat scopes`, static PAT-scope listing;
- `azureauth info`, assembly version and upstream telemetry device ID; and
- `azureauth info reset-device-id`, upstream telemetry-identifier reset.

The root and grouping behavior is established by the
[root command](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAzureAuth.cs#L15-L27)
and
[`ado` command](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAdo.cs#L11-L24).

### Generic `aad` inputs

The declared options are:

- `--resource`;
- `--client`;
- `--tenant`;
- `--prompt-hint`;
- repeatable `--scope`;
- `--clear`;
- `--domain`;
- repeatable `--mode`;
- `--output`;
- `--alias`;
- `--config`; and
- `--timeout`.

Their declarations are recoverable from
[`CommandAad`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L146-L217).

The complete rendered help, inherited framework options, parser diagnostics, and ordinary
process-exit propagation are not fully recoverable because hosting is partly owned by the
unavailable `Microsoft.Office.Lasso` dependency.

### Ambient inputs

Material environment-controlled behavior includes:

- `AZUREAUTH_CONFIG`;
- `AZUREAUTH_MODE`;
- `AZUREAUTH_NO_USER`;
- `Corext_NonInteractive`;
- `OEAUTH_MSAL_DISABLE_CACHE`;
- `BROWSER`;
- `AZUREAUTH_ADO_PAT`;
- `SYSTEM_ACCESSTOKEN`;
- `TF_BUILD`;
- `AZUREAUTH_APPLICATION_INSIGHTS_INGESTION_TOKEN`;
- installer-specific `AZUREAUTH_*` settings; and
- environment names supplied to upstream telemetry.

These names and their V1 precedence are compatibility facts, not native V2 defaults.

### Output and process surface

V1 exposes:

- AAD `status`, `token`, `json`, and `none` output modes;
- PAT `none`, `status`, `token`, `base64`, `header`, `headervalue`, and `json` modes;
- predominantly `0` and `1` command-handler results;
- a hard-coded SIGINT exit of `2`;
- intended separation of token stdout from warning/error diagnostics; and
- framework-owned parser, logging, and process-exit behavior that is not completely
  visible in the fixed repository.

## Product, command, and compatibility findings

### Delegated public-client and subprocess boundary

**Evidence type:** Explicit public promise.
**Confidence:** 10/10 for the documented V1 purpose.

V1 promises delegated public-client access-token acquisition and recommends invoking the
CLI as a subprocess to isolate callers from authentication-library dependencies and
change.
[README](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/README.md#L10-L24),
[usage](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/docs/usage.md#L102-L129).

**Disposition:** Delegated public-client authentication is retained by `V2-REQ-001`.
`V2-REQ-004` now defines one machine request and one terminal outcome per native
authentication process. Subprocess isolation does not require V1 command or wire
compatibility.

### Command hierarchy and stale integration example

**Evidence type:** Source finding plus known defect/workaround.
**Confidence:** 10/10.

The root command became help-only before the audited baseline, but the published Python
example still invokes authentication options at the root.
[example](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/examples/python/azureauth.py#L7-L28),
[changelog](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/CHANGELOG.md#L93-L102).

The fixed-source workaround is to insert `aad` after the executable. No execution is
needed to establish the source contradiction.

**Disposition:** V1 command names and hierarchy are compatibility-only. Do not copy the
stale invocation into native V2 documentation. A compatibility adapter would need to
satisfy the compatibility-adapter gate before acceptance.

### Platform and mechanism promises

**Evidence type:** Explicit public promise.
**Confidence:** 10/10 for documentation; no runtime confidence is inferred.

V1 claims Windows, macOS, and Ubuntu support and documents cache, IWA, broker, browser,
and device-code combinations.
[README](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/README.md#L14-L24).

**Disposition:** These promises are inputs to the
[Real Environment Tests](../validation/strategy.md#real-environment-tests) and platform
evidence in the validation strategy. They do not establish that V2 supports the same
combinations or that every V1 matrix cell works.

## Request, authority, profile, and precedence findings

### Request fields and precedence

**Evidence type:** Source finding with test corroboration.
**Confidence:** 10/10.

The generic request surface carries client, tenant, scopes derived from either resource
or explicit scopes, optional preferred domain, prompt hint, mode flags, timeout, output
preference, and alias values. It has no explicit authority-host, tenant-policy, stable
account constraint, interaction policy, host context, or ordered acquisition-stage
field.

Explicit command values override non-null alias values. Explicit command modes override
`AZUREAUTH_MODE`, which otherwise supplies comma-separated ambient defaults.
[alias merge](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Alias.cs#L43-L63),
[environment parsing](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/IEnvExtensions.cs#L42-L71).

**Disposition:** Retain the concepts under `V2-REQ-010`, `V2-REQ-011`, and
`V2-REQ-017`. V1 option names, TOML structure, and ambient-variable names remain
compatibility-only.

### Resource and scope contradiction

**Evidence type:** Explicit public promise plus known defect/workaround.
**Confidence:** 10/10.

Usage says client, resource, and tenant are always required. The implementation instead
requires client, tenant, and either resource or one or more scopes. Resource is converted
to `<resource>/.default`; explicit scopes supersede resource with a warning.
[usage](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/docs/usage.md#L64-L70),
[source](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L293-L304).

**Disposition:** `V2-REQ-011` owns required application and resource/scope identity.
Resource shorthand, explicit-scope precedence, and invalid combinations require an
explicit native request-contract disposition rather than inheritance from V1.

### Client, tenant, and authority validation

**Evidence type:** Source finding.
**Confidence:** 10/10 for source shape; real MSAL authority handling is not inferred.

The CLI checks the client and tenant for nonemptiness. Client conversion to `Guid` occurs
later. Tenant remains a string appended beneath fixed host
`https://login.microsoftonline.com/`; the CLI does not expose an arbitrary authority
host.
[request object](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthParameters.cs#L12-L47),
[authority construction](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Web.cs#L97-L112).

**Disposition:** Retain `V2-REQ-011`, `V2-REQ-011A`, and typed invalid-request behavior
under `V2-REQ-032`. Native V2 must define trusted-cloud, tenant-policy, and
malformed-input handling explicitly.

### Built-in Azure DevOps profile

**Evidence type:** Source finding.
**Confidence:** 10/10 for identifiers and command wiring; no account-support confidence
is inferred.

The V1 Azure DevOps path embeds:

- client `872cd9fa-d31f-45e0-9eab-6e460a02d1f1`, described as "Visual Studio 2019 and
  earlier";
- Azure DevOps scope `499b84ac-1321-427f-aa17-267ca6975798/.default`;
- a Microsoft tenant default; and
- preferred domain `microsoft.com`.

[constants](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Ado/Constants.cs#L13-L60),
[profile construction](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Ado/AuthParameters.cs#L7-L18).

**Disposition:** The identifiers are nonsecret configuration and recoverable V1
compatibility evidence. They map to `V2-REQ-042` and the externally owned client-profile
gate. They do not establish current owner-approved reuse, account-type support, or
availability. `V2-REQ-018` defines generic deterministic profile selection but does not
make this candidate an available profile.

## Account and interaction findings

### Account selection is advisory

**Evidence type:** Explicit public promise, source finding, and known defect.
**Confidence:** 10/10 for the source contract.

`--domain` is explicitly described as a preferred cached-account filter. Source matching
uses a case-insensitive username suffix rather than a provider-native stable identifier.
No account, no matching account, and multiple matching accounts collapse to `null`.
[help](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L72-L80),
[lookup](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L150-L180).

On Windows broker paths, that `null` becomes
`PublicClientApplication.OperatingSystemAccount`, widening absence or ambiguity to
OS-account acquisition.
[broker resolution](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L119-L142).

Device-code and IWA paths do not enforce a returned-identity match against the preferred
domain.

**Disposition:** Retain without weakening:

- `V2-REQ-012`, requiring stable provider identifiers and limiting username/domain to
  hints;
- `V2-REQ-017`, preserving caller intent;
- `V2-REQ-020`, exact selected-account silent acquisition;
- `V2-REQ-022`, strict account, tenant, authority, and client postconditions;
- `V2-REQ-023`, terminal mismatch or unvalidated success; and
- `V2-REQ-031` and `V2-REQ-032`, authoritative identity metadata and typed absence,
  ambiguity, and mismatch.

The V1 nullable selector, domain-suffix matching, and OS-account widening must not be
reused as V2 policy.

### Acquisition modes discard caller order

**Evidence type:** Source finding and known defect.
**Confidence:** 10/10.

`AuthMode` is a flag set. Repeated modes are combined using bitwise OR, discarding
textual order. The factory imposes cache, IWA, broker, web, and device-code ordering and
may inject cache even when the caller selected a different mechanism.
[mode combination](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthMode.cs#L124-L133),
[factory](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/AuthFlowFactory.cs#L38-L87).

**Disposition:** Replace under `V2-REQ-013` and `V2-REQ-017`. Cache-first behavior may be
represented by an explicit requested stage or accepted profile default, but must not be
injected invisibly.

### Broker combines silent and interactive policy

**Evidence type:** Source finding plus bounded inference.
**Confidence:** 10/10 for sequencing.

Broker resolves an account, attempts silent acquisition, and proceeds to interactive
broker acquisition after a miss. One reported broker attempt therefore contains two
policy-distinct stages.
[broker](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L78-L116).

The bounded inference is that V1 was optimized for broad human-oriented fallback rather
than exact caller-controlled stage policy.

**Disposition:** Retain `V2-REQ-014`, `V2-REQ-020`, and `V2-REQ-021`. Mechanism-level
calls may be adapted behind separate V2 silent and interactive stages; the composite V1
policy contract must not be reused.

### No-interaction policy is not independent

**Evidence type:** Explicit public promise, source finding, known defect, and completed
`RECHECK-001`.
**Confidence:** 10/10 for the source and current named-source disposition; no UI
occurrence is claimed.

V1 derives noninteractive behavior from `AZUREAUTH_NO_USER` or
`Corext_NonInteractive`, not from a per-request interaction-policy field. On Windows the
filter replaces requested modes with IWA rather than preserving broker-backed silent
acquisition. On non-Windows builds the broker flag can survive, while the composite
broker source can proceed from a silent miss to the interactive operation.
[environment control](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/IEnvExtensions.cs#L31-L40),
[filter](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/AuthModeExtensions.cs#L15-L42).

At the 2026-09-04 recheck,
[upstream issue #464](https://github.com/AzureAD/microsoft-authentication-cli/issues/464)
remained an open, unanswered request for independent interaction permission and a
machine-distinguishable interaction-required result. The authorized source set contained
no current documented upstream contract that preserves silent-capable mechanisms while
guaranteeing no UI.

**Disposition:** `RECHECK-001` is completed with no weakening. Retain:

- `V2-REQ-014`, independent interaction permission;
- `V2-REQ-020`, exact-account silent-first behavior;
- `V2-REQ-021`, an absolute no-user-interface guarantee;
- `V2-REQ-023`, typed retryable and terminal fallback; and
- interaction-required or blocked categories in `V2-REQ-032`.

Do not reuse the global environment filter or combined broker orchestration as the V2
interaction contract.

### Fallback lacks typed retryability

**Evidence type:** Source finding and known defect.
**Confidence:** 10/10.

The executor advances after any attempt without a token rather than after an outcome
explicitly classified as retryable. A small set of exceptions is captured, other
exceptions may escape, and broker unavailability is represented by omission or
fall-through. A non-null token stops the chain even when prior errors exist.
[flow base](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/AuthFlowBase.cs#L19-L55),
[executor](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/AuthFlowExecutor.cs#L57-L87).

**Disposition:** Retain `V2-REQ-023` and `V2-REQ-032`. Replace exception-driven
fall-through with stable caller-action classifications. Cancellation, denial, identity
mismatch, and failure to validate reported success remain terminal.

### Claims retry loses account continuity

**Evidence type:** Source finding and known defect.
**Confidence:** 10/10.

Web and broker retry after `MsalUiRequiredException` without requiring a semantically
classified claims challenge. The claims overload constructs a new interactive request
with scopes and claims but does not preserve the selected account.
[web retry](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Web.cs#L55-L78),
[claims overload](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L86-L135).

**Disposition:** Retain `V2-REQ-015`, `V2-REQ-022`, and `V2-REQ-024`. Claims retry must
require a real claims challenge and preserve account, tenant, authority, interaction, and
deadline constraints.

### Deadline, cancellation, and locking are separate lifecycles

**Evidence type:** Explicit public promise, source finding, inference, and known defect.
**Confidence:** 10/10 for timer and lock topology; no real prompt-cleanup behavior is
inferred.

The public timeout is described as an allowed-runtime contract, but acquisition first
waits under a separate fixed 15-minute named mutex. The requested timeout starts after
that wait.
[usage](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/docs/usage.md#L121-L127),
[wrapper](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/MsalWrapper.cs#L35-L68).

Individual operations use separate timers. `TaskExecutor` may request cancellation and
return without proving the underlying operation stopped. Global timeout does not pass
cancellation into the active flow or join it before returning.
[task executor](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/TaskExecutor.cs#L27-L54),
[global executor](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/AuthFlowExecutor.cs#L92-L144).

The mutex may therefore be released without source proof that prior controlled work has
terminated. SIGINT bypasses cooperative cancellation and calls `Environment.Exit(2)`.

**Disposition:** Retain `V2-REQ-015`, `V2-REQ-025`, and timeout and cancellation
categories in `V2-REQ-032`. The named-lock concept is architecture evidence only.

`V2-REQ-026` is now a retirement marker targeting `V2-REQ-041`. Shared-state locking and
update integrity remain required, while suppressing duplicate interaction across
separate CLI processes is not a product commitment.

### Host and mechanism ownership

**Evidence type:** Explicit public promise and source finding.
**Confidence:** 10/10 for source construction; no real-host result is inferred.

Windows broker derives a parent handle from the process console and root owner without
accepting caller-provided host context or rejecting a zero handle. macOS broker uses a
fixed redirect, Company Portal gate, and main-thread scheduler. Linux browser acquisition
invokes `$BROWSER` when set and otherwise delegates URI opening through shell execution.
Device code writes the provider message through the warning channel. IWA supplies
neither a strict account nor returned-identity check.
[Windows broker](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L193-L244),
[Linux browser launcher](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L189-L207),
[device code](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/DeviceCode.cs#L51-L102).

No distinct WSL host model appears in the fixed source.

**Disposition:** Retain `V2-REQ-016`, `V2-REQ-021`, `V2-REQ-022`, `V2-REQ-025`, and
`V2-REQ-032`. Mechanism call patterns are architecture inputs, not support evidence.
Support claims remain governed by the
[Real Environment Tests](../validation/strategy.md#real-environment-tests).

`V2-REQ-016` now requires V2 to establish validated host context from process-owned
capabilities or the selected profile. The native request does not require an external UI
owner or raw platform handle; combinations that cannot establish safe ownership without
such integration remain unsupported.

## Result and process findings

### Authoritative result metadata is discarded

**Evidence type:** Source finding and known defect.
**Confidence:** 10/10.

`PCAWrapper` receives an MSAL `AuthenticationResult` but retains only the access token
and correlation ID. Provider account, home-account identifier, tenant, authority, granted
scopes, token type, client, and other acquisition metadata are discarded.
[result reduction](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L209-L217).

`TokenResult` parses the access token as a JWT and derives user, display name, SID, and
expiry from token claims.
[token result](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/TokenResult.cs#L12-L77).

**Disposition:** Retain `V2-REQ-022`, `V2-REQ-030`, `V2-REQ-031`, and `V2-REQ-033`.
Provider identity and acquisition metadata must be preserved before access-token
handling, and access tokens must remain opaque.

### `RECHECK-002`: strict account and result validation

**Evidence type:** Current public source, fixed source, bounded inference, and public
reported observation.
**Confidence:** 10/10 for the source contract and no-change disposition.

At the 2026-09-04 recheck,
[upstream issue #465](https://github.com/AzureAD/microsoft-authentication-cli/issues/465)
remained open and unanswered. It reports that AzureAuth on Windows could silently return
the operating-system account despite a different preferred domain. That real-host
behavior is a reporter observation and was not independently reproduced.

The reuse decision does not depend on reproducing that observation. Fixed source
independently establishes advisory suffix filtering, ambiguity collapse, OS-account
widening, token-only success, and absence of an authoritative result postcondition.

**Disposition:** `RECHECK-002` is completed with no weakening. Retain:

- `V2-REQ-012` and `V2-REQ-017`;
- `V2-REQ-020`, `V2-REQ-022`, and `V2-REQ-023`;
- complete identity metadata under `V2-REQ-031`; and
- typed absence, ambiguity, and mismatch outcomes under `V2-REQ-032`.

Do not reuse V1 account resolution, OS-account fallback, token-derived identity, or
"nonempty token equals success" as V2 contract behavior. Mechanism-level MSAL calls may
be adapted only behind V2 account and result validation.

### JSON and status output are lossy

**Evidence type:** Source finding and known defect.
**Confidence:** 10/10.

AAD JSON contains only `user`, `display_name`, `token`, and string-form expiration. It
has no protocol version or typed status and omits tenant, authority, client, stable
provider account ID, scopes/resource, token type, mechanism, and silent/interactive
classification. It is created through manual interpolation without a JSON-escaping step
for claim-derived strings.
[serialization](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/TokenResult.cs#L88-L102).

The human status output always says the token cache is warm, even when source flow
selection does not establish a cache hit.
[status](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/TokenResult.cs#L79-L86).

**Disposition:** Retain `V2-REQ-030`, `V2-REQ-031`, and `V2-REQ-034`. Native V2 must use
schema-backed serialization and accurate acquisition metadata. V1 JSON and status text
remain compatibility-only; the inaccurate cache-warm status is a drop candidate.

### Failure and process status are collapsed

**Evidence type:** Source finding.
**Confidence:** 10/10 for handler values; exact ordinary process propagation remains
unresolved.

Invalid request, exhausted acquisition, null result, timeout, provider failure, cache
failure, and caught exception generally converge on handler value `1`. SIGINT directly
exits `2`.
[command handler](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L314-L331),
[failure path](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L384-L424),
[SIGINT](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Program.cs#L131-L137).

`MainInner` calls the Lasso host without returning or assigning its execution result. The
fixed repository therefore does not establish exact process status for handler returns,
parse failures, enum conversion, unknown options, or unhandled exceptions.
[host call](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Program.cs#L123-L138).

**Disposition:** Retain `V2-REQ-004`, `V2-REQ-030`, and `V2-REQ-032`. V1 numeric exits
and framework behavior are compatibility-only. Native V2 requires one terminal result
and deterministic typed-result-to-exit mapping.

### Output, diagnostics, and secret channels

**Evidence type:** Source finding and unresolved implementation limit.
**Confidence:** High for application call sites; lower for unavailable Lasso behavior.

Program comments and configuration intend token output on stdout and warnings or errors
on stderr, but private Lasso behavior controls parts of routing, formatting, buffering,
and persistence.
[program configuration](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Program.cs#L113-L121).

Device-code text is emitted through the warning channel. Telemetry and debug paths
collect request identifiers, cached usernames, correlation data, and recursively
serialized raw exception messages without an application-owned redaction guarantee.
[device-code path](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/DeviceCode.cs#L52-L101),
[telemetry conversion](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/AuthFlowResultExtensions.cs#L39-L64).

The source does not prove that a secret was emitted, but it does not provide the V2
containment guarantee.

**Disposition:** Retain `V2-REQ-034` and `V2-REQ-035`. Human interaction and ordinary
diagnostics require explicitly owned channels. Secret-bearing content must not pass
through logs, telemetry, crash output, process arguments, or unrelated result fields.

## Cache, state, and coordination findings

### Cross-platform cache promise and secure-store attempt

**Evidence type:** Explicit public promise and source finding.
**Confidence:** 10/10 for the promise and source setup; no persistence success is
inferred.

V1 claims token caching on Windows, macOS, and Ubuntu, including headless Linux. Source
configures MSAL Extensions persistence for platform secure stores, verifies persistence,
and then registers the cache.
[README](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/README.md#L14-L24),
[cache setup](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L64-L84).

**Disposition:** Retain `V2-REQ-040` and `V2-REQ-045`. Real persistence and
cross-invocation support claims remain governed by the
[Real Environment Tests](../validation/strategy.md#real-environment-tests).

### Headless Linux silently falls back to plaintext

**Evidence type:** Source finding and known policy defect.
**Confidence:** 10/10.

After a persistence exception, headless Linux is inferred solely from missing `DISPLAY`
and `WAYLAND_DISPLAY`. V1 then creates or reuses an unprotected file under
`~/.azureauth` and registers it through `WithUnprotectedFile`. Permission-hardening
failure produces warnings but does not prevent use.
[fallback](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L85-L155),
[permissions](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/LinuxHelper.cs#L40-L85).

**Disposition:** This directly supports `V2-REQ-040` and `V2-REQ-045`. Drop V1's
implicit plaintext fallback. Any plaintext mode would require separately accepted policy
and must never be selected silently.

### Cache-disabled and persistence-failure behavior is untyped

**Evidence type:** Source finding plus bounded inference.
**Confidence:** 9/10.

Any nonempty `OEAUTH_MSAL_DISABLE_CACHE` value skips cache registration. On some
non-headless persistence failures, source logs and records the exception but continues
without selecting another persistent mode. The bounded inference is that acquisition can
continue with only process-local MSAL state, while callers receive no storage-mode result.
[cache setup](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L59-L105).

**Disposition:** Retain `V2-REQ-040` and cache failure in `V2-REQ-032`. Native policy
must distinguish an accepted nonpersistent mode, secure-store unavailability, policy
rejection, and cache failure.

### Namespace and lifecycle semantics are incomplete

**Evidence type:** Source finding and unresolved dependency limit.
**Confidence:** 9/10.

Application-visible cache names are at most tenant-scoped and use upstream
`.IdentityService` and `.azureauth` namespaces. The application does not define a
complete contract for atomic update, corruption, logout, migration, or incompatible
versions. A Linux keyring attribute named `Version=1` is not an application-level
version dispatcher.
[configuration](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L22-L56).

MSAL Extensions behavior absent from the fixed repository is not inferred.

**Disposition:** Retain `V2-REQ-041` and `V2-REQ-044`. Cache technology, serialization,
and dependency-specific locking remain architecture and validation concerns. V2 has no
V1 importer and must not read, modify, delete, take over, or otherwise own V1 cache or
configuration state.

### Cache clearing is not a transactional logout

**Evidence type:** Explicit public promise and source finding.
**Confidence:** 10/10.

`--clear` promises to clear the cache for the supplied AAD application. It constructs a
PCA, enumerates accounts, removes them one at a time, and logs each username. It does not
delete the containing store and does not run under the acquisition mutex.
[clear option](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L176-L180),
[implementation](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L366-L381).

V1 uninstall removes installation and PATH state but does not promise authentication-state
cleanup.

**Disposition:** Retain logout, namespace, and lifecycle semantics under `V2-REQ-041`.
V1 clearing syntax is compatibility-only. The
[compatibility policy](../product/compatibility-and-migration.md#migration-rules)
provides no V1 importer: V2 must not read, modify, delete, migrate, take over, or own V1
configuration, aliases, account records, token caches, credentials, PATs, telemetry
configuration, or device identifiers.

## Telemetry and diagnostics findings

### Network telemetry promise and unavailable backend semantics

**Evidence type:** Explicit public promise, source finding, and unresolved implementation
limit.
**Confidence:** 8/10 overall; 10/10 for application configuration.

README says network telemetry is off unless an Application Insights ingestion token is
supplied through an environment variable or upstream Windows registry path.
[README](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/README.md#L96-L109).

Program always constructs Lasso telemetry. Without a configured token it selects a dummy
token and `StandardOut`; with a token it selects Application Insights and asynchronous
delivery.
[configuration](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Program.cs#L62-L121).

The fixed source does not contain Lasso transport, serialization, persistence, privacy,
flushing, or shutdown behavior. "Telemetry off" therefore supports only the documented
network-export statement; it does not establish absence of local output or delayed
completion.

**Disposition:** `V2-REQ-046` now requires optional telemetry, disables network export
unless explicitly configured, and prevents export or bounded-flush failure from changing
the authentication result, process status, retry, fallback, interaction, or finite
termination. `V2-REQ-035`, `V2-REQ-043`, and `V2-REQ-044` continue to govern secret
containment and independent identity. OpenTelemetry remains a later architecture choice.

### Collected telemetry and diagnostic fields

**Evidence type:** Source finding and security limitation.
**Confidence:** 10/10 for call-site collection.

Command telemetry records client, resource, tenant, prompt hint, and scopes. Per-flow
telemetry includes flow name, success, duration, recursively serialized exception
messages, correlation ID, token validity, and silent status. Debug paths include cached
usernames and provider exception messages.
[command telemetry](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L314-L331),
[flow telemetry](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/AuthFlowResultExtensions.cs#L39-L64).

**Disposition:** Retain `V2-REQ-034`, `V2-REQ-035`, `V2-REQ-043`, and `V2-REQ-046`. V2
diagnostics and telemetry require fork-owned schemas, redaction, identity, and lifecycle
behavior.

### Upstream telemetry device identity

**Evidence type:** Source finding.
**Confidence:** 9/10.

`azureauth info` obtains and displays a Lasso telemetry device ID;
`reset-device-id` asks Lasso to delete it. Its storage, generation, collision, and
uninstall semantics are not visible in the fixed repository.
[info](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandInfo.cs#L17-L41),
[reset](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/Info/CommandInfoResetDeviceID.cs#L13-L30).

**Disposition:** Drop the upstream identifier under `V2-REQ-043` and `V2-REQ-044`; never
import it. Any fork-owned telemetry identity must follow the accepted independent
operational-identity requirements.

## Azure DevOps consumer findings

### `ado token` mixes authentication and consumer policy

**Evidence type:** Source finding.
**Confidence:** 10/10.

`ado token` combines a built-in Azure DevOps profile with:

- PAT precedence from `AZUREAUTH_ADO_PAT` and `SYSTEM_ACCESSTOKEN`;
- pipeline detection through `TF_BUILD`;
- refusal of interactive fallback in selected pipeline conditions;
- fallback to delegated AAD acquisition; and
- raw token, header, and header-value formatting.

[command](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/Ado/CommandToken.cs#L20-L145),
[PAT environment source](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Ado/PatFromEnv.cs#L36-L63).

PAT material from the environment is passed through a logging call. The unavailable
logging implementation prevents a stronger persistence claim, but this is at least a
secret-channel risk.

**Disposition:** Pipeline policy, PAT selection, and HTTP header formatting are
downstream consumer concerns outside the authentication core under `V2-REQ-002`. Secret
containment remains governed by `V2-REQ-035`.

### PAT creation and lifecycle

**Evidence type:** Explicit public promise, source finding, and known defect.
**Confidence:** 10/10.

`ado pat` validates organization, display name, scope, and prompt hint; enforces or
bypasses a static scope list; creates and caches PATs; and applies seven-day validity and
two-day renewal thresholds.
[usage](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/docs/usage.md#L142-L160),
[manager](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AdoPat/PatManager.cs#L20-L88).

PAT output includes raw token, base64, header, header value, status, JSON, and `none`.
The `none` formatter returns an empty string, but the command still calls
`Console.WriteLine`, emitting a newline.

**Disposition:** PAT lifecycle is explicitly unsupported in the V2 authentication core
under `V2-REQ-002`. A separate PAT product would require its own accepted product,
security, lifecycle, support, and migration authorities. V1 output formats remain
compatibility-only.

## Installation, release, support, and operational-identity findings

### Upstream operational identities

**Evidence type:** Source finding.
**Confidence:** 10/10.

Upstream-visible identities include:

- executable `azureauth`;
- package `microsoft.authentication.azureauth`;
- Microsoft root namespaces;
- installation roots such as `%LOCALAPPDATA%\Programs\AzureAuth`, `~/.azureauth`, and
  `/usr/bin/azureauth`;
- cache roots `.IdentityService` and `.azureauth`;
- upstream environment-variable prefixes;
- registry path `SOFTWARE\Microsoft\AzureAuth`;
- lock names; and
- telemetry namespace `azureauth`.

**Disposition:** These are compatibility facts, not reusable defaults. Retain
`V2-REQ-003`, `V2-REQ-043`, and `V2-REQ-044`, plus the
[side-by-side compatibility policy](../product/compatibility-and-migration.md#side-by-side-first).

### Installation and package surface

**Evidence type:** Explicit public promise and source finding.
**Confidence:** 10/10 for installer and release definitions; no installed behavior is
inferred.

V1 publishes exact-version installation paths for:

- Windows x64 and arm64 ZIP artifacts, with user-PATH updates by default;
- macOS x64 and arm64 tarballs, with shell-profile updates by default; and
- Linux x64 and arm64 Debian packages installed through `sudo dpkg -i`.

The release definition targets self-contained `net8.0` artifacts for all six
platform/architecture combinations.
[release matrix](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/.azuredevops/release.yml#L9-L47),
[artifact definitions](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/.azuredevops/release.yml#L355-L480).

Bootstrap scripts download release artifacts without an application-level checksum or
digest-verification step. That statement does not assess GitHub transport or external
signing.

**Disposition:** Installer behavior and artifact names are compatibility-only. Packaging
knowledge is an architecture input. `V2-REQ-044` requires independent operational
identity, and platform support remains governed by the
[Real Environment Tests](../validation/strategy.md#real-environment-tests).

### Public build dependency boundary

**Evidence type:** Source finding.
**Confidence:** 10/10.

The audited `nuget.config` clears package sources and selects a credentialed Office Azure
Artifacts feed. `AzureAuth.csproj` directly references `Microsoft.Office.Lasso`.
[NuGet configuration](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/nuget.config),
[project](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/AzureAuth.csproj#L28-L35).

This is a source finding only. It does not repeat or extend any runtime build
observation.

**Disposition:** Retain `V2-REQ-053`. V2 restore, build, test, and packaging must use
publicly retrievable dependencies and fork-owned infrastructure. Hosting, environment
access, logging, diagnostics, and telemetry responsibilities currently associated with
Lasso require removal, replacement, or isolation through a separately selected
architecture.

### Release-documentation inconsistencies

**Evidence type:** Known defect/workaround.
**Confidence:** 10/10.

At tag `0.9.5`, the README badge still advertises `0.9.2`. At tag `0.9.6`, the README
and installation examples still identify `0.9.5`, while the changelog places the macOS
broker and dependency changes under "Unreleased."
[0.9.5 README](https://github.com/AzureAD/microsoft-authentication-cli/blob/21258ff3a2cbb01d6891243114a55abe9ae3587e/README.md#L1-L5),
[0.9.6 README](https://github.com/AzureAD/microsoft-authentication-cli/blob/8ef1b8b00782bf20a51de078289819a79c3cba70/README.md#L1-L5),
[0.9.6 changelog](https://github.com/AzureAD/microsoft-authentication-cli/blob/8ef1b8b00782bf20a51de078289819a79c3cba70/CHANGELOG.md#L7-L20).

**Disposition:** Bind compatibility evidence to exact tag commits rather than badges or
changelog section names.

### Upstream support statement

**Evidence type:** Explicit public promise.
**Confidence:** 10/10.

V1 directs support through the Microsoft-owned upstream repository.
[support policy](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/SUPPORT.md#L3-L13).

**Disposition:** This is historical V1 context only. `V2-REQ-003` prohibits implying an
official Microsoft release, upstream support, or ownership of a Microsoft registration.

## Fixed-version deltas

### `0.9.5` to `0.9.6`

The material caller-visible change is opt-in macOS Enterprise SSO broker integration.
Non-Windows `AuthMode` gains broker; source adds Company Portal/version checks and
main-thread scheduling; and MSAL and native-interoperability dependencies change.
[Fixed comparison](https://github.com/AzureAD/microsoft-authentication-cli/compare/21258ff3a2cbb01d6891243114a55abe9ae3587e...8ef1b8b00782bf20a51de078289819a79c3cba70).

This is an explicit documentation and source delta. It does not establish real macOS
broker availability, MDM behavior, account selection, cancellation, or support.

### `0.9.6` to the audited baseline

Only project dependency declarations materially changed: cryptography packages were
updated and `OpenTelemetry.Api` was added. No command, option, output, installer, README,
usage, or release-definition source changed.
[Fixed comparison](https://github.com/AzureAD/microsoft-authentication-cli/compare/8ef1b8b00782bf20a51de078289819a79c3cba70...de20930c34b3b86c8a0ed7bbdeeca3f662dae918).

No runtime equivalence or telemetry-backend conclusion follows from that source-only
delta. OpenTelemetry remains a later architecture choice.

## Fired recheck dispositions

### `RECHECK-001`: silent-only acquisition

**Required outcome:** Determine whether upstream now exposes a documented no-interaction
acquisition contract and whether that changes the V2 interaction-policy requirements.

**Current-source finding:** At the evaluation time,
[issue #464](https://github.com/AzureAD/microsoft-authentication-cli/issues/464)
remained an open, unanswered request. It asks for interaction permission independent of
authentication mode and states that the reporter could not identify an existing
supported invocation. The named source contains no maintainer response, documentation
pointer, resolution, or implementation reference.

**Bounded inference:** Within the authorized source set, upstream does not expose a
documented no-interaction contract that preserves silent-capable mechanisms while
guaranteeing no UI. This does not claim that every mutable upstream file outside the
authorized source set was searched.

**Outcome:** Completed with no requirements weakening. Retain `V2-REQ-014`,
`V2-REQ-020`, `V2-REQ-021`, `V2-REQ-023`, and interaction-required or blocked outcomes
under `V2-REQ-032`. Replace V1 global interaction filtering and combined broker
orchestration.

### `RECHECK-002`: strict account selection

**Required outcome:** Determine whether upstream now provides strict account selection
and result-identity validation that changes the V2 account contract or reuse decision.

**Current-source finding:** At the evaluation time,
[issue #465](https://github.com/AzureAD/microsoft-authentication-cli/issues/465)
remained open and unanswered. Its Windows/WAM behavior is a public reporter observation
rather than a newly reproduced result.

**Bounded inference:** Fixed source independently establishes a non-strict contract:
suffix-based preference, absence/ambiguity collapse, OS-account widening, token-derived
identity, and no authoritative returned-identity postcondition. The reuse decision
therefore does not depend on treating the reporter's real-host observation as
independently reproduced.

**Outcome:** Completed with no requirements weakening. Retain `V2-REQ-012`,
`V2-REQ-017`, `V2-REQ-020`, `V2-REQ-022`, `V2-REQ-023`, `V2-REQ-031`, and the
applicable `V2-REQ-032` failure categories. Do not reuse V1 account resolution or result
handling as V2 policy.

### `RECHECK-007`: Azure DevOps Microsoft-account behavior

**Required outcome:** Record current public guidance and reproducible account-type
behavior before selecting or enabling an Azure DevOps compatibility client profile.

**Current-source finding:** Microsoft Learn currently states that Microsoft Entra
applications do not natively support Microsoft-account users for the Azure DevOps
resource, recommends Azure DevOps OAuth apps for applications requiring MSA or mixed
users, and says Microsoft is working on native MSA support through Entra OAuth. It
identifies Azure DevOps resource `499b84ac-1321-427f-aa17-267ca6975798` and recommends
its `.default` scope.
[Microsoft Learn](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/entra-oauth?view=azure-devops#tips-for-building-and-migrating).

Fixed AzureAuth source proves that V1 submits the Microsoft-owned Visual Studio client ID
and Azure DevOps scope. It does not establish successful MSA behavior, owner-approved
third-party reuse, supported authority or host combinations, or continued registration
availability. The mock `live.com` account in unit tests establishes suffix-filter logic
only.

**Bounded inference:** The Learn statement describes ordinary Entra applications and
does not establish the behavior or intended reuse boundary of this particular
Microsoft-owned registration. Conversely, the ability to submit the client ID is not
evidence of MSA support or intended reuse.

**Outcome:** Desk evaluation completed, but the substantive selection prerequisite
remains unresolved because reproducible account-type behavior evidence is absent.

Do not:

- add an MSA-support promise;
- select, enable, default, or distribute the Microsoft-owned profile;
- treat it as an available built-in or sole candidate; or
- classify the registration as supported or categorically unsupported for MSA.

Retain `V2-REQ-003`, `V2-REQ-011`, `V2-REQ-018`, `V2-REQ-022`, `V2-REQ-023`,
`V2-REQ-042`, and the
[external-client-profile gate](../product/compatibility-and-migration.md#externally-owned-client-profile-gate).
Generic profile-selection semantics apply independently, but this candidate remains
unavailable until the gate is satisfied.

## Separately proposed empirical question

> On a disposable Windows 11 WAM user or VM with an empty AzureAuth/MSAL application
> cache, using released AzureAuth `0.9.6`
> (`8ef1b8b00782bf20a51de078289819a79c3cba70`), client
> `872cd9fa-d31f-45e0-9eab-6e460a02d1f1`, tenant authority `common`, and scope
> `499b84ac-1321-427f-aa17-267ca6975798/.default`, what acquisition and read-only Azure
> DevOps authorization outcomes--and what sanitized returned account/tenant metadata or
> provider error--occur once with a dedicated MSA-only Azure DevOps identity and once
> with a dedicated Microsoft Entra work-or-school Azure DevOps identity?

Execution requires a separate accepted Delivery Wave entry and accepted protocol,
dedicated identities, disposable broker state, bounded read-only resource access, finite
repetition, stop conditions, cleanup, and sanitized evidence under the
[experiment-safety policy](experiment-safety.md#experiment-authorization).

## Contradictions and unsupported conclusions

The following conflicts and evidence limits are retained rather than silently resolved:

1. Usage says resource is required, while source permits explicit scopes without
   resource.
2. Windows usage labels web acquisition as an embedded view, while fixed source requests
   a non-embedded/system-browser path.
3. The changelog describes `--timeout` as an allowed-runtime contract, while lock waiting
   occurs outside that timeout and active-work termination is not proved.
4. V1's noninteractive wording implies interaction suppression, while source does not
   structurally separate silent and interactive broker stages.
5. Status output claims the token cache is warm regardless of the successful acquisition
   path.
6. AAD JSON is documented as machine output but is manually interpolated, incomplete,
   and not guaranteed to escape arbitrary claim-derived text.
7. Source intends stdout and stderr separation, but unavailable Lasso behavior prevents
   an exact V1 stream and process-exit contract.
8. "Telemetry off" is supportable only as the documented network-export statement;
   default local output, persistence, flushing, and shutdown behavior remain unknown.
9. Platform, mechanism, cache, installer, and package statements are public V1 promises
   or source definitions, not runtime evidence or inherited V2 support.
10. Release tags, README badges, installation examples, and changelog headings disagree;
    exact commits govern this baseline.
11. Issue #465's Windows/WAM account behavior is a public reported observation, not an
    independently reproduced result. Static source is sufficient to establish that the
    contract is non-strict.
12. Current general Azure DevOps guidance does not establish the behavior or reuse
    boundary of the particular Microsoft-owned Visual Studio registration used by V1.
13. The private feed and Lasso dependency are static build-input findings. This record
    makes no new restore, build, test, or packaging result claim.
14. `OpenTelemetry.Api` appearing in the project file does not establish a telemetry
    backend, export contract, or equivalence with Lasso.

## Bounded conclusion

AzureAuth V1 is useful evidence for mechanism integration, caller-visible promises,
failure modes, cache-policy defects, and packaging knowledge. It is not a sufficient
deterministic machine authentication contract or a V2 platform-support baseline.

The per-surface dispositions above map these findings to the
[canonical V2 requirements](../product/requirements/), while the
[compatibility policy](../product/compatibility-and-migration.md) and
[validation strategy](../validation/strategy.md) own their respective decisions and
obligations. Those records, rather than this evidence record, define current product
behavior, compatibility, and support-claim validation.

V1 commands, option names, aliases, environment variables, output forms, numeric exits,
installation paths, and upstream identities remain compatibility-only. Azure DevOps PAT
behavior and downstream HTTP formatting remain outside the authentication core.
Mechanism and platform source may inform later architecture, but does not establish
support.

`RECHECK-001` and `RECHECK-002` are complete and support no weakening of the interaction
or account contracts. `RECHECK-007` has completed its desk evaluation, but the
Microsoft-owned Azure DevOps profile remains unresolved and unselected pending separately
authorized evidence for the single retained empirical question.

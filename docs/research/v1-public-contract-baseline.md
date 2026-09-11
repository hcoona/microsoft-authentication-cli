# AzureAuth V1 Public Contract Baseline

## Purpose and authority

This record is the public-source research authority for the caller-visible AzureAuth V1
baseline used by [Issue #25](https://github.com/hcoona/microsoft-authentication-cli/issues/25).
It preserves material promises, source behavior, defects, inferences, and unresolved
limits without converting V1 behavior into a V2 compatibility, support, architecture, or
release commitment.

The original research was authorized by `main-v2` commit
[`d09d357c3fee953740d4a7470f57c57da56bbf5d`](https://github.com/hcoona/microsoft-authentication-cli/commit/d09d357c3fee953740d4a7470f57c57da56bbf5d).
Its accepted
[Delivery Wave](https://github.com/hcoona/microsoft-authentication-cli/blob/d09d357c3fee953740d4a7470f57c57da56bbf5d/docs/delivery-wave.md#L18-L79)
authorized fixed-scope V1 research, the three fired public-source rechecks, and
reconciliation of the canonical V2 requirements.

The initial [Issue #29](https://github.com/hcoona/microsoft-authentication-cli/issues/29)
consumer reconciliation and `RECHECK-006` incorporation used the accepted
[story-grounded Wave at `1a02498`](https://github.com/hcoona/microsoft-authentication-cli/blob/1a02498589769c38bc16eefc2efc5f9eca6e6994/docs/delivery-wave.md).
Subsequent story and reuse refinement uses the accepted
[product-bounded Wave at `c281406`](https://github.com/hcoona/microsoft-authentication-cli/blob/c281406feb4141b2b0f75d43c3a0ca26d449c37b/docs/delivery-wave.md).
These changes amend current requirement dispositions, not the pinned V1 source findings.

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

The later `RECHECK-006` retrieved only
[upstream issue #398](https://github.com/AzureAD/microsoft-authentication-cli/issues/398)
and its public comments on **2026-09-09 UTC**. Its
[dated outcome](#recheck-006-secure-store-availability) is a separate evaluation of that
source, not a refresh of the three sources above.

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
- **Publicly reported observation:** a public reporter's account, not an independently
  reproduced runtime result.

Confidence is high for direct fixed-source findings and documented public text.
Confidence in real provider, broker, host, secure-store, installer, or network effects is
not inferred from those materials.

V1 is an existing engineering baseline, not a hypothetical implementation. Its released
integrations, documented dependency contracts, and applicable public experience can
support architecture decisions without a new local reproduction. A public runtime report
retains its actual scenario and provenance; it need not be relabeled as our experiment
to be useful. Neither adoption alone nor an unspecified successful login establishes a
different account, resource, host, or V2 postcondition. Investigate the material difference
from an established path rather than reopening the feasibility of its entire mechanism.

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

`RECHECK-001` and `RECHECK-002` confirm that the 2026-09-04 upstream public evidence does not
weaken the accepted V2 interaction or account requirements. `RECHECK-007` records current
guidance but does not satisfy the prerequisite for selecting or distributing the
Microsoft-owned Azure DevOps profile.

## Architecture Reuse and Remaining Deltas

This desk assessment uses the fixed V1 source above and MSAL.NET **4.83.1**, commit
[`d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/tree/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f),
retrieved on **2026-09-10 UTC**. That is the managed MSAL and MSAL Extensions version
referenced by AzureAuth
[`0.9.6`](https://github.com/AzureAD/microsoft-authentication-cli/blob/8ef1b8b00782bf20a51de078289819a79c3cba70/src/MSALWrapper/MSALWrapper.csproj#L29-L35).
It is a comparison baseline, not a selected V2 dependency pin. No authentication,
cache, build, or platform experiment was performed for this assessment.

### Existing Mechanism and Result Contracts

**Source findings:** V1's
[`PCAWrapper`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L81-L180)
already calls MSAL account enumeration, selected-account silent acquisition, interactive
acquisition, and device-code acquisition. The dependency's
[`IClientApplicationBase`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/IClientApplicationBase.cs#L37-L74)
defines application-cache account enumeration and account-scoped silent acquisition,
including `MsalUiRequiredException` when interaction is needed. These operations do not
need to be invented or experimentally rediscovered to allocate V2 responsibilities.

MSAL's
[`AuthenticationResult`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/AuthenticationResult.cs#L257-L331)
exposes the access token, expiry, account, token tenant, and granted scopes. V1's
[`TokenResultOrNull`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L209-L216)
reduces that result to a parsed access token and correlation ID. Preserving the provider
result at the V2 adapter boundary therefore remedies an application-layer information
loss; absence of a metadata API is not an open feasibility question.

The narrower limit is meaningful:
[`IAccount.Username`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/IAccount.cs#L17-L22)
is documented as a displayable UPN-format value that can be null. `AuthenticationResult`
also documents missing account elements and tenant information. Those contracts alone do
not guarantee that every profile returns the requested full email, exposes every OS
account on first use, or represents aliases identically. Keep exact matching and missing
metadata handling in V2; do not infer aliases or parse the access token to fill gaps.

### Persistence Completion and Observability

**Source findings:** In the pinned managed request path,
[`RequestBase`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/Internal/Requests/RequestBase.cs#L322-L362)
awaits cache processing before constructing the authentication result. The
[`token cache`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/TokenCache.ITokenCacheInternal.cs#L250-L282)
awaits the after-access callback. MSAL Extensions
[`registers`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Extensions.Msal/MsalCacheHelper.cs#L306-L318)
its persistence callback, whose
[`write path`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Extensions.Msal/MsalCacheHelper.cs#L443-L488)
catches and logs a storage-write exception, then releases its lock.

Further inspection of the same pinned sources on **2026-09-11 UTC** distinguishes
available API signals from confirmation of a particular safe-state update:

- [`AuthenticationResultMetadata`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/AuthenticationResultMetadata.cs#L24-L55)
  describes the token's source and time spent in cache callbacks; neither is a durable
  write result.
- [`CacheChanged`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Extensions.Msal/MsalCacheHelper.cs#L73-L94)
  listens for disk-originated updates. Its
  [watcher](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Extensions.Msal/MsalCacheHelper.cs#L167-L217)
  compares account sets; it is not a request-local write receipt.
- [`VerifyPersistence`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Extensions.Msal/MsalCacheHelper.cs#L494-L505)
  tests the underlying mechanism with a write/read/clear operation without overwriting
  the token cache. It does not confirm that an acquisition's cache write completed.
- [`TokenCacheNotificationArgs.CancellationToken`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/TokenCacheNotificationArgs.cs#L210-L214)
  carries the acquisition cancellation token to custom cache implementations. The
  synchronous helper callbacks cited above do not establish that all underlying I/O or
  lock waits honor that token.

**Architecture inference:** Treating every provider task as returning before persistence,
or equating successful task completion with confirmed durable storage, would both be
incorrect assumptions about this path. V2 can retain the existing secure-store
integration knowledge. Its [state-observation boundary](../architecture/request-lifecycle.md#state-ownership-and-persistence-observation)
can classify the evidence already available after acquisition and validation, with the
`V2-REQ-041` warning when safe persistence failed or is unconfirmed. This requires no
extra write/readback test, watcher, or background persistence service and does not require
an early result from inside MSAL's acquisition operation. Lack of a completion receipt
alone is not a provider-selection blocker. The selected integration still has to satisfy
secure-only state, recovery, integrity, and request lifetime. These are source findings
and an architectural allocation, not runtime validation of a chosen store. The managed
callback behavior does not generalize to broker-owned storage.

### Decision Impact

| Concern | Existing basis to reuse | V2 difference and smallest remaining investigation |
| --- | --- | --- |
| Account discovery and silent acquisition | Real `IAccount` enumeration and account-scoped MSAL calls already exist. | Check first-use OS-account visibility and whether the selected profile supplies the exact email needed by the primary journey; ordinary cached-account matching is application logic. |
| Result identity | MSAL exposes account, token tenant, scopes, and expiry. | Preserve those fields and enforce the accepted postconditions; inspect profile-specific missing or alias metadata only where it affects the journey. |
| Interaction | V1 integrates broker, browser, and device code; MSAL separates silent and interactive APIs. | Replace V1's combined fallback policy. Host-owned completion and cancellation need evidence for the concrete host choice, not a new proof that OAuth interaction exists. |
| Secure reuse | V1 configures MSAL Extensions and platform stores. | Remove plaintext fallback and upstream namespaces; use the defined state-observation boundary and assess compatible reuse, recovery, integrity, and lifetime for the selected integration. Rely on platform protection contracts within the workstation threat model. |
| Personal-account Azure DevOps access | V1 supplies the Visual Studio client ID and Azure DevOps scope. The subsequent [Windows observation](experiments/windows-msal-account-metadata.md#gcm-informed-msa-acquisition-and-silent-reuse) demonstrates exact-account token/discovery success and fresh-process silent reuse with the GCM-informed configuration. | The [client-profile assessment](#client-profile-and-tenant-mapping-assessment) records tenant-mapping evidence and the external-dependency boundary. Concrete Profile/support acceptance remains separate under RECHECK-007. |

Use this delta assessment when accepting high-level responsibilities. It does not require
every integration or future release scenario to be demonstrated before the architecture
can be useful. Only an unresolved difference that could invalidate a particular choice
keeps that choice open. The [validation strategy](../validation/strategy.md) separately
governs evidence before implementation behavior or platform support is claimed.

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

**Disposition:** `V2-REQ-010`, `V2-REQ-011`, `V2-REQ-017`, and `V2-REQ-018` own the
explicit versioned CLI request, request scopes, intent precedence, and mandatory Client
Profile selection. V1 aliases, ambient defaults, option names, and TOML structure are not
native V2 request semantics.

### Resource and scope contradiction

**Evidence type:** Explicit public promise plus known defect/workaround.
**Confidence:** 10/10.

Usage says client, resource, and tenant are always required. The implementation instead
requires client, tenant, and either resource or one or more scopes. Resource is converted
to `<resource>/.default`; explicit scopes supersede resource with a warning.
[usage](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/docs/usage.md#L64-L70),
[source](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L293-L304).

**Disposition:** `V2-REQ-011` excludes a separate resource input and profile scope
presets. `V2-REQ-027` owns dynamic permission coverage and the distinct `/.default`
request/result association. V1 resource shorthand and precedence are not inherited.

### Client, tenant, and authority validation

**Evidence type:** Source finding.
**Confidence:** 10/10 for source shape; real MSAL authority handling is not inferred.

The CLI checks the client and tenant for nonemptiness. Client conversion to `Guid` occurs
later. Tenant remains a string appended beneath fixed host
`https://login.microsoftonline.com/`; the CLI does not expose an arbitrary authority
host.
[request object](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthParameters.cs#L12-L47),
[authority construction](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Web.cs#L97-L112).

**Disposition:** `V2-REQ-011`, `V2-REQ-011A`, and `V2-REQ-019` own one-cloud profiles,
trusted authority validation, and fixed/common/exact token-tenant policy. Invalid inputs
follow `V2-REQ-032`; the V1 string-concatenation behavior does not define that policy.

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
availability. `V2-REQ-018` requires explicit profile selection but does not make this
candidate an available profile. The V1 resource-specific bundle is not the V2 Client
Profile model.

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

**Disposition:** Replace advisory account selection under the reconciled requirements:

- `V2-REQ-012`, requiring a strict full email rather than stable-ID or Account Kind input;
- `V2-REQ-017`, preserving caller intent;
- `V2-REQ-020`, unique real-account resolution before silent acquisition;
- `V2-REQ-013`, mandatory selected-account silent-first ordering;
- `V2-REQ-022`, terminal email, tenant, profile, and scope postconditions;
- `V2-REQ-023`, terminal mismatch or unvalidated success; and
- `V2-REQ-031` and `V2-REQ-032`, provider-observed email metadata and typed
  interaction-required, ambiguity, and identity-validation failure.

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

**Disposition:** `V2-REQ-013` owns documented product acquisition order, compatible
mechanism filtering, and mandatory silent-first behavior after unique account resolution.
V1's discarded order is a source fact, not a reason to expose caller ordering or profile
order defaults in V2.

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
- `V2-REQ-013` and `V2-REQ-020`, silent-first order and its account precondition;
- `V2-REQ-021`, an absolute no-user-interface guarantee;
- `V2-REQ-023`, typed retryable and terminal fallback; and
- the interaction-required category in `V2-REQ-032`.

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

**Disposition:** `V2-REQ-015`, `V2-REQ-022`, and `V2-REQ-024` own request-local provider
claims handling and preservation of every original constraint. This does not authorize
a public resource/CAE continuation protocol or `cp1` advertisement.

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

`V2-REQ-016` owns self-contained interactive surfaces and completion channels without
caller-provided UI ownership or raw handles. Unavailable paths cannot initiate unmanaged
interaction. This selects no concrete host implementation.

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
Provider-authoritative metadata is needed for validation, but `V2-REQ-031` limits public
account identity to the observed email. Stable provider IDs are not public success
metadata. Access tokens remain opaque; expiration is not a minimum-validity promise.

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
- typed interaction-required, ambiguity, and identity-validation outcomes under
  `V2-REQ-032`.

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

**Disposition:** `V2-REQ-030`, `V2-REQ-031`, and `V2-REQ-034` own the single structured
success/failure result and authoritative metadata. V1 raw, JSON, and status modes are
not alternative native V2 outputs. Wire-schema selection remains later contract work.

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
and binary success/failure exit semantics, with specific failure detail in the payload.
The concrete shared nonzero value is not inherited from V1.

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

**Disposition:** `V2-REQ-034`, `V2-REQ-035`, and `V2-REQ-036` distinguish structured
results, necessary authentication/UI channels, and diagnostics. Authentication secrets,
raw emails, and stable email-derived identifiers are not diagnostic or telemetry content.
Email in the explicit request and validated success is a deliberate contract boundary.

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

**Disposition:** This motivates the no-plaintext product choice in `V2-REQ-040`; it does
not prove a V2 implementation. `V2-REQ-045` still gates headless repeated-reuse claims.
There is no first-version selectable plaintext or fallback mode.

### Cache-disabled and persistence-failure behavior is untyped

**Evidence type:** Source finding plus bounded inference.
**Confidence:** 9/10.

Any nonempty `OEAUTH_MSAL_DISABLE_CACHE` value skips cache registration. On some
non-headless persistence failures, source logs and records the exception but continues
without selecting another persistent mode. The bounded inference is that acquisition can
continue with only process-local MSAL state, while callers receive no storage-mode result.
[cache setup](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L59-L105).

**Disposition:** `V2-REQ-040` owns the single secure-state product policy.
`V2-REQ-041` owns unusable-state-as-miss recovery and validated-token success with a
machine-readable persistence warning. `V2-REQ-032` has no standalone cache/integrity
status. The source does not demonstrate that acquisition and persistence failures can
be separated on any current V2 platform; see the [dated recheck](#recheck-006-secure-store-availability).

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

**Disposition:** `V2-REQ-041` excludes first-version Logout, Cache Clear, Force Refresh,
and Account List. V1 clearing syntax and lifecycle are not native V2 capabilities. The
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
containment and independent identity. `V2-REQ-036` adds the email privacy boundary.
The existing OpenTelemetry direction remains an input to later architecture work; this
reconciliation does not select its implementation or backend.

### Collected telemetry and diagnostic fields

**Evidence type:** Source finding and security limitation.
**Confidence:** 10/10 for call-site collection.

Command telemetry records client, resource, tenant, prompt hint, and scopes. Per-flow
telemetry includes flow name, success, duration, recursively serialized exception
messages, correlation ID, token validity, and silent status. Debug paths include cached
usernames and provider exception messages.
[command telemetry](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L314-L331),
[flow telemetry](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/AuthFlowResultExtensions.cs#L39-L64).

**Disposition:** `V2-REQ-034`, `V2-REQ-035`, `V2-REQ-036`, `V2-REQ-043`, and
`V2-REQ-046` govern diagnostic separation, secret/email containment, independent identity,
and bounded optional telemetry. No diagnostic schema or backend is selected here.

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
`V2-REQ-013`, `V2-REQ-020`, `V2-REQ-021`, `V2-REQ-023`, and the interaction-required
outcome under `V2-REQ-032`. Replace V1 global interaction filtering and combined broker
orchestration. This remains the 2026-09-04 source outcome, not a fresh source-status claim.

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

### `RECHECK-006`: secure-store availability

**Required outcome:** Record current secure-store behavior and unresolved platform
limitations before accepting cache fallback or declaring a platform supported.

**Provenance:** Desk retrieval on **2026-09-09 UTC**, under accepted Wave
`1a02498589769c38bc16eefc2efc5f9eca6e6994`, was limited to
[issue #398](https://github.com/AzureAD/microsoft-authentication-cli/issues/398), its
[public Issue API](https://api.github.com/repos/AzureAD/microsoft-authentication-cli/issues/398),
and its
[public comments API](https://api.github.com/repos/AzureAD/microsoft-authentication-cli/issues/398/comments).
At retrieval, the Issue was open, had zero comments, and reported
`updated_at = 2024-08-13T16:18:59Z`; the first comments page was empty.
The [desk outcome](https://github.com/hcoona/microsoft-authentication-cli/issues/29#issuecomment-5595449718)
and [independent review](https://github.com/hcoona/microsoft-authentication-cli/issues/29#issuecomment-5595466517)
retain the prerequisite disposition and actual merged-Wave evaluation.

**Evidence type:** Publicly reported observation, not an independently reproduced runtime
result. The reporter describes AzureAuth **0.8.6.0**, installed from a Debian package on
a headless Ubuntu VM, failing during an Azure DevOps PAT invocation. The report describes
persistence-verification failures followed by a keyring-read failure associated with an
unavailable `org.freedesktop.secrets` service. Device-code interaction appears in the
report but does not establish successful token acquisition or reusable-state persistence.
The Issue/comments contain no maintainer resolution or documented supported nonpersistent
path. Raw diagnostics, authentication instructions, codes, and account or organization
details are not reproduced here.

**Bounded conclusion:** The desk prerequisite is satisfied, not a platform-support gate.
This report does not establish current-release behavior, all-headless-Linux behavior,
Windows/WAM or macOS behavior, or V2's ability to separate acquisition from persistence
failure. The pinned [plaintext fallback](#headless-linux-silently-falls-back-to-plaintext)
and [process-local continuation](#cache-disabled-and-persistence-failure-behavior-is-untyped)
findings remain source findings for their audited commit. The
[architecture audit's #398 reference](v1-architecture-audit.md#finding-6-cache-policy-contains-an-implicit-security-decision)
remains only a reported example, not a current fix or support guarantee.

**Disposition:** The no-plaintext choice (`V2-REQ-040`), unusable-state recovery and
success-with-persistence-warning behavior (`V2-REQ-041`) are product decisions, not facts
demonstrated by #398. Secure-store availability, error separation, concurrent state
integrity, and cross-invocation reuse require later implementation and platform evidence
under the [validation strategy](../validation/strategy.md). No experiment is authorized
by this result.

### Issue #29 reconciliation trigger evaluation

The requirements reconciliation continues the `interaction-policy`, `account-contract`,
and `cache-design` decision concerns. Their recheck controls therefore apply even though
this change performs no experiment or release:

- `RECHECK-001` and `RECHECK-002`: the accepted 2026-09-04 outcomes and fixed-source reuse
  conclusions remain unchanged. The primary-story wording does not rely on a new
  upstream feature or refresh those mutable status claims. Their current requirement
  dispositions are updated above.
- `RECHECK-006`: the 2026-09-09 source-only outcome and independent disposition satisfy
  the desk prerequisite for this reconciliation, with implementation/support still gated.
- `RECHECK-003`, `RECHECK-004`, and `RECHECK-005`: no WSL, system-browser, or Linux-broker
  workstream is selected; these triggers are not activated by this change.
- `RECHECK-007`: no profile is selected or enabled. The existing empirical prerequisite
  remains outstanding; the first-release journey does not satisfy it.

The actual #31 merged-Wave fallback evaluated all seven entries in the independent
review linked above. This proposal does not change the Wave. Any later merged-Wave,
release, or newly fired source-relevant trigger still requires its applicable review.

### Architecture Boundary Recheck Assessment

The high-level architecture allocation under Issue #35 continues the interaction,
account, and cache decision concerns. A desk refresh on **2026-09-09 UTC** inspected the
named public sources for RECHECK-001, RECHECK-002, and RECHECK-006:

| Entry and source | Retrieved public state | Bounded decision impact |
| --- | --- | --- |
| RECHECK-001: [Issue #464](https://github.com/AzureAD/microsoft-authentication-cli/issues/464) | Open, zero comments; `updated_at = 2026-08-17T21:12:04Z`. The Issue API and first comments page were read; the comments page was empty. | The named source remains an unanswered interaction-policy request, not a documented upstream no-interaction contract. Preserve separate engine policy and provider operations. |
| RECHECK-002: [Issue #465](https://github.com/AzureAD/microsoft-authentication-cli/issues/465) | Open, zero comments; the public page's embedded issue metadata reports `updatedAt = 2026-08-27T22:02:13Z`. | No new resolution in this carrier changes the fixed-source strict-selection findings. Preserve real-account resolution and final authoritative result validation. |
| RECHECK-006: [Issue #398](https://github.com/AzureAD/microsoft-authentication-cli/issues/398) | Open, zero comments; the public page's embedded issue metadata reports `updatedAt = 2024-08-13T16:18:59Z`. | The accepted bounded report remains unresolved. It does not demonstrate current dependency behavior or select a store, plaintext fallback, or supported platform. |

Authenticated upstream API retrieval was unavailable because of organization SAML
enforcement. Anonymous Issue #464 API retrieval succeeded; subsequent anonymous API
retrieval hit a rate limit, so the refresh used the public HTML pages for #465 and #398.
The latter snapshots establish the Issue state and comment count, not a new runtime
observation or a fresh audit of upstream implementations. Raw #398 diagnostics were not
retained. The earlier source findings and their limitations remain authoritative for
their recorded versions.

For this architecture boundary allocation, the three desk outcomes preserve the accepted
requirements and source-reuse dispositions. They do not establish that a particular
provider exposes the needed account metadata, persistence separation, or no-UI behavior.
Those decision-critical premises remain open in the
[architecture](../architecture/overview.md#decision-critical-open-questions).

RECHECK-003, RECHECK-004, and RECHECK-005 do not fire: no WSL, system-browser, or
Linux-broker workstream is selected by the mechanism-neutral views. RECHECK-007's
account-type prerequisite remains unresolved; no profile is selected or enabled, and
its dated public-guidance finding below is not refreshed by these Issue snapshots. There
is no release or Wave change. Later selections and fired triggers still require their
applicable outcomes and independent evidence review.

#### State-Ownership Refinement Recheck

The **2026-09-11 UTC** state-ownership and result-delivery refinement fires RECHECK-006's
`cache-design` trigger. Anonymous retrieval of the public Issue #398 API and its first
comments page found the Issue still open, with zero comments and
`updated_at = 2024-08-13T16:18:59Z`; the comments response was empty. The
[bounded secure-store conclusion](#recheck-006-secure-store-availability) remains
unchanged. The pinned callback findings above refine the architecture's observation
boundary without claiming a current Linux fix or a validated storage integration.

All seven entries were evaluated for this refinement. RECHECK-001 and RECHECK-002 retain
their accepted interaction-policy and account-contract dispositions; neither contract
changes here. RECHECK-003, RECHECK-004, and RECHECK-005 do not fire because no WSL,
system-browser, or Linux-broker integration is selected. RECHECK-007's existing
[account-type evidence](#observed-msa-token-git-discovery-and-silent-reuse) and Profile gate
remain unchanged: the tenant-policy clarification preserves accepted intent without
selecting a client configuration. No Profile, platform, release, Wave change, or new
experiment is part of this refinement.

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

**Outcome:** Desk evaluation completed. The subsequent
[2026-09-11 Windows sequence](experiments/windows-msal-account-metadata.md#gcm-informed-msa-acquisition-and-silent-reuse)
adds reproducible evidence of exact personal-account token acquisition, authenticated
Git discovery, and fresh-process silent reuse for the declared existing host, state,
client, authority, options, and target. The earlier absence of account-type observations
no longer applies to that configuration. Intended external registration reuse, other
configurations, and the product's Profile/support decision are not established by that
experiment. The subsequent [client-profile assessment](#client-profile-and-tenant-mapping-assessment)
records the available public reuse evidence, first-party capability limit, and absence
of a fork support commitment. The concrete Profile selection gate remains open.

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

## WSL Direct Invocation and Azure Artifacts

**Public source findings, retrieved 2026-09-11 UTC:** Microsoft's
[WSL interoperability documentation](https://learn.microsoft.com/en-us/windows/wsl/filesystems#run-windows-tools-from-linux)
documents direct execution of Windows `.exe` files from WSL, running as the active Windows
user, with pipes and redirection. Arguments reach the Windows binary unmodified; file
arguments therefore need Windows-understood paths. Interoperability can be disabled.
These documented abstractions support using the ordinary Windows CLI as the selected
WSL caller's authentication engine. They do not establish application cancellation,
result encoding, Profile eligibility, or UI behavior for a future implementation.

The WSL decision fires RECHECK-003 and RECHECK-005. The registry evaluation also records
the retained outcomes for the other entries:

| Recheck | Source state and decision impact |
| --- | --- |
| RECHECK-003 | [Issue #460](https://github.com/AzureAD/microsoft-authentication-cli/issues/460) remains open with no comments, updated `2026-05-13T17:25:51Z`. It proposes Linux-side detection and a Windows helper, including trust, version, transport, and missing-helper failures; it does not supply an implemented bridge or require V2 to adopt one. Direct executable invocation keeps Windows-side authentication ownership without introducing that proposed forwarding layer. |
| RECHECK-003/005 | [MSAL.NET WSL guidance](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/linux-dotnet-sdk-wsl) describes Linux `BrokerOptions`, .NET 8, native libraries, and an unlocked `libsecret` keyring; it identifies WSL 2.4.13 or later for the WAM account-control dialog. Those are prerequisites of its Linux application path, not a new Linux dependency of the selected Windows executable. |
| RECHECK-005 | [PR #462](https://github.com/AzureAD/microsoft-authentication-cli/pull/462) remains open and unmerged in the retrieved public page. Its patch ends at `dea657fda153a45ffe782755f952a2890e42db13`, adding Linux broker availability/routing, a native-client redirect, OS-account listing, and an OS-default sentinel fallback. It supplies no Windows CLI forwarding protocol or V2 strict-account guarantee. Its Linux path remains outside this deployment. |
| RECHECK-001/002 | Issues [#464](https://github.com/AzureAD/microsoft-authentication-cli/issues/464) and [#465](https://github.com/AzureAD/microsoft-authentication-cli/issues/465) remain open with no comments, updated `2026-08-17T21:12:04Z` and `2026-08-27T22:02:13Z`. No new documented silent-only or strict-account contract changes the accepted V2 requirements. |
| RECHECK-004 | Issues [#459](https://github.com/AzureAD/microsoft-authentication-cli/issues/459) and [#461](https://github.com/AzureAD/microsoft-authentication-cli/issues/461) remain open, updated `2026-05-14T00:13:01Z` and `2026-05-14T00:12:30Z`. Browser/callback support is not selected by direct invocation; the existing bounded disposition remains applicable. |
| RECHECK-006 | [Issue #398](https://github.com/AzureAD/microsoft-authentication-cli/issues/398) remains open with no comments, updated `2024-08-13T16:18:59Z`. No cache fallback or secure-store support claim changes. |
| RECHECK-007 | The same-day [Client Profile and tenant assessment](#client-profile-and-tenant-mapping-assessment) remains applicable. Neither direct invocation nor another Azure DevOps consumer enables a Profile or enlarges the observed account/host coverage. |

### Azure Artifacts Token Forms and NuGet Paths

**Immutable source findings, retrieved 2026-09-11 UTC:** Azure Artifacts Credential Provider at
[`bca6c32fdb9611aea25819147ef4508f730aa5fb`](https://github.com/microsoft/artifacts-credprovider/tree/bca6c32fdb9611aea25819147ef4508f730aa5fb)
defines the Azure DevOps MSAL scope as
`499b84ac-1321-427f-aa17-267ca6975798/.default` in
[`MsalConstants.cs`](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/src/Authentication/MsalConstants.cs#L9-L10).
This is the same resource/scope used by
[GCM v2.9.1](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Microsoft.AzureRepos/AzureDevOpsConstants.cs).

Its NuGet integration has both direct-token and exchange paths. The exchange is the
default, not a requirement of the NuGet plugin protocol. The
[`VstsCredentialProvider` branch](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/CredentialProvider.Microsoft/CredentialProviders/Vsts/VstsCredentialProvider.cs#L164-L188)
returns the acquired access token directly when
`ARTIFACTS_CREDENTIALPROVIDER_RETURN_ENTRA_TOKENS=true`.
[`EnvUtil`](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/CredentialProvider.Microsoft/Util/EnvUtil.cs#L171-L174)
defaults that option to false. The same branch and option exist in released v2.0.4 at
[`14855bba1b20482623697fe9497cc5398d5077cd`](https://github.com/microsoft/artifacts-credprovider/blob/14855bba1b20482623697fe9497cc5398d5077cd/CredentialProvider.Microsoft/CredentialProviders/Vsts/VstsCredentialProvider.cs#L164-L188).
This is source evidence for an available path, not a new execution result.

| Path or token form | Source-defined behavior | Lifetime and state distinction |
| --- | --- | --- |
| Direct access token, called an Entra token by the plugin | Return MSAL's access token as `Password`, username `EntraToken`, and authentication type `Basic`; skip the session-token endpoint. | Identity-platform expiry applies. The handler disables its session-token cache for this mode; MSAL caching remains available. |
| Exchanged `SelfDescribing` token | Use the access token to request an Azure DevOps-issued JWT session token, then return it to NuGet as a Basic credential. | The provider normally requests four hours and caps its requested duration at 24 hours. Actual validity comes from the service; a rejected requested expiry can be retried with service-defined validity. The provider has a separate session-token cache. |
| Exchanged `Compact` token | Use the access token to request an Azure DevOps PAT. | The provider normally requests 90 days, subject to service policy. PATs are outside the selected V2 Slice. |

The cache distinction is explicit in
[`GetAuthenticationCredentialsRequestHandler`](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/CredentialProvider.Microsoft/RequestHandlers/GetAuthenticationCredentialsRequestHandler.cs#L126-L142).
The exchange provider
[selects `Compact` by default after interactive acquisition and `SelfDescribing` otherwise](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/CredentialProvider.Microsoft/CredentialProviders/Vsts/VstsSessionTokenFromBearerTokenProvider.cs#L33-L61),
unless its token-type option overrides that choice. Thus, leaving direct-token mode off
does not establish a PAT-free path. These are upstream defaults, not V2 behavior.

[`VstsSessionTokenClient`](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/CredentialProvider.Microsoft/CredentialProviders/Vsts/VstsSessionTokenClient.cs#L60-L149)
uses bearer authorization to call `/_apis/Token/SessionTokens`, requesting
`vso.packaging_write vso.drop_write`. Those are downstream service-credential scopes,
not an additional MSAL resource or an engine operation. A session token has its own
issuance and validity; it is not the MSAL refresh token. The name `SelfDescribing`
identifies the ADO JWT form, not a general distinction between JWT and OAuth tokens.
Source descriptions of scope and duration alone do not establish that one path is
universally safer. Existing token-opacity and secure-state requirements remain in force;
none of these upstream caches or fallback behaviors is imported into V2.

### Personal Accounts and Evidence Limits

**Source finding:** The pinned provider's
[`AzureArtifacts` builder](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/src/Authentication/AzureArtifacts.cs#L18-L70)
enables broker MSA passthrough, and
[`MsalExtensions`](https://github.com/microsoft/artifacts-credprovider/blob/bca6c32fdb9611aea25819147ef4508f730aa5fb/src/Authentication/MsalExtensions.cs#L32-L53)
handles MSA accounts and the transfer-tenant workaround. The subsequent direct-token
branch tests the configuration option, not the account type. The plugin's `EntraToken`
label is not an organizational-account selector. Its production application registration
also differs from the Visual Studio registration used in the accepted Windows probe;
the source does not enable that newer registration as a V2 Profile.

**Inference:** Personal-account selection does not by itself require a SelfDescribing
exchange. Both branches first need a usable MSAL access token. This conclusion depends
on an eligible client/authority path, including the documented legacy MSA compatibility
boundary; it does not establish personal-account support for arbitrary Entra applications.

| Question | Current evidence and limit |
| --- | --- |
| Can the selected personal-account compatibility path acquire an access token and use it directly for ADO Git? | The [accepted Windows observation](#observed-msa-token-git-discovery-and-silent-reuse) records exact-account token acquisition, successful authenticated Git discovery, and later-process silent reuse without PAT or session-token exchange. It is bounded to that existing host/account-state/target scenario. |
| Does the official NuGet provider expose direct access-token presentation? | Yes, in the pinned source and released-source revision above. It passes the token through a Basic credential response and does not branch on personal versus work account. |
| Has this project's personal-account token been used through NuGet Basic authentication against an Artifacts feed? | No such observation exists. Git bearer-token success and the shared resource/scope do not themselves demonstrate this downstream path or a package operation. |
| Has SelfDescribing exchange been shown necessary for personal accounts? | No. Neither the inspected branch nor the accepted observation establishes that requirement. Absence of a NuGet/feed observation must not be converted into either a forced-exchange rule or a claim of validated direct-feed access. |

**Architectural inference:** Azure DevOps Git and Azure Artifacts can use the same engine
capability for explicitly requested personal or work accounts. Artifacts authentication
does not need a separate deferred engine mechanism. Compatible account, Profile, tenant,
resource, and scope contexts can reuse eligible state; identical resource IDs alone do
not make different account or tenant requests interchangeable. Git and package adapters
retain service authorization, protocol handling, and any derived-credential lifecycle
under [decision 0004](../decisions/0004-keep-the-authentication-engine-separate-from-consumers.md).
This conclusion includes Artifacts token acquisition in the same authentication scope;
it does not claim that the CLI implements NuGet credential exchange or that a token alone
grants repository/feed access. The [architecture boundary](../architecture/overview.md#system-boundary)
owns the selected direct-access-token design;
[V2-REQ-005](../product/requirements/product-boundary.md#v2-req-005-no-personal-access-tokens)
owns the PAT prohibition. NuGet presentation and
feed behavior remain explicitly scoped [validation obligations](../validation/strategy.md#platform-matrix).

**Refinement recheck assessment:** All seven registry entries were evaluated. This
correction selects no new Profile, account contract, interaction policy, cache design,
or host path, and changes neither the Wave nor a release; no new trigger fires.
RECHECK-001/002/006 retain their accepted interaction/account/state dispositions;
RECHECK-003/004/005 retain the accepted WSL and unselected Linux/browser boundaries;
RECHECK-007 retains the current client/tenant assessment and bounded MSA evidence.
The immutable source findings above do not claim a fresh mutable-source status or a
new platform-support result.

This assessment executed no application, authentication, cache access, or resource request.
It adds no corporate-account or feed observation and does not extend the completed
personal-account probe's capacity or evidence.

## Windows MSAL Probe Basis

The [bounded Windows protocol](experiments/windows-msal-account-metadata.md) governs
account discovery, selected-account acquisition, result metadata, conditional broker reuse,
and discovery at the single owner-designated Azure DevOps Git repository. It uses V1's
managed/native dependency versions in a small research probe. The first sequence stopped
without a token; the diagnostic sequence later timed out with structured cancellation
fields, also without a token. Authentication configuration and selection logic were
unchanged, but the observed exact-match count changed. A subsequent explicitly attended
action returned an unexpected broker failure, also without a token. These observations
do not establish resource authorization, registration eligibility, or a Profile/support
commitment, and no corporate-account comparison is performed. A subsequent GCM-informed
sequence succeeded in both interactive acquisition and fresh-process silent reuse, with
exact returned email and recognized authenticated Git discovery. Its bounded current
conclusion is recorded below; earlier failures retain their original evidence limits.

The protocol's [execution history](experiments/windows-msal-account-metadata.md#execution-history)
records the initial public-index and launcher failures, followed by successful Windows
compilation and synthetic self-check of the metadata-only subject and the amended
Git-discovery subject, then the diagnostic subject with its error-output self-check.
The preparations retain their distinct source and artifact identities. Preparation used
public packages transferred through WSL to a Windows local feed and did not change the
native Windows account or token boundary.

The first account sequence found one exact match for the designated account among
multiple visible accounts and an anonymous HTTP 302 response with an authentication
challenge header. Silent acquisition required interaction; the permitted interactive
action returned the probe's `provider-rejected` category without an authentication result.
The sequence stopped without an authenticated Git request or reuse follow-up. The error
category does not identify the cause or establish categorical MSA incompatibility.
That first sequence left successful result metadata, token acceptance, fresh-state
behavior, and later reuse unobserved; the [protocol history](experiments/windows-msal-account-metadata.md#account-visibility-and-unresolved-acquisition-failure)
owns the exact observations and limitations.

The later [diagnostic action](experiments/windows-msal-account-metadata.md#diagnostic-subject-preparation-and-acquisition)
reported zero exact matches and used the existing login-hint branch, rather than the
previous matched-account branch. It reached the process deadline with
`authentication_canceled` / `UserCanceled`, no authentication result, and no authenticated
resource request. The cancellation category does not establish manual cancellation or
explain the previous service-exception category. The cause of the changed account
visibility and detailed operator UI steps remain unknown. That sequence stopped; no
reuse follow-up ran, and the evidence does not select a Profile or establish support.

The subsequent [attended sequence](experiments/windows-msal-account-metadata.md#attended-preparation-and-structured-broker-failure)
completed preparation and the explicit readiness handoff, then again found one exact
match and used the matched-account branch. It returned `unknown_broker_error`, broker
status `Unexpected`, and code `2147786073` (`0x80049D59`) about 20.6 seconds after launch,
with no authentication result or resource request. The owner reported the input form,
apparent automatic fill/submission, and a brief possible WAM surface before the windows
closed. The brief surface was not conclusively identified and no detailed sign-in/MFA/
consent steps were reported. This adds structured failure and UI observations, not an
explanation of the code, proof of the earlier failure's cause, or Profile eligibility.
That sequence stopped. The later successful configuration and its limits are described below.

**Source interpretation, checked 2026-09-11 UTC:** The same pinned
[`WamAdapters` default branch](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/WamAdapters.cs#L116-L120)
returns a service exception with `UnknownBrokerError` for statuses outside its explicit
cases. This supports the reported generic category for `Unexpected`, not a specific
cause or identity-service rejection. Reported service status zero is not an observed
HTTP response. The two failed matched-account actions need not share a cause; the first
one lacks the finer fields needed to compare them.

**Source interpretation, retrieved 2026-09-10 UTC:** The pinned MSAL
[`WamAdapters` exception mapping](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/WamAdapters.cs#L58-L120)
uses `MsalServiceException` for configuration/API-contract failures, network or temporary
server failures, and unknown broker failures. Its
[runtime-response wrapper](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/WamAdapters.cs#L379-L385)
also wraps other response-processing exceptions in that type. The probe's literal
`provider-rejected` label therefore denotes an acquisition-failure category, not proof
that a remote identity service rejected the account. No finer error code/status was
retained; these source possibilities do not identify which failure occurred in this run.

The same pinned API documents [`ErrorCode`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/MsalException.cs#L129-L154)
as a protocol code for exception handling, [`IsRetryable` and broker keys](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/MsalException.cs#L30-L61),
service [`StatusCode`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/MsalServiceException.cs#L149-L163),
and [`UiRequiredExceptionClassification`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/MsalUiRequiredException.cs#L66-L89).
The [`broker decorator`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/WamAdapters.cs#L214-L225)
populates separate status-name and numeric-code entries alongside private context and
telemetry. The diagnostic subject selects only the protocol/enum/numeric fields. These
contracts justify retaining useful error classification without raw exception/property-bag
export. A retry hint does not authorize another attempt, and a reported status remains
bounded evidence rather than proof of every underlying failure cause. The earlier run's
missing fields cannot be reconstructed from this source finding.

**Pinned source findings, reviewed on 2026-09-10 UTC:** MSAL 4.83.1's
[`BrokerOptions`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/ApiConfig/BrokerOptions.cs#L81-L87)
exposes `ListOperatingSystemAccounts`. The
[`runtime broker`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/RuntimeBroker.cs#L571-L632)
returns an empty list when this option is off and otherwise calls discovery, filters the
cloud environment, and converts the returned accounts. V1 0.9.6's
[`Windows broker configuration`](https://github.com/AzureAD/microsoft-authentication-cli/blob/8ef1b8b00782bf20a51de078289819a79c3cba70/src/MSALWrapper/AuthFlow/Broker.cs#L232-L242)
does not enable that option. This is an available dependency capability, not evidence
that a particular existing personal account will be visible or have an exact email.

MSAL's
[`broker availability query`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/PublicClientApplication.cs#L80-L98)
and
[`custom web UI callback`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/Extensibility/ICustomWebUI.cs#L30-L52)
let the probe require WAM and decline browser fallback. The callback implements no OAuth
exchange. The earlier probe left the hidden first-party `MsaPassthrough` option off,
as in V1's Windows configuration. The following comparison changes that experiment
input without upgrading MSAL.

### GCM MSA Configuration Comparison

**Public source findings, retrieved 2026-09-11 UTC:** GCM **v2.9.1**, commit
[`6760f0ef069c994aa2bb1d703fb374986ee82a3e`](https://github.com/git-ecosystem/git-credential-manager/tree/6760f0ef069c994aa2bb1d703fb374986ee82a3e),
provides a concrete Azure Repos MSA configuration reference. This is a pinned source
comparison, not a claim about the installed GCM version or its execution on this host.

| Concern | GCM source finding | Probe comparison |
| --- | --- | --- |
| Client and scope | [Azure DevOps constants](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Microsoft.AzureRepos/AzureDevOpsConstants.cs#L11-L16) specify the Visual Studio client and Azure DevOps `.default` scope. | The earlier and amended probe use these same public values. The client remains Microsoft-owned. |
| MSA passthrough | [Azure Repos token acquisition](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Microsoft.AzureRepos/AzureReposHostProvider.cs#L347-L353) passes `msaPt: true`; the [Windows broker builder](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Core/Authentication/MicrosoftAuthentication.cs#L633-L643) forwards it to `BrokerOptions.MsaPassthrough`. | The earlier probe used the default false; the amended subject enables it. |
| Authority | [Authority discovery](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Microsoft.AzureRepos/AzureDevOpsRestApi.cs#L30-L88) prefers the service's Bearer authority, then its resource-tenant header. An empty resource-tenant GUID selects `organizations` for an MSA-backed organization; absent information falls back to `common`. | The earlier probe fixed `common`. The amended subject fixes `organizations` as an MSA candidate, without claiming that this private target has an empty resource tenant or reproducing GCM's discovery. |
| Silent transfer tenant | [Selected-account silent acquisition](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Core/Authentication/MicrosoftAuthentication.cs#L533-L554) applies `WithTenantId` for an MSA home account; the [public constants](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Core/Constants.cs#L21-L32) identify the home and Microsoft transfer tenants. | The conditional silent follow-up applies the same tenant rule to its unique exact account and records only whether it applied. |

The probe's pinned MSAL 4.83.1 already exposes
[`MsaPassthrough`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/ApiConfig/BrokerOptions.cs#L74-L79),
documented in public source as a legacy first-party option. Its
[`WAM adapter`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/WamAdapters.cs#L153-L164)
passes the consumer-passthrough request property to the native runtime. This source
contract supports a bounded experiment with the already declared Microsoft client; it
does not establish eligibility for arbitrary registrations or intended external reuse.
GCM v2.9.1 [pins](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/Directory.Packages.props)
MSAL 4.84.2. The probe keeps 4.83.1, its owned parent, exact account checks, and lack of an
application cache or browser fallback. It does not reproduce GCM's full runtime or policy.

**Hypothesis and consequence:** The configuration difference could explain why the earlier
probe did not reach a usable MSA path. The completed comparison below demonstrates a
successful configuration; it does not isolate one option's causal effect or prove the
cause of `0x80049D59`. The existing
[protocol](experiments/windows-msal-account-metadata.md#current-disposition-msa-acquisition-and-reuse-observed)
owns execution limits, readiness, and actual results. No GCM helper, cache, credential,
organization API, or extra discovery request was used. No Profile or platform is selected.

### Client Profile and Tenant Mapping Assessment

**Scope and provenance:** Public desk inspection on **2026-09-11 UTC** addresses the
tenant-mapping and external-registration questions from the high-level architecture.
The MSAL sources remain pinned to **4.83.1** at
`d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f`; the GCM comparison remains **v2.9.1** at
`6760f0ef069c994aa2bb1d703fb374986ee82a3e`. No dependency was built or executed, and no
account, cache, authentication, or resource request was part of this assessment.

**Source findings:**

- Microsoft's [authority configuration guidance](https://learn.microsoft.com/en-us/entra/identity-platform/msal-client-application-configuration#authority)
  describes `common` as admitting work/school and personal accounts, and ordinary
  `organizations` as admitting work/school accounts. The effective audience is constrained
  by both the code configuration and the application registration. The same retrieval
  of [Azure DevOps guidance](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/entra-oauth?view=azure-devops#tips-for-building-and-migrating)
  still states that ordinary Entra applications do not natively support MSA users for
  the Azure DevOps resource. Neither statement is a new observation of the legacy client.
- MSAL's [`BrokerOptions.MsaPassthrough`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/ApiConfig/BrokerOptions.cs#L74-L79)
  and its [public API documentation](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identity.client.brokeroptions.msapassthrough?view=msal-dotnet-latest)
  describe a legacy option available only to Microsoft first-party applications and
  recommend avoiding it where possible. The WAM adapter forwards the option to the
  runtime, as recorded above. This is a specific registration capability, not a way to
  add MSA support to an arbitrary application registration.
- MSAL's [`AuthorityInfo` request resolution](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/AppConfig/AuthorityInfo.cs#L505-L583)
  can resolve a tenantless authority using the selected account's home tenant. Its
  request-override branch preserves an explicit non-tenantless authority and has a
  separate `organizations`/MSA-passthrough case.
  [`WithTenantId`](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client/ApiConfig/AbstractAcquireTokenParameterBuilder.cs#L248-L276)
  overrides the request tenant while preserving the authority host and validation
  setting. These contracts distinguish configured authority, request override, and
  resolved authority; they do not make every `common` request use a literal `/common`
  endpoint throughout acquisition.
- GCM's [Azure DevOps authority discovery](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Microsoft.AzureRepos/AzureDevOpsRestApi.cs#L36-L88)
  explicitly uses `organizations` for its MSA-passthrough service path. Its
  [silent acquisition workaround](https://github.com/git-ecosystem/git-credential-manager/blob/6760f0ef069c994aa2bb1d703fb374986ee82a3e/src/shared/Core/Authentication/MicrosoftAuthentication.cs#L533-L554)
  selects public transfer tenant `f8cdef31-a31e-4b4a-93e4-5f571e91255a` when passthrough
  is enabled and the selected account has MSA home tenant
  `9188040d-6c67-4c5b-b112-36a304b66dad`. That branch has no separate guard for V2's
  explicit caller resource-tenant constraint. Copying it indiscriminately could replace
  the exact tenant the V2 caller requested.
- GCM links the workaround to public [MSAL Issue #3077](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/issues/3077).
  At retrieval, the Issue was closed with `state_reason = not_planned`, five comments,
  and `updated_at = 2025-06-09T10:50:04Z`. The report concerns MSAL 4.37.0 on macOS
  and a first-party application; it identifies the transfer-tenant workaround as Public
  Cloud only. A [maintainer comment](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/issues/3077#issuecomment-1507353678)
  confirms the workaround's then-current necessity. Issue closure is not evidence that
  the behavior was fixed in the pinned Windows dependency. Private work-item links were
  not followed, and account details and raw diagnostics are not reproduced here.

**External reuse evidence and limits:** AzureAuth's [public README](https://github.com/AzureAD/microsoft-authentication-cli/blob/8ef1b8b00782bf20a51de078289819a79c3cba70/README.md#L10-L12)
describes a CLI returning tokens for public-client applications and acting as an Azure
DevOps credential provider. Its Visual Studio identifier and GCM's use of the same
identifier are pinned above. These establish published tool use of the Microsoft-owned
registration. They do not identify a Microsoft support or continued-availability
commitment for this fork, grant ownership of the registration, or show that independently
registered clients have the same legacy capability. The API's first-party limitation
also does not, by itself, establish a blanket prohibition on all third-party tool use
of that public identifier.

**Architecture inference:** Under `V2-REQ-019`, normalized `common` leaves the result
tenant unconstrained within the selected Profile's eligible audience; an explicit or
fixed tenant remains an exact constraint. A separately reviewed legacy provider mapping
can therefore retain `common` intent while using the demonstrated `organizations` and
MSA-transfer routes. It must not run the transfer substitution for an explicit or fixed
resource tenant, and final result metadata remains authoritative. This is the allocation
in the [client-identity view](../architecture/client-application-identity.md#provider-mapping),
not a new runtime result or a generic equivalence between `common` and `organizations`.

Decision `0003` already defines the unofficial external-compatibility posture. The
[external dependency boundary](../architecture/client-application-identity.md#external-dependency-boundary)
now records the actual public reuse evidence and support limits instead of treating a
support guarantee as something established by token success. Profile distribution and
acceptance still require the existing host, authority, redirect/broker, consent, audit,
branding, state-partitioning, explicit-selection, and failure evidence. The successful
probe did not retain the actual result-tenant value and does not validate V2's exact-tenant
branch or prove that the result tenant equals a routing constant.

**Recheck disposition:** RECHECK-007's `client-profile` trigger fires for this assessment.
Its named Azure DevOps source was refreshed above; the accepted Windows observation
remains the bounded account-type evidence. The architecture maps tenant intent and states
the legacy external-dependency boundary without enabling or distributing a Profile.
All seven registry entries were evaluated. RECHECK-001 and RECHECK-002 retain their
accepted dispositions: interaction permission and strict account/result constraints are
unchanged. RECHECK-003, RECHECK-004, and RECHECK-005 do not fire because no new WSL,
system-browser, or Linux-broker path is selected. RECHECK-006's accepted state-ownership
disposition is unchanged. There is no Wave change, release, or new experiment. Mutable
Issue status is dated context for the pinned source finding, not an ongoing claim of a
fix or a separate prerequisite to applying the selected dependency's contract.

### Observed MSA Token, Git Discovery, and Silent Reuse

**Runtime observation, 2026-09-11 UTC:** Under the
[accepted PR #52 protocol](experiments/windows-msal-account-metadata.md#gcm-informed-msa-acquisition-and-silent-reuse),
preparation attempt 12 passed, followed by attended interactive attempt 13 and conditional
fresh-process silent attempt 14. Both account actions found one exact match among multiple
visible accounts and returned the exact requested email, a nonempty unexpired token,
and recognized HTTP 200 authenticated Git discovery for the single designated target.
The interactive operator identified WAM and manually changed the apparent Security Key
selection to Windows Hello PIN. The silent action applied the public MSA transfer-tenant
rule to the newly resolved real account, without an application cache file. Both owned
probe and input-automation processes exited; the sequence is complete and stopped.

**Bounded conclusion:** Requested-personal-account metadata, usable token acquisition,
and later-process silent reuse work in this declared existing Windows scenario with the
GCM-informed configuration. The mechanism's feasibility for that scenario need not remain
an unobserved premise. Existing state, a single host/target, and the paired configuration
limit attribution and generalization. No clean first-use, alias coverage, cross-consumer
interoperability, actual returned-tenant identity, full Git operation, or broader support
is inferred. RECHECK-007 now has bounded token/resource behavior evidence. The
[client-profile assessment](#client-profile-and-tenant-mapping-assessment) records the
separate public reuse and support boundary; the concrete Profile-selection gate remains
open.

### Host and Registration Recheck for the Probe

The 2026-09-10 UTC desk refresh inspected the public sources below before proposing
native Windows execution initiated from WSL. This evaluates the applicable research
boundary; it selects no V2 WSL or Linux-broker implementation and transports no token.

| Concern and source | Retrieved state and bounded outcome |
| --- | --- |
| Windows [WAM guidance](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/wam) | The page identifies supported Windows versions, a required parent window, account picking for mixed authority audiences, and possible browser fallback. The probe owns a Windows Forms parent, requires broker availability, and declines browser fallback. These are preparation choices, not observed host behavior. |
| RECHECK-003: [Issue #460](https://github.com/AzureAD/microsoft-authentication-cli/issues/460) | Open; `updated_at = 2026-05-13T17:25:51Z`. Its body proposes a Windows helper, trust/version/transport boundaries, and missing-helper/fallback handling. It is a proposal, not evidence of an upstream implemented bridge. This probe uses an exact local Windows executable and returns only flags. |
| RECHECK-003/005: [current WSL guidance](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/linux-dotnet-sdk-wsl) | Documents native Linux broker packages, dependencies, and an unlocked keychain. It does not supply the Windows-helper protocol proposed by #460. This experiment uses native Windows WAM; it does not install or invoke that Linux broker. |
| RECHECK-005: [PR #462](https://github.com/AzureAD/microsoft-authentication-cli/pull/462) | Open and unmerged; `updated_at = 2026-08-14T10:00:41Z`. The inspected diff adds Linux broker routing, a Linux redirect, and OS-account listing, while retaining an OS-default sentinel fallback. Its reported Ubuntu test is public author-reported experience, not a V2 support result or this experiment's implementation. |
| RECHECK-007: [Azure DevOps guidance](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/entra-oauth?view=azure-devops) | The dated guidance concerns ordinary Entra applications. Earlier account sequences returned no token; the subsequent [GCM-informed sequence](experiments/windows-msal-account-metadata.md#gcm-informed-msa-acquisition-and-silent-reuse) returned exact-account tokens and recognized authenticated discovery through both attended interaction and fresh-process silent reuse. This resolves the token/resource feasibility question for the declared existing Windows configuration. It does not identify the earlier failure cause or establish intended external registration reuse; no Profile is selected. |

RECHECK-001, RECHECK-002, and RECHECK-006 retain their bounded desk dispositions; this
protocol does not amend product interaction, account, or cache requirements. RECHECK-004
is not activated as a browser workstream: the probe declines that mechanism. Later
platform/Profile choices and fired triggers retain their full recorded outcomes.

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
Microsoft-owned Azure DevOps profile remains unselected. The accepted Windows observation
now supplies bounded exact-account token/resource and later-process reuse evidence. The
[client-profile assessment](#client-profile-and-tenant-mapping-assessment) records the
public reuse evidence, first-party capability limitation, and absence of a fork support
commitment; the concrete product selection gate remains open.

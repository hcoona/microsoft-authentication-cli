# Validation Strategy

This record defines the evidence required before v2 can claim support. No implementation
or release currently satisfies these gates.

Scenario tests provide the main coverage of business behavior. Focused unit and contract
tests protect core rules and public behavior, while targeted real-environment tests cover
properties that simulation cannot establish.

## Test Design and Evidence Selection

Organize most business-behavior coverage around the user journeys and the account,
interaction, reuse, and failure scenarios below. Exercise the application boundary with
controlled dependency substitutes where practical, and assert caller-visible outcomes
and required side effects. Scenario tests need not contact a service, open real UI, or
run the entire deployed system.

Use focused unit tests for core algorithms and functions whose correctness warrants
precise protection, such as strict account matching, scope satisfaction, terminal versus
retryable classification, and deadline transitions. Protect serialized public behavior
with contract tests. Avoid locking ordinary orchestration code to private method calls,
mock call counts, class layouts, or incidental internal ordering. Required ordering, such
as selected-account silent acquisition before interaction, remains observable behavior to
test. A behavior-preserving refactor should not require rewriting business expectations.

The layers and matrices below describe coverage responsibilities, not a requirement to
repeat every case at every test level. Choose the least costly level that establishes
the property. Rely on documented dependency contracts for behavior delegated to that
dependency; test the engine's use of the contract and the integration assumptions that
could change an architectural choice. Do not attempt to re-prove an operating system or
provider through an exhaustive mock suite.

Use public desk evidence when it answers a decision-relevant question. Real broker,
browser, secure-store, and WSL behavior still require the applicable bounded observations
before support is claimed; simulated success cannot supply that evidence. This strategy
does not waive the primary-journey gate, required rechecks, experiment authorization, or
accepted protocols. Evidence depth should reflect the decision, credible failure, and
cost, rather than an arbitrary unit-test count or coverage target.

For architecture work, start from V1's existing integrations and the
[V1-to-V2 delta assessment](../research/v1-public-contract-baseline.md#architecture-reuse-and-remaining-deltas).
Use relevant public runtime experience with its reported scope, alongside source and
dependency contracts; local repetition is not a prerequisite for learning from an
existing product. Focus new observations on a changed assumption that can alter the
decision. This avoids repeating established mechanism checks while preserving the
V2-specific primary-journey and release evidence below.

Owner-operated observations on existing machines are valid evidence when collected
under an accepted [experiment protocol](../research/experiment-safety.md#experiment-authorization).
Record relevant prior state, manual steps, actual host, attempt history, and retention
limits. An existing-state result must not be described as a clean first-use result;
manual assistance cannot substitute for a capability the product itself must provide.

## Primary Journey Gate

The [personal Azure DevOps Git journey](../product/user-stories.md#primary-journey-personal-azure-devops-git-access)
is a first-release blocker. Before release, bounded evidence must demonstrate that an
external adapter can request the selected personal Microsoft account's Azure DevOps
access token without silently receiving the corporate default account, and that usable
state enables strict selected-account silent reuse across invocations.

The proof concerns the engine's authentication boundary under
[V2-REQ-005](../product/requirements/product-boundary.md#v2-req-005-no-personal-access-tokens),
including independence from PAT prerequisites or fallback. Git protocol and repository
remote parsing remain outside this boundary. The adapter supplies a Client Profile, full
email,
Azure DevOps scope, interaction permission, and protocol version. It is not evidence
that WAM must implement this path or that any profile or platform is already supported.

The unresolved obligations include:

- a suitable external client registration and bounded MSA/Azure DevOps behavior under the
  [external-client-profile gate](../product/compatibility-and-migration.md#externally-owned-client-profile-gate)
  and `RECHECK-007`;
- real provider-account enumeration and authoritative email metadata sufficient for
  pre-resolution and final validation, including alias and same-email visibility limits;
- repeated silent reuse without an identity-opaque operating-system default;
- secure persistence, safe recovery, and accurate persistence warnings for the exact
  supported combination.

The [bounded Windows probe](../research/v1-public-contract-baseline.md#observed-msa-token-git-discovery-and-silent-reuse)
now demonstrates unique exact-account resolution, matching token-result metadata,
authenticated Git discovery, and one fresh-process silent reuse in existing state.
This is mechanism evidence for that configuration, not completion of the engine/adapter
release gate, first-use/alias coverage, cross-consumer reuse, or persistence-failure tests.
No experiment is required merely to state desired behavior; execution requires separately accepted authorization
and a protocol under [experiment safety](../research/experiment-safety.md).
This strategy records proof obligations, not an executable experiment protocol.

## Validation Layers

The [architecture allocation](../architecture/overview.md#user-goal-allocation) and
[request lifecycle views](../architecture/request-lifecycle.md) identify the application
boundaries and paths exercised by these scenarios. Their diagrams are design views, not
evidence that a mechanism or platform passes the corresponding tests.

### Contract Tests

- Explicit command-line request versioning; unsupported majors and invalid arguments
  rejected before authentication.
- One request and one terminal outcome per native authentication process.
- Stable versioned structured stdout for success and failure, including invalid requests;
  prompts, usage text, and diagnostics separated; no alternate authentication output mode.
- Required fields, invalid combinations, and unknown-enum behavior.
- Explicit Client Profile selection, including missing selection with exactly one
  available profile; no implicit/default selection or inline full client configuration.
- Equal interpretation and validation of pre-distributed and user-provided profiles.
- Explicit email, scopes, and interaction permission; no environment-supplied intent,
  scope/resource presets, separate resource input, or request-level mechanism order.
- Fixed profile and trust conflicts rejected; only applicable product deadline and tenant
  defaults applied.
- Zero exit status for success, including persistence warnings, and one stable nonzero
  value for every normally emitted typed failure, consistent with the payload.
- Complete success metadata under
  [`V2-REQ-031`](../product/requirements/result-and-process-protocol.md#v2-req-031-complete-success-metadata),
  one opaque access token, and no public stable account ID or reusable credential artifact.
- Exactly the caller-action outcomes under
  [`V2-REQ-032`](../product/requirements/result-and-process-protocol.md#v2-req-032-caller-action-failure-taxonomy);
  consent and transient origins confined to safe reason details.
- Synthetic token/code and email redaction, including stable email-derived hashes,
  nested exceptions, diagnostics, and telemetry; permitted request/success email channels
  distinguished from prohibited diagnostic propagation.
- Unchanged adapter fixtures across engine updates for every still-supported protocol
  major under
  [`V2-REQ-037`](../product/requirements/result-and-process-protocol.md#v2-req-037-supported-protocol-compatibility).
  A breaking change requires a different major, not a reinterpretation of an old one.

### Policy Tests

- [V2-REQ-005](../product/requirements/product-boundary.md#v2-req-005-no-personal-access-tokens)
  applied to personal- and work-account scenarios: successful delegated acquisition
  needs no PAT input or bootstrap and produces no PAT credential or PAT persistence.
- After permitted delegated paths are exhausted or a terminal failure occurs, return the
  applicable existing outcome without a PAT prompt, exchange, or fallback. Cover silent-only
  exhaustion, denial, unavailable mechanisms, and invalid configuration. Request/Profile
  settings and inherited provider defaults, including a Compact-token default, cannot
  enable PAT behavior. Verify provider-operation semantics and observable effects;
  do not classify credential types by parsing or scanning opaque token contents.
- Versioned product order, profile compatibility filtering without reordering, and
  mandatory silent-first acquisition after unique real-account pre-resolution.
- Host capability discovery never changing caller intent.
- No authentication or state-unlock interaction under every no-interaction request shape.
- Terminal versus retryable failure classification.
- Caller cancellation, user denial, strict identity mismatch, and reported-success
  validation failure remaining terminal.
- Request-local provider claims handling preserving every original constraint; no public
  resource/CAE continuation or `cp1` advertisement.
- Full-string case-insensitive email matching, without alias/domain inference, Account
  Kind, stable-ID selection, or hidden first-account binding.
- No match permitting only policy-allowed interaction; multiple visible matches remaining
  ambiguous without a wrong-account silent attempt.
- Interactive login hint when supported and final authoritative validation regardless of
  hint use.
- Fixed single-tenant policy, eligible multitenant/MSA `common` default, compatible exact
  token/resource-tenant GUID, B2B home/resource-tenant distinction, and no exact-to-common
  fallback or email-domain inference.
- The [provider mapping](../architecture/client-application-identity.md#provider-mapping)
  preserving normalized intent: ordinary `common` requests do not gain legacy passthrough;
  the eligible legacy compatibility path can use its documented routing while preserving
  `common` and strict identity checks. For an MSA account with an explicit resource tenant,
  both silent and interactive operations retain that exact tenant, including across
  permitted fallback. Wrong-tenant results fail validation; routing metadata never
  substitutes for actual result metadata. Fixed-tenant conflicts fail before acquisition.
- Dynamic permission coverage with provider extras allowed; `/.default` resource/result
  association without literal returned-scope matching or access-token parsing; rejection
  of mixed dynamic permissions and `/.default`.
- One finite total deadline across resolution, locks, state, authentication, retries,
  fallback, validation, and persistence; bounded caller override, no profile default or
  timer reset.
- Host combinations that require an external UI owner or raw platform handle remaining
  unavailable under the native CLI contract.
- Unusable state treated as a miss and never consumed; recovery preserving request
  constraints, interaction permission, and the original deadline.
- Compatible OS sign-in state considered on first engine use without a prior V2 sign-in
  or V2-created cache; strict pre-resolution and terminal validation still required.
- A change of consumer, package ecosystem, or working repository alone not causing
  another sign-in when valid, safe state can satisfy the otherwise compatible request.
- Validated result delivery not waiting for persistence; success carries a
  machine-readable warning when safe persistence fails or is not confirmed complete.
  No plaintext fallback or caller/profile cache modes.
- Network telemetry remaining disabled until explicitly configured, and export or flush
  failure leaving the authentication result and process status unchanged within a finite
  shutdown bound.

### Mechanism Tests

- Selected-account silent acquisition.
- The exact accepted Profile/host's ordinary, legacy-passthrough, and explicit-tenant
  paths where applicable. Existing legacy `organizations`/transfer observations do not
  establish direct `/common` passthrough, exact-tenant MSA behavior, or arbitrary client
  registration eligibility. Use dependency contracts first and bounded observations only
  for remaining integration uncertainty; no all-platform cross-product matrix is implied.
- Rejection of identity-opaque operating-system-account silent acquisition.
- Broker interactive acquisition.
- System-browser acquisition.
- Device-code acquisition.
- Secure state read/write, unreadable/undecryptable/corrupt/incompatible state recovery,
  and persistence-failure separation from acquisition success.
- Concurrent access to shared cache state preserving locking and update integrity.

These are future mechanism evidence obligations, not a selected implementation list.
The first version has no Logout, Cache Clear, Force Refresh, or Account List tests as
supported operations; contract tests instead verify that they are not exposed.
Cross-process interaction single-flight is not an acceptance condition.

### Real Environment Tests

Real broker and host behavior must be exercised on supported systems. Mocked MSAL builders
cannot prove UI ownership, account picker behavior, keyring integration, or cancellation.
Broker tests must stay within the environment and account-state boundaries of the
accepted Wave and experiment protocol under
[`../research/experiment-safety.md`](../research/experiment-safety.md); cache-directory
separation alone does not isolate OS accounts.

## Account-State Matrix

| State | Required observations |
| --- | --- |
| Empty application cache | Resolve visible real provider accounts before any silent attempt; absence cannot trigger ambient silent acquisition. |
| First V2 use with compatible OS sign-in state and no V2-created cache | Consider the OS state without requiring prior V2 sign-in; resolve the unique requested real account before silent acquisition and validate every success postcondition. |
| First V2 use with only opaque or incompatible OS state | Do not substitute the OS default or assume resource authorization; preserve account resolution, typed outcomes, and interaction permission. |
| One exact visible account with usable state | Selected account is attempted silently first and success reports provider-observed email, not a stable ID. |
| Multiple visible accounts with one full-email match | Only the unique matching account is eligible for silent acquisition. |
| No matching account | No silent fallback to another account; interaction-required handling follows request permission. |
| Corporate OS default differs from requested personal email | Default is not substituted; identity-opaque OS-account acquisition is never used. |
| Multiple visible accounts with the same email | Account ambiguity is terminal; no hidden binding or Account Kind disambiguation. |
| Aliases, missing provider email, or non-enumerated accounts | Different aliases do not match; unverifiable success fails; document visibility limits without claiming detection of hidden duplicates. |
| Guest and home-tenant representations | Exact selector checks the token/resource tenant, not the account home tenant. |
| Microsoft account and work account | Behavior is recorded per client application/resource, without an independent public Account Kind postcondition. |
| Usable state on a subsequent invocation | Strict pre-resolution and silent-first behavior recur without silently relaxing identity or storage policy. |

### Account-Context Variants

The following are variants of the [requested-account goal](../product/user-stories.md#account-context-variants),
not separate stories or an automatic supported-platform or first-release matrix:

| Computer account context | Requested account | Evidence focus |
| --- | --- | --- |
| Company account | Company account | Select the requested email, not an assumed company default. |
| Company account | Personal account | Preserve the primary wrong-default scenario and its first-release gate. |
| Non-company account | Company account | Do not substitute the computer's non-company default. |
| Non-company account | Personal account | Do not assume that the selected email is the computer's default personal identity. |

For any combination selected for support, record default-account relation, target-account
state, and device-management, join, and compliance context independently. Exercise first
engine use with OS state separately from later engine-state reuse. Account labels alone
are not evidence of device state or service eligibility.

## Cross-Consumer Reuse Scenarios

These scenarios validate
[`V2-REQ-041`](../product/requirements/cache-security-and-operational-identity.md#v2-req-041-safe-reusable-state-recovery-and-concurrency)
for [package consumers](../product/user-stories.md#reuse-authentication-across-package-ecosystems-and-repositories)
and other compatible callers. They do not select a cache architecture or credential
translation path.

| Scenario | Required evidence |
| --- | --- |
| Sequential compatible calls from different package ecosystems or working repositories with valid, safe reusable state | Changing only the consumer context does not cause another user sign-in. Each result independently satisfies strict account, tenant, profile, resource, and scope constraints. |
| Concurrent compatible calls with reusable state already available | State remains consistent and updates retain integrity; consumer differences alone do not cause another sign-in. Lock waiting and acquisition stay within each request's original deadline. |
| Concurrent calls when usable state is absent or insufficient | Each call obeys its interaction permission, classified fallback, and deadline. Do not require a cross-process single prompt or identical token bytes. |
| Changed account, tenant, profile/cloud, resource/scopes, or security context | Prior success in another context is not sufficient for reuse or result validity. Verify the current request's constraints rather than widening them to consume state. |
| Missing, locked, corrupt, incompatible, or unpersisted state | Unsafe state is not consumed, no plaintext fallback occurs, and recovery preserves interaction permission and deadline; validated success with a persistence warning does not promise state will be reusable later. |

Observe engine requests, validated results, user-facing interaction, and safe state
outcomes rather than treating equal token bytes as proof of reuse. Package-ecosystem
credential materialization, session-credential exchange, and derived-credential lifecycle
are downstream concerns, not engine acceptance criteria. Public implementation examples
do not establish cross-consumer interoperability.

## Generic Caller Scenarios

The [direct-service](../product/user-stories.md#direct-protected-service-access) and
[integrated-tool](../product/user-stories.md#authentication-integrated-into-a-remote-tool-workflow)
goals consume the existing delegated public-client and process boundary, not new engine
protocols. Planned contract and policy fixtures cover:

- a direct caller supplying an explicit profile, selected email, intended resource
  scopes, interaction permission, and protocol version, receiving only a validated
  structured access-token result and authoritative metadata;
- an external tool integration making that same engine request and handling the typed
  result without an engine-owned service connection or consumer-protocol implementation;
- wrong or missing identity, incompatible target/profile, insufficient authoritative
  scope metadata, and prohibited interaction producing the existing constrained failure
  behavior rather than an unvalidated token or broader fallback;
- repeated compatible requests exercising the reuse scenarios above, with token
  application and any consumer-specific credential translation left downstream.

Mocks can validate this engine boundary without contacting a protected service or
implementing an adapter. Actual profile/resource/account eligibility and real-platform
reuse require separately authorized bounded evidence before support is claimed. These
goals do not imply service authorization for every user identity, personal-account
support for every resource, an MCP engine protocol, or a new first-release support matrix.

## Interaction Matrix

For every supported mechanism:

- no-interaction request;
- interaction allowed after silent miss;
- user cancellation;
- user denial;
- consent required;
- provider-local claims challenge;
- prompt timeout;
- interactive-surface owner or completion channel unavailable;
- external browser left open after request termination.

No-interaction tests must detect broker, browser, device-code, terminal, and state-unlock
surfaces, not merely an absent token. Cleanup observations distinguish controlled UI from
external surfaces that cannot be closed, prove that a late response cannot resume an
ended request, and do not claim reversal of independently completed provider sessions.

## Platform Matrix

| Platform or host | Required decision and evidence |
| --- | --- |
| Windows native | WAM availability, selected account, v2-owned interaction context, cancellation, cache, and multi-account behavior. |
| WSL directly invoking the Windows CLI | Caller-selected executable, interoperability availability, unchanged CLI contract, Windows configuration and path interpretation, account selection, UI ownership, cancellation/disconnect, timeout, and confidential result transport. |
| WSL with native Linux broker, outside the selected deployment | A separate selection would require WSL version, broker package, native dependencies, keyring state, account UI, and failure-mode evidence. |
| Linux headful | System browser, callback, secure store, and cancellation. |
| Linux headless | Device code, no-browser behavior, secure-store absence, product-owned secure-state policy, and cross-invocation reuse for any claimed repeated-noninteractive capability. |
| macOS | System browser, Keychain, and broker behavior if declared supported. |

This is an evidence-planning matrix, not a selection of supported platforms or mechanisms.
The first supported release may choose a smaller matrix while satisfying the primary
journey gate. Unsupported combinations must be explicit and fail safely.

The [selected WSL deployment](../architecture/overview.md#deployment-wsl-caller-and-windows-cli)
requires scenario coverage for both a requested personal account accessing a personal
Azure DevOps repository and a requested work account accessing a company repository.
Exercise a different available/default account, exact resource-tenant constraints,
silent reuse, interaction forbidden/allowed, and wrong-account or wrong-tenant rejection.
Verify ordinary CLI output reaches the WSL caller without prompt or diagnostic mixing.
Missing executables and disabled interoperability remain launch failures; there is no
automatic Linux fallback. Cancellation and caller disconnection must be assessed at the
Windows process boundary, including the CLI's own finite request deadline.

Azure Artifacts consumes the same Azure DevOps token-acquisition capability under the
[public source assessment](../research/v1-public-contract-baseline.md#wsl-direct-invocation-and-azure-artifacts).
Cross-consumer scenarios cover reuse with compatible account, Profile, tenant, and scopes,
and separation when any relevant context differs. Downstream integration evidence must
identify whether the adapter presents the access token directly or uses a separately
selected derived-credential path; NuGet does not universally require an exchange.
For the selected direct-token design, a claim of NuGet/Artifacts support needs the actual
account, Profile, feed, and credential-presentation path, including Basic authentication
where used. The accepted personal-account Git discovery result does not satisfy that
downstream obligation. [V2-REQ-005](../product/requirements/product-boundary.md#v2-req-005-no-personal-access-tokens)
applies throughout; a failed direct request does not authorize the upstream default
exchange or a new engine mechanism.
Feed permissions and package-manager protocols remain downstream integration evidence;
token acquisition alone does not demonstrate a successful restore or package operation.

## Failure and Resilience Matrix

- Network unavailable before and during each mechanism.
- Proxy and TLS failures.
- Authority, tenant, scope, or client misconfiguration.
- Explicit-request conflicts with enforced-profile or trust constraints.
- Unsupported, noncanonical, or untrusted authority hosts.
- Broker unavailable or unsupported.
- Browser launch or callback failure.
- Locked, missing, corrupt, undecryptable, incompatible, or permission-invalid state.
- Secure storage unavailable under the product state policy, without plaintext fallback;
  validated token plus persistence failure, safe recovery, and retained deadline.
- For a timely validated candidate, compare confirmed safe persistence, known failure,
  and unavailable confirmation: only the first omits the persistence warning. Classify
  evidence already available from the provider/state integration without additional
  I/O, acquisition, or a watcher wait at delivery. Provider success or cache timing alone
  must not fabricate confirmation. Broker reuse does not require an engine-owned copy.
- Provider failure before a candidate result is returned: classify the acquisition
  outcome without emitting a partial token or relabeling it as success with a warning.
- Acquisition and all required success validation complete with persistence still
  pending and no deadline expiry: return success, the validated token, a persistence
  warning, and zero exit status without waiting for persistence or the deadline.
- Incidental deadline expiry after acquisition and all required success validation
  completed within budget but before result delivery: accept either validated success
  or timeout under `V2-REQ-015`, without requiring a particular completion ordering.
  Success carries the token, zero exit status, and a persistence warning if safe
  persistence failed or is unconfirmed; timeout carries no token and the common nonzero
  exit status. Neither outcome extends the deadline or leaves V2-controlled persistence
  work running after the request ends.
- Acquisition or required success validation incomplete at deadline expiry: return
  timeout without a token and with the common nonzero exit status; late results cannot
  resume the ended request.
- Process cancellation during lock wait and each mechanism, including while persistence
  is pending after validation; persistence status cannot override cancellation.
- Dependency exception not recognized by the policy layer.
- Process output overflow, malformed output, or diagnostic contamination.

Operating-system kill, incomplete output, and malformed output must be distinguished by
consumer validation from a normal typed failure; they do not justify fabricating a
complete result. The
[2026-09-09 secure-store desk outcome](../research/v1-public-contract-baseline.md#recheck-006-secure-store-availability)
is not evidence that the V2 failure/recovery matrix passes.

## Windows Slice Design Acceptance

The [concrete Windows design](../designs/windows-ado-authentication.md) and
[protocol/Profile schemas](../../contracts/v1/request.schema.json) select the bounded
design for the two Azure DevOps account journeys. This section owns its scenario evidence
basis. A schema-valid example is not an executed CLI request, a passing authentication
scenario, or Profile/support acceptance.

Before design acceptance, validate every schema against its metaschema, validate embedded
synthetic examples with JSON Schema 2020-12 and format checking, and exercise negative
shape cases: missing explicit intent, unsupported versions/enums, duplicate scopes,
deadline limits, conflicting legacy Profile identity/tenant policy, and credentials in a
failure result. Check additive result-field tolerance separately from strict input
readers. Review the semantic cases below alongside those checks; JSON Schema does not
prove resource equivalence, tenant precedence, provider behavior, or lifecycle correctness.

| Scenario | Required observable outcome | Evidence before the corresponding claim |
| --- | --- | --- |
| Personal request with a different corporate OS default | Unique matching real account is used silently first; permitted interactive completion must still return the exact requested email. No PAT bootstrap or default-account request. | Orchestration scenario plus bounded Windows personal-account integration before Profile/support acceptance. Existing .NET 8 evidence is limited to its recorded setup. |
| Work request for company Azure DevOps | Requested work email and, when supplied, exact resource tenant are retained through silent/interactive acquisition and final validation. | Orchestration scenario; bounded work-account integration before claiming that combination. Company repository access is a separate downstream test. |
| First use and later invocation | Discovery considers eligible broker accounts without a prior V2 cache. Later compatible invocation attempts selected-account silent reuse. | Scenario doubles for ordering; real first-use/existing-state Windows evidence for availability and UI behavior. |
| Git followed by Artifacts acquisition | Changing the downstream consumer alone does not force another sign-in. Different account/client/tenant/resource contexts are not substituted. | Two-process broker integration; actual Git and feed/package operations remain downstream evidence. |
| No match, duplicate match, and alias-only visibility | No match follows permission policy; duplicate exact matches stop as ambiguity; an alias or missing email does not pass identity validation. | Scenario tests of calls and outcomes; unit tests only for the pure matching rule. |
| Tenant and scope normalization | Fixed or explicit tenant wins over legacy MSA routing. `common` uses the selected integration's mapping. Mixed resources/default-plus-dynamic scopes fail admission; dynamic coverage uses provider metadata. | Table-driven core tests plus scenario tests that preserve constraints through both calls. |
| Wrong/missing provider metadata | No token reaches stdout after wrong email, exact-tenant mismatch, missing actual tenant, insufficient scope coverage, or a mismatched operation/client context. | Candidate-validation scenarios and core validation tests; real result metadata coverage before activation. |
| Noninteractive request in locked or expired state | No owned UI, broker interaction, browser, device-code instruction, or unlock prompt is initiated. Return the applicable interaction/unavailability outcome. | Scenario call assertions and attended real-platform no-UI observation; do not infer this solely from API names. |
| Broker unavailable or disappears between checks | Return `mechanism_unavailable`; rejecting custom web UI prevents automatic browser fallback. | Provider/host scenario, then bounded Windows failure test before support. |
| User cancellation, denial, or another claims challenge | Stop within the same request; no alternate account, tenant, registration, mechanism, PAT, or repeated interaction. Only current silent-challenge data may reach the permitted interactive call. | Scenario outcomes and provider-call trace; bounded UI cancellation/denial evidence. |
| Lifetime pipe closes before discovery or during WAM | Cancel without late success, end owned UI and process, and expose no token. Reject console/file stdin when the pipe flag is selected. | Deterministic lifecycle scenario and actual WSL-to-Windows pipe integration, including writer-handle inheritance. |
| Linux caller dies without the optional lifetime pipe | Do not assert Linux signal delivery to Windows. Windows work ends through detected transport failure or the original finite deadline. | Bounded WSL process-lifetime test; no immediate-disconnect support claim for this combination. |
| Deadline during Profile reading, discovery, silent, interaction, or validation | Original deadline is never restarted. Incomplete validation yields timeout; late candidates cannot resume. | Clock-driven scenarios and bounded real host tests for dependency cancellation and process exit. |
| Blocked stdout/stderr or uncooperative completion | The shutdown watchdog ends the one process within the defined local shutdown allowance. Incomplete output is a transport failure, never a complete typed result. | Controlled process/pipe scenario before shipping; no tests using real credentials are needed for this transport condition. |
| Validated token with no broker persistence receipt | Return success with `persistence_unconfirmed`, no readback, extra acquisition, write, or persistence wait. Next invocation may still reuse usable state. | Scenario and real reuse evidence; do not infer durable-write confirmation from provider success. |
| Concurrent invocations | Broker integrity is preserved through supported APIs; no app-owned cache or locking is introduced. Duplicate prompts are not suppressed by contract. | Concurrent Windows integration before that support claim; trust broker internals within their documented boundary. |
| Explicit Profile file and compatibility candidate | Same parser for user-provided and eventually provisioned files; no implicit selection, hot reread, external URL, inherited configuration, or upstream cache import. Show external ownership without claiming Microsoft endorsement. | Admission scenarios, contract examples, and later bounded consent/audit/branding validation under the external Profile gate. |
| Output and optional local telemetry | One complete result with matching 0/1 status, or recognizable transport failure. Only validated success exposes a token; stderr has no token/email/identifier/provider text. Local telemetry opt-in, overflow, or sink failure cannot alter authentication. | Contract and orchestration scenarios with synthetic secret markers; no production credential fixture. |

The design's public dependency premises and security/TMT update receive independent
architecture, consistency, minimality, security, record-system, and research-evidence
review. Record schema checks, native TMT open/analysis, review identities, findings and
dispositions, and exact reviewed tree in the PR. Design acceptance does not require
pretending that these future runtime cases already pass, nor does it authorize running
them. A newly found premise that invalidates a selected implementation path must be
resolved before calling that path design-ready.

The Slice explicitly excludes browser/device code, Linux forwarding/native brokers,
non-Public Cloud, service/impersonated/disconnected Windows sessions, ARM64, Profile
activation/distribution, service protocols, derived-credential exchange, and network
telemetry export. Requirements outside this bounded design retain their existing gates;
no complete-product or platform-support acceptance follows from this Slice alone.

## Native AOT Publishing

For [V2-REQ-055](../product/requirements/quality-build-and-validation.md#v2-req-055-native-aot-publishing),
the design records a disposition for every in-scope executable and accepted runtime
identifier: a supported candidate Native AOT path with its exact prerequisites, an
evidence-backed exception with a specified alternative publishing mode and reassessment
condition, or an unresolved choice that cannot be called implementation-ready. Review
public toolchain/dependency contracts and supported alternatives before accepting an
exception. Requirement acceptance does not establish compatibility of the current
UI/MSAL host; the [concrete disposition](../designs/windows-ado-authentication.md#native-aot-target-disposition)
currently leaves Windows publishing unresolved while assessing the Win32/Native AOT
candidate. No non-AOT exception or implementation-readiness claim is accepted.

For that candidate, close the exact Broker/NativeInterop compatibility premise before
implementation readiness: recover the resolved net8 client, netstandard Broker and net9
NativeInterop assets, inspect all relevant AOT/trim diagnostics and native dependencies,
and establish that the public loader works within the application-directory/System32
search boundary. A separately authorized synthetic publish/loading check may establish
part of that premise without accounts or token operations. The
[synthetic protocol](../research/experiments/windows-native-aot.md) defines its exact
scope and limits; execution authority remains with the current accepted Delivery Wave.
Record the exact Windows C++ compiler/SDK/linker as well as .NET inputs in its protocol.
Missing, wrong-architecture or unavailable native assets must fail without probing an
arbitrary working directory or using a developer-machine dependency.

The [recorded synthetic results](../research/experiments/windows-native-aot.md#retained-native-artifact-runtime-results)
now cover native artifact production and actual Windows-host execution of the exact
retained EXE. The positive case created MSAL configuration and entered the upstream
NativeInterop configuration-allocation import with the module loaded from the application
directory. Missing-library and working-directory/PATH-decoy cases both returned
`DllNotFoundException` without loading the module. All three had explicit normal controller
completion, zero job-process counts, and no termination request. These observations
satisfy those three synthetic cases only; all experiment capacity is consumed.

The producing publish's historical controller stop still has no uniquely identified
origin or retained AOT/trim diagnostics. The accepted retained-artifact disposition
preserves that uncertainty; new runtime success does not satisfy publish-warning review
or prove every native release/shutdown operation. Before implementation readiness or
production publishing, retain the outstanding warning/dependency, full native cleanup,
wrong-architecture, WAM/UI/authentication and complete-application evidence obligations.
Preserve historical artifacts, receipts, consumption and trust-processing uncertainty.
No non-AOT exception or disabled platform check is justified by these results.

The [supplemental result](../research/experiments/windows-native-aot.md#readiness-results)
adds a completed local-feed restore and native artifact production with the provider
surface rooted for compilation. Its publish controller stopped on a remaining Job member
and confirmed termination/quiescence before diagnostic screening. No publish-completion
receipt or warning evidence, cleanup result, or wrong-architecture result follows. A
recovery requires its own accepted Wave/protocol within carried-forward limits; subject
exit zero and data inspection cannot substitute for the missing evidence.

The [recovery result](../research/experiments/windows-native-aot.md#recovery-results)
provides complete screened diagnostic evidence for the exact rooted symbol-free probe,
with no observed AOT/trim/compiler/link warning. Its publish again stopped on a surviving
Job member after the bounded normal drain; owned termination succeeded and final
quiescence was confirmed. No publish-completion receipt or runtime result follows.
Static x64 PE/import observations do not settle dynamic native dependencies. Preserve
the remaining normal-completion, cleanup, wrong-architecture, dependency and product-symbol
obligations and all historical diagnostic unknowns. The stopped recovery cannot resume
or use its unused runtime capacity; restore/publish limits are exhausted. Further
execution must use the later accepted buffered Wave and a fresh exact protocol amendment.
The [first diagnostic round](../research/experiments/windows-native-aot.md#diagnostic-round-01-results)
retained complete warning-free output and a verified Job member with unknown image class,
then stopped with successful owned termination and final quiescence. It supplies no new
runtime or normal-publish evidence. Preserve all these obligations; the publishing choice
and preimplementation gap remain unresolved.

The [third diagnostic round](../research/experiments/windows-native-aot.md#diagnostic-round-03-results)
adds a sampled image-string match for MSVC `vctip.exe`, complete warning-free diagnostics
and confirmed owned termination. It still lacks normal publish completion and runtime
cases. A public build system's acceptance of surviving helpers cannot satisfy this
experiment's zero-process completion rule. Preserve historical unknowns, the remaining
cleanup/x86/dependency obligations and the unresolved publishing disposition.

Review and render the C4 deployment and UML request, UI-cancellation and terminal-state
sources against their normative contracts. Later candidate tests must cover HWND
readiness, creation failure, callback lifetime/ABI, creating-thread destruction, stalled
UI dispatch, keyboard/accessibility/DPI/focus behavior, and cancellation racing provider
completion. Verify strict Profile parsing and result allowlists on the published binary,
including duplicate/unknown JSON fields and synthetic secret markers. Use the existing
scenario matrix for account, tenant, interaction, reuse and lifetime semantics rather
than treating an AOT publish as their acceptance.

Before claiming a publishing mode is supported, retain evidence for the exact source,
SDK, runtime identifier, native compiler, dependency versions, and publish configuration.
Verify that the artifact uses the selected mode, includes every required native/runtime
asset, and starts on its declared host without undeclared development-machine packages.
Inspect AOT/trimming diagnostics and justify each remaining suppression against a real
reachable-path obligation. A successful publish or absence of warnings alone does not
prove runtime compatibility.

Exercise the applicable existing contract and scenario basis on the published artifact,
including serialization, native broker loading, strict account/result validation,
silent and permitted interactive paths, owned UI, cancellation, deadline, and process
termination. Select the least costly evidence level that establishes each property;
real WAM/UI behavior still needs bounded Windows evidence. Apply these obligations to
an accepted non-AOT exception as well. Do not add redundant copies of the scenario matrix
or weaken the primary-journey, Profile, security, and release gates.

Before a performance comparison runs, define a representative workload, host and
account-state assumptions, the selected non-AOT baseline, sample/attempt limits, and
decision-relevant acceptance criteria. Compare process startup separately from network
or user-interaction time, memory, total deployed size including native assets, and
build/diagnostic costs using equivalent functionality and configuration. Record the
measurement method and variability; claim only observed benefits. A desired benefit or
an AOT setting alone is not a measured improvement. This validation basis is not an
execution protocol; experiments require their own accepted authorization and protocol.

The Windows comparison baseline is the same Win32 host, .NET/runtime, RID, provider pins,
request/serialization behavior and native assets, published self-contained with JIT,
without trimming or ReadyToRun. It is a comparison input, not an accepted exception.
Separate synthetic help/invalid-request startup from silent and interactive network/UI
time. Before running a comparison, its accepted protocol must specify numerical criteria
appropriate to those workloads, warm/cold cache conditions, sample limits and variability;
this desk review invents no measurement or benefit threshold after seeing results.

## Dependency Upgrade Matrix

Each MSAL, native broker, cache, and platform dependency upgrade, including native
interop, must be independently testable, pinnable, and reversible. An evaluation must
isolate the target upgrade and any directly required adaptation from unrelated product
or dependency changes.

At minimum:

1. establish a known baseline source and explicitly pinned dependency set;
2. change one target dependency category per evaluation;
3. verify that both the baseline and proposed versions can be selected through explicit
   pins and tested independently;
4. exercise the applicable Windows, WSL, multiple-account, claims, cancellation, cache,
   secure-storage, and host states;
5. record whether a failure belongs to v2 policy, MSAL, the native broker, cache, platform
   integration, or host
   configuration;
6. restore the prior pin, rerun the applicable matrix, and retain the verified rollback
   path.

The 0.9.5 to 0.9.6 public dependency change is an initial case study, not a presumed
root cause.

## Release Gates

A platform or mechanism is supported only when:

- the first-release primary journey gate is satisfied for the release;
- its required contract, policy, and real-environment tests pass;
- no-interaction and strict-identity postconditions are directly observed;
- cancellation leaves no v2-owned task, listener, lock, or controllable prompt running;
  externally owned browser sessions can no longer complete the pending request;
- output and diagnostics obey authentication-material and email-channel containment;
- secure-state recovery, incompatible-state handling, concurrency, and persistence-warning
  behavior are documented and validated;
- a claimed headless-Linux repeated-noninteractive capability demonstrates compliant
  cross-invocation authentication-state reuse;
- the exact client application and dependency versions are recorded;
- the selected publishing mode meets the [Native AOT validation basis](#native-aot-publishing),
  including any accepted target-specific exception;
- installation and update behavior cannot collide with upstream AzureAuth.

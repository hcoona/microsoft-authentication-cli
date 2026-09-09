# Validation Strategy

This record defines the evidence required before v2 can claim support. No implementation
or release currently satisfies these gates.

Unit tests are necessary for policy and serialization, but simulated tests alone cannot
establish broker, browser, secure-store, or WSL behavior.

## Primary Journey Gate

The [personal Azure DevOps Git journey](../product/user-stories.md#primary-journey-personal-azure-devops-git-access)
is a first-release blocker. Before release, bounded evidence must demonstrate that an
external adapter can request the selected personal Microsoft account's Azure DevOps
access token without silently receiving the corporate default account, and that usable
state enables strict selected-account silent reuse across invocations.

The proof concerns the engine's authentication boundary, not Git protocol, repository
remote parsing, or PAT lifecycle. The adapter supplies a Client Profile, full email,
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

Existing desk evidence does not establish these properties. No experiment is required
merely to state desired behavior; execution requires separately accepted authorization
and a protocol under [experiment safety](../research/experiment-safety.md).
This strategy records proof obligations, not an executable experiment protocol.

## Validation Layers

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
- Dynamic permission coverage with provider extras allowed; `/.default` resource/result
  association without literal returned-scope matching or access-token parsing; rejection
  of mixed dynamic permissions and `/.default`.
- One finite total deadline across resolution, locks, state, authentication, retries,
  fallback, and validation; bounded caller override, no profile default or timer reset.
- Host combinations that require an external UI owner or raw platform handle remaining
  unavailable under the native CLI contract.
- Unusable state treated as a miss and never consumed; recovery preserving request
  constraints, interaction permission, and the original deadline.
- Validated access-token success plus a machine-readable warning when safe persistence
  fails; no plaintext fallback or caller/profile cache modes.
- Network telemetry remaining disabled until explicitly configured, and export or flush
  failure leaving the authentication result and process status unchanged within a finite
  shutdown bound.

### Mechanism Tests

- Selected-account silent acquisition.
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
Broker tests must use the dedicated operating-system user or VM required by
[`../research/experiment-safety.md`](../research/experiment-safety.md); cache-directory
isolation alone does not isolate OS accounts.

## Account-State Matrix

| State | Required observations |
| --- | --- |
| Empty application cache | Resolve visible real provider accounts before any silent attempt; absence cannot trigger ambient silent acquisition. |
| One exact visible account with usable state | Selected account is attempted silently first and success reports provider-observed email, not a stable ID. |
| Multiple visible accounts with one full-email match | Only the unique matching account is eligible for silent acquisition. |
| No matching account | No silent fallback to another account; interaction-required handling follows request permission. |
| Corporate OS default differs from requested personal email | Default is not substituted; identity-opaque OS-account acquisition is never used. |
| Multiple visible accounts with the same email | Account ambiguity is terminal; no hidden binding or Account Kind disambiguation. |
| Aliases, missing provider email, or non-enumerated accounts | Different aliases do not match; unverifiable success fails; document visibility limits without claiming detection of hidden duplicates. |
| Guest and home-tenant representations | Exact selector checks the token/resource tenant, not the account home tenant. |
| Microsoft account and work account | Behavior is recorded per client application/resource, without an independent public Account Kind postcondition. |
| Usable state on a subsequent invocation | Strict pre-resolution and silent-first behavior recur without silently relaxing identity or storage policy. |

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
| WSL with native Linux broker | WSL version, broker package, native dependencies, keyring state, account UI, and failure modes. |
| WSL invoking a Windows helper | Executable trust, protocol version, Windows configuration, UI ownership, timeout, and token transport. |
| Linux headful | System browser, callback, secure store, and cancellation. |
| Linux headless | Device code, no-browser behavior, secure-store absence, product-owned secure-state policy, and cross-invocation reuse for any claimed repeated-noninteractive capability. |
| macOS | System browser, Keychain, and broker behavior if declared supported. |

This is an evidence-planning matrix, not a selection of supported platforms or mechanisms.
The first supported release may choose a smaller matrix while satisfying the primary
journey gate. Unsupported combinations must be explicit and fail safely.

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
- Process cancellation during lock wait and each mechanism.
- Dependency exception not recognized by the policy layer.
- Process output overflow, malformed output, or diagnostic contamination.

Operating-system kill, incomplete output, and malformed output must be distinguished by
consumer validation from a normal typed failure; they do not justify fabricating a
complete result. The
[2026-09-09 secure-store desk outcome](../research/v1-public-contract-baseline.md#recheck-006-secure-store-availability)
is not evidence that the V2 failure/recovery matrix passes.

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
- installation and update behavior cannot collide with upstream AzureAuth.

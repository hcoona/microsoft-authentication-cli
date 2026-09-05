# Validation Strategy

This record defines the evidence required before v2 can claim support. No implementation
or release currently satisfies these gates.

Unit tests are necessary for policy and serialization, but simulated tests alone cannot
establish broker, browser, secure-store, or WSL behavior.

## Validation Layers

### Contract Tests

- Request and result schema versioning.
- One request and one terminal outcome per native authentication process.
- Stable serialization and stdout discipline.
- Required fields, invalid combinations, and unknown-enum behavior.
- Explicit profile selection overriding a configured default, configured defaults
  overriding sole-candidate selection, and zero or multiple unresolved candidates
  failing safely.
- Explicit request fields overriding selected-profile and ambient defaults.
- Selected-profile defaults overriding ambient defaults.
- Enforced-profile and trust conflicts rejected as invalid requests.
- Deterministic typed-result-to-exit-code mapping that cannot contradict the payload.
- Redaction and synthetic-secret detection.

### Policy Tests

- Exact preservation of acquisition-stage order.
- Host capability discovery never changing caller intent.
- No interaction under every no-interaction request shape.
- Terminal versus retryable failure classification.
- Caller cancellation, user denial, strict identity mismatch, and reported-success
  validation failure remaining terminal.
- Claims retry preserving identity and deadline constraints.
- Identity mismatch and ambiguity failing closed.
- Host combinations that require an external UI owner or raw platform handle remaining
  unsupported by the native CLI contract.
- Network telemetry remaining disabled until explicitly configured, and export or flush
  failure leaving the authentication result and process status unchanged within a finite
  shutdown bound.

### Mechanism Tests

- Selected-account silent acquisition.
- Explicit operating-system-account silent acquisition when permitted.
- Broker interactive acquisition.
- System-browser acquisition.
- Device-code acquisition.
- Cache read, write, logout, corruption, and v2 cache-version migration behavior.
- Concurrent access to shared cache state preserving locking and update integrity.

### Real Environment Tests

Real broker and host behavior must be exercised on supported systems. Mocked MSAL builders
cannot prove UI ownership, account picker behavior, keyring integration, or cancellation.
Broker tests must use the dedicated operating-system user or VM required by
[`../research/experiment-safety.md`](../research/experiment-safety.md); cache-directory
isolation alone does not isolate OS accounts.

## Account-State Matrix

| State | Required observations |
| --- | --- |
| Empty application cache | Silent result is typed and creates no interaction. |
| One exact cached account | Exact account succeeds silently and reports its stable ID. |
| Multiple cached accounts | Strict selection remains deterministic. |
| No matching account | No silent fallback to another account. |
| OS account differs from requested account | OS account is not used unless explicitly allowed. |
| Duplicate or aliased usernames | Stable account IDs disambiguate or the request fails. |
| Guest and home-tenant representations | Tenant and account postconditions remain explicit. |
| Microsoft account and work account | Behavior is recorded per client application and resource. |

## Interaction Matrix

For every supported mechanism:

- no-interaction request;
- interaction allowed after silent miss;
- user cancellation;
- user denial;
- consent required;
- claims challenge;
- prompt timeout;
- parent-window unavailable;
- interactive-surface owner or completion channel unavailable;

No-interaction tests must detect any broker, browser, device-code, or terminal surface,
not merely an absent token.

## Platform Matrix

| Platform or host | Required decision and evidence |
| --- | --- |
| Windows native | WAM availability, selected account, v2-owned interaction context, cancellation, cache, and multi-account behavior. |
| WSL with native Linux broker | WSL version, broker package, native dependencies, keyring state, account UI, and failure modes. |
| WSL invoking a Windows helper | Executable trust, protocol version, Windows configuration, UI ownership, timeout, and token transport. |
| Linux headful | System browser, callback, secure store, and cancellation. |
| Linux headless | Device code, no-browser behavior, secure-store absence, explicit cache policy, and cross-invocation state reuse for any claimed repeated-noninteractive capability. |
| macOS | System browser, Keychain, and broker behavior if declared supported. |

The first supported release may intentionally choose a smaller matrix. Unsupported
combinations must be explicit and fail safely.

## Failure and Resilience Matrix

- Network unavailable before and during each mechanism.
- Proxy and TLS failures.
- Authority, tenant, scope, or client misconfiguration.
- Explicit-request conflicts with enforced-profile or trust constraints.
- Unsupported, noncanonical, or untrusted authority hosts.
- Broker unavailable or unsupported.
- Browser launch or callback failure.
- Locked, missing, corrupt, or permission-invalid cache.
- Secure storage unavailable under each accepted persistence and fallback policy.
- Process cancellation during lock wait and each mechanism.
- Dependency exception not recognized by the policy layer.
- Process output overflow, malformed output, or diagnostic contamination.

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

- its required contract, policy, and real-environment tests pass;
- no-interaction and strict-identity postconditions are directly observed;
- cancellation leaves no v2-owned task, listener, lock, or controllable prompt running;
  externally owned browser sessions can no longer complete the pending request;
- output and diagnostics contain no secrets;
- cache security and v2 cache-version migration behavior are documented;
- a claimed headless-Linux repeated-noninteractive capability demonstrates compliant
  cross-invocation authentication-state reuse;
- the exact client application and dependency versions are recorded;
- installation and update behavior cannot collide with upstream AzureAuth.

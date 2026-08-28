# Validation Strategy

## Status

This record defines the evidence required before v2 can claim support. No implementation
or release currently satisfies these gates.

Unit tests are necessary for policy and serialization, but simulated tests alone cannot
establish broker, browser, secure-store, or WSL behavior.

## Validation Layers

### Contract Tests

- Request and result schema versioning.
- Stable serialization and stdout discipline.
- Required fields, invalid combinations, and unknown-enum behavior.
- Typed failure-to-exit-code mapping.
- Redaction and synthetic-secret detection.

### Policy Tests

- Exact preservation of acquisition-stage order.
- No interaction under every no-interaction request shape.
- Terminal versus retryable failure classification.
- Claims retry preserving identity and deadline constraints.
- Identity mismatch and ambiguity failing closed.

### Mechanism Tests

- Selected-account silent acquisition.
- Explicit operating-system-account silent acquisition when permitted.
- Broker interactive acquisition.
- System-browser acquisition.
- Device-code acquisition.
- Cache read, write, logout, corruption, and migration behavior.

### Real Environment Tests

Real broker and host behavior must be exercised on supported systems. Mocked MSAL builders
cannot prove UI ownership, account picker behavior, keyring integration, or cancellation.
Broker tests must use the dedicated operating-system user or VM required by
`experiment-safety.md`; cache-directory isolation alone does not isolate OS accounts.

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
- concurrent equivalent requests;
- concurrent requests for different strict accounts.

No-interaction tests must detect any broker, browser, device-code, or terminal surface,
not merely an absent token.

## Platform Matrix

| Platform or host | Required decision and evidence |
| --- | --- |
| Windows native | WAM availability, selected account, parent HWND, cancellation, cache, and multi-account behavior. |
| WSL with native Linux broker | WSL version, broker package, native dependencies, keyring state, account UI, and failure modes. |
| WSL invoking a Windows helper | Executable trust, protocol version, Windows configuration, UI ownership, timeout, and token transport. |
| Linux headful | System browser, callback, secure store, and cancellation. |
| Linux headless | Device code, no-browser behavior, secure-store absence, and explicit cache policy. |
| macOS | System browser, Keychain, and broker behavior if declared supported. |

The first supported release may intentionally choose a smaller matrix. Unsupported
combinations must be explicit and fail safely.

## Failure and Resilience Matrix

- Network unavailable before and during each mechanism.
- Proxy and TLS failures.
- Authority, tenant, scope, or client misconfiguration.
- Unsupported, noncanonical, or untrusted authority hosts.
- Broker unavailable or unsupported.
- Browser launch or callback failure.
- Locked, missing, corrupt, or permission-invalid cache.
- Process cancellation during lock wait and each mechanism.
- Dependency exception not recognized by the policy layer.
- Process output overflow, malformed output, or diagnostic contamination.

## Dependency Upgrade Matrix

MSAL and native broker upgrades must be tested independently from unrelated product
changes.

At minimum:

1. establish a known baseline source and dependency set;
2. upgrade MSAL without other source changes;
3. upgrade native interop without other source changes;
4. exercise Windows, WSL, multiple-account, claims, cancellation, and cache states;
5. record whether the failure belongs to v2 policy, MSAL, the native broker, or host
   configuration;
6. retain a documented rollback path.

The 0.9.5 to 0.9.6 public dependency change is an initial case study, not a presumed
root cause.

## Release Gates

A platform or mechanism is supported only when:

- its required contract, policy, and real-environment tests pass;
- no-interaction and strict-identity postconditions are directly observed;
- cancellation leaves no v2-owned task, listener, lock, or controllable prompt running;
  externally owned browser sessions can no longer complete the pending request;
- output and diagnostics contain no secrets;
- cache security and migration behavior are documented;
- the exact client application and dependency versions are recorded;
- installation and update behavior cannot collide with upstream AzureAuth.

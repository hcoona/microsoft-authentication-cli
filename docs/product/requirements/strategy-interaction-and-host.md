# Strategy, Interaction, and Host Requirements

## V2-REQ-013: Deterministic Acquisition Order

V2 must apply a documented, deterministic acquisition order using only mechanisms
compatible with the selected Client Profile and host. When an account satisfying the
request has been uniquely resolved, V2 must attempt silent acquisition before initiating
permitted interaction. The first version must not expose caller-defined mechanism
ordering.

The versioned product policy owns the per-platform mechanism order. A Client Profile
filters incompatible mechanisms but must not redefine that order.

## V2-REQ-014: Explicit Per-Request Interaction Permission

Every authentication request must explicitly state whether user interaction is prohibited
or permitted when necessary. This permission must apply throughout the request,
independently of the authentication mechanism. Profile configuration, fallback, retries,
and ambient state must not permit interaction that the request prohibits.

The first version has two modes: `non-interactive-only` and `interactive-if-needed`.
It must not expose a caller-selected prompt-type whitelist.

## V2-REQ-015: Common Deadline

Every authentication request must have a finite overall deadline, specified by the caller
or supplied by a documented product default. The same deadline must cover account
resolution, state access, lock waiting, authentication, retries, fallback, and result
validation. No stage may restart or extend that deadline. If the deadline expires before
completion, V2 must stop acquisition and return a timeout outcome.

Caller overrides must remain within documented product limits. The first version must
not expose an unbounded mode or a Client Profile deadline default.

## V2-REQ-016: Self-Contained Interactive Authentication

For each supported interactive authentication path, V2 must establish the interactive
surface and its completion channel without requiring the caller to supply an external UI
owner or raw platform window handle. If that interaction cannot be established under the
current host and request constraints, V2 must treat the path as unavailable rather than
initiate unmanaged interaction.

When the provider supports a login hint, interactive acquisition must use the requested
email as that hint. A hint does not replace final identity validation under `V2-REQ-022`.

## V2-REQ-020: Pre-resolved Account for Silent Acquisition

V2 may attempt silent acquisition only after resolving exactly one provider account whose
provider-observed email satisfies the request's strict email constraint. It must not
perform silent acquisition through an identity-opaque operating-system default or
another ambient account. No matching account must produce an interaction-required
outcome when interaction could satisfy the request; multiple matching accounts must
produce an account-ambiguous outcome.

The identity-opaque `OperatingSystemAccount` sentinel is not a resolved account. With
`interactive-if-needed`, an interaction-required acquisition outcome may proceed to
permitted interaction under `V2-REQ-023`; it is terminal without interaction permission.
Account ambiguity must not fall back to another account or a picker that bypasses the
strict-email ambiguity.

## V2-REQ-021: No-Interaction Guarantee

For a request that prohibits interaction, V2 must not initiate user-facing authentication
or state-unlock interaction, including broker prompts, browser sign-in, device-code
instructions, or terminal prompts. If an otherwise available acquisition path requires
interaction, V2 must return an interaction-required outcome without initiating that
interaction.

## V2-REQ-022: Strict Result Identity

Before returning success, V2 must validate the provider-observed account email, effective
tenant policy, selected Client Profile identity, and requested scope semantics against
the normalized request. A missing or mismatched account email, an exact-tenant mismatch,
or another unverifiable required postcondition is terminal: V2 must not expose the access
token or continue to a later acquisition mechanism.

## V2-REQ-023: Classified Fallback

V2 must advance to a later acquisition mechanism only for an explicitly retryable outcome
permitted by its acquisition policy. Every subsequent attempt must preserve the request's
account email, effective tenant policy, Client Profile, scopes, interaction permission,
and overall deadline. User cancellation, user denial, and failure to validate a
provider-reported success must terminate the request.

Caller cancellation is also terminal; it must not trigger retry or fallback.

## V2-REQ-024: Request-Bounded Claims Handling

V2 may retry with claims only in response to a real provider challenge arising within the
current token-acquisition request. Such handling must preserve the original account,
tenant, Client Profile, scopes, interaction permission, deadline, and terminal-outcome
rules. The first version must not expose a cross-process resource-claims continuation
protocol or advertise support for it.

Public resource-claims payloads, a claims-challenge terminal status, and `cp1`
advertisement are outside the first version.

## V2-REQ-025: No Orphaned Work

After success, failure, cancellation, or timeout, V2 must leave no V2-controlled
authentication work or coordination resources active for the ended request. It must
close interactive surfaces it controls. If an externally owned surface cannot be closed,
V2 must invalidate the pending flow so that a late response cannot resume the request,
and provide a clear completion or error indication.

This requirement does not promise revocation of independently completed provider
account/session changes.

## V2-REQ-026: Retired - current authority: V2-REQ-041

Shared-state concurrency remains governed by `V2-REQ-041`. Suppressing duplicate
interaction across separate CLI processes is not a product commitment.

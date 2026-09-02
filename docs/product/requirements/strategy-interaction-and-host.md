# Strategy, Interaction, and Host Requirements

## V2-REQ-013: Ordered Acquisition Strategy

A request must carry or select an ordered list of acquisition stages. The implementation
must not collapse that order into an unordered flag set.

## V2-REQ-014: Independent Interaction Policy

The permission to create user interaction must be represented independently from the
authentication mechanism.

## V2-REQ-015: Common Deadline

One deadline and cancellation scope must cover account resolution, lock acquisition,
cache access, every authentication stage, and result validation.

## V2-REQ-016: Explicit Host Context

A request requiring interactive work must provide or select a validated host context for
the chosen mechanism. The context must identify ownership of the interactive surface and
its completion channel, including a broker parent window, system-browser callback, or
owned terminal where applicable.

## V2-REQ-020: Selected-Account Silent First

When requested, v2 must attempt silent acquisition for the exact selected account before
creating interaction.

## V2-REQ-021: No-Interaction Guarantee

A no-interaction request must not create WAM, browser, device-code, terminal, or other
user-facing prompts.

## V2-REQ-022: Strict Identity Postcondition

V2 must validate the returned provider account, tenant, authority, and client constraints
before returning success. Ambiguous or mismatched identity must fail closed.

## V2-REQ-023: Classified Fallback

Fallback must be driven by typed policy outcomes. Caller cancellation, user denial,
strict identity mismatch, and failure to validate a result reported as successful are
terminal. Cache corruption remains governed by `V2-REQ-041`. Only an outcome explicitly
classified as retryable may advance to a later requested stage.

## V2-REQ-024: Claims-Challenge Preservation

A claims retry must run only for a real claims challenge and must preserve the original
account, tenant, authority, interaction, and deadline constraints.

## V2-REQ-025: No Orphaned Work

After success, failure, cancellation, or timeout, no v2-owned acquisition task, callback
listener, lock, or controllable interactive surface may remain active. For an externally
owned system-browser tab that the process cannot close, v2 must invalidate the pending
flow and provide a safe terminal completion or error state.

## V2-REQ-026: Cross-Process Interaction Coordination

Equivalent concurrent requests must coordinate across processes so they do not
independently create duplicate user interaction. Coordination waits must remain within
the common deadline and cancellation scope defined by `V2-REQ-015`.

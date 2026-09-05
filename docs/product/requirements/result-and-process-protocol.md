# Result and Process-Protocol Requirements

## V2-REQ-030: Versioned Result

Every machine result must declare a protocol version and one typed success or failure
status. Process exit status for a normally emitted result must map deterministically to
that status and must not contradict the payload.

## V2-REQ-031: Complete Success Metadata

A successful result must preserve token type, expiry, provider account identifiers,
tenant, authority, scopes or resource, mechanism, silent or interactive classification,
and correlation metadata where available.

## V2-REQ-032: Typed Failure Taxonomy

The result contract must distinguish invalid request, account absence or ambiguity,
interaction required or blocked, consent or claims challenge, mechanism unavailability,
identity mismatch, cancellation, denial, network or service failure, timeout, cache
failure, integrity failure, and internal failure.

Public failure statuses must be defined by the action available to the caller and must
not expose provider or platform exception types as the protocol taxonomy.

## V2-REQ-033: Opaque Access Tokens

Identity correctness must not depend on parsing access-token claims. Access tokens must
be treated as opaque bearer material.

## V2-REQ-034: Output Discipline

Protocol stdout must contain only the selected versioned payload. Human prompts and
diagnostics must use explicitly owned channels. Secrets must never reach logs or
telemetry.

## V2-REQ-035: Secret Channel Containment

Authentication secrets may appear only in schema-authorized protocol fields and the
provider or operating-system interfaces that require them. Tokens, authorization codes,
device codes, and other authentication secrets must not appear in process arguments,
diagnostics, exception or crash output, logs, telemetry, or unrelated protocol fields.
Errors must expose safe classifications rather than raw secret-bearing content.

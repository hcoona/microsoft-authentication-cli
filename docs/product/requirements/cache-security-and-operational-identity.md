# Cache, Security, and Operational-Identity Requirements

## V2-REQ-040: Secure Authentication State

V2 must persist reusable authentication material only in broker-owned or platform-secure
storage. It must not fall back to plaintext persistence. The first version must apply a
product-defined state policy rather than expose caller-selected or Client-Profile-selected
cache modes.

## V2-REQ-041: Safe Reusable-State Recovery and Concurrency

V2 must treat unreadable, undecryptable, corrupt, or incompatible reusable state as a
cache miss and must not consume it. Recovery must preserve the account email, effective
tenant policy, Client Profile, scopes, interaction permission, and original overall
deadline.

When V2 acquires and validates an access token but cannot safely persist reusable state,
it must return success with a machine-readable persistence warning rather than fail the
authentication result. A later invocation with usable state remains subject to
selected-account silent-first acquisition under `V2-REQ-013` and `V2-REQ-020`.

Concurrent processes sharing authentication state must preserve locking and atomic-update
integrity and observe consistent state. This does not promise cross-process interaction
single-flight. File names, locking mechanisms, serialization, and storage lifecycle are
not selected here.

The first version must not expose Logout, Cache Clear, caller-visible Force Refresh, or
Account List operations.

## V2-REQ-042: Client Registration as Configuration

Public-client application IDs must be treated as nonsecret configuration and supplied
through Client Profiles rather than hard-coded into the authentication core. A profile
using an externally owned registration must make its ownership and external-dependency
status explicit. V2 must not imply ownership of that registration or its owner's
endorsement or support for the project.

## V2-REQ-043: No Upstream Telemetry Reuse

The unofficial fork must not send telemetry under the upstream Microsoft product
identity or use upstream ingestion configuration.

## V2-REQ-044: Independent Distribution Identity

Any distributed v2 artifact must use independently defined package, executable,
installation, cache, signing, diagnostic, and update identities.

## V2-REQ-045: Headless-Linux Reusable-State Support

A headless Linux combination may claim support for repeated noninteractive acquisition
only when an accepted authentication-state mechanism can be reused across invocations
without requiring interactive unlock on every call. If no such mechanism satisfies the
accepted cache-security policy, that capability for the combination must be declared
unsupported rather than silently weakening storage.

## V2-REQ-046: Optional Telemetry Semantics

V2 must provide optional telemetry. Network export must be disabled unless explicitly
configured. Export or bounded-flush failure must not change the authentication result or
its process status, trigger authentication retry, fallback, or interaction, or prevent
process termination beyond a finite bound.

Telemetry remains subject to the authentication-material and email containment in
`V2-REQ-035` and `V2-REQ-036` and the independent identity requirements in `V2-REQ-043`
and `V2-REQ-044`.

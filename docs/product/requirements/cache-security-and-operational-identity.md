# Cache, Security, and Operational-Identity Requirements

## V2-REQ-040: Secure Storage by Default

Persistent cache material must use broker-owned or platform secure storage by default.
Cache persistence and fallback must follow an explicit request or selected-profile policy
composed only of separately accepted cache modes. A request or profile cannot authorize
an otherwise unaccepted mode. When secure storage is unavailable, v2 must return a typed
outcome consistent with the accepted policy and must not silently select plaintext,
nonpersistent operation, or another storage mode.

## V2-REQ-041: Versioned Cache Semantics

Cache state must define namespace, locking, atomic update, corruption, logout, migration,
and incompatible-version behavior for v2-owned state.

## V2-REQ-042: Client Registration as Configuration

Public-client IDs must be treated as nonsecret application configuration. Microsoft-owned
registrations must be visibly identified as externally owned dependencies and must be
replaceable by configuration or profile.

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

Telemetry remains subject to the secret containment in `V2-REQ-035` and the independent
identity requirements in `V2-REQ-043` and `V2-REQ-044`.

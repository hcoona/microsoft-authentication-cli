# Cache, Security, and Operational-Identity Requirements

## V2-REQ-040: Secure Storage by Default

Persistent cache material must use broker-owned or platform secure storage by default.
The implementation must not silently downgrade to plaintext.

## V2-REQ-041: Versioned Cache Semantics

Cache state must define namespace, locking, atomic update, corruption, logout, migration,
and incompatible-version behavior.

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

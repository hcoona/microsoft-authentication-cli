# Draft V2 Requirements

## Status

These requirements capture the current direction before implementation. They are
reviewable requirements, not a frozen wire protocol or support commitment.

Each requirement has a stable identifier. A future revision must preserve identifiers or
record why a requirement was replaced.

## Product Boundary

### V2-REQ-001: Delegated Public-Client Scope

V2 must provide delegated Microsoft Entra public-client token acquisition. It must not
implicitly select confidential-client, service-principal, managed-identity, or
workload-identity flows.

### V2-REQ-002: No Implicit Product Expansion

Git credential protocols, Azure DevOps PAT lifecycle, a daemon, a GUI, and general SDK
credential chaining must remain outside the core unless separately accepted.

Downstream credential-provider products and host-tool adapters must remain separate
consumers of the v2 authentication protocol.

### V2-REQ-003: Unofficial Product Identity

Every user-facing surface must identify the project as unofficial and must not imply an
official Microsoft release, upstream support, or ownership of a Microsoft application
registration.

## Request Contract

### V2-REQ-010: Versioned Request

Every machine request must declare a protocol version and fail safely when the major
version is unsupported.

### V2-REQ-011: Explicit Application and Authority

A request or selected profile must identify the client application, authority host,
tenant policy, and requested scopes or resource.

### V2-REQ-011A: Trusted Authority

An authority must be selected from an explicitly supported Microsoft Entra cloud or a
trusted client profile and must pass MSAL authority validation. Arbitrary caller-supplied
authority hosts and disabling authority validation are prohibited unless a separate
accepted decision defines the trust model.

### V2-REQ-012: Stable Account Constraint

A strict account constraint must use a provider-native stable identifier where available.
Username and domain may be used only as discovery or display hints.

### V2-REQ-013: Ordered Acquisition Strategy

A request must carry or select an ordered list of acquisition stages. The implementation
must not collapse that order into an unordered flag set.

### V2-REQ-014: Independent Interaction Policy

The permission to create user interaction must be represented independently from the
authentication mechanism.

### V2-REQ-015: Common Deadline

One deadline and cancellation scope must cover account resolution, lock acquisition,
cache access, every authentication stage, and result validation.

### V2-REQ-016: Explicit Host Context

A request requiring interactive work must provide or select a validated host context,
including parent-window ownership where the broker requires it.

## Execution

### V2-REQ-020: Selected-Account Silent First

When requested, v2 must attempt silent acquisition for the exact selected account before
creating interaction.

### V2-REQ-021: No-Interaction Guarantee

A no-interaction request must not create WAM, browser, device-code, terminal, or other
user-facing prompts.

### V2-REQ-022: Strict Identity Postcondition

V2 must validate the returned provider account, tenant, authority, and client constraints
before returning success. Ambiguous or mismatched identity must fail closed.

### V2-REQ-023: Classified Fallback

Fallback must be driven by typed policy outcomes. Cancellation, denial, integrity
failure, and strict identity mismatch must be terminal unless an explicit strategy says
otherwise.

### V2-REQ-024: Claims-Challenge Preservation

A claims retry must run only for a real claims challenge and must preserve the original
account, tenant, authority, interaction, and deadline constraints.

### V2-REQ-025: No Orphaned Work

After success, failure, cancellation, or timeout, no v2-owned acquisition task, callback
listener, lock, or controllable interactive surface may remain active. For an externally
owned system-browser tab that the process cannot close, v2 must invalidate the pending
flow and provide a safe terminal completion or error state.

## Result and Protocol

### V2-REQ-030: Versioned Result

Every machine result must declare a protocol version and one typed success or failure
status.

### V2-REQ-031: Complete Success Metadata

A successful result must preserve token type, expiry, provider account identifiers,
tenant, authority, scopes or resource, mechanism, silent or interactive classification,
and correlation metadata where available.

### V2-REQ-032: Typed Failure Taxonomy

The result contract must distinguish invalid request, account absence or ambiguity,
interaction required or blocked, consent or claims challenge, mechanism unavailability,
identity mismatch, cancellation, denial, network or service failure, timeout, cache
failure, integrity failure, and internal failure.

### V2-REQ-033: Opaque Access Tokens

Identity correctness must not depend on parsing access-token claims. Access tokens must
be treated as opaque bearer material.

### V2-REQ-034: Output Discipline

Protocol stdout must contain only the selected versioned payload. Human prompts and
diagnostics must use explicitly owned channels. Secrets must never reach logs or
telemetry.

## Cache and Security

### V2-REQ-040: Secure Storage by Default

Persistent cache material must use broker-owned or platform secure storage by default.
The implementation must not silently downgrade to plaintext.

### V2-REQ-041: Versioned Cache Semantics

Cache state must define namespace, locking, atomic update, corruption, logout, migration,
and incompatible-version behavior.

### V2-REQ-042: Client Registration as Configuration

Public-client IDs must be treated as nonsecret application configuration. Microsoft-owned
registrations must be visibly identified as externally owned dependencies and must be
replaceable by configuration or profile.

### V2-REQ-043: No Upstream Telemetry Reuse

The unofficial fork must not send telemetry under the upstream Microsoft product
identity or use upstream ingestion configuration.

### V2-REQ-044: Independent Distribution Identity

Any distributed v2 artifact must use independently defined package, executable,
installation, cache, signing, diagnostic, and update identities.

## Quality

### V2-REQ-050: Public Evidence

Committed rationale and support claims must be based on public source, standards,
documentation, issues, or reproducible experiments.

### V2-REQ-051: Real Platform Validation

Supported broker, browser, device-code, cache, and WSL behavior must be validated on the
real operating-system and account-state combinations declared as supported.

### V2-REQ-052: Dependency Upgrade Isolation

MSAL, native broker, cache, and platform dependency upgrades must be independently
testable, pinnable, and reversible.

### V2-REQ-053: Public Build Chain

V2 implementation and release builds must restore, build, test, and package from publicly
retrievable dependencies and fork-owned infrastructure. They must not require Microsoft
private feeds, private service connections, or upstream signing systems.

### V2-REQ-054: Isolated Experiments

Build, authentication, cache, installer, and migration experiments must follow
`experiment-safety.md`. Public-build claims must be tested without inherited credentials
or package caches, and authentication experiments must not mutate unrelated user or
upstream state.

## Open Requirement Questions

- Which platforms are required for the first supported release?
- Is WSL supported through the native Linux broker, a Windows helper, or both?
- Is an existing Microsoft-owned compatibility profile enabled by default or only by
  explicit selection?
- Is any v1 cache or command compatibility required?
- Which mechanism supplies the first end-to-end vertical slice?

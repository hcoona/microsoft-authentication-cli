# Architecture Direction

## Status

This document records the architectural direction accepted before implementation. The
types and command names are conceptual and remain subject to contract design.

## Architectural Decision

V2 will rebuild the authentication-policy and orchestration core. It will not extend the
v1 `AuthMode` bit flags or fixed flow executor.

Selected v1 mechanism and operational code may be reused behind v2 contracts. The
boundary is therefore a core reset, not a requirement to rewrite every platform
integration.

## Replace and Reuse

| V1 area | V2 direction |
| --- | --- |
| `AuthMode` flag composition | Replace with an ordered acquisition strategy. |
| Fixed `AuthFlowFactory` ordering | Replace with request-defined, validated stages. |
| `Broker` combining silent and interactive work | Split into policy-distinct operations. |
| Nullable cached-account resolution | Replace with typed account-resolution outcomes. |
| Domain-suffix account preference | Replace with stable account selectors and explicit preferences. |
| Token-only `TokenResult` | Replace with a versioned result preserving MSAL metadata. |
| Exit `1` for most failures | Replace with a typed failure taxonomy and stable process mapping. |
| Global environment interaction policy | Replace with per-request interaction policy. |
| Implicit console-window discovery | Replace with explicit host capability and UI ownership. |
| MSAL, broker, browser, and device-code calls | Reuse or adapt behind mechanism interfaces. |
| Platform secure-cache integration | Reuse selectively after threat-model and migration review. |
| Packaging and release knowledge | Reuse as evidence; create independent v2 identities and channels. |
| ADO PAT implementation | Defer behind a separate product-specific decision. |

## Conceptual Layers

### 1. Protocol Boundary

Parses a versioned request, validates its shape, invokes the application service, and
writes one versioned result. Protocol stdout must contain only the selected machine
payload. Diagnostics belong on stderr.

### 2. Authentication Policy

Validates whether the requested strategy is coherent and permitted. It decides which
stage may run next based on typed outcomes, not on arbitrary exception fallthrough.

### 3. Account Resolution

Resolves a strict account selector to provider-native account metadata. Username and
domain may assist discovery but are not stable identity keys.

### 4. Mechanism Adapters

Provide narrow operations such as:

- selected-account silent acquisition;
- explicitly permitted operating-system-account silent acquisition;
- broker interactive acquisition;
- system-browser interactive acquisition;
- device-code acquisition.

Each operation returns a complete provider result or a typed failure. A mechanism does
not decide the global fallback strategy.

### 5. Host Capabilities

Reports supported broker, browser, terminal, parent-window, keyring, and process-host
capabilities. WSL is modeled explicitly rather than inferred as generic Linux or generic
Windows.

### 6. Cache and Coordination

Owns cache namespace, secure storage, corruption behavior, logout, migration, and
cross-process coordination. Lock acquisition participates in the same request deadline
as authentication.

Downstream credential providers and host-tool protocols sit outside these layers. They
may invoke the versioned process protocol but do not become part of the authentication
core.

## Conceptual Request

A v2 request is expected to include:

- protocol version and correlation context;
- client application identity;
- trusted authority or cloud profile and tenant policy;
- scopes or resource;
- strict account selector and optional display/login hints;
- ordered acquisition stages;
- interaction policy;
- cache policy;
- one deadline;
- host context, including UI ownership where applicable;
- output policy.

The exact serialized schema must be frozen separately after empirical validation.

## Conceptual Result

A successful result is expected to preserve:

- token type, token, and expiry;
- MSAL home and local account identifiers where available;
- display username as non-authoritative metadata;
- tenant and authority;
- granted scopes or resource metadata;
- mechanism and silent/interactive classification;
- correlation information;
- cache provenance relevant to diagnostics.

A failed result must identify at least:

- invalid request;
- account not found or ambiguous;
- interaction required or blocked;
- consent or claims challenge;
- broker, browser, terminal, or cache unavailable;
- identity mismatch;
- user cancellation or denial;
- network or service failure;
- timeout;
- integrity or internal failure.

Secrets and raw provider diagnostics must not be included in safe error text.

## Required Invariants

1. **Identity postcondition:** never return a credential that violates a strict account,
   tenant, authority, or client constraint.
2. **Stable identity:** use provider-native stable account identifiers. Treat username and
   domain as hints or display data.
3. **Order preservation:** execute the validated strategy in its declared order.
4. **Independent interaction policy:** mechanism selection must not imply permission to
   create UI.
5. **No-UI guarantee:** a no-interaction request creates no WAM, browser, device-code, or
   terminal prompt.
6. **Classified fallback:** cancellation, denial, integrity failure, and strict identity
   mismatch are terminal unless the request explicitly defines otherwise.
7. **Claims preservation:** a claims retry must preserve account constraints and run only
   for a real claims challenge.
8. **Single deadline:** lock acquisition and every mechanism share one deadline and
   cancellation scope.
9. **No orphaned owned work:** completion, timeout, or cancellation leaves no v2-owned
   acquisition task, callback listener, lock, or controllable prompt active. An external
   system-browser tab may remain, but its pending flow must be invalidated and terminated
   safely from the application's perspective.
10. **Explicit host context:** interactive broker work receives validated UI ownership or
    fails with a typed unsupported-host result.
11. **Secure cache:** storage is secure by default, namespaced by relevant application and
    authority dimensions, and never silently downgraded to plaintext.
12. **Opaque token:** identity correctness does not depend on parsing access-token claims.
13. **Output discipline:** stdout is schema-controlled; diagnostics use stderr; secrets
    never reach logs or telemetry.
14. **Version negotiation:** protocols and persisted state have explicit versions and
    fail safely when incompatible.
15. **Trusted authority:** authority hosts come from supported Entra cloud metadata or a
    trusted profile and retain MSAL authority validation.

## Compatibility

V2 has no default commitment to v1 CLI syntax, environment variables, cache layout, or
fallback behavior. A compatibility adapter may be added only when:

- the supported v1 surface is explicitly enumerated;
- translation to v2 has deterministic semantics;
- unsupported or ambiguous v1 behavior fails clearly;
- the adapter does not weaken a v2 invariant.

## Open Architectural Questions

- Which executable and package names avoid upstream product confusion?
- Which .NET and MSAL release line should establish the initial dependency baseline?
- Should WSL use the native Linux broker, a Windows helper, or two explicitly supported
  modes?
- Which account identifier is portable enough for persisted bindings across broker and
  non-broker mechanisms?
- Which cache formats, if any, should migrate from v1?
- Which product-specific Azure DevOps capabilities belong outside the generic core?

These questions are not implementation invitations. They must be resolved through
evidence and accepted decisions in the order established by `docs/roadmap.md`.

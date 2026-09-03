# Architecture Overview

This record defines the current target architecture before implementation. It does not
freeze command names, serialized contracts, platform support, or compatibility behavior.

## System Boundary

The normative product boundary is defined by
[`V2-REQ-001`](../product/requirements/product-boundary.md#v2-req-001-delegated-public-client-scope)
and [`V2-REQ-002`](../product/requirements/product-boundary.md#v2-req-002-no-implicit-product-expansion).
This architecture allocates that behavior to a command-line authentication engine and
separate downstream consumers under decision
[`0004`](../decisions/0004-keep-the-authentication-engine-separate-from-consumers.md).

## Governing Decisions

- [`0002`](../decisions/0002-rebuild-the-authentication-core.md) resets the v1 policy and
  orchestration model while permitting selective mechanism reuse.
- [`0003`](../decisions/0003-treat-client-registration-as-an-external-dependency.md)
  treats client registrations as explicit externally owned configuration.
- [`0004`](../decisions/0004-keep-the-authentication-engine-separate-from-consumers.md)
  keeps consumer protocols outside the core.
- [`0005`](../decisions/0005-establish-independent-operational-identity.md) requires
  independent runtime and distribution identities.

## Replace and Reuse

| V1 area | V2 direction |
| --- | --- |
| `AuthMode` flag composition | Replace with an ordered acquisition strategy. |
| Fixed `AuthFlowFactory` ordering | Replace with request-defined, validated stages. |
| `Broker` combining silent and interactive work | Split into policy-distinct operations. |
| Nullable cached-account resolution | Replace with typed account-resolution outcomes. |
| Domain-suffix account preference | Replace with stable account selectors and explicit preferences. |
| Token-only `TokenResult` | Replace with a versioned result preserving provider metadata. |
| Exit `1` for most failures | Replace with a typed failure taxonomy and stable process mapping. |
| Global environment interaction policy | Replace with per-request interaction policy. |
| Implicit console-window discovery | Replace with explicit host capability and UI ownership. |
| MSAL, broker, browser, and device-code calls | Reuse or adapt behind mechanism interfaces. |
| Platform secure-cache integration | Reuse selectively after threat-model and migration review. |
| Packaging and release knowledge | Reuse as evidence; create independent v2 identities and channels. |
| ADO PAT implementation | Defer behind a separate product-specific decision. |

## Conceptual Layers

### Protocol Boundary

Parses a versioned request, validates its shape, invokes the application service, and
writes one versioned result. Protocol stdout contains only the selected machine payload;
diagnostics use stderr.

### Authentication Policy

Validates whether the requested strategy is coherent and permitted. It selects the next
stage from typed outcomes rather than arbitrary exception fallthrough.

### Account Resolution

Resolves strict account constraints to provider-native account metadata. Username and
domain may assist discovery but are not stable identity keys.

### Mechanism Adapters

Expose narrow operations such as:

- selected-account silent acquisition;
- explicitly permitted operating-system-account silent acquisition;
- broker interactive acquisition;
- system-browser interactive acquisition;
- device-code acquisition.

A mechanism returns a complete provider result or typed failure. It does not own the
global fallback strategy.

### Host Capabilities

Describe broker, browser, terminal, parent-window, keyring, and process-host
capabilities. WSL is explicit rather than inferred as generic Linux or Windows.

### Cache and Coordination

Own cache namespace, secure storage, corruption behavior, logout, migration, and
cross-process coordination under the request deadline.

## Architecture Invariants

- The protocol boundary, authentication policy, account resolution, mechanism adapters,
  host capabilities, and cache coordination remain separate ownership boundaries.
- Mechanism adapters return typed mechanism outcomes; the authentication policy owns
  global ordering and fallback.
- Protocol serialization and diagnostics remain outside mechanism adapters.
- Host-specific UI and storage integrations remain behind capability and platform
  boundaries.

Behavioral obligations, including identity validation, interaction, deadlines, secure
storage, output discipline, and trusted authority selection, are defined by the
[`product requirements`](../product/requirements/product-boundary.md) and their sibling
capability modules. Serialized contracts are created only when a future Delivery Wave
entry authorizes a bounded public-contract outcome.

## Scoped Architecture Views

[`client-application-identity.md`](client-application-identity.md) defines how client
application registrations and compatibility profiles relate to the core.

Additional views are added only when a subsystem or cross-cutting concern has an
independent consumer and lifecycle.

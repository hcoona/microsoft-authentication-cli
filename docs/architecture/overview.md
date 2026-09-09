# Architecture Overview

This record defines the current target architecture before implementation. It does not
freeze command names, serialized contracts, platform support, or compatibility behavior.

## System Boundary

The normative product boundary is defined by
[`V2-REQ-001`](../product/requirements/product-boundary.md#v2-req-001-delegated-public-client-scope)
through
[`V2-REQ-004`](../product/requirements/product-boundary.md#v2-req-004-one-authentication-request-per-process).
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

## Design Principles

### Explicit Assumptions and Dependency Responsibilities

Base each design on the accepted requirements, concrete user scenarios, and the documented
contracts of its dependencies. Identify the assumptions that could invalidate a choice
and the boundary responsible for satisfying them. Rely on supported operating-system,
MSAL, broker, and secure-store abstractions within their declared contracts; the engine
does not need to independently reimplement or mechanically prove those abstractions.

The engine remains responsible for its request constraints and required result checks.
Trust in a dependency does not establish an undocumented capability or prove that a
particular profile and host combination satisfies those constraints. When a required
capability is absent, keep that path unavailable. When the limitation blocks a required
journey, report the feasibility gap for owner disposition rather than silently weakening
the requirement or compensating through an expanded application boundary.

### Scenario-Driven Abstractions

Introduce a component, interface, or extension point only when a current scenario,
responsibility boundary, or independently changing dependency justifies it. Evaluate the
abstraction against the primary journey and another applicable scenario or failure path;
do not invent future consumers to justify generality. A conceptual responsibility does
not automatically require a separate service, package, interface, or class.

Keep design and implementation inside the accepted product boundary. Additional consumer
protocols, platform services, or compatibility behavior require an explicit owner scope
decision and the applicable accepted work authorization before work begins.

### Bounded Failure and Proportionate Assurance

When an edge case prevents establishing a required safety condition, use the existing
terminal outcome or mark the path unavailable. Do not add unbounded retries, fallback
chains, or speculative repair mechanisms to make every environment succeed. Apply the
accepted recovery and persistence semantics where the requirements already permit a safe
outcome; fail-closed behavior does not turn every recoverable condition into failure.

The [threat model](../security/threat-model.md#security-design-tradeoffs) owns security
assumptions and mitigation tradeoffs. The
[validation strategy](../validation/strategy.md#test-design-and-evidence-selection)
owns the balance of scenario, unit, contract, and real-environment evidence. Neither
mechanical checks nor exhaustive testing substitutes for contextual design judgment.

### Architecture Views

Use standard C4 system-context and container views, with component views where they
clarify responsibilities inside a container. A C4 container denotes an application or
data store, not necessarily a deployment container. Use UML sequence and state-machine
views for interactions and lifecycles whose ordering or termination matters. Keep each
diagram at one stated level and consistent with the surrounding authoritative text.

Choose diagrams for a concrete reader question; a complete diagram catalog is not a
deliverable. The existing user stories, capability requirements, and validation scenarios
provide the requirements basis. Add a use-case diagram only if it resolves an actual
ambiguity about actors, goals, or the system boundary.

## Replace and Reuse

| V1 area | V2 direction |
| --- | --- |
| `AuthMode` flag composition | Replace with documented deterministic product acquisition policy. |
| Fixed `AuthFlowFactory` ordering | Separate product order, profile compatibility filtering, and typed fallback. |
| `Broker` combining silent and interactive work | Split into policy-distinct operations. |
| Nullable cached-account resolution | Replace with typed account-resolution outcomes. |
| Domain-suffix account preference | Replace with strict full-email resolution and terminal result validation. |
| Token-only `TokenResult` | Replace with a versioned result preserving provider metadata. |
| Exit `1` for most failures | Replace with a typed failure taxonomy and stable process mapping. |
| Global environment interaction policy | Replace with per-request interaction policy. |
| Implicit console-window discovery | Replace with self-contained interactive-surface and completion-channel ownership. |
| MSAL, broker, browser, and device-code calls | Reuse or adapt behind mechanism interfaces. |
| Platform secure-cache integration | Reuse selectively after threat-model and cache-lifecycle review. |
| Packaging and release knowledge | Reuse as evidence; create independent v2 identities and channels. |
| ADO PAT implementation | Defer behind a separate product-specific decision. |

## Conceptual Layers

### Protocol Boundary

Parses the explicitly versioned command-line request, validates its shape, invokes the
application service, and writes one structured success or failure result. The boundary
separates protocol stdout from designated prompt and diagnostic channels. It owns the
binary success/failure process mapping under
[`V2-REQ-030`](../product/requirements/result-and-process-protocol.md#v2-req-030-versioned-result-and-exit-status).
Serialization and flag spellings remain later contract work.

### Authentication Policy

Applies versioned product acquisition order after filtering for profile and host
compatibility. It selects the next legal mechanism from typed retryable outcomes rather
than arbitrary exception fallthrough, preserving normalized request constraints and the
original deadline.

### Account Resolution

Resolves the required full email to a unique real provider account before silent
acquisition. The provider account is an internal acquisition input, not a stable-ID
caller contract or persistent first-account binding. Identity-opaque operating-system
defaults are excluded. A provider-observed email remains necessary for final validation.
The feasibility of enumeration and authoritative email metadata for any particular
provider/profile remains a [validation obligation](../validation/strategy.md#primary-journey-gate).

### Mechanism Adapters

Expose narrow operations such as:

- selected-account silent acquisition;
- broker interactive acquisition;
- system-browser interactive acquisition;
- device-code acquisition.

A mechanism returns provider-authoritative result metadata for validation or a typed
failure. It does not own global fallback policy or public result serialization. These
operation boundaries do not select mechanisms or assert platform support.

### Host Capabilities

Describe broker, browser, terminal, v2-owned interaction, keyring, and process-host
capabilities. WSL is explicit rather than inferred as generic Linux or Windows.

### Cache and Coordination

Own product-policy state access, safe persistence, unusable-state recovery, and
cross-process shared-state integrity under the request deadline. Authentication success
validation and persistence status remain separable under
[`V2-REQ-041`](../product/requirements/cache-security-and-operational-identity.md#v2-req-041-safe-reusable-state-recovery-and-concurrency).
Concrete stores, formats, namespace values, locking mechanisms, and storage lifecycle
remain later design work. Local state-management commands and cross-process interaction
single-flight are not first-version capabilities.

The same requirement owns first-use OS-state eligibility and reuse across compatible
consumers. Engine-created state is not a prerequisite for considering OS sign-in state;
consumer-specific credential translation remains outside this layer. This allocation
does not choose a shared-cache design or establish provider-state availability.

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

# V2 Roadmap

The roadmap defines durable stages and exit conditions. GitHub Milestones and Issues
carry current work state, and `project-state.md` identifies the active stage and permitted
work.

A later stage becomes active only through an accepted project-state change after its
entry conditions and the Record-System Gate are satisfied.

## Stage 1: Empirical Baseline

Establish public, reproducible evidence before selecting implementation contracts.

Required outcomes:

- a public restore, build, test, and packaging baseline for the audited upstream source;
- dependency and platform inventories;
- approved experiment records and isolation;
- reproducible v1 account, interaction, cancellation, cache, and host observations;
- explicit separation of source facts, observations, inference, and unresolved questions.

Exit when the behavior v2 must change or preserve is demonstrable without private
evidence, and no private build dependency has been accepted into the v2 implementation.

## Stage 2: Contract and Architecture

Define the smallest versioned contract and architecture supported by Stage 1 evidence.

Required outcomes:

- request, result, failure, deadline, host, cache, and versioning contracts;
- accepted account-selection and interaction policy;
- selected first implementation slice;
- contract and policy validation cases;
- explicit compatibility and unsupported-behavior decisions.

Exit when implementation can proceed without relying on unspecified behavior.

## Stage 3: Incremental Implementation and Validation

Implement the mechanism-neutral core and add real platform slices incrementally.

Each slice requires:

- governing requirements, architecture, and contracts;
- deterministic policy tests;
- real-environment validation appropriate to the claimed host and mechanism;
- bounded cancellation, output, cache, and identity behavior;
- explicit unsupported cases.

Windows broker, browser, device code, WSL, compatibility, and product-specific features
are workstreams activated by evidence and owner decisions, not mandatory sequential
stages.

Exit when the selected release scope is implemented and supported by its required
evidence.

## Stage 4: Release Qualification

Prepare an independently identifiable and verifiable release.

Required outcomes:

- final product and operational identities;
- public build, dependency, provenance, and signing records;
- supported platform, account, client, and mechanism matrix;
- installation, update, uninstall, and migration behavior;
- user documentation and known limitations;
- release artifacts whose claims match the recorded evidence.

Exit through an explicit repository-owner release decision and immutable tag.

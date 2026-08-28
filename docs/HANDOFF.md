# V2 Handoff

## Purpose

This is the canonical orientation document for a contributor or agent with no prior
conversation context. It summarizes the current direction and points to the records that
hold authoritative detail.

Do not infer requirements from the upstream product name or v1 source. Read
`project-state.md` before acting.

## What This Repository Is

`main-v2` is an unofficial, orphan development line for a new authentication engine
derived from lessons and selected mechanisms in
[Microsoft Authentication CLI](https://github.com/AzureAD/microsoft-authentication-cli).

The intended product is a deterministic command-line boundary around delegated Microsoft
Entra public-client authentication. It must preserve exact account intent, interaction
policy, acquisition order, host context, cancellation, cache policy, and typed outcomes.

It is not currently an implementation or release.

## What This Repository Is Not

This repository is not the downstream credential-provider product that may consume its
tokens. Git, NuGet, Python, npm, and other host-protocol adapters belong in their own
products. Do not copy their requirements into this authentication engine or make this
repository responsible for their configuration.

It is also not:

- an official Microsoft product or official AzureAuth successor;
- a Git credential manager;
- a general Azure SDK credential chain;
- a daemon, GUI, OAuth server, token validator, or secrets manager;
- an implicit selector for service principals, managed identities, or workload identity;
- a promise of v1 compatibility or Azure DevOps PAT support.

## Why V2 Exists

Public source review found that v1 cannot faithfully express or enforce the required
machine contract:

- repeated modes become an unordered flag set and then a fixed flow order;
- broker silent and broker interactive work are combined;
- preferred-domain account filtering is lossy and can widen to the OS account;
- the full MSAL result is reduced to token-oriented output;
- most failures collapse into a nullable result and exit code `1`;
- timeout, lock wait, and cancellation do not form one deadline;
- Windows UI ownership and WSL host context are implicit;
- cache fallback policy includes a silent security decision.

The public evidence and confidence boundaries are in
[`research/v1-architecture-audit.md`](research/v1-architecture-audit.md).

## Accepted Direction

V2 will rebuild the policy and orchestration core instead of extending v1 `AuthMode`.

The core model is:

```text
versioned process protocol
    -> validated request
    -> ordered authentication policy
    -> capability-aware orchestrator
    -> mechanism adapters
    -> MSAL and platform broker/browser/cache
    -> validated, typed result
```

Selected mechanism-level source and operational knowledge may be reused. Reuse never
imports v1 public semantics by default.

The normative direction and invariants are in [`architecture.md`](architecture.md), and
the accepted decisions are under [`decisions/`](decisions/).

## Client Application Identity

Public-client IDs are identifiers, not secrets. They still refer to application
registrations owned and configured by a specific party.

The upstream Azure DevOps convenience path uses a Microsoft-owned Visual Studio public
client registration. V2 may represent that behavior as a clearly named, configurable
compatibility profile. This fork does not own the registration, promise its availability,
or imply Microsoft sponsorship.

An ordinary fork-owned Entra app currently cannot assume equivalent Azure DevOps access
for personal Microsoft accounts. This limitation must remain visible rather than being
hidden behind fallback.

See [`client-application-identity.md`](client-application-identity.md).

## Stop Conditions

Stop and update `project-state.md` instead of inventing an answer when work requires:

- a final request or result protocol that has not been accepted;
- a product, executable, package, cache, or telemetry identity that has not been chosen;
- a client registration whose ownership or supported account types are unknown;
- a new product-specific feature or downstream protocol;
- a private dependency, service, signing identity, or telemetry endpoint;
- a claim that real broker, browser, cache, or WSL behavior works without a recorded
  experiment;
- a compatibility or migration behavior not covered by an accepted decision.

## Evidence Language

Use these labels where a distinction would otherwise be unclear:

- **SOURCE-VERIFIED:** follows from immutable public source, a standard, or stable public
  documentation.
- **DECISION:** chosen by this fork; not an upstream fact.
- **HYPOTHESIS:** plausible explanation that is not demonstrated.
- **VALIDATE-RUNTIME:** requires a reproducible authentication or platform experiment.
- **RECHECK-UPSTREAM:** mutable issue, pull request, branch, or release status.

Prefer links pinned to an upstream commit. Runtime records must state the fork commit,
dependency versions, operating system, host, account-state shape, requested policy,
expected result, and sanitized observation.

## Current Work Boundary

Phase 0 established the public handoff and repository constitution. It is complete.
Production authentication code remains blocked.

Phase 1 is active. Its bounded work is:

1. prove a clean public build or identify every private dependency that must be removed;
2. inventory exact MSAL, native broker, cache, telemetry, and packaging dependencies;
3. define safe synthetic test identities and handling rules;
4. reproduce v1 account, interaction, cancellation, cache, and host behavior;
5. record facts separately from hypotheses.

All experiments must follow [`experiment-safety.md`](experiment-safety.md). Do not freeze
the v2 wire contract or begin platform implementation during this phase.

## Reading Map

| Question | Authority |
| --- | --- |
| What may be worked on now? | `project-state.md` |
| What is the product boundary? | `vision.md` |
| Which behavior must the design preserve? | `requirements.md`, `architecture.md` |
| Why is the v1 core being replaced? | `research/v1-architecture-audit.md` |
| How are client IDs treated? | `client-application-identity.md` |
| Which security assumptions apply? | `threat-model.md` |
| Which names and stores may not collide? | `namespaces.md` |
| What compatibility or migration is promised? | `compatibility-and-migration.md` |
| What proves support? | `validation-strategy.md` |
| How must experiments be isolated? | `experiment-safety.md` |
| In what order may work proceed? | `roadmap.md` |
| Where did source come from? | `../UPSTREAM.md` |
| Which choices are durable? | `decisions/` |
| Which evidence is known and mutable? | `evidence-register.md` |

# Project Records

This index routes human readers to the canonical record for each project concern. It is
navigation, not an independent authority.

## Current Work

- Current phase and permitted work: [`project-state.md`](project-state.md)
- Durable stage model and exit gates: [`roadmap.md`](roadmap.md)
- Active downstream tracking:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)

## Product and Engineering

| Question | Canonical record |
| --- | --- |
| Why does v2 exist and what is outside its boundary? | [`product/vision.md`](product/vision.md) |
| What behavior must v2 provide? | [`product/requirements/`](product/requirements/) |
| What is the current architectural direction? | [`architecture.md`](architecture.md) |
| What threats and trust boundaries apply? | [`threat-model.md`](threat-model.md) |
| What evidence is required for a support claim? | [`validation-strategy.md`](validation-strategy.md) |
| Which durable choices have been made? | [`decisions/`](decisions/) |

## Research and Upstream

| Question | Canonical record |
| --- | --- |
| Why is the v1 core not the v2 foundation? | [`research/v1-architecture-audit.md`](research/v1-architecture-audit.md) |
| How must experiments be isolated? | [`research/experiment-safety.md`](research/experiment-safety.md) |
| Which mutable public facts require rechecking? | [`evidence-register.md`](evidence-register.md) until its structured replacement is merged |
| What is the upstream baseline and import policy? | [`../UPSTREAM.md`](../UPSTREAM.md) |

## Governance

| Question | Canonical record |
| --- | --- |
| How are project rules maintained? | [`governance/governance-system.md`](governance/governance-system.md) |
| How are repository records and controls organized? | [`governance/record-system.md`](governance/record-system.md) |
| What project identity and public-record rules apply? | [`governance/project.md`](governance/project.md) |
| What compatibility or migration is currently promised? | [`product/compatibility-and-migration.md`](product/compatibility-and-migration.md) |
| Which operational identifiers must remain separate? | [`namespaces.md`](namespaces.md) until its structured replacement is merged |
| How are public-client application registrations treated? | [`client-application-identity.md`](client-application-identity.md) |

The root [`README.md`](../README.md) is the public landing page. The root
[`AGENTS.md`](../AGENTS.md) is an AI-agent interface and is not human onboarding
documentation.

# Project State

## Authority

This is the authoritative record of the current v2 phase, settled decisions, open
questions, blocked work, and next permitted task.

- **Last updated:** 2026-08-28
- **Branch:** `main-v2`
- **Phase:** Phase 1 - Empirical Baseline
- **Implementation status:** Not started
- **Release status:** No v2 release exists

## Settled Decisions

| Decision | Status | Record |
| --- | --- | --- |
| Establish v2 as an orphan branch with explicit upstream provenance. | Accepted | `decisions/0001-establish-main-v2.md` |
| Rebuild the authentication-policy core and selectively reuse mechanisms. | Accepted | `decisions/0002-rebuild-the-authentication-core.md` |
| Treat client registrations as configurable external dependencies, not fork-owned secrets or assets. | Accepted | `decisions/0003-treat-client-registration-as-an-external-dependency.md` |
| Keep downstream credential providers and host protocols outside the v2 authentication engine. | Accepted | `decisions/0004-keep-the-authentication-engine-separate-from-consumers.md` |
| Use independent operational namespaces and no upstream telemetry identity. | Accepted | `decisions/0005-establish-independent-operational-identity.md` |

## Normative Governance Policies

| Policy | Authority |
| --- | --- |
| Keep the project unofficial and make no current support or compatibility promise. | `../README.md`, `governance.md` |
| Use only public, reviewable evidence in committed records. | `../AGENTS.md`, `governance.md` |
| Follow the isolation protocol before any build, authentication, cache, installer, or migration experiment. | `experiment-safety.md` |

## Current Architectural Direction

- The v1 `AuthMode`, fixed flow ordering, composite broker, nullable account resolution,
  and token-only result do not define v2.
- V2 uses versioned requests and results, stable account identifiers, ordered strategies,
  independent interaction policy, one deadline, explicit host context, secure cache, and
  typed failures.
- MSAL and maintained platform brokers remain the authentication mechanisms.
- A Microsoft-owned Azure DevOps client ID may be represented by an explicit
  compatibility profile, but the fork does not own or control that registration.
- Git credential management, general credential chains, non-user identities, a daemon,
  a GUI, and ADO PAT lifecycle are outside the v2 core.
- Downstream credential-provider products remain separate consumers.

## Completed Foundation

- The orphan `main-v2` baseline is committed and published.
- `main-v2` is the repository default branch.
- The repository description identifies the fork as unofficial and experimental.
- Issues and GitHub private vulnerability reporting are enabled.
- The initial handoff, evidence, governance, architecture, requirements, threat model,
  validation strategy, roadmap, and decisions are durable.

## Active Work

Phase 1 public empirical-baseline work is permitted. No production authentication code,
wire-contract freeze, packaging, migration, or compatibility implementation is active.

## Next Permitted Task

The next bounded task is:

> Establish the Phase 1 public empirical baseline: document reproducible upstream build
> and test prerequisites; determine how the authenticated Office feed and
> `Microsoft.Office.Lasso` are removed or replaced; inventory the exact authentication
> and cache dependencies; and design a safe behavior matrix for v1 account, interaction,
> cancellation, and host experiments.

That task must not redesign the v2 contract or begin production implementation.

## Open Questions

1. What product, executable, and package names avoid confusion with official AzureAuth?
2. Which platform and mechanism form the first real v2 slice?
3. Does the first supported WSL path use the native Linux broker, a Windows helper, or
   both as explicit modes?
4. Which client application is used for development and acceptance tests?
5. Is explicit opt-in required before using a Microsoft-owned compatibility client in a
   public binary?
6. Which v1 commands, cache data, or ADO-specific features have current value worth
   preserving?
7. Which real operating-system and account states can be maintained as release canaries?
8. What independent artifact signing and update mechanism is available?
9. Which public replacement, if any, should provide the upstream Lasso logging and
   telemetry responsibilities?

## Blocked or Deferred Work

- Production authentication implementation.
- Public request/result schema freeze.
- V1 compatibility adapter.
- Cache migration.
- ADO PAT lifecycle.
- Product naming and release packaging.
- Support claims or published binaries.
- Claims about a 0.9.6 runtime regression beyond public evidence and reproducible tests.

## State Update Rule

Any change that activates a phase, settles an open question, changes the project boundary,
or permits previously blocked work must update this file. Accepted architectural
decisions are changed or superseded through decision records. Normative governance
policies are changed in their named authority and reflected here; a change that alters
architecture or product scope also requires a decision record.

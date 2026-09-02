# Project State

## Acceptance Semantics

This record authorizes work only as accepted on the target branch, normally `main-v2`.
On a pull-request or feature branch, changes to this file propose the state after merge;
the target branch's accepted copy continues to govern work before merge.

Preparing and reviewing an explicitly repository-owner-approved pull request whose sole
substantive purpose is a project-state transition is permitted. Work newly authorized by
that proposal may begin only after the transition merges.

## Current Stage

**Empirical Baseline**

No v2 production implementation or release exists.

## Current Objective

Establish **AzureAuth Unofficial V2** as the canonical public repository display name
under [Issue #17](https://github.com/hcoona/microsoft-authentication-cli/issues/17)
without selecting a distributed product or runtime identity.

## Permitted Work

- Execute only the public project naming unification bounded by Issue #17.
- Update the canonical project-identity record, public repository landing page,
  documentation portal, and directly affected audience entry points to use the selected
  display name.
- Update the GitHub repository description after the accepted repository records use the
  selected display name.
- Review existing public-facing self-identification only to preserve clear unofficial
  status and distinguish fork identity from upstream provenance.

## Blocked Work

- Selecting or implementing any distributed product, executable, command, package,
  namespace, installation, cache, lock, configuration, telemetry, diagnostic, signing,
  update, or user-agent identity.
- Renaming the GitHub repository slug or changing its upstream fork relationship.
- Product-requirement, architecture, design, public-contract, implementation,
  compatibility, migration, packaging, release, or support-commitment changes.
- Authentication, broker, cache, installer, migration, build, or other platform
  experiments.
- Execution of any Issue other than Issue #17 before it is named by a later accepted
  project-state change.
- Modifying upstream provenance, license notices, historical or research references, or
  immutable evidence merely to replace an official upstream name.
- Publishing or citing private downstream evidence, activating Issue #12, or expanding
  the delegated public-client authentication engine into Git, credential-provider,
  Azure DevOps PAT, or other downstream product behavior.

## Active Tracking

- Milestone:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)
- Current work:
  [Issue #17 — Establish the AzureAuth Unofficial V2 Public Project Name](https://github.com/hcoona/microsoft-authentication-cli/issues/17)

## Transition Condition

Issue #17 completes only when the canonical project record, public repository entry
points, and GitHub description consistently use **AzureAuth Unofficial V2**; the inherited
repository slug and upstream provenance remain intact; distributed and runtime identities
remain unselected; applicable checks and contextual reviews pass; and the repository
owner records the final disposition.

Completion does not change the Empirical Baseline stage or authorize a follow-up Issue.
Any next work requires a separately accepted project-state transition and, for a later
stage, the entry conditions and Record-System Gate defined by the
[roadmap](roadmap.md).

If GitHub is unavailable, stop because the bounded scope in Issue #17 cannot be verified.

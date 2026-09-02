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

Reconcile and baseline the existing v2 product requirements under
[Issue #14](https://github.com/hcoona/microsoft-authentication-cli/issues/14) before
selecting contracts, architecture, or implementation.

## Permitted Work

- Execute only the source reconciliation and requirement-gap analysis bounded by
  Issue #14.
- Update the existing capability-scoped requirement records and validation strategy only
  when an accepted requirement disposition requires the change.
- Create a separately bounded future research Issue only when a named unresolved fact
  prevents disposition of a specific candidate requirement. Creating that Issue does not
  authorize its execution.

## Blocked Work

- Architecture or design selection, public-contract freezing, implementation,
  compatibility commitments, migration, packaging, release, or work on Issue #12.
- Authentication, broker, cache, installer, migration, build, or other platform
  experiments.
- Execution of any Issue other than Issue #14 before it is named by a later accepted
  project-state change.
- Publishing or citing private downstream evidence, or expanding the delegated
  public-client authentication engine into Git, credential-provider, Azure DevOps PAT,
  or other downstream product behavior.

## Active Tracking

- Milestone:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)
- Current work:
  [Issue #14 — Reconcile and Baseline the V2 Product Requirements](https://github.com/hcoona/microsoft-authentication-cli/issues/14)

## Transition Condition

Issue #14 completes only when its completion criteria are satisfied, the existing
requirement and validation authorities contain every accepted change, applicable checks
and contextual reviews pass, and the repository owner records the final disposition.

Completion does not enter Contract and Architecture or authorize a follow-up Issue. Any
next work requires a separately accepted project-state transition and, for a later stage,
the entry conditions and Record-System Gate defined by the [roadmap](roadmap.md).

If GitHub is unavailable, stop because the bounded scope in Issue #14 cannot be verified.

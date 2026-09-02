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

No work item is currently authorized.

## Permitted Work

- Preparing and reviewing an explicitly repository-owner-approved pull request whose sole
  substantive purpose is a project-state transition.

## Blocked Work

- All product, research, experiment, implementation, validation, maintenance,
  compatibility, migration, packaging, release, and work-item activity other than the
  permitted project-state transition preparation and review.
- Work on any issue before it is named by an accepted project-state change.

## Active Tracking

- Milestone:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)
- Current work: None.

## Transition Condition

The repository owner must identify the next bounded work item and explicitly approve a
sole-purpose project-state proposal that names it. Work on that item may begin only after
the proposal merges. A later stage also requires the entry conditions and Record-System
Gate defined by the [roadmap](roadmap.md).

If GitHub is unavailable, stop. No work item is authorized.

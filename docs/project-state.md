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

Establish the public build and dependency baseline tracked by
[issue #1](https://github.com/hcoona/microsoft-authentication-cli/issues/1).

## Permitted Work

- Changes required by issue #1.
- Review, validation, and correction of those changes.
- Maintenance necessary to keep the baseline work reproducible and reviewable.

## Blocked Work

- Production authentication implementation.
- Public request or result contract freeze.
- Compatibility adapters or cache migration.
- Product naming, release packaging, support claims, or published binaries.
- Authentication, broker, token-cache, installer, or migration experiments.
- Other Phase 1 experiments not authorized by issue #1.

## Active Tracking

- Milestone:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)
- Current work:
  [issue #1 — Establish the Public Build and Dependency Baseline](https://github.com/hcoona/microsoft-authentication-cli/issues/1)

## Transition Condition

Issue #1 must record its required outcomes and pass the applicable hk and independent
research-evidence reviews. A later task becomes permitted only through an accepted
project-state change.

If GitHub is unavailable, do not begin another work item. Continue only a change already
authorized above, or stop.

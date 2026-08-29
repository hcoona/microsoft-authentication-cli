# Project State

## Current Stage

**Empirical Baseline**

No v2 production implementation or release exists.

## Current Objective

Complete the repository record and governance migration tracked by
[issue #2](https://github.com/hcoona/microsoft-authentication-cli/issues/2).

## Permitted Work

- Changes required by issue #2.
- Review, validation, and correction of those changes.
- Maintenance necessary to keep the migration branch buildable and reviewable.

## Blocked Work

- The public build and dependency baseline in
  [issue #1](https://github.com/hcoona/microsoft-authentication-cli/issues/1), until the
  Record-System Gate in issue #2 passes.
- Production authentication implementation.
- Public request or result contract freeze.
- Compatibility adapters or cache migration.
- Product naming, release packaging, support claims, or published binaries.
- Authentication, broker, cache, installer, or migration experiments.

## Active Tracking

- Milestone:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)
- Current work:
  [issue #2 — Establish the Repository Record and Governance System](https://github.com/hcoona/microsoft-authentication-cli/issues/2)
- Next permitted work after the Record-System Gate:
  [issue #1 — Establish the Public Build and Dependency Baseline](https://github.com/hcoona/microsoft-authentication-cli/issues/1)

## Transition Condition

Issue #2 must satisfy its recorded Record-System Gate. Its final accepted change must
retain this stage, remove the migration authorization, and designate issue #1 as the
current permitted work.

If GitHub is unavailable, do not begin issue #1 or any other new work. Continue only a
change already authorized above, or stop.

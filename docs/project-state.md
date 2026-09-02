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

Amend the repository work-authorization model under
[Issue #21](https://github.com/hcoona/microsoft-authentication-cli/issues/21) so bounded
independent work can proceed concurrently without using `project-state.md` as an
active-Issue ledger.

## Permitted Work

- Execute only the governance analysis and amendment bounded by Issue #21 after this
  project-state proposal merges.
- Update the directly affected governance policies, current project state, roadmap,
  catalogs, controls, contributor and Agent interfaces, review Skills, evaluation
  fixtures, and experiment-authorization policy as one coherent migration.
- Review and validate those changes under the accepted governance rules, including
  independent record-system and research-evidence review and independent triage of any
  material finding.

## Blocked Work

- Product-requirement, architecture, design, implementation, compatibility, migration,
  packaging, release, support-commitment, or operational-identity changes.
- Authentication, broker, cache, installer, migration, build, or other platform
  experiments and new empirical claims.
- Selecting or freezing the first v2 slice, changing the Empirical Baseline stage, or
  authorizing product delivery as part of the governance amendment.
- Execution of any Issue other than Issue #21 before later accepted records authorize
  it.
- Applying the proposed authorization-envelope rules before the Issue #21 governance
  amendment merges.

## Active Tracking

- Milestone:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)
- Current work:
  [Issue #21 — Simplify work authorization and enable bounded slice concurrency](https://github.com/hcoona/microsoft-authentication-cli/issues/21)

## Transition Condition

Issue #21 must preserve one canonical authority for stage and work authorization,
distinguish authorization from work tracking, retain explicit high-risk and owner
decision gates, and pass the applicable hk checks, independent reviews, finding triage,
and Record-System Gate.

This proposal authorizes no Issue #21 amendment work before it merges. If GitHub becomes
unavailable after acceptance, continue only already-bounded Issue #21 work recoverable
from the accepted records, or stop.

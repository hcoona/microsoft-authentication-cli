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

## Authorization Envelope

The current envelope permits:

- non-executing planning through proposed Issues and Milestones;
- preparing and reviewing an explicitly repository-owner-approved pull request whose
  sole substantive purpose is to change the roadmap stage or this authorization
  envelope.

Planning a work item does not authorize its execution or a change to a canonical record.
Independent work inside an accepted envelope may proceed concurrently, but this envelope
currently authorizes no product, research, experiment, architecture, implementation, or
release work.

## Blocked Work

- Product, research, experiment, architecture, design, implementation, validation,
  compatibility, migration, packaging, release, maintenance, support-commitment, or
  operational-identity work outside the permitted planning and envelope-change classes.
- Treating an Issue, Milestone, branch, or pull request as authority to expand this
  envelope.
- Selecting or freezing the first v2 slice before a later accepted envelope permits that
  activity.

## Active Tracking

- Milestone:
  [Phase 1 — Empirical Baseline](https://github.com/hcoona/microsoft-authentication-cli/milestone/1)
- Issues and pull requests carry proposed and current work and are intentionally not
  enumerated in this record.

## Transition Condition

The repository owner may change the authorization envelope through a reviewable
project-state pull request. Entering a later roadmap stage also requires that stage's
entry conditions and the Record-System Gate.

Opening, starting, completing, or closing an in-envelope Issue does not require a
project-state change.

If GitHub is unavailable, continue only non-owner-gated work whose accepted envelope,
prerequisites, and bounded carrier are already recoverable. Unfinished work that depends
on a repository-owner disposition must pause when the carrier's current disposition
cannot be checked. Follow the accepted domain protocol when safe interruption requires
additional action. Do not begin work that requires a new repository-owner disposition.

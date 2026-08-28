# V2 Roadmap

## Planning Model

The roadmap uses evidence and exit criteria rather than target dates. A later phase must
not become active until the preceding phase's required records are complete and
`docs/project-state.md` is updated.

## Phase 0: Foundation and Handoff

**Goal:** Establish an orphan v2 line with enough public context for independent work.

Required outputs:

- unofficial status, license, provenance, and governance boundaries;
- vision, architecture direction, threat model, and draft requirements;
- public v1 architecture audit;
- validation strategy;
- accepted initial decision records;
- authoritative project state and agent instructions.

**Exit:** All records are internally consistent, public-safe, and reviewed. No product
implementation is expected.

## Phase 1: Empirical Baseline

**Goal:** Convert source findings into reproducible behavior evidence.

Required outputs:

- reproducible upstream build and test instructions;
- proof of whether the upstream baseline restores anonymously, including disposition of
  the authenticated Office feed and `Microsoft.Office.Lasso`;
- dependency and platform inventory;
- safe test identities and data-handling protocol;
- accepted execution isolation following `experiment-safety.md`;
- v1 behavior matrix for account selection, no-interaction, cancellation, cache, and host
  behavior;
- explicit facts versus unresolved runtime hypotheses.

**Exit:** The behavior that v2 must change or preserve is demonstrable without private
evidence, and no private build dependency has been accepted into the v2 implementation.

## Phase 2: Contract Freeze

**Goal:** Define the smallest versioned contract that preserves v2 invariants.

Required outputs:

- request and result schemas;
- account selector and client-profile contracts;
- ordered-stage and interaction-policy model;
- failure taxonomy and process exit mapping;
- deadline, host-context, cache, and protocol rules;
- compatibility decision for v1 commands and state.

**Exit:** Contract examples and negative cases are reviewable, and no implementation
question is hidden inside unspecified behavior.

## Phase 3: Mechanism-Neutral Core

**Goal:** Implement policy, orchestration, typed results, protocol routing, and fake
mechanisms without real credentials.

Required outputs:

- complete contract and policy tests;
- deterministic fake account and mechanism adapters;
- cancellation and concurrency model;
- stdout, stderr, redaction, and secret-shape tests;
- no platform-specific auth dependency in the core.

**Exit:** Every strategy and failure rule can be proven with fakes.

## Phase 4: First Real Platform Slice

**Goal:** Add one narrow MSAL mechanism path end to end.

The platform and mechanism are not yet selected. The slice must include:

- explicit client application and authority;
- strict stable-account binding;
- selected-account silent acquisition;
- complete result metadata;
- secure cache;
- real environment acceptance.

**Exit:** One supported host satisfies all applicable v2 invariants without compatibility
fallback.

## Phase 5: Interactive Mechanisms

**Goal:** Add explicitly ordered broker, browser, and device-code mechanisms as justified.

Each mechanism requires:

- independent interaction permission;
- result identity validation;
- cancellation and timeout proof;
- typed unavailable, denied, and challenge outcomes;
- real host validation.

**Exit:** Supported interactive mechanisms can be composed without hidden fallback or
duplicate prompts.

## Phase 6: WSL Architecture

**Goal:** Select and validate the supported WSL model.

Candidate models:

- native Linux broker;
- versioned Windows helper;
- two explicit modes with no implicit fallback between them.

**Exit:** Host prerequisites, UI ownership, cache boundary, transport, cancellation,
installation, and unsupported cases are explicit and tested.

## Phase 7: Compatibility and Product-Specific Features

**Goal:** Add only the compatibility surfaces justified by current demand.

Potential work:

- bounded v1 CLI adapter;
- selected cache migration;
- Azure DevOps compatibility profile;
- separately approved ADO PAT lifecycle.

**Exit:** Every retained surface maps deterministically to v2 and cannot weaken a v2
invariant.

## Phase 8: Distribution and Support Declaration

**Goal:** Produce independently identifiable artifacts and declare their actual support
envelope.

Required outputs:

- final product, executable, package, cache, signing, and update identities;
- isolated installation and upgrade path;
- supported platform/account/client matrix;
- security reporting and dependency-update process;
- signed artifacts and provenance;
- release notes stating limitations and unofficial status.

**Exit:** A release claim is supported by evidence rather than aspiration.

# Repository Record System

## Purpose

This record defines how durable project information is assigned to repository files,
structured records, Git, GitHub, Agent Skills, and automated controls.

The system follows the governance principles in
[`governance-system.md`](governance-system.md).

## Authority by Concern

Authority is scoped rather than globally ranked.

| Concern | Canonical carrier |
| --- | --- |
| Public project identity and release posture | `docs/governance/project.md` |
| Public navigation to canonical records | Root `README.md` |
| AI-agent behavior | Root `AGENTS.md` |
| Human contribution workflow | Root `CONTRIBUTING.md` |
| Current phase and work authorization | `docs/project-state.md` |
| Durable phase model and exit gates | `docs/roadmap.md` |
| Product purpose and directional boundary | Product vision |
| Required product behavior | Product requirements |
| Current system structure and invariants | Architecture records |
| Durable design choices and rationale | Accepted decision records |
| Public source and empirical evidence | Research records |
| Security assumptions and trust boundaries | Security records |
| Validation needed for a claim | Validation records |
| Upstream relationship and imports | Root `UPSTREAM.md` and import records |
| Work ownership, discussion, and progress | GitHub Issues and Milestones |
| Proposed repository state | Pull requests |
| Current accepted repository state | `main-v2` |
| Published state | Git tags and GitHub Releases |
| Authorship, changes, and deleted records | Git history |

An index or overview may identify the authoritative record but must not restate its
normative content.

## Record Admission

Before adding a record or control, identify:

1. the concern it owns;
2. who or what produces it;
3. who maintains it when the concern changes;
4. the human, Agent, or automation consumer and its use point;
5. the failure that occurs if the record is absent;
6. why an existing carrier cannot serve the same purpose.

If these questions do not have concrete answers, do not add the record.

## Granularity

Split information when parts have independent producers, consumers, acceptance,
versioning, security boundaries, or retirement conditions.

Keep information together when it must be reviewed as one decision, shares the same
lifecycle, and would require duplicated context if separated.

File length is evidence that a review may be useful, not a mechanical split rule.

A directory may establish a stable authority namespace even when it initially contains
one record, provided the domain is already distinct and is expected to gain another
consumer or record within the next one or two iterations.

## Formats

Choose the canonical format by the primary operation:

| Primary operation | Format |
| --- | --- |
| Explanation, rationale, policy, architecture, or synthesis | Markdown |
| Small human-maintained structured state | YAML |
| Strict machine contract or interchange | JSON with JSON Schema |
| Repeated homogeneous observations | JSONL |
| Flat analytical data | CSV when nested structure is unnecessary |
| Dependencies and supply-chain data | An established format such as CycloneDX or SPDX |
| Test and scanner output | The tool's standard format, such as JUnit or SARIF |

Do not maintain a Markdown copy of a structured record. A narrative report may summarize
structured evidence when it adds a distinct conclusion, limitation, or decision impact.

Structured records require a real consumer, a schema or equivalent typed contract, and a
defined validation point.

## Lifecycle Through Git and GitHub

- An Issue expresses a problem, question, or bounded work item.
- A pull-request branch expresses a proposal.
- A branch may propose a changed `docs/project-state.md`, but work authorization continues
  to come from the target branch's accepted copy until merge.
- Merge into `main-v2` accepts the changed records as current within their declared
  scopes.
- A tag and GitHub Release identify published state.
- Git history retains replaced and deleted records.

Ordinary records do not need `accepted`, `effective`, `author`, `last_updated`, branch, or
revision-history metadata.

Rejected proposals remain in closed Issues or pull requests. They do not need a rejected
record in `main-v2`.

## Deletion and Replacement

Delete a replaced record after:

- all current consumers have moved;
- internal links have been updated;
- unique current rationale or evidence has moved to its new authority;
- applicable checks pass.

Do not create a general archive or supersession graph. Retain multiple versions only when
current consumers require them.

## Current, Scheduled, Conditional, and Discarded Mechanisms

- **Current:** has an active producer and consumer.
- **Scheduled:** is expected within the current or next major stage and has a phase or
  event trigger, evaluator, activation action, and fallback review.
- **Conditional:** may be needed if an observable condition occurs.
- **Discarded:** lacks sufficient value, consumer, or trigger.

Current and scheduled record families and controls may be represented in structured
catalogs when those catalogs are consumed by hk, Agent routing, or phase gates.
Conditional mechanisms remain in this policy or another relevant policy until activated.

## Workflows

Long-term information is organized by stable concern. Chronology and execution waves are
represented by Issues, Milestones, pull requests, commits, and releases.

Requirements are organized by capability rather than by phase or wave. Architecture uses
a global overview and scoped views. Designs are created only for coherent implementation
boundaries that need independent review. Research is organized by question and baseline;
experiments are organized by reproducible protocol.

Requirement identifiers are permanent once merged into the accepted target branch. If a
requirement is retired, replaced, or moved, retain its identifier exactly once as a
nonnormative marker that names the replacement or current authority. Never assign an
established identifier to a different requirement.

## Enforcement

Use:

- hk for deterministic syntax, schema, identifier, path, reference, and secret-shape
  checks;
- Agent Skills for repeatable contextual review;
- human review for product value, risk, scope, and release decisions.

The full CI hk set must include every check in the local fast subset. Local hooks may omit
slower checks but must not implement different semantics.

Agent Skills reference this policy and the policies for their domains. They do not become
independent authorities.

## Record-System Gate

A record-system change is complete only when:

- each retained concern has one canonical authority;
- active structured records pass their schemas;
- current and scheduled mechanisms identify their producer, maintainer, consumer, failure
  mode, and review or execution point;
- scheduled mechanisms identify their trigger, evaluator, activation action, and
  phase-transition fallback review;
- audience interfaces and controls agree with their governing policies;
- replaced records and broken references have been removed;
- mechanical checks and required contextual reviews have recorded results.

The repository owner determines whether the gate has passed from those results.

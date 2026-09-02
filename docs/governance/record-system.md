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
| Current roadmap stage and work-authorization envelope | `docs/project-state.md` |
| Durable stage model, slice lifecycle order, and minimum entry and exit gates | `docs/roadmap.md` |
| Product purpose and directional boundary | Product vision |
| Required product behavior | Product requirements |
| Current system structure and invariants | Architecture records |
| Durable design choices and rationale | Accepted decision records |
| Public source and empirical evidence | Research records |
| Security assumptions and trust boundaries | Security records |
| Validation needed for a claim | Validation records |
| Upstream relationship and imports | Root `UPSTREAM.md` and import records |
| Issue-backed work scope, ownership, discussion, dependencies, and progress | GitHub Issues and Milestones |
| Direct single-PR work scope and proposed repository state | Pull requests |
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

## Work Authorization and Concurrency

The target branch's accepted `docs/project-state.md` defines the current roadmap stage
and work-authorization envelope. The stage is a global ceiling. The envelope identifies
permitted product or research boundaries, activity classes, required accepted
prerequisites, and constraints.

A work item is executable only when:

- its activity class and boundary are inside the accepted envelope;
- its requirement, architecture, evidence, or other declared prerequisites are already
  accepted;
- any policy-required repository-owner disposition is recorded in the applicable
  carrier; and
- it does not depend on an unaccepted result.

Relied-on prerequisites and shared canonical authorities must remain current through
acceptance. If the target branch supersedes or materially changes one, dependent work
must pause until its scope and gate evidence are reevaluated and its validation and
review are refreshed against the current authority.

An Issue, Milestone, branch, or pull request cannot expand that envelope. A proposed
change to `project-state.md` cannot authorize work on its own branch. Change project
state only when the roadmap stage or authorization envelope changes; do not mirror the
list or lifecycle of active Issues and pull requests there.

An Issue is the work carrier when advance owner disposition is required, the work spans
multiple pull requests or contributors, dependencies need coordination, an experiment
or another policy requires a pre-execution carrier, or the result contributes to a stage
gate. A bounded, low-risk change that fits the accepted envelope and needs no separate
planning or advance disposition may use its pull request as the work carrier.

Opening or refining a proposed Issue or Milestone is planning, not authorization to
execute the described work or change a canonical record. Closing an Issue records
progress; it does not change project state.

The latest explicit repository-owner disposition in a work carrier controls. Rejection,
cancellation, or withdrawal ends authority for unfinished work and requires renewed
approval before resumption. Closing a carrier after authorized work completes records
that completion and does not retroactively invalidate it.

Independent work items inside the same envelope may proceed concurrently. Work remains
ordered when it has an unresolved dependency, modifies the same canonical authority
under conflicting assumptions, or requires an earlier owner decision. Concurrency is a
permission, not a reason to duplicate records or weaken review independence.

The roadmap is the authority for an implementation slice's lifecycle order and minimum
entry and exit gates. Applicable domain records remain authoritative for the content and
activation of additional preconditions. Different slices may occupy different lifecycle
activities concurrently when the accepted envelope permits those activities.
Implementation of one accepted slice may overlap requirements or architecture work for
a later slice, but a slice cannot begin implementation until it satisfies both the
roadmap gate and every applicable domain precondition.

## Lifecycle Through Git and GitHub

- An Issue expresses a problem, question, proposed work item, or bounded work carrier.
- A pull-request branch expresses a repository proposal and may be the direct work
  carrier when this policy permits.
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

Issues and Milestones may show planned, active, blocked, and completed work without
copying those states into `project-state.md`.

Requirements are organized by capability rather than by phase or wave. Architecture uses
a global overview and scoped views. Designs are created only for coherent implementation
boundaries that need independent review. Research is organized by question and baseline;
experiments are organized by reproducible protocol.

Requirement identifiers are permanent once merged into the accepted target branch. An
active requirement heading uses `V2-REQ-NNN: Nonempty title`. If a requirement is
retired, replaced, or moved, retain its identifier exactly once as a nonnormative
`V2-REQ-NNN: Retired - current authority: <requirement ID or repository path#anchor>`
marker. Never assign an established identifier to a different requirement. Mechanical
checks enforce the two representations and target existence; review determines whether
the requirement's meaning was preserved.

## Enforcement

Use:

- hk for deterministic syntax, schema, identifier, path, reference, and secret-shape
  checks;
- Agent Skills for repeatable contextual review;
- human review for product value, risk, scope, and release decisions.

The repository checker discovers record candidates independently from the mutable family
catalog. Its bounded record roots are the canonical root interfaces and the `docs/`,
`schemas/`, `contracts/`, and `designs/` namespaces. Adding another record-bearing root
requires updating the checker and catalog in the same change. A catalog edit therefore
cannot remove a retained record from family, schema, or portal validation merely by
deleting its family entry. Governed records must use direct repository paths; symbolic
links are rejected rather than treated as authority routing.

Every current hk control maps each declared hk execution point to the concrete step names
that implement it. The repository checker evaluates HK's actual `pre-commit` and `check`
plans and verifies those steps are reachable at the declared execution point.

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

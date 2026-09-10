# Current Delivery Wave

This record is the sole positive work-authorization authority. An entry is authorized
only as accepted on `main-v2`. An Issue, Milestone, branch, pull request, comment, label,
or unmerged edit cannot add to or enlarge this record.

Adding or changing an entry through merge grants or changes its bounded authorization.
Deleting an entry through merge ends that authorization. Git and the proposing pull
request retain the reason and history; this record contains no progress or historical
status.

Preparing and reviewing an explicitly repository-owner-approved pull request whose sole
substantive purpose is to change this record is permitted without an existing entry. The
proposal does not authorize any work it would add before merge.

## Authorized Advancements

### Develop the high-level architecture and resolve decision-critical feasibility risks

- **Work carrier:** [Issue #35](https://github.com/hcoona/microsoft-authentication-cli/issues/35)
- **Prerequisite:** The requirements baseline in
  [PR #32](https://github.com/hcoona/microsoft-authentication-cli/pull/32) is accepted on
  `main-v2`. A material change to a relied-on requirement, policy, or evidence authority
  pauses dependent work until its scope and review are refreshed.
- **Architecture boundary:** Refine the existing [architecture overview](architecture/overview.md)
  and scoped views into a high-level allocation of component responsibilities,
  dependency direction, trust boundaries, and end-to-end request, token, interaction,
  and reusable-state lifecycles. Trace all seven [user goals](product/user-stories.md),
  prioritizing the primary requested-personal-account Azure DevOps journey. Requirements
  remain authoritative; an implementation limitation cannot silently weaken them.
  Record significant choices in existing architecture or decision families rather than
  creating a parallel specification.
- **Accepted research inputs:** Accepted product, architecture, security, compatibility,
  validation, and research records; relevant public standards, official documentation,
  public software repositories and dependency implementations, Issues, pull requests,
  and release material. Prefer official service and protocol guidance for service
  behavior. Pin recoverable source locations and revisions where available, date mutable
  retrieval, and preserve source findings, hypotheses, and observations as distinct
  evidence. Sources within these categories need no per-repository Wave amendment.
- **Research and experiment subjects:** Resolve questions that could change a high-level
  decision: external client-registration eligibility for the primary journey, strict
  account enumeration and authoritative identity metadata, first-use OS-state and
  subsequent cross-consumer reuse, and the interaction, deadline, result, and secure-state
  boundaries that integrate these capabilities. Use public desk evidence when sufficient.
  Necessary empirical work may use minimal non-product probes and the public dependency
  restore, build, or test steps needed to run them. Probe code and results are research
  artifacts, not a production implementation or an implementation Slice.
- **Execution prerequisites:** No experiment under this entry may execute until the
  accepted [experiment policy](research/experiment-safety.md) covers its environment
  and effects, and a Git-tracked protocol for its exact subject,
  environment, versions, expected observations, effects, finite attempt/time/cumulative
  limits, sensitive-output handling, stop conditions, and cleanup or retention is
  independently reviewed and accepted on `main-v2`. Bind execution to that revision.
  Count manual as well as automated attempts, including failed starts, and retain prior
  consumption when revising a protocol. Do not run when remaining authorized capacity
  cannot be established. Repetition within those accepted bounds needs no new per-run
  owner approval. Desk architecture and research may proceed independently of this
  execution prerequisite.
- **Environment and owner risk decision:** The owner accepts using existing,
  non-disposable owner-designated Windows, Linux, or macOS machines and their authorized
  account, broker, and secure-cache state for these bounded experiments. The owner may
  switch machines and operate interactive steps manually; VM or disposable-user setup
  is not a prerequisite. This accepts the protocol-declared token acquisition and
  ordinary authentication/session and secure-state updates for the selected account
  and scopes, not arbitrary account or machine changes. User-consent interaction remains
  operator-controlled. Existing state is not assumed clean, and provider-side changes
  are not assumed reversible. Native or cross-host paths must be explicitly covered by
  the accepted protocol and applicable rechecks before use.
- **Maximum effects:** Outside record operations and public-source retrieval, permit only
  protocol-declared execution on the designated machine, the necessary public
  development dependencies and local probe artifacts, selected-account authentication
  and its declared state effects, and read-only public test-resource probes. Bound
  artifact and dependency locations, retained authentication state, network endpoints,
  repetitions, and cleanup in the protocol; do not reinstall or reprovision machines,
  remove existing installations, or clear unrelated account/cache state. No experiment
  may exceed this effects envelope through a protocol or a change of machine.
- **Evidence and consumers:** Record public, sanitized, reproducible outcomes with their
  actual environment, existing-state limitations, manual steps, and finite execution
  history. Operator-assisted observations require the same accepted protocol and
  evidence review as automated runs; private anecdotes are not a substitute. Use the
  minimum admitted research/protocol carriers and update directly affected architecture,
  security, validation, and evidence consumers. Evaluate
  [rechecks](research/rechecks.yaml) at this Wave's merge and each fired trigger, and
  complete the applicable outcomes before accepting the decisions they govern.
- **Bounded outcome and acceptance:** A coherent high-level architecture and its
  decision-critical evidence are accepted on `main-v2`. Every user goal has an
  architectural allocation; an unresolved premise that could invalidate a choice keeps
  that choice unselected. Applicable independent architecture, consistency, minimality,
  record-system, and research-evidence reviews have no unresolved material findings.
  Research observations do not themselves enable a Client Profile or establish support.
- **Excluded:** Product implementation or upstream production-code imports; medium- or
  low-level implementation design; frozen public wire or Profile-file schemas;
  distributed Client Profile activation; platform support selection; downstream adapter,
  packaging, installer, migration, or release work. No private repository, feed,
  unpublished service, or private-evidence access; no credentials, private identities,
  raw broker diagnostics, or private observations in retained research artifacts.
  No PAT creation, administrator consent, application or tenant administration, resource
  writes, or remote mutation beyond the declared authentication/session effects.

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

### Reconstruct the AzureAuth V1 public contract baseline

- **Work carrier:** [Issue #25](https://github.com/hcoona/microsoft-authentication-cli/issues/25)
- **Accepted inputs:** The product requirements, upstream policy, and public research
  records accepted on `main-v2`; upstream commit
  `de20930c34b3b86c8a0ed7bbdeeca3f662dae918`; and upstream tags `0.9.5` and `0.9.6`.
- **Authorized advancement:** Inspect the fixed public source scope and produce a
  recoverable evidence baseline of caller-visible AzureAuth V1 promises, source facts,
  inferred intent, known defects or workarounds, and unresolved empirical questions.
- **Bounded outcome:** One public research authority that preserves evidence type and
  maps each material finding to an accepted V2 requirement, a candidate requirement
  clarification or owner decision, a compatibility-only or consumer concern, an
  architecture or implementation choice, an explicit `drop` or `unsupported` candidate,
  or a separately proposed empirical question.
- **Acceptance condition:** The bounded research authority and its material mappings are
  accepted on `main-v2` with the applicable independent research-evidence,
  record-system, requirements, and minimality reviews.
- **Excluded:** Executing AzureAuth, MSAL, broker, cache, installer, migration, restore,
  build, test, or packaging experiments; freezing requirements or a public contract;
  selecting an implementation Slice; architecture or implementation; compatibility or
  support promises; private evidence; and downstream credential-provider or host
  behavior.
- **External effects:** None. This advancement is limited to public-source inspection and
  repository records.

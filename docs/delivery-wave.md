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

### Analyze and reconcile the AzureAuth V2 requirements baseline

- **Work carrier:** [Issue #25](https://github.com/hcoona/microsoft-authentication-cli/issues/25)
- **Accepted inputs:** The product vision, requirements, compatibility policy,
  architecture, validation strategy, upstream policy, and public research records
  accepted on `main-v2`; upstream commit
  `de20930c34b3b86c8a0ed7bbdeeca3f662dae918`; upstream tags `0.9.5` and `0.9.6`; and
  the current public sources named by `RECHECK-001`, `RECHECK-002`, and `RECHECK-007`,
  solely for those fired rechecks.
- **Accepted product dispositions:** Preserve the delegated public-client,
  one-request-per-process boundary; strict caller constraints and result validation;
  independent interaction permission; ordered acquisition and typed fallback;
  end-to-end deadline and cancellation; a versioned typed machine protocol; secret
  containment; secure explicit state policy; a public build chain; independent
  operational identity; and no native V1 compatibility, importer, downstream
  credential-provider behavior, or nondelegated identity flow. Retire cross-process
  duplicate-interaction suppression as a requirement; clarify that supported
  interactions do not require a caller-supplied external UI owner; and route dependency
  upgrade and experiment procedure out of product requirements while retaining
  established requirement identifiers.
- **Conditional dispositions:** Define generic built-in and caller-defined profile
  selection, configured-default, sole-candidate, and ambiguity behavior. Treat selection
  or distribution of a Microsoft-owned Azure DevOps profile as unresolved until
  `RECHECK-007` records current public guidance and recoverable, reproducible public
  account-type behavior evidence; if public evidence is insufficient, retain an
  empirical question for a separate Wave rather than selecting the profile. Retain
  optional telemetry behavior with explicit network-export configuration, bounded
  best-effort failure semantics, secret containment, and no upstream telemetry identity;
  route OpenTelemetry itself to later architecture work.
- **Authorized advancement:** Analyze the V2 requirements from the core caller outcome
  through product, security, state, operability, compatibility, and support boundaries.
  Inspect the fixed public V1 source scope where it supplies decision-relevant evidence,
  evaluate the fired `RECHECK-001`, `RECHECK-002`, and `RECHECK-007` through public desk
  evidence, preserve evidence type and confidence, and apply the accepted dispositions
  above to the canonical requirement authorities. Later Issue edits, comments, or owner
  dispositions cannot enlarge these inputs or outcomes without an accepted Delivery Wave
  amendment.
- **Bounded outcome:** One recoverable public authority for the material caller-visible
  V1 contract evidence and one coherent V2 requirements baseline. The baseline may
  amend canonical product requirements, product compatibility policy, validation
  obligations, and directly affected existing consumer records only as needed to:
  preserve accepted behavior; clarify or add required behavior; retire a nonrequirement;
  record an explicit `drop` or `unsupported` disposition; or route an architecture,
  implementation, consumer, or separately proposed empirical question to its proper
  authority without deciding it. A Microsoft-owned client-profile selection remains
  unresolved unless the desk-evidence outcome required by `RECHECK-007` is sufficient.
  The interaction-policy and account-contract requirements cannot be finalized until
  the outcomes required by `RECHECK-001` and `RECHECK-002` are recorded.
- **Acceptance condition:** The research authority, material evidence-to-disposition
  mappings, canonical requirement changes, and directly affected record updates are
  accepted on `main-v2`. Every retained requirement states product behavior rather than
  research, validation, architecture, or engineering procedure, and the applicable
  independent research-evidence, record-system, requirements, consistency, and
  minimality reviews have no unresolved material findings.
- **Excluded:** Executing AzureAuth, MSAL, broker, cache, installer, migration, restore,
  build, test, or packaging experiments; freezing a public request, result, process, or
  wire contract; selecting an implementation Slice or support matrix; architecture or
  implementation selection; production code or upstream imports; compatibility adapters,
  migration tooling, packaging, release, or current support claims; private evidence;
  and downstream credential-provider or host behavior.
- **External effects:** None. This advancement is limited to public-source inspection and
  repository records.

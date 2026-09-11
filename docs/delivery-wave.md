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

### Complete the WSL-to-Windows Azure DevOps Slice design and contracts

- **Work carrier:** [Issue #56](https://github.com/hcoona/microsoft-authentication-cli/issues/56)
- **Prerequisites:** The requirements accepted in
  [PR #32](https://github.com/hcoona/microsoft-authentication-cli/pull/32), current
  [high-level architecture](architecture/overview.md),
  [client and tenant mapping](architecture/client-application-identity.md#provider-mapping),
  and [public evidence](research/v1-public-contract-baseline.md) are the accepted basis.
  A material prerequisite change pauses dependent work until its scope, evidence, and
  review are refreshed.
- **Selected Slice:** A WSL caller explicitly invokes the Windows CLI to obtain an Azure
  DevOps token for a specified personal Microsoft account or work account. Cover the
  personal-repository journey and cloning a company Azure DevOps repository with its
  selected company account. Include Azure Artifacts token acquisition and compatible
  authentication-state reuse in the same Slice: the
  [public source assessment](research/v1-public-contract-baseline.md#wsl-direct-invocation-and-azure-artifacts)
  establishes the shared Azure DevOps resource/scope. Artifacts inclusion is settled;
  Git/package protocols, service access, feed permissions, and derived-credential
  lifecycle remain downstream under
  [decision 0004](decisions/0004-keep-the-authentication-engine-separate-from-consumers.md).
  Select no Linux CLI detection/forwarding or native Linux broker path.
- **Bounded advancement:** Complete the detailed design and contracts needed before
  implementation of this Slice. Select the concrete Windows runtime, dependency and
  broker integration; specify strict account resolution, silent reuse and permitted
  interaction, authoritative result validation, tenant mapping, original deadline,
  cancellation/disconnect handling, owned UI/completion, and secure-state observations.
  Preserve the accepted requirements; implementation convenience cannot weaken them.
  Define the versioned CLI request/result/process contract and the minimum Client Profile
  configuration contract, including explicit selection, Windows configuration/path
  ownership, validation, typed failures, and compatibility boundaries. Define a concrete
  candidate Profile with the external-dependency, consent/audit/branding, partitioning,
  and failure obligations required by its gate; defining it does not enable or distribute
  it. Refine scenario requirements only inside the selected personal/work-account
  journeys and existing product boundary.
- **Design and validation records:** Use existing canonical architecture, requirements,
  security, validation, design, and contract families at the minimum useful granularity.
  Permit the reviewed catalog/routing changes needed to activate the existing scheduled
  design and contract families for design before implementation, plus schema checks and
  synthetic contract examples. Apply the accepted governance amendment reviews to those
  changes; this grant does not waive the accepted activation rules. Use C4 deployment and
  UML sequence/state views where they answer concrete design questions. Update the native
  TMT model when flows or boundaries change and record native open/analysis validation
  for a changed model. Define scenario and contract validation for both account journeys,
  Git/Artifacts reuse, host/process failures, and explicit unsupported combinations.
  Use unit tests for core algorithms; ordinary business orchestration is covered through
  scenario outcomes rather than private implementation structure.
- **Accepted inputs and effects:** Accepted repository authorities and public standards,
  official documentation, public source/dependency implementations, Issues, pull requests,
  and release material. Pin recoverable source revisions and date mutable retrievals.
  Permit record operations, public-source retrieval, deterministic repository/contract
  checks, and native TMT authoring/analysis with the existing tool installation. No
  authentication, account/cache access, resource access, installation, dependency restore
  or build experiment is authorized. Existing probe consumption and evidence limitations
  remain intact. Private account, tenant, repository, and feed identifiers or contents
  must not enter public records. Evaluate every recheck at this Wave's merge and each
  fired trigger, updating materially affected consumers.
- **Acceptance:** The Slice has accepted requirements, concrete design and contracts,
  a scenario validation basis, and explicit unsupported cases. Required independent
  architecture, consistency, minimality, security, record-system, and research-evidence
  reviews have no unresolved material findings. Any missing premise that can invalidate
  a concrete choice keeps that choice unselected and prevents claiming its design ready
  for implementation. Separate design acceptance from future runtime evidence, Profile
  activation, and support acceptance. Completion ends at the design gate; product
  implementation requires a later accepted Wave grant.
- **Excluded:** Product implementation or upstream production-code imports; new executable
  probes or repetition of completed experiments; live Git clone, repository/feed access,
  package operations, or corporate-account authentication; Linux forwarding, native Linux
  or macOS integration, and browser/device-code support expansion; downstream adapters,
  service credentials, service/organization discovery, confidential or workload identities;
  Profile activation/distribution, general platform-support promises, packaging,
  installation, migration, and release. A necessary experiment or product-boundary change
  requires its own accepted authorization and applicable protocol or owner disposition.

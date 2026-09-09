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

### Complete user-story and requirements analysis within the V2 product boundary

- **Work carrier:** [Issue #29](https://github.com/hcoona/microsoft-authentication-cli/issues/29)
- **Prerequisite:** The requirements baseline proposed by
  [PR #28](https://github.com/hcoona/microsoft-authentication-cli/pull/28) is accepted on
  `main-v2`. If that prerequisite or another relied-on authority changes materially,
  pause this advancement and refresh its scope and review.
- **Analysis boundary:** Complete user-story elicitation, requirements analysis, and
  cross-requirement consistency review for the delegated public-client authentication
  engine within the accepted
  [V2 product boundary](product/requirements/product-boundary.md).
  Cover caller-visible identity and token outcomes, interaction, authentication-state
  reuse, process results, privacy, compatibility, and support requirements. Git and Azure
  Artifacts are known consumer scenarios, not an exhaustive authorization list.
  Additional scenarios may be analyzed without another Wave amendment when they remain
  inside this product boundary, bounded advancement, accepted inputs, exclusions, and
  effects. A scenario does not authorize a new product capability outside that boundary,
  an additional source, or a new external effect. V1 `aad` and `ado` behavior is research
  input, not a blanket grant to inherit V1 features or compatibility.
- **Accepted primary user story:** As a developer working with a personal Azure DevOps
  Git repository while my Windows WAM default account is a corporate work account, I
  want the Git credential adapter to request an Azure DevOps access token from the
  AzureAuth Unofficial V2 authentication engine for the personal Microsoft account email
  selected for that repository, so that Git operations do not silently authenticate as
  the corporate account and can reuse valid authentication state without prompting when
  it is available.
- **Known scenarios, not an exhaustive list:** Consider all four combinations of
  company-account and non-company-account computer contexts with a requested company or
  personal account accessing its Azure DevOps Git repositories. Distinguish the default
  account, existing target-account sign-in state, and device-management state rather than
  inferring one from another. Include first-use reuse of operating-system sign-in state
  separately from reuse after an earlier authentication-engine invocation. Include Azure
  Artifacts consumers that use multiple package ecosystems and repositories and want to
  avoid repeated authentication for the same feed when the account and authorization
  context permit reuse. Clarify sequential and concurrent calls, token reuse versus
  ecosystem-specific credential translation, and the boundary between engine and adapter.
  Including a scenario does not preaccept identical token bytes, cross-process
  interaction single-flight, or additional first-release support commitments.
- **Accepted inputs:** The product vision, requirements, compatibility policy,
  architecture, validation strategy, upstream policy, and public research records
  accepted on `main-v2`; the public sources and public comments named by `RECHECK-001`,
  `RECHECK-002`, `RECHECK-006`, and `RECHECK-007` in
  [the registry at `1a024985`](https://github.com/hcoona/microsoft-authentication-cli/blob/1a02498589769c38bc16eefc2efc5f9eca6e6994/docs/research/rechecks.yaml),
  limited to the interaction,
  account-selection, secure-state, and account-type questions relevant to this entry;
  Microsoft Learn public documentation for application tenancy, identity-platform
  endpoints, Windows sign-in and SSO, WAM, IWA, and Azure DevOps and Azure Artifacts
  authentication; and public MSAL.NET documentation and source for strict-account
  pre-resolution, interaction, and authentication-state reuse. The public
  [`azureauth-credprovider` project in hcoona/three](https://github.com/hcoona/three/tree/2360c205dea8c789280448c2cae8252f33cc9583/src/private/app/azureauth-credprovider),
  pinned to `2360c205dea8c789280448c2cae8252f33cc9583`,
  and its directly referenced public contracts may be inspected solely to understand
  consumer credential requirements and the engine/adapter boundary. Public findings
  require recoverable source locations and revisions; mutable-source retrieval must be
  dated and must not be presented as runtime evidence. Later Issue edits, comments,
  source additions, or owner dispositions cannot enlarge this entry.
- **Private contextual access:** The repository owner permits local, read-only
  inspection of the single private downstream workspace already designated for this
  amendment, limited to package-ecosystem authentication call sites and package-source
  configuration structure. No other private workspace may be added or substituted
  under this grant. This access may inform questions, not establish repository evidence.
  Do not execute workspace code or commands, follow private service links, inspect
  credential-bearing files or account stores, or traverse into other private sources.
  Do not publish private workspace names, paths, repository or feed URLs, code,
  identifiers, personal information, or unpublished observations in Git, documentation,
  Issues, pull requests, review comments, or other public artifacts. Redaction does not
  make a private observation admissible evidence. Restate any motivated technical
  question generically and obtain independently publishable support before using a
  factual answer as repository rationale, under the
  [public record boundary](governance/project.md#public-record-boundary).
- **Accepted product dispositions:** Treat the accepted primary user story as a
  first-release blocking scenario while keeping the Git credential adapter outside the
  authentication engine. Require a strict request email, pre-resolved account selection
  before silent acquisition, and terminal validation of the provider-observed email; do
  not expose a stable account identifier or Account Kind selector, infer a hidden account
  binding, or use an identity-opaque operating-system default. Define Client Profiles
  around stable public-client application and platform integration rather than a
  resource preset; keep scopes in each request; bind each profile to one authority cloud;
  and minimize exact tenant-GUID input by using fixed tenant policy for single-tenant
  clients and `common` by default for eligible multitenant clients. Retain explicit
  per-request interaction policy, one finite product deadline, selected-account
  silent-first behavior, strict terminal identity failures, one access token per result,
  secure product-owned state policy, and no first-version Logout, Cache Clear, Force
  Refresh, Resource/CAE claims round trip, or Account List.
- **Authorized advancement:** Establish and refine a concise Product User Stories
  authority within the analysis boundary above, retaining the primary journey. Split
  stories by distinct user goals, not mechanically by matrix cell, acquisition stage, or
  error case. Continue bounded repository-owner requirements elicitation and analyze the
  permitted public sources and private context within their separate boundaries.
  Reconcile accepted decisions into
  capability-scoped product requirements and their directly affected validation,
  compatibility, security, architecture-consumer, record-family, navigation, and
  existing research records. Check the combined scenarios for contradictory
  requirements, missing behavior, and unsafe cross-account or cross-authorization
  reuse. Reuse explicit owner decisions without requesting confirmation merely for
  changed wording; bring genuinely new decisions or conflicts to the owner. Preserve
  the distinction among user context, normative behavior, architecture choices,
  public-source findings, and runtime evidence.
- **Bounded outcome:** One canonical Product User Stories record whose first entry
  captures the primary launch journey without duplicating normative requirements; one
  coherent requirements baseline for this bounded analysis; and atomic updates to the
  existing records that directly consume those requirements. Existing requirement
  identifiers remain unique and are amended or retired under the record-system policy.
  Architecture candidates may be routed to later work but not selected here.
- **Acceptance condition:** The user story, requirements, validation obligations,
  evidence limits, record-family routing, and direct consumer updates are accepted on
  `main-v2`. Every retained requirement states observable product behavior, every
  support-blocking empirical question remains explicitly gated, private context has not
  become public evidence, and the applicable independent research-evidence,
  record-system, requirements, consistency, and minimality reviews have no unresolved
  material findings.
- **Excluded:** Executing AzureAuth, MSAL, broker, cache, installer, migration, restore,
  build, test, packaging, or authentication experiments; selecting or implementing a
  Client Profile, Profile file format or storage lifecycle, public wire schema,
  implementation Slice, platform support matrix, Git or package-ecosystem credential
  adapter, compatibility adapter, migration tool, package, release, or current support
  claim; production code or upstream imports; private evidence; and design or
  implementation of downstream credential protocols. No feed access, package restore,
  PAT or session-credential creation, or actual shared-state experiment is permitted.
- **External effects:** Public-source retrieval, the bounded local private-context reads
  above, and normal GitHub Issue, pull-request, review, and repository-record operations
  only. The owner's private-context permission does not authorize credential access,
  private network requests, execution, modification, or publication. No authentication,
  account, tenant, cache, build, installation, or resource effects are permitted.

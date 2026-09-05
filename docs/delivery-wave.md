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

### Ground V2 requirements in the primary Git credential user story

- **Work carrier:** [Issue #29](https://github.com/hcoona/microsoft-authentication-cli/issues/29)
- **Prerequisite:** The requirements baseline proposed by
  [PR #28](https://github.com/hcoona/microsoft-authentication-cli/pull/28) is accepted on
  `main-v2`. If that prerequisite or another relied-on authority changes materially,
  pause this advancement and refresh its scope and review.
- **Accepted primary user story:** As a developer working with a personal Azure DevOps
  Git repository while my Windows WAM default account is a corporate work account, I
  want the Git credential adapter to request an Azure DevOps access token from the
  AzureAuth Unofficial V2 authentication engine for the personal Microsoft account email
  selected for that repository, so that Git operations do not silently authenticate as
  the corporate account and can reuse valid authentication state without prompting when
  it is available.
- **Accepted inputs:** The product vision, requirements, compatibility policy,
  architecture, validation strategy, upstream policy, and public research records
  accepted on `main-v2`; Microsoft Learn public documentation for single-tenant and
  multitenant applications and tenant-scoped identity-platform endpoints; and public
  MSAL.NET documentation and source solely to evaluate whether a strict-email account can
  be resolved before silent acquisition. Later Issue edits, comments, or owner
  dispositions cannot enlarge this entry. Mutable public sources must be recorded with
  recoverable provenance and must not be presented as runtime evidence.
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
- **Authorized advancement:** Establish a concise Product User Stories authority for the
  primary journey and continue bounded repository-owner requirements elicitation for
  that journey from core identity and token outcomes through interaction, state,
  process-result, privacy, compatibility, and support behavior. Reconcile the accepted
  decisions into capability-scoped product requirements and their directly affected
  validation, compatibility, security, architecture-consumer, record-family, and
  navigation records. Preserve the distinction among user context, normative behavior,
  architecture choices, public-source findings, and runtime evidence.
- **Bounded outcome:** One canonical Product User Stories record whose first entry
  captures the primary launch journey without duplicating normative requirements; one
  coherent requirements baseline derived from that journey; and atomic updates to the
  existing records that directly consume those requirements. Existing requirement
  identifiers remain unique and are amended or retired under the record-system policy.
  Architecture candidates may be routed to later work but not selected here.
- **Acceptance condition:** The user story, requirements, validation obligations,
  evidence limits, record-family routing, and direct consumer updates are accepted on
  `main-v2`. Every retained requirement states observable product behavior, every
  support-blocking empirical question remains explicitly gated, and the applicable
  independent research-evidence, record-system, requirements, consistency, and
  minimality reviews have no unresolved material findings.
- **Excluded:** Executing AzureAuth, MSAL, broker, cache, installer, migration, restore,
  build, test, packaging, or authentication experiments; selecting or implementing a
  Client Profile, Profile file format or storage lifecycle, public wire schema,
  implementation Slice, platform support matrix, Git credential adapter, compatibility
  adapter, migration tool, package, release, or current support claim; production code
  or upstream imports; private evidence; and downstream Git protocol behavior.
- **External effects:** Public-source retrieval and normal GitHub Issue, pull-request,
  review, and repository-record operations only. No authentication, account, tenant,
  cache, build, installation, or resource effects are permitted.

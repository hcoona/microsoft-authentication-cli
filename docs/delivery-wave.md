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

### .NET 10 Development and Agent Tooling

**Accepted inputs:** The repository's current agent and contributor interfaces,
[governance policy](governance/governance-system.md),
[record policy](governance/record-system.md), catalogs, controls, pinned mise/hk toolchain,
and the .NET 10 baseline in the accepted
[Windows Slice design](designs/windows-ado-authentication.md#selected-boundary-and-dependencies).
The repository owner requested .NET 10/C# configuration and selected APM-managed skills
for GitHub Copilot CLI and Codex CLI, with Microsoft Learn tooling following Microsoft's
official implementation and documentation.
Public configuration in `hcoona/three` and the public `microsoft/apm`, `dotnet/skills`,
and `microsoftdocs/mcp` sources are implementation references, not repository authority.
The proposing pull request records their reviewed source revisions.

**Bounded advancement and outcome:** Configure the .NET 10 developer baseline and
repository-scoped agent tooling for exactly the `copilot` and `codex` APM targets:

- Pin the .NET 10 SDK through mise and consistent `global.json` selection, starting from
  the accepted design's SDK 10.0.401. Adapt directly applicable C# style, shared MSBuild
  settings, and public NuGet configuration from `three`. Introduce shared build/package
  files only where they have a concrete consumer; do not import unrelated package lists,
  metadata, licensing choices, build extensions, or preview settings. Preserve the
  historical .NET 8 probe, toolchain, and experiment inputs, including their dependency
  versions and effective build configuration.
- Pin `github:microsoft/apm` through mise, and declare APM dependencies and their resolved
  revisions in a root `apm.yml` and `apm.lock.yaml`. Start from the reference repository's
  APM v0.29.0 baseline and review any necessary version change explicitly.
- Install only `directory-build-organization`, `property-patterns`, and
  `msbuild-antipatterns` from `dotnet/skills`, including their referenced support files.
  Use explicit skill selection rather than whole-plugin activation. Review their exact
  source and component dependencies; selecting skills does not authorize bundled MCP
  servers, LSP servers, hooks, or agents.
- Configure the public `https://learn.microsoft.com/api/mcp` endpoint for both clients
  at repository scope. Pin the public `@microsoft/learn-cli` package and a compatible
  Node.js runtime through the repository toolchain. Provide the upstream
  `microsoft-docs` and `microsoft-code-reference` skills from `microsoftdocs/mcp` through
  one declared installation owner. Adopt the official skill content, configuration, and
  usage guidance without defining a repository-specific tool preference or invocation
  order. Record installed versions and distinguish locked setup from any floating
  package references in upstream runtime instructions.
- Define install, frozen replay, explicit update, generated-file ownership, and removal
  behavior in the existing contributor/tooling interfaces. Preserve the hand-maintained
  `AGENTS.md`, both existing review Skills, and ignored private local supplements.
  Generated projections must not become a second manually maintained authority.
- Use existing hk checks plus the smallest necessary deterministic validation for
  dependency locks, selected targets, repeatable deployment, and preservation of local
  instructions. Make any required record routing or control changes atomically under
  the accepted governance review; do not waive an existing obligation.

Completion requires reviewed dependency/provenance and license information, a repeatable
locked setup, the same selected skills discoverable by both clients without conflicting
duplicate installations, documented Windows-friendly commands, working repository-scoped
Learn MCP configuration and official CLI retrieval, consistent .NET 10 SDK selection,
and passing applicable hk/CI and independent reviews. Identify the actual host and client
versions for discovery evidence; document any unverified host rather than claiming
cross-platform runtime coverage.

**Permitted external effects:** Public source and package metadata reads; public .NET 10
SDK, APM, Node.js, and Learn CLI downloads into mise-managed tool locations and declared
package caches; repository-local APM dependency/deployment and client MCP configuration
files; and bounded checks of installation, frozen replay, target/skill discovery, SDK
selection, and CLI help/version behavior. Permit at most one successful Learn search,
page fetch, and code-sample search through each of MCP and CLI, with at most two attempts per operation
per interface and a 60-second limit per attempt, against public documentation using
nonprivate queries. Retain installed tools and declared caches for developer use.
Removal may affect only identified files owned by this setup. Client
discovery checks must not submit model prompts or execute installed skill workflows.
Any check that is an experiment under the existing experiment policy still requires its
separately reviewed and accepted exact protocol before execution; this entry does not
waive that prerequisite.

**Exclusions:** Authentication-engine implementation or probe execution; .NET subject
restore/build, account/token/cache access, real-account authentication, Profile activation,
downstream Git/feed operations, packaging or release; user-global agent configuration;
other MCP services, LSP registration, model changes, automatic hooks or skill-script
execution; unrelated skill collections or the reference repository's monorepo framework.
Installed skills cannot grant work authorization, broaden the product, or override the
accepted repository policies and experiment limits.

### Native AOT Requirements

**Accepted inputs:** The current
[product requirements](product/requirements/quality-build-and-validation.md),
[primary user journey](product/user-stories.md#primary-journey-personal-azure-devops-git-access),
[architecture](architecture/overview.md),
[Windows Slice design](designs/windows-ado-authentication.md), and
[validation strategy](validation/strategy.md). The repository owner requested a Native
AOT requirement wherever feasible; [Issue #67](https://github.com/hcoona/microsoft-authentication-cli/issues/67)
carries that proposal and its scope, not an already accepted requirement.

**Bounded advancement and outcome:** Amend the existing quality/build requirements to
make Native AOT the preferred production publishing mode for eligible .NET 10 targets.
Define what qualifies a target, the obligation to investigate remediable blockers,
evidence-backed exceptions and reassessment conditions, and the behavior that optimization
must preserve. Distinguish executable publishing from library compatibility and Native
AOT from trimming, ReadyToRun, or self-contained deployment alone. Update the requirement's
validation basis and directly affected requirements or navigation atomically; retain
established requirement identifiers and avoid a parallel specification.

Use public desk evidence to assess requirement feasibility and identify implications for
Windows Forms, MSAL/Broker/NativeInterop, native dependencies, and the public build chain.
The requirement must not promise measured performance or select an unverified compatible
implementation. Keep concrete target disposition and UI/dependency selection in the
separate design advancement below. Completion requires an accepted, testable requirement
and validation basis, explicit exceptions, and the applicable independent reviews.

**Permitted external effects:** Public documentation, source, and package-metadata reads;
repository documentation edits and normal record/diagram validation. No subject execution
or dependency installation is granted by this entry.

**Exclusions:** Product or probe implementation; restore, build, publish, performance,
authentication, or cache experiments; changes to the delegated public-client boundary,
supported platforms, first-release journeys, or required security behavior; Profile
activation, packaging, release, and renewed historical probe capacity. Existing concrete
design choices remain current until an authorized design amendment is accepted.

### Primary Windows Scenario Design Revision

**Accepted inputs:** The current
[primary journey and work-account variant](product/user-stories.md#primary-journey-personal-azure-devops-git-access),
capability requirements, [architecture](architecture/overview.md),
[Windows Slice design and protocol](designs/windows-ado-authentication.md),
[public dependency evidence](research/v1-public-contract-baseline.md),
[security model](security/threat-model.md), and
[Slice validation basis](validation/strategy.md#windows-slice-design-acceptance).
[Issue #67](https://github.com/hcoona/microsoft-authentication-cli/issues/67) also carries
the related Native AOT design work. Any design work that depends on the proposed Native
AOT requirement must wait until that requirement and its validation basis merge into
`main-v2`; an unmerged requirement cannot serve as a design premise. Refresh dependent
work whenever its accepted prerequisites materially change.

**Bounded advancement and outcome:** Revise the existing first-scenario design for a WSL
caller explicitly invoking the Windows .NET 10 CLI for an Azure DevOps access token for
the requested account. Preserve the accepted personal-account journey, company-account
variant, and Azure Artifacts access-token/reuse scope. Apply the accepted Native AOT
requirement to this Slice and assess the exact toolchain, RID, MSAL/Broker/NativeInterop,
UI host, serialization, native loading, and deployment constraints using public sources.
Investigate compatible alternatives before selecting an evidence-backed non-AOT
exception. A necessary UI or dependency design change may be proposed within the existing
engine boundary while preserving required HWND ownership, interaction, cancellation,
security, and process semantics; unresolved essential premises keep the choice unselected.

Update the canonical design, affected architecture/contracts, security rationale, public
evidence, and validation obligations together where their meaning changes. Preserve one
authority per concern and use a decision record only for a qualifying durable choice.
Apply the existing [architecture-view standard](architecture/overview.md#architecture-views):
use C4 structural/deployment views and UML sequence/state-machine views to explain
responsibility boundaries, request/provider/UI interactions, cancellation, and terminal
states. Use other UML views only when they answer a concrete design question. Maintain
renderable diagram sources, validate their rendering, and review their consistency with
the normative text and contracts; a diagram inventory alone is not design acceptance.

Completion requires a coherent reviewed design, explicit target compatibility or
exception decisions, unresolved/unsupported cases stated without a support claim, and a
validation plan for both behavioral preservation and the relevant AOT tradeoffs. Do not
declare implementation readiness while a required premise remains unresolved. Applicable
independent record/evidence reviews and contextual design/contract/security/validation
review must pass. Changes to the native threat model also require its existing native
open/analysis validation before acceptance.

**Permitted external effects:** Public documentation, source, and package-metadata reads;
repository design, contract, and evidence edits; normal record/diagram checks; and local
native threat-model open/analysis validation when required by a model change. This entry
does not permit execution of the authentication subject or installation of new tools.

**Exclusions:** Product code, probe code or execution, restore/build/publish or performance
experiments, real-account authentication or credential-store access, private evidence,
Profile activation/distribution, downstream Git/feed operations or host-protocol
implementation, additional platforms/providers, packaging, and release. Historical
experiment inputs and consumed limits remain unchanged. A later experiment or
implementation requires its own accepted bounded authorization and prerequisites.

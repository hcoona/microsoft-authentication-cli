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

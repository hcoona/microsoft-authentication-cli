# Developer Tooling Installation and Discovery Protocol

## Question and Authority

Determine whether the selected .NET 10 and Agent tooling can be installed reproducibly,
preserve repository instructions and historical experiment inputs, expose the same five
Skills to GitHub Copilot CLI and Codex CLI, and retrieve public Microsoft documentation
through the official MCP endpoint and CLI. [Issue #68](https://github.com/hcoona/microsoft-authentication-cli/issues/68)
coordinates bootstrap and acceptance changes.

The accepted [.NET 10 Development and Agent Tooling Wave entry](../../delivery-wave.md)
and [experiment policy](../experiment-safety.md) govern execution. The owner's Wave grant
explicitly permits and retains these developer installations, caches, and repository
projections. This protocol narrows that existing effects decision; it grants no new
product, account, or machine effects. Execute only after this protocol and its bootstrap
inputs merge into `main-v2`; record the accepted commit and input hashes before starting.
An accepted bootstrap is preparation for validation, not an installation-success claim.

## Subject and Environment

Use the current owner-designated WSL 2 Ubuntu 26.04 x64 development host, with existing
mise 2026.8.10, Python 3.13.15, Git, and the repository's pinned check tools. No Windows
subject or historical probe executes. Windows commands are documented but Windows runtime
discovery remains unverified by this protocol. Existing public package caches are permitted;
do not infer an empty-cache restore or cross-platform coverage.

| Input | Exact selection and public provenance |
| --- | --- |
| .NET SDK | 10.0.401, `core:dotnet` in `mise.development.toml`, matching root `global.json`; Microsoft public SDK release distribution |
| APM | `github:microsoft/apm` v0.29.0, official release assets |
| Node.js | 22.22.2, public Node.js distribution; use its bundled npm |
| Learn CLI | `@microsoft/learn-cli` 1.0.0 from `https://registry.npmjs.org/`; `tools/learn-cli/package.json` owns the direct dependency |
| MSBuild Skills | `directory-build-organization`, `property-patterns`, and `msbuild-antipatterns` below `dotnet/skills/plugins/dotnet-msbuild/skills` at `8a5a42d3e392b402768fc29416831643b79e402b` |
| Microsoft Learn Skills | `microsoft-docs` and `microsoft-code-reference` below `microsoftdocs/mcp/skills` at `f8ffde185dfd232dbf5d187c22ce299eadc3d583` |
| MCP | Only `https://learn.microsoft.com/api/mcp`, unauthenticated HTTP transport |
| Codex CLI | Existing Linux x64 0.153.4 installation; verify reported version and record executable SHA-256 before discovery |
| Copilot CLI | Existing Linux x64 executable with SHA-256 `35310a023f92c126099fe5e955728b565c0e77da5d67b34e609802460d065fad`; identify its release using `--version` and public release metadata before discovery |

The root `apm.yml` owns the five exact leaf dependencies, MCP declaration, and exactly
`copilot` and `codex` targets. Each leaf explicitly declares its public HTTPS `git` URL,
`path`, and commit `ref`; do not replace these with shorthand that can inherit an APM
default registry. `--https` controls Git transport, not registry routing. Inspect each selected Skill and its referenced support files
at the fixed revision; preserve upstream notices and instructions. Neither a whole
plugin nor its bundled hooks, agents, binaries, LSP, or other MCP components is selected.
APM owns deployment; do not run `apm compile` or `mslearn setup`, and do not install a
second copy through an Agent's global Skill installer.

The configuration reference is `hcoona/three` at
`516af0e99dfa4327e72c7e9bc2878b8dd26aad2f`. Apply only conventional configuration choices;
no reference-repository license header, package inventory, or monorepo machinery is
imported. Existing `tools/probes/windows-msal` inputs and disabled .NET 8 toolchain remain
unchanged. There is no product consumer for shared MSBuild/package files yet.

## Effects and Preflight

Use a repository worktree and a dedicated temporary validation directory. Record their
roles, not personal absolute paths, in public evidence. Permitted retained state is:

- public SDK/APM/Node installations in mise-managed locations and their download cache;
- a declared APM cache (`APM_CACHE_DIR`), APM's own ordinary manager configuration,
  repository `apm_modules/`, generated `apm.lock.yaml`, and the five Skill projections;
- Learn package metadata/archives in a dedicated npm cache, `tools/learn-cli/node_modules/`,
  and generated `package-lock.json`;
- the development mise lock and repository `.github/mcp.json` / `.codex/config.toml`
  projections; and temporary public-only client discovery/validation output.

Before mutation, inventory and hash `AGENTS.md`, the two hand-maintained review Skills
including support files, the historical probe directory, root `mise.toml`/`mise.lock`,
and existing files at prospective deployment paths. Locally record whether ignored
private supplements exist and compare their hashes afterward without publishing their
content or hashes. Stop on a conflicting existing Skill name or configuration entry.
Unrelated MCP/configuration entries must survive; only this setup's named entries are
owned. Do not redirect or overwrite `HOME` or `CODEX_HOME`.

Before invoking APM, check its manager configuration without using or emitting stored
credential values. Permit absence or only the known nonsecret `default_client`,
`install_target`, and `auto_integrate` keys, with auto-integration enabled or absent.
Inspect only these nonsecret settings and key presence; reject any other key, including
registry, credential, experimental, policy/service, scanner, or hook configuration. An
unknown configuration is a preflight stop, not permission to read its credential values
or rewrite user state. Recheck before every APM invocation, including frozen replay.
Explicit Git dependencies prevent ambient registry routing even if a default registry
would otherwise apply; preflight also prevents other inherited external effects.

Installer subprocesses must not use ambient credentials: omit token/authorization
variables; use a dedicated empty `GH_CONFIG_DIR`, disable Git credential helpers and
prompts through process-only Git configuration, and use only public HTTPS sources.
Do not use a package-manager authentication fallback. Configure npm with an empty user
configuration, the public registry, `--ignore-scripts`, `--no-audit`, and `--no-fund`.
Do not copy user npm configuration or invoke `npx` with an unresolved package reference.
Keep APM's built-in checks enabled and pass `--no-trust-bin`; stop on unexpected components
or an authentication request. APM manager state is not user-global Agent configuration.

Set `DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1`,
`DOTNET_GENERATE_ASPNET_CERTIFICATE=false`, `DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false`, and
`DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true` for SDK checks. Suppress client telemetry
through the fixed client's documented controls before discovery. If safe discovery cannot
avoid authentication, model requests, account stores, or persistent global Agent writes,
stop that operation and report the limitation. Do not log ambient configuration, account
identifiers, tokens, or full private directory inventories.

## Finite Execution Procedure

Run operations sequentially. Before every attempt, verify the current accepted Wave and
protocol, recover cumulative consumption, and append a started entry to a local sequential
journal. Record operation, attempt, UTC start/end, accepted revision, input hashes, outcome,
and retained effects. Failed starts, interruptions, and manual attempts all consume a slot.
Recover unresolved starts as consumed before continuing; amendments do not reset limits.
A subprocess timeout terminates its owned process group, then verifies that it exited.

| Operation | Cumulative maximum | Per-attempt limit |
| --- | --- | --- |
| Development mise lock generation and installation | 3 invocations each | 15 minutes |
| npm lock generation and package installation | 3 invocations each | 10 minutes |
| Initial APM resolution/deployment | 3 invocations | 10 minutes |
| Frozen APM replay | 3 invocations | 10 minutes |
| Generated-file removal check in a disposable validation copy | 2 invocations | 60 seconds |
| Tool help/version/SDK-selection diagnostics | 24 commands total | 60 seconds |
| Local discovery for each Agent client | 4 sessions per client | 60 seconds |
| MCP initialization/tool-list discovery | 2 sessions | 60 seconds |
| Public Learn retrieval | Limits below, separately per operation and interface | 60 seconds |

1. Verify released binary identities against public distribution metadata; record resolved
   artifact checksums. Generate the development mise lock for the selected versions, then
   install only those public developer tools. Do not modify or reinstall the disabled
   historical .NET 8 tool. Record host, mise, Node/npm, APM, and SDK versions. Run only
   `dotnet --version` / `--info` at the repository root to check SDK selection; do not run
   restore, build, publish, workload, certificate, or probe commands.
2. Generate the npm lock with `npm install --package-lock-only --ignore-scripts --no-audit
   --no-fund` in `tools/learn-cli`. Inspect the resolved transitive graph, public source
   URLs, integrity values, engines, licenses, and lifecycle scripts before `npm ci` with
   the same script/audit/funding restrictions. A supported direct dependency does not
   automatically justify a private source or extra executable lifecycle component.
3. Ensure `.codex/` exists. Run `apm install --target copilot,codex --no-trust-bin --https`.
   Inspect the resulting lock, package graph, hashes, support-file closure, and projections.
   The only selected Skills are the five above. Both client MCP projections must identify
   the declared public endpoint without secrets. No instruction compilation is permitted.
4. Run `apm install --frozen --target copilot,codex --no-trust-bin --https` on the resolved
   graph, including a fresh repository-local deployment copy with no `apm_modules/`.
   Compare manifests, locks, Skill/support-file content, and MCP entries; separate any
   documented generated metadata from content. Warm public download caches remain allowed.
   Verify instruction/probe/private-supplement preservation after each mutation. Check
   removal only in a disposable copy by removing this setup's inventoried projections
   and named MCP entries; preserve a seeded unrelated entry and instructions. Do not use
   `apm uninstall --dry-run`: upstream documents that it can run pre-uninstall scripts.
5. Verify each existing client's version and use its local Skills listing/discovery
   surface (CLI menu or documented local protocol) without a model prompt or Skill
   execution. Read help/source to select the non-prompt discovery operation and retain
   the exact commands/protocol messages in the acceptance evidence. Only initialize,
   list local Skills/configured MCP servers, and close; no authentication or tool call
   through an Agent is permitted. Restrict results to repository entries. Confirm both
   clients resolve each selected Skill to the intended repository path exactly once.
   A directory inventory alone is not actual client-discovery evidence.
6. Initialize the official Learn endpoint and list its tool schemas using the installed
   CLI's MCP SDK dependency or direct protocol requests. Verify the two generated client
   configurations independently; this protocol does not submit a model prompt to prove
   automatic tool selection. Use the official standalone CLI for CLI retrieval and direct
   MCP `tools/call` for MCP retrieval, with the same public inputs below.

| Operation | Public input | MCP tool | CLI operation |
| --- | --- | --- | --- |
| Documentation search | `.NET 10 Native AOT deployment` | `microsoft_docs_search` | `search` |
| Page fetch | `https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/` | `microsoft_docs_fetch` | `fetch` |
| Code-sample search | `System.Text.Json source generation`, language `csharp` | `microsoft_code_sample_search` | `code-search --language csharp` |

For each row and each interface independently, allow **at most two attempts and one
successful retrieval**, with **60 seconds per attempt**. Success consumes that operation's
remaining capacity. MCP initialization/listing is not a retrieval; do not add `doctor`
requests or hide retries in a helper. Disable automatic operation retries or count each
actual call within the same maximum. The CLI may initialize/list tools as part of its
single operation. Record status, tool/command, representative public title/URL or sample
presence, and elapsed time. A protocol/HTTP success with an application error is not a
successful retrieval. No private query, account, downstream service, or returned code
execution is permitted.

## Stop, Cleanup, and Acceptance

Stop the affected operation on exhausted/unknown capacity, unexpected credential or UI
requests, tool/version/source mismatch, unapproved side effects/components, lost process
control, unsafe output, or preservation failure. Stop dependent operations until the
problem has a reviewed disposition. Do not widen scope, switch machines, suppress a
finding, or install another tool to make the result pass.

Retain the granted developer tools and declared public caches for developer use. Remove
only identified disposable validation files and owned temporary processes. Retain the
sanitized journal until its observations and consumption are accepted here; public PR
check/review results carry mechanical and contextual validation. Never commit raw client
logs or private supplements. Capture only the bounded repository-related evidence.

The acceptance change must commit resolved APM/npm/mise locks, finalized contributor
install/replay/update/removal guidance, dependency/provenance/license findings, the smallest
necessary deterministic checks, and sanitized actual observations/consumption. Installed
upstream Skills retain their original behavior and any floating package examples; clearly
distinguish those instructions from the repository's locked setup. Passing installation
or retrieval does not establish Agent model behavior, Windows runtime coverage, .NET
subject compatibility, authentication support, or product implementation readiness.

## Execution History

No attempt has executed under this protocol. Bootstrap acceptance alone does not establish
repeatable installation or client discovery. The first execution must recover this zero
baseline and bind the accepted revision before reserving its first attempt.

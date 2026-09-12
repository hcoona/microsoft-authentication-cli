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
mise 2026.9.3, Python 3.13.15, Git, and the repository's pinned check tools. CI separately
uses mise 2026.8.10; that workflow pin is not evidence of the local executable version.
The existing Linux x64 mise executable must match the public
[2026.9.3 release asset](https://github.com/jdx/mise/releases/tag/v2026.9.3), SHA-256
`981bd9179cc089114a87b491fce2c4007ab05b5445dee7ad08e87e5dffcc154d`.
Resolve and record its absolute path and hash before each operation, invoke that bound
path, and stop if its identity changes. Do not update mise or alter the CI toolchain.
No Windows subject or historical probe executes. Windows commands are documented but Windows runtime
discovery remains unverified by this protocol. Existing public package caches are permitted;
do not infer an empty-cache restore or cross-platform coverage.

| Input | Exact selection and public provenance |
| --- | --- |
| .NET SDK | 10.0.401, `http:dotnet-development` in `mise.development.toml`, matching root `global.json`; exact Microsoft public Linux x64 and Windows x64 SDK archives and SHA-512 values |
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
This includes help/version diagnostics and APM invoked through `mise exec`; dispatching
only on an operation-category name is insufficient.
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
Bind expected version/help observations before each diagnostic. Compare the result
immediately and stop on a mismatch before invoking the next command; a zero exit code
alone does not satisfy an expected-version check. Verify the host mise version before
the first resumed installer operation.

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
   Use `http:dotnet-development`, not the `dotnet` registry alias: the observed alias
   resolution selects a vfox backend whose lock identifies a mutable install script
   without an SDK-archive checksum. The exact HTTP tool declares Microsoft's versioned
   archives and SHA-512 values from the pinned
   [.NET 10 release metadata](https://github.com/dotnet/core/blob/3b2b11b56f0dfa0f4c273fed44efbc32342ea475/release-notes/10.0/releases.json).
   Lock only `http:dotnet-development`, `github:microsoft/apm`, and `node`, for
   `linux-x64,windows-x64`; require archive URLs and checksums for all six tool/platform
   entries before installation. This does not alter the separate historical HTTP tool.
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

On **2026-09-12 UTC**, mise lock generation attempt **1 of 3** executed under bootstrap
revision `ec34c446c8c2528ad389a6cc64f706624e096cbb`, from 00:20:02.758673 to
00:20:04.838337 UTC. The existing WSL development host and PATH-resolved mise generated six
Linux x64/Windows x64 entries and exited zero. The earlier attribution to mise 2026.8.10
was not supported by a local executable/version receipt; it incorrectly used the CI pin.
Inspection found that `core:dotnet` resolved
to `vfox:dotnet`; its entries named the mutable `dot.net/v1/dotnet-install` scripts and
contained no SDK-archive checksums. This is a lock-generation observation, not successful
locked SDK installation. No developer tool or package was installed, and no client or
retrieval operation executed. All preserved instruction/probe/historical-toolchain and
private-supplement comparisons matched.

The generated lock is retained as temporary validation evidence rather than accepted as
the developer lock. Installation stopped before invocation. The amended exact HTTP SDK
descriptor resolves that discovered reproducibility gap without changing the SDK version,
host scope, public source, or retained-installation boundary. Execute the corrected
descriptor only after its amendment merges. At the end of that attempt, **two
lock-generation invocations remained** and all other operation limits were unused. Later
observations below supersede that snapshot for current consumption; amendments do not
reset capacity.

### Host Identity and Diagnostic Preflight Correction

The following later observations do not establish full conformance to the preceding
protocol. Under the still-accepted bootstrap, diagnostics 1–3 ran sequentially on
2026-09-12 from 00:33:50.021536 to 00:34:31.075287 UTC in the independently reviewed
offline client namespace. They reported Codex CLI 0.153.4, Copilot CLI 1.0.84-4, and
Copilot's documented OTel controls. Both installed client binaries matched their public
release archives. No Skill listing, model request, or account access occurred.

After SDK-descriptor amendment `df43187b8581ad73a5f7638a1df0589c4f932390` merged, lock
attempt 2 ran from 00:38:25.482697 to 00:38:25.855217 UTC; mise installation attempt 1
ran from 00:38:41.413793 to 00:38:54.470896 UTC on the same host. The six generated
Linux/Windows archive URLs and checksums matched Microsoft's exact SDK 10.0.401 metadata,
APM v0.29.0 release metadata, and Node.js 22.22.2 SHASUMS. The installer reported SDK/APM
installation and reuse of the existing Node.js installation. The generated lock remains
temporary evidence pending corrected validation.

Diagnostics 4–9 then completed from 00:39:08 to 00:39:11 UTC. Diagnostic 4 reported
**mise 2026.9.3**, contradicting the declared 2026.8.10 host. The diagnostic loop failed
to compare that output immediately and continued with SDK version/info, Node, npm, and
APM version commands. Those reported SDK 10.0.401, runtime 10.0.12, Node 22.22.2, npm
10.9.7, and APM 0.29.0. No product/probe command executed. Earlier PATH-resolved mise
invocations lacked a pre-attempt executable receipt, so attributing them to the later
verified 2026.9.3 binary is an inference, not established execution identity.

The APM version diagnostic also bypassed the repeated manager preflight because the
helper checked only `apm-*` operation categories. The subsequent manager allowlist check
passed without changing configuration, but cannot retroactively satisfy that preflight.
All recorded preservation comparisons passed; this does not waive either deviation.
Independent triage in Issue #68 confirmed both author-discovered failures. Further
installer, discovery, and retrieval execution stopped before npm/APM package installation
or any Skill-discovery/Learn operation.

This correction binds the actual existing host executable, adds immediate diagnostic
comparison, and covers indirect/diagnostic APM invocation without changing developer
dependency pins, hosts, endpoints, retained-state boundaries, or CI. The now-recorded mise
hash matches the public release's executable digest; the public 2026.9.3 HTTP/GitHub
backend and installation sources support the required versioned archives, lock checks,
and selected-tool installation. No tool update is required.

Resume only after this correction merges. Verify the bound host version, regenerate and
compare the development lock, perform a locked installation check against the declared
existing installed state, and repeat the required SDK/tool version checks with immediate
assertions and the APM preflight. Do not claim a fresh-cache installation or retroactive
protocol compliance. Preserve and disclose the earlier deviations and installed state.
Current consumption is **lock generation 2 of 3, mise installation 1 of 3, and diagnostics
9 of 24**; respectively 1, 2, and 15 invocations remain. All other categories remain
unused. The correction does not reset capacity; recover the sequential journal before
every subsequent attempt.

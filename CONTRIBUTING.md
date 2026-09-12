# Contributing to AzureAuth Unofficial V2

**AzureAuth Unofficial V2** is an unofficial, pre-release fork. Contributions must remain
within the current project boundary and work authorization.

## Before Starting

1. Read the [project record index](docs/README.md).
2. Determine authorization from the target branch's accepted
   [`docs/delivery-wave.md`](docs/delivery-wave.md), normally the copy on `main-v2`.
3. Confirm that one current entry authorizes the bounded advancement and that its
   accepted inputs, exclusions, and external-effects boundary fit the work.
4. Treat a working-branch change to that file as a proposal that cannot authorize
   additional work before merge.
5. Read the applicable Issue when work needs separate proposal, dependency, or progress
   coordination. Otherwise, use the pull request as the bounded work carrier.
6. Read the canonical product, architecture, research, security, and validation records
   relevant to the change.

Do not add private company information, credentials, tokens, private account details, or
unpublished downstream evidence.

## Work Carriers and Concurrency

Use a separate Issue when work spans multiple pull requests or contributors, coordinates
dependencies or progress, or benefits from separate proposal discussion. A bounded
single-PR change may use the pull request itself as its work carrier when its accepted
Wave entry already contains sufficient scope.

An Issue, Milestone, branch, pull request, comment, label, or unmerged Wave edit does not
grant or enlarge work authorization.

An explicitly repository-owner-approved pull request limited to adding, changing,
deleting, or replacing Delivery Wave entries may be prepared and reviewed without an
existing entry. Newly proposed work begins only after that change merges.

Independent authorized work may proceed concurrently. Work remains ordered when it
depends on an unaccepted result or changes the same canonical authority under conflicting
assumptions. Implementation requires accepted Slice requirements, applicable
architecture and contracts, a validation basis, explicit unsupported cases, and every
applicable domain precondition. Another authorized Slice may concurrently remain in
requirements or architecture work. If the target branch materially changes a relied-on
prerequisite or shared canonical authority, pause dependent work and refresh its gate
evidence, validation, and review before merge.

Before an experiment runs, its accepted Wave entry must bound the outcome and maximum
effects and its accepted protocol must define environment, account-state and effects
boundaries, observations, finite attempt/time limits, stop conditions, and cleanup or
intentional retention. Owner-operated steps and machine switches use the same protocol
and cumulative limits. Repeated executions inside those bounds
do not require another owner approval. A material effects boundary requires the owner
risk decision defined by the experiment policy.

## Local Checks

Install the pinned repository toolchain and hooks:

```sh
mise install --locked
mise run hooks:install
```

The locked toolchain is supported on platforms represented for every required tool in
`mise.lock`. The pinned hk release has no Intel macOS binary; use CI or another supported
development host on Intel macOS.

The pre-commit hook runs the local fast set through hk. Run the complete CI-equivalent
set before requesting review:

```sh
mise run check
```

The hook fails closed while any unstaged or untracked path remains. Stage the final
intended snapshot or temporarily set other work aside before committing so repository-wide
path-based checks inspect the same tree Git will record.

## .NET and Agent Tooling

The optional `mise.development.toml` environment selects .NET SDK 10.0.401, APM v0.29.0,
and Node.js 22.22.2. Root `global.json` requires that SDK without roll-forward. The
historical .NET 8 probe retains its own SDK and package inputs. Shared MSBuild/package
files wait for a concrete product consumer.

The locked development toolchain has Linux x64 and Windows x64 entries. Acceptance
observations cover the declared WSL Linux host and client versions in the
[developer-tooling protocol](docs/research/experiments/developer-tooling.md); Windows
runtime discovery is not established. Installation and experiments remain subject to
current work authorization and the applicable protocol.

Apply the protocol's public-only preflight first: empty process-local GH/npm configuration,
disabled Git credential helpers/prompts, omitted token variables, and a checked empty
`NETRC` file. Keep APM's built-in checks enabled. An inherited registry, policy, credential,
or hook configuration is a stop condition. From the repository root, these command
forms work in PowerShell and a POSIX shell:

```text
mise -E development install --locked http:dotnet-development github:microsoft/apm node
mise -E development exec -- npm ci --prefix tools/learn-cli --ignore-scripts --no-audit --no-fund
mise -E development exec -- apm install --frozen --target copilot,codex --no-trust-bin --https
mise -E development exec -- dotnet --version
```

Use public package sources and preserve existing instruction/configuration entries.
Do not invoke an authentication fallback or override a conflicting installation. The
accepted protocol details the credential-free acceptance environment and APM manager
preflight. Ordinary repository checks continue to use the default mise environment.

`apm.yml` selects exactly `directory-build-organization`, `property-patterns`,
`msbuild-antipatterns`, `microsoft-docs`, and `microsoft-code-reference`. APM owns their
shared `.agents/skills/` deployment and the named `microsoft-learn` entries in
`.github/mcp.json` and `.codex/config.toml`. Both clients consume that shared Skill
location. The two hand-maintained review Skills remain in `.github/skills/`.

Commit `apm.lock.yaml`, `mise.development.lock`, and `tools/learn-cli/package-lock.json`.
Generated dependency directories and client projections remain ignored. Preserve
`AGENTS.md`, review Skills, and the ignored private `AGENTS.local.md`. Never run
`apm compile` over the hand-maintained instructions, duplicate the selected Skills with a
global installer, or use `mslearn setup` to create another installation owner.

Microsoft's official Skill content owns its usage guidance. The repository adds no tool
preference or invocation order. Upstream examples may use floating `npx` references;
those examples are not this repository's locked installation. The locked official CLI
is available as:

```text
mise -E development exec -- node tools/learn-cli/node_modules/@microsoft/learn-cli/dist/index.js --help
```

[UPSTREAM.md](UPSTREAM.md) identifies sources and license notices.

### Explicit Updates and Removal

An update is a reviewed change to the direct version/ref declarations and their generated
locks under current work authorization. Regenerate only the development mise lock for
`http:dotnet-development`, `github:microsoft/apm`, and `node`, on `linux-x64,windows-x64`;
do not regenerate the historical toolchain. Resolve the Learn package lock with
`--package-lock-only --ignore-scripts --no-audit --no-fund`, review its graph, then use
`npm ci` with the same restrictions. Resolve APM with the same explicit targets,
`--no-trust-bin`, and `--https`, then verify a frozen replay and content preservation.
Review provenance, licenses, Skill support files, generated targets, and any new effects
before accepting a changed lock.

To remove this setup, first inventory its owned paths and compare their content with the
accepted lock/source. Remove only its five Skill directories, its APM dependency data,
and the Learn `node_modules` directory; remove only the `microsoft-learn` entry from each
client configuration. Preserve unrelated servers, settings, Skills, and instructions.
Remove an empty generated config only if this setup originally created it and no other
content remains. Do not use `apm uninstall --dry-run`: upstream documents that it can run
pre-uninstall scripts. mise-managed tools and public caches are intentionally retained
and may be shared by other projects; repository removal does not authorize deleting
them. Removing the committed manifests/locks is a separate reviewed repository change.

## Pull Requests

A pull request should:

- state the repository outcome if merged;
- link the accepted Delivery Wave entry, any applicable Issue, and governing records;
- define its scope and material non-goals;
- identify any record-system impact;
- distinguish evidence from inference and decision;
- provide the smallest validation that supports the claimed change;
- describe material security or external effects.

Not every change needs an Issue, decision record, design record, or documentation update.
Use them only when their repository policies or the work's coordination needs require
them.

## Review Routing

Before merge:

1. Consult [`docs/governance/controls.yaml`](docs/governance/controls.yaml) and run or
   request every control required by the change and its execution point.
2. Evaluate every fired entry in
   [`docs/research/rechecks.yaml`](docs/research/rechecks.yaml), even when no research file
   changed before the trigger.
3. For governance amendments, use the accepted target-branch versions of `AGENTS.md`, the
   governance policies, `controls.yaml`, and the applicable review Skill as the review
   authority. Treat proposed versions as review subjects until merge.
4. Send each material review finding to a reviewer independent of the originating
   review, change author, and implementation agent for triage before remediation or
   dismissal.
5. Obtain repository-owner disposition when an applicable control, unresolved finding,
   or owner-decision finding requires it.
6. Record the review, triage, recheck, and owner-disposition evidence in the pull request.

## Commits

Use Conventional Commits. Keep each commit focused on one human-reviewable semantic
concern and include a nonempty body and final footer block.

## Upstream Source

Follow [`UPSTREAM.md`](UPSTREAM.md) when copying or substantially deriving upstream
source. Preserve required copyright and license notices and record the exact source
commit.

## License

By contributing, you agree that your contribution is provided under the MIT License in
[`LICENSE.txt`](LICENSE.txt).

# Portable Package Host Test Protocol

This protocol governs item 4 of the Delivery Wave entry
[Windows Portable Package, Local Build and Test](../../delivery-wave.md), coordinated in
[Issue #506](https://github.com/hcoona/microsoft-authentication-cli/issues/506). It follows
the [experiment policy](../experiment-safety.md). Merging it into `main-v2` is the protocol
acceptance; it adds no product, support or release claim. The Wave entry owns the owner
risk decisions, the circuit-breaker limits and the exclusions; this record only narrows
them. Results are appended under [Results](#results) through reviewed pull requests.

The question is whether the archive that `packaging/windows/package.ps1` builds, once
extracted into a fresh directory, authenticates the existing personal and work roles on
the designated host from native Windows and WSL callers with the bundled Profile.

## Subject and Inputs

- **Source.** A full clone of this repository at a recorded `main-v2` commit whose copy of
  this file is unchanged, under a fresh root `C:\Temp\azureauth-pkgtest-YYYYMMDD[-n]`
  (`<root>` below), in `<root>\src`. A local `main-v2` branch is reset to that commit and
  checked out, so `HEAD` is on `refs/heads/main-v2`; the worktree is clean. Record the full
  commit hash in the ledger before the first build. No `PublicRelease` override is used.
- **Toolchain.** .NET SDK 10.0.403 with runtime 10.0.14 from `mise install --locked` on the
  Windows side (`%LOCALAPPDATA%\mise\installs\http-dotnet-development\10.0.403`), called by
  its absolute path with `DOTNET_ROOT` set to it and `DOTNET_MULTILEVEL_LOOKUP=0`; the
  same SDK from `mise install --locked` in WSL, called through `mise exec` for R1; the installed Visual Studio 18 C++ tools (MSVC
  14.51.36231) for Native AOT and `dumpbin`; PowerShell 7 as the native caller; bash in
  the host's WSL 2 distribution as the WSL caller. Record each version before B1.
- **Dependencies.** MSAL and Broker 4.83.1, NativeInterop 0.20.3, Nerdbank.GitVersioning
  3.10.94 and the rest of the committed `packages.lock.json` files.
- **Profile.** `profiles\visual-studio-legacy-wam.json` from the extracted archive, passed by
  its absolute Windows path. Every request uses Public Cloud, `--tenant common` and the
  Azure DevOps default scope `499b84ac-1321-427f-aa17-267ca6975798/.default`.

## Restore Route

The Windows host cannot complete a TLS connection to `api.nuget.org`, so the Wave's Windows
restore route applies. `NUGET_PACKAGES` and `NUGET_HTTP_CACHE_PATH` point to new empty
directories `<root>\packages` and `<root>\http-cache` on both sides.

- **R1, WSL fill.** In WSL, from `<root>\src` through its `/mnt/c` path at the same commit:
  `dotnet restore Windows.slnx --locked-mode --configfile nuget.config -p:EnableWindowsTargeting=true`
  with NuGet audit at its default, bounded at 900 s. Record the exit code and the
  warning and error counts. Any audit warning or error, lock mismatch or nonzero exit stops the experiment.
- **R2, Windows.** `package.ps1 -DisableNuGetAudit` restores from that folder alone, in locked
  mode. Audit is off for this step only.

The committed lock files verify every package they list. The implicit runtime packs
(`Microsoft.NETCore.App.Runtime.win-x64`, `Microsoft.NETCore.App.Host.win-x64`,
`Microsoft.NETCore.App.Runtime.NativeAOT.win-x64`) are not lock-verified; record this as an
evidence limit. This is not a public-restore claim.

## Build and Synthetic Steps

These steps are development validation and are not counted against the Wave limits.
They run sequentially with `DOTNET_CLI_TELEMETRY_OPTOUT=1` and `DOTNET_NOLOGO=1`.

| Step | Action | Bound |
| --- | --- | --- |
| B1 package | From `<root>\src`: `pwsh packaging\windows\package.ps1 -DisableNuGetAudit -OutputDirectory <root>\out`, without `-AllowNonPublicRelease` | 1,800 s |
| B2 validator | `dotnet build tools\result-validation\cli -c Release -o <root>\validator` | 300 s |
| B3 extract | Verify both `.sha256` files; record both hashes and the archive's file list; `Expand-Archive` the package zip into the new empty `<root>\app` | 60 s |
| B4 artifact checks | See below | 60 s |

B1 runs every packaging check, including the public-release check; a failure stops the
experiment. B1's `--version` check is the first run of the executable's bytes: record
whether Windows blocked or warned on it, including a block that makes B1 fail. After B1 and B2, stop the SDK build servers and list processes whose image is
under `<root>`; any survivor other than a stopped build server stops the experiment.

**B4 artifact checks.** From a new empty directory with `PATH` set to System32 only, run
`<root>\app\azureauth-unofficial.exe --version` (expect exit 0 and
`azureauth-unofficial <version>+<commit>` for the recorded commit) and `--help` (expect exit 0
and the unofficial first line). This is the first run from the extracted directory;
record whether Windows blocked or warned on it. Record the current Smart App Control mode
with `citool.exe -lp`, read-only, as Microsoft's
[Smart App Control test guide](https://learn.microsoft.com/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control#verify-smart-app-controls-current-mode)
describes: only the Smart App Control policy's friendly name and enforced flag. If
CiTool cannot run without elevation, record the registry value
`VerifiedAndReputablePolicyState` instead, labeled as the configured value rather than the
verified mode. The archive was built locally and never downloaded, so it has no Mark of
the Web; neither observation says anything about a downloaded archive.

## Environment and Account State

- **Host.** The owner-designated Windows 11 x64 host and its designated interactive user,
  with WSL 2 under that user as the second caller. Both callers run
  `<root>\app\azureauth-unofficial.exe`; account state, WAM and any UI belong to the Windows
  user session in every case.
- **Session.** The owner keeps an active, connected desktop session for every real call,
  and gives a fresh readiness answer immediately before each interactive-capable call,
  after all preparation for it is complete.
- **Roles.** `personal` (a personal Microsoft account) and `work` (an organizational
  account), both existing on the host with unknown prior broker state. Their emails exist
  only in `%LOCALAPPDATA%\azureauth-pkgtest\roles.json`.
- **Launchers.** Two local launchers in that directory, PowerShell 7 for native and bash
  for WSL, read `roles.json`, pass the values and the Windows-form Profile path, and
  print only the evidence allowlist. They are not committed, never echo arguments, and
  run with tracing disabled.
- **Effects.** Token acquisition for the two existing accounts; WAM sessions and caches
  receive ordinary updates and are retained. No account addition or removal, sign-out,
  consent change, cache clearing or resource request.

## Real Calls

Every call is `authenticate --protocol 1 --profile <profile> --account-email <role email>`
`--scope <ADO default> --tenant common --telemetry stderr` with the interaction below and the
default 120 s deadline. WSL calls also pass `--cancel-on-stdin-close` with a dedicated pipe
whose only writer the launcher holds until completion. Units follow the Wave: **I** is
interactive-capable, **N** is `non-interactive-only`. The external bound is 130 s; at the
bound the native launcher ends its own product process, and the WSL launcher closes the
lifetime writer. After every call the launcher confirms from Windows that no process with
image `<root>\app\azureauth-unofficial.exe` remains; calls never overlap.

| Case | Interaction and action | Expected (outcome/route, exit) | Unit |
| --- | --- | --- | --- |
| A | `non-interactive-only`, the first call for the role and caller | `Success/Silent`, 0 (silent success); or `InteractionRequired/None`, 1 (interaction required) | N |
| B | Only if A required interaction: `interactive-if-needed`; the owner completes any account choice, credential or MFA prompt | `Success`, Silent or Interactive, 0 | I |
| C | Fresh process: `non-interactive-only` | `Success/Silent`, 0 (fresh-process silent reuse) | N |
| D | `force-interactive`; the owner chooses the designated account | `Success/Interactive`, 0 | I |

**Order.** Personal native, personal WSL, work native, work WSL, each running A, B when
needed, C and D. A result of `Success/Silent` in A records the interaction-required case as
**not reached** for that role and caller; no state is changed to reach it. A consent or
permission prompt in any case is cancelled by the owner and recorded as an unexpected
outcome. The plan uses at most 8 N and 8 I of the Wave's 60 N and 40 I.

**Circuit breaker.** No automatic retry. A case may run again only after a recorded
diagnosis of its failure. Two consecutive unexpected outcomes of the same case stop that
case until an independent review of the sanitized evidence. Any unexpected effect, stop
condition or deviation stops all real calls, as the experiment policy requires.

## Validation and Evidence

The validator is `<root>\validator\ResultValidation.dll` from B2, started after the product
exits by the absolute path of the Windows SDK's `dotnet.exe` named under Toolchain, from both
callers; record its runtime version (10.0.14). Its arguments are the product exit code, the
receipt time in round-trip `O` format, the role email, `common`, `non-interactive-only` or
`interactive-if-needed` (for every interactive-capable case), the expected `Outcome` and
`Route` (`None` accepts any route) and the scope. For case A the launcher chooses the
expectation from the product exit code alone: exit 0 expects `Success Silent`, exit 1
expects `InteractionRequired None`. The launcher never parses stdout.

The caller holds product stdout only in bounded process memory (at most 1 MiB) and writes
it into the validator's stdin; it never reaches a file, terminal or log. A WSL success
returns the token to the trusted Linux caller as the owner risk decision accepts, and the
WSL launcher passes it to the Windows validator through interop in the same way. A call
passes only with validator exit 0, `Passed` and `ProtocolValid` true, a matching product
exit, and for a success also `MetadataValid` and `PersistenceUnconfirmed` true and
`PersistenceFailed` false, as the design's success contract requires.

**Evidence allowlist.** Only these are recorded: the validator projection and exit;
product exit; wall durations; from `--telemetry stderr` the `event`, `stage`, `status`,
`outcome`, `error.type` and `durationMilliseconds` values and any fixed
`Mechanism unavailable at <category>` indication; whether the pre-interaction notice line
appeared; and owner yes/no answers (WAM shown, account chosen, no unexpected window).
Trace IDs, token-shape fields, provider text, screenshots and crash dumps are excluded.
No crash dump is collected. A product crash is recorded by its exit code only and is a
stop condition. Any Windows Error Reporting report is operating-system state that the
experiment does not read, collect or delete.

**Ledger.** Before each counted call starts, append a row to
`%LOCALAPPDATA%\azureauth-pkgtest\ledger.md` with case, role class, caller, unit, start time
(UTC) and remaining I and N after charging the call; fill the outcome after the call. The
rows are copied unchanged into [Results](#results). If the ledger cannot be read or
reconciled, stop. Protocol amendments and corrected archives share these counts.

## Stop Conditions

Stop all real calls and preserve state when: a token, email or raw provider text would
enter captured output, a trace or a record; a prompt appears outside the case's
interaction or in another session; the owner cannot identify or close a prompt; a call
exceeds its external bound or its process cannot be confirmed ended; the subject commit,
archive hash, Profile or validator differs from the recorded values; R1 reports an audit
warning or error, or a restore or lock mismatch occurs; the product process crashes;
remaining capacity is unknown;
or any account, cache, installation or remote effect outside this protocol is observed.

## Retention and Cleanup

The package zip and the symbols zip, with their `.sha256` files, stay in `<root>\out` until
the results pull request merges, as the identity of the tested subject; they are never
uploaded or published. After that merge, stop the SDK build servers and delete `<root>`
(source, packages, HTTP cache, outputs, extraction directory and validator). Keep the
local launchers, `roles.json` and ledger until the Wave entry ends, then delete them.
WAM sessions and caches are retained; deleting local files reverses no provider-side
change.

## Corrected Archives

A defect fix follows Wave item 5. Before further real calls, a reviewed amendment to this
file names the new `main-v2` commit; the new subject repeats R1 and B1 to B4 in a new
`<root>` and continues the same ledger and limits. Earlier evidence stays attributed to its
own commit and archive hashes.

## Results

No execution has occurred. Record the bound commit, OS build, WSL version, toolchain
versions and sanitized initial state before R1; then R1 and B1 to B4 outcomes, hashes,
the first-run observations and the ledger. The results state every field the experiment
policy's Authentication Experiment Records section requires, including this protocol's
revision, and each deviation with its disposition:

| # | Case | Role | Caller | Unit | Start (UTC) | Outcome and exits | I left | N left |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

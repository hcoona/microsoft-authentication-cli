# Real-Host Validation Protocol

This protocol governs the real-host evidence items of the Delivery Wave entry
[Real-Host Validation and Threat-Model Re-Review (2026-10-15)](../../delivery-wave.md),
coordinated in
[Issue #482](https://github.com/hcoona/microsoft-authentication-cli/issues/482). It follows
the [experiment policy](../experiment-safety.md). Merging it into `main-v2` is the protocol
acceptance; it adds no product, support or release claim. The Wave entry owns
the owner risk decision, call limits and exclusions; this record only narrows them.
Results are appended under [Results](#results) through reviewed pull requests.

**Amendment (2026-10-16).** Per the
[repository-owner disposition](https://github.com/hcoona/microsoft-authentication-cli/pull/486#issuecomment-6206595584),
the experiment policy's telemetry rule governs only the upstream AzureAuth v1 binary,
which this procedure does not run. The former toolchain telemetry preflight and its stop
condition are removed, and the `vctip.exe` termination rationale is restated as process
hygiene. No execution had occurred.

**Amendment (2026-10-16, rebind).** The first subject, `c9ac862`, stopped at S1 before any
real call (see [Results](#results)). S1-2 failed from an operator error and S1-3 from an
outdated test assertion, corrected by
[PR #489](https://github.com/hcoona/microsoft-authentication-cli/pull/489); neither
indicates a product defect. No real call is made against `c9ac862`. Execution rebinds
under [Corrected Builds](#corrected-builds) to the commit defined in Source below, which
repeats B1 to B4, the artifact checks and S1 in a new `<root>` with the shared limits and
recorded consumption; S1-2 now fixes its argument form.

## Subject and Inputs

- **Source.** Execution binds this protocol's merge commit on `main-v2`, or a later
  `main-v2` commit whose copy of this file is unchanged; either contains `edc9ce0`, the
  merge of PR #489. Record the full commit hash in the ledger before the first build.
  Materialize it with
  `git archive <commit> | tar -x -C <root>/src` into a fresh
  `C:\Temp\azureauth-real-host-YYYYMMDD\src` (`<root>` below); no Git metadata, local
  edits or other checkout is used.
- **Dependencies.** MSAL and Broker 4.83.1, NativeInterop 0.20.3, and the other versions
  fixed by the committed `packages.lock.json` files. Restore uses `--locked-mode`; a
  lock mismatch stops the build. No dependency, SDK or runtime is added or installed.
- **Toolchain.** The installed `C:\Program Files\dotnet` SDK 10.0.402 (selected by
  `global.json`), whose only installed .NET 10 runtime is 10.0.13; the installed Visual
  Studio 18 MSVC 14.51.36231 and Windows SDK 10.0.26100.0 for Native AOT linking;
  `dumpbin.exe` from the same MSVC directory; installed PowerShell 7.6.7 as the native
  caller.
- **Profile.** A Windows-local file `%LOCALAPPDATA%\azureauth-real-host\profile.json`
  whose content is exactly the `visual-studio-legacy-wam` example in
  [`client-profile.schema.json`](../../../contracts/v1/client-profile.schema.json), copied
  from the bound commit. Requests use Public Cloud, `--tenant common` (or the work role's
  exact tenant GUID when `roles.json` supplies one) and the Azure DevOps default scope
  `499b84ac-1321-427f-aa17-267ca6975798/.default`. Source finding
  (`MsalAuthenticationProvider.cs`): for this Profile, `common` resolves to the
  `https://login.microsoftonline.com/organizations` authority with MSA passthrough, and a
  GUID resolves to that tenant's authority.

## Build and Synthetic Steps

All steps run sequentially in a Windows PowerShell 7 process of the designated user. Its
ordinary command environment sets
`DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_NOLOGO=1`, `TESTINGPLATFORM_TELEMETRY_OPTOUT=1`,
`POWERSHELL_TELEMETRY_OPTOUT=1`, `DOTNET_CLI_USE_MSBUILD_SERVER=0` and
`MSBUILDDISABLENODEREUSE=1`. `NUGET_PACKAGES` and `NUGET_HTTP_CACHE_PATH` point to new empty
directories under `<root>`. Every restore passes `--configfile <root>\src\nuget.config`,
which admits only nuget.org; no credential provider, feed credential or private package
is used. Builds pass `--disable-build-servers -nr:false -p:UseSharedCompilation=false`.
These steps are not counted against the Wave call limits.

**Step termination.** Each step runs as one foreground process tree. On overrun, stop
that tree, record the step as failed and stop the experiment. After B3 and S1, list
processes whose image path is under `<root>` or the pinned MSVC directory; a remaining
`vctip.exe` compiler helper from that directory is terminated and recorded so that no
unexpected process remains; any other survivor stops the experiment. No outer Job
object is used although the scenario fixture's comment assumes one; S1 records that.

| Step | Command (from `<root>\src`) | Bound |
| --- | --- | --- |
| B1 restore | `dotnet restore Windows.slnx --locked-mode --configfile nuget.config` | 600 s |
| B2 build | `dotnet build Windows.slnx -c Release --no-restore` | 900 s |
| B3 publish | `dotnet publish src\Authentication.Cli -c Release -r win-x64 --no-restore -o <root>\publish` | 1,200 s |
| B4 validator | `dotnet restore tools\result-validation\cli --configfile nuget.config`, then `dotnet build tools\result-validation\cli -c Release --no-restore -o <root>\validator` | 300 s |
| S1 scenarios | See below | 900 s |

**Runtime binding.** Source finding: framework-dependent outputs pin
`Microsoft.NETCore.App` 10.0.12 with `rollForward: Disable` (`src/Directory.Build.props`,
the validator project), and the Windows scenario fixture starts its `--scenario-child`
processes with an explicit `DOTNET_ROLL_FORWARD=Disable` environment
(`ProcessFixture.cs`), so a host roll-forward option would not reach those children.
When only 10.0.13 is installed, the single probe change is: replace the framework
version `10.0.12` with `10.0.13` in the built
`Authentication.Windows.Scenarios.runtimeconfig.json` only, recording its SHA-256 before
and after. The validator launches as `dotnet --fx-version 10.0.13 ResultValidation.dll`,
the binding accepted for the earlier Slice. The Native AOT product is self-contained and
keeps its locked 10.0.12 packages. No other output is edited. The validator project has
no package reference and therefore no lock file; B4 records that its restore resolved no
packages.

**Native artifact checks.** Record byte size and SHA-256 of every file in
`<root>\publish`, then copy it unchanged to `<root>\run`. Run `dumpbin /DEPENDENTS` on
`Authentication.Cli.exe` and `msalruntime.dll` and record the imported DLL names (public
Windows names only); if `dumpbin.exe` is absent, record that. From a new empty directory
with `PATH=C:\Windows\System32` only, run `Authentication.Cli.exe help` (expect exit 0 and
the unofficial first line) and `Authentication.Cli.exe authenticate --protocol 0`
(expect exit 1 and `invalid_request`). These two runs are conservatively charged as
N units. They do not load `msalruntime.dll`; application-directory/System32 loading of the
broker is established only by the real calls reaching a non-`dll_search` and
non-`broker_initialization` outcome.

**S1**, after the native artifact checks. Run the built scenario host once with
`dotnet <dll>` and no filter, covering all categories including `WindowsHostTiming`;
then once (S1-2) directly from the PowerShell 7 session, without a wrapper script or
`cmd.exe`, exactly as

```powershell
dotnet <dll> --native-cli-executable <root>\run\Authentication.Cli.exe --filter 'Name=RootHelpCompletesWithoutAuthentication|Name=MalformedAuthenticationReturnsTheBootstrapFailure'
```

so that the single-quoted filter, including its `|`, reaches the host as one argument;
S1-2 passes only if it runs exactly 2 tests. Then
`--native-profile-cases <root>\run\Authentication.Cli.exe` once. The fixture refuses
to reuse a `%TEMP%\process-<scenario>` directory and latches a `process-safety-stop.json`
there, so each of the three runs sets `TEMP` and `TMP` to its own new empty directory
`<root>\tmp\s1-1`, `s1-2` or `s1-3`; a nonempty directory stops S1. Record only the runner
exit codes and passed, failed and skipped counts. A failure is recorded and stops real
calls until reviewed; S1 is not repeated on the same subject.

## Environment and Account State

- **Host.** The owner-designated Windows 11 x64 host and its designated interactive user,
  WSL 2 Ubuntu Linux x64 under that user as the second caller. Both callers run the same
  `<root>\run\Authentication.Cli.exe`; account state, WAM and UI belong to the Windows
  user session in every case.
- **Session.** Product admission rejects a disconnected session (on this Remote Desktop
  host, the locked state). The owner keeps an active connected desktop session for every
  real call and gives a fresh readiness answer immediately before each interactive-capable
  call, after all preparation is complete.
- **Roles.** `personal` (a personal Microsoft account) and `work` (an organizational
  account), both existing on the host with unknown prior broker state. Their emails and an
  optional work tenant GUID exist only in `%LOCALAPPDATA%\azureauth-real-host\roles.json`.
- **Launchers.** Two small local launchers in that directory (PowerShell 7 for native,
  bash for WSL) read `roles.json`, pass the values and the Windows-form Profile path as
  product and validator arguments, and print only the evidence allowlist. They are not
  committed, never echo arguments, and run with tracing disabled. Emails, tenants,
  tokens, raw stderr and provider text never enter logs, records, agent traces or chat.
- **Effects.** Token acquisition for the two existing accounts; WAM sessions and caches
  receive ordinary updates and are retained. No account addition or removal, sign-out,
  consent change, cache clearing or resource request.

## Real Calls

Every call uses `authenticate --protocol 1 --profile <profile> --account-email <role email>`
`--scope <ADO default> --tenant <common or role GUID> --telemetry stderr` plus the options
below, default deadline 120 s unless stated. WSL calls also pass `--cancel-on-stdin-close`,
with stdin a dedicated pipe whose only writer the launcher holds until completion. Units:
**I** = interactive-capable, **N** = `non-interactive-only`. External bound = product
deadline + 10 s. At the bound the native launcher ends its own product process; the WSL
launcher closes the lifetime writer so the product's cancellation and deadline end it, and
does not rely on a Linux signal. After every call, and 10 s after any bound, the launcher
checks from Windows that no process with image path `<root>\run\Authentication.Cli.exe`
remains (calls never overlap, so any such process belongs to this attempt). A remaining
process stops the experiment with state preserved; an overrun is a transport failure.

| Case | Interaction and action | Expected (outcome/route, exit) | Unit | Bound |
| --- | --- | --- | --- | --- |
| P7 | Native only, first call per role: `non-interactive-only` | `InteractionRequired/None`, 1 | N | 130 s |
| P1 | `interactive-if-needed`; owner completes any account choice, credential or MFA prompt | `Success`, Silent or Interactive, 0 | I | 130 s |
| P2 | Fresh process after accepted P1: `non-interactive-only` | `Success/Silent`, 0 | N | 130 s |
| P3 | `force-interactive`; owner chooses the designated account | `Success/Interactive`, 0 | I | 130 s |
| P4 | `force-interactive`; owner cancels on the WAM surface | `Cancelled/None`, 1 | I | 130 s |
| P5 | WSL only, `force-interactive`; launcher closes the writer after the owner confirms WAM is shown | `Cancelled/None`, 1 | I | 130 s |
| P6 | `force-interactive --timeout-seconds 30`; owner confirms WAM and does not act | `Timeout/None`, 1 | I | 40 s |

**Order and plan.** P7 comes first because a P1 success would make it unreachable.
Personal native (P7, P1, P2, P3, P4, P6), personal WSL (P1, P2, P3, P4, P5, P6), then
work likewise: 18 I and 6 N, plus 2 N artifact runs, within the Wave's 24 I and 40 N. A P7 result of `Success/Silent` means existing state already permits
silent use: record P7 as **not reached** for that role. It is not repeated, and no state is
changed to reach it. A consent or permission prompt in any case is cancelled by the owner
and recorded as an unexpected outcome. After P5 and P6 the owner closes any WAM surface
left open. Calls never overlap.

**Repeats.** No automatic retry. A case may be repeated once, from the remaining capacity,
only when its first attempt failed for a recorded operator-side reason (for example,
`host_session_inactive` or WAM not confirmed in time) and the attempt row says so.
Any other unexpected outcome stops the remaining cases of that role and caller until an
independent review of the sanitized evidence.

## Validation and Evidence

The Windows validator is `<root>\validator\ResultValidation.dll`, built from
`tools/result-validation` at the bound commit. Its arguments, from `Program.cs`, are:
product exit code; receipt time in round-trip `O` format; expected email; `common` or
an exact tenant GUID; `non-interactive-only` or `interactive-if-needed` (used for every
UI-capable case, including `force-interactive`); expected `Outcome`; expected `Route`
(`None` accepts any route); the ADO default scope. It reads at most 1 MiB from stdin and
prints either a fixed projection (`Outcome`, `Route`, `Passed`, `ProtocolValid`,
`MetadataValid`, `PersistenceUnconfirmed`, `PersistenceFailed`) with exit 0, or
`{"ValidationFailed":true}` with exit 2.

Because the product exit code is a validator argument, the validator starts after the
product exits. The caller holds product stdout only in bounded process memory (at most
1 MiB) and writes it into the validator's stdin pipe; it is never written to a file,
terminal or log. The native launcher reads stdout bytes through
`System.Diagnostics.Process`, rejects more than 1 MiB and clears its buffer afterwards.
The WSL launcher captures stdout, product exit and trailing bytes with
`out=$(product | head -c 1048577; s=${PIPESTATUS[0]}; printf x; exit "$s"); status=$?`,
strips the `x`, treats more than 1 MiB as a validation failure, and pipes it through
interop to
`dotnet.exe --fx-version 10.0.13 <validator dll>`, as the owner risk decision permits.
A call passes only with validator exit 0, `Passed` and `ProtocolValid` true, matching
product exit, and for success also `MetadataValid` and `PersistenceUnconfirmed` true.

**Correlation (CORE-01).** Source finding: the coordinator rejects a candidate whose
provider-returned correlation ID differs from the ID it sent, as
`identity_validation_failed` (`RequestCoordinator.ValidateCandidate`,
`MsalBoundary.Project`). A validated success is therefore recorded as an **inference**
that the MSAL result returned the sent correlation ID and that this fail-closed check
did not reject a real broker success. The pinned MSAL source builds that value from its
own request context, so broker-level echo is not established. The ID is not recorded.

**Evidence allowlist.** Only these items are recorded: the validator projection and exit;
product exit; wall durations; from `--telemetry stderr`, the `event`, `stage`,
`status`, `outcome`, `error.type` and `durationMilliseconds` values and any fixed
`Mechanism unavailable at <category>` indication; whether the pre-interaction notice line
appeared; and owner yes/no answers (WAM shown, account chosen, cancelled, no unexpected
window). Trace IDs, token-shape fields, provider text and screenshots are excluded.

**Ledger.** Before each counted call starts, append a row to the local sanitized ledger
`%LOCALAPPDATA%\azureauth-real-host\ledger.md` with case, role class, caller, unit, start
time (UTC) and remaining I/N after charging this call; fill the outcome after the call.
The rows are copied unchanged into [Results](#results). If the ledger cannot be read or
its counts reconciled, stop. Protocol amendments and corrected builds share and never
reset these counts.

## Stop Conditions

Stop all real calls and preserve state when: a token, email, tenant or raw provider text
would enter captured output, a trace or a record; a prompt appears outside the case's
interaction or in another session; the owner cannot identify or close a prompt; a call
exceeds its external bound or its process cannot be confirmed ended; the subject hash,
Profile or validator differs from the recorded values; a lock or restore mismatch occurs;
remaining capacity is unknown; or any account, cache, installation or remote effect
outside this protocol is observed. Unexpected typed outcomes follow the repeat rule above.

## Retention and Cleanup

After the public artifact hashes, S1 counts and the ledger are recorded, delete
`<root>` (source, packages, build, publish, run and validator directories). Keep the local
launchers, `roles.json`, Profile and ledger until the Wave entry ends, then delete them.
Provider-managed WAM sessions and caches are retained; no sign-out or cache removal is
performed, and deleting local files reverses no provider-side change.

## Corrected Builds

If evidence exposes a product defect, the correction merges to `main-v2` with its tests
under the Wave entry. Before further real calls, a reviewed amendment to this file names
the new commit and any changed steps or cases; the new subject repeats B1 to B4, S1 and the
artifact checks in a new `<root>`, and continues the same ledger and limits.
Earlier evidence stays attributed to its own commit and artifact hashes.

## Results

**First subject `c9ac862` (closed; no real call).** B1: owner-exempted machine-local
restore workaround used (PR #487 closure comment); this is not a public-restore result,
and this protocol neither grants nor changes that exemption. Locked-mode verification
passed for 26 of 26 lock-file packages; 3 implicit runtime packages were not
lock-verified. B2, B3, B4 and the native artifact checks passed. S1-1: 183 of 183
passed. S1-2: exit 5, no tests run, because a local wrapper split the filter at `|` into
two arguments (operator error). S1-3: exit 1 from an outdated `NativeProfileScenarios`
assertion (test defect, corrected by PR #489). The two artifact runs were charged as N;
24 I and 38 N remain and carry over to the next subject.

For each subject, record the bound commit, OS build, WSL version and
sanitized initial state before B1; then B1 to S1 outcomes, hashes, imports and the ledger:

| # | Case | Role | Caller | Unit | Start (UTC) | Outcome and exits | I left | N left |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

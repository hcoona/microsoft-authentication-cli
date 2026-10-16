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
  `C:\Temp\azureauth-real-host-YYYYMMDD[-n]\src` (`<root>` below; add the lowest free
  `-n` if the name exists, and record the actual `<root>` in the ledger); no Git metadata,
  local edits or other checkout is used.
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

**First subject `c9ac86266b87d701052554fdb3b9c3031a47a059` (closed; no real call).** B1: owner-exempted machine-local
restore workaround used (PR #487 closure comment); this is not a public-restore result,
and this protocol neither grants nor changes that exemption. Locked-mode verification
passed for 26 of 26 lock-file packages; 3 implicit runtime packages were not
lock-verified. B2, B3, B4 and the native artifact checks passed. S1-1: 183 of 183
passed. S1-2: exit 5, no tests run, because a local wrapper split the filter at `|` into
two arguments (operator error). S1-3: exit 1 from an outdated `NativeProfileScenarios`
assertion (test defect, corrected by PR #489). The two artifact runs were charged as N;
24 I and 38 N remain and carry over to the next subject. These first-subject results
record only capacity consumption and stop causes; they are not evidence for any Wave
real-host item, and no artifact, hash or B1 outcome from this subject is relied on.
Before B1 of the next subject, the executor reconciles the first subject's two N rows in
the local ledger to 24 I and 38 N remaining (otherwise stop) and records whether the
first `<root>` was deleted or is retained and why; those rows are copied unchanged below,
ahead of the next subject's rows.

For each subject, record the bound commit, OS build, WSL version and
sanitized initial state before B1; then B1 to S1 outcomes, hashes, imports and the ledger:

**First-subject ledger reconciliation and root.** Before B1 of the second subject, rows 1
and 2 below reconciled to 0 I and 2 N used, leaving 24 I and 38 N. The first `<root>` was
deleted after its sanitized outcomes were recorded, because no first-subject artifact is
relied on and no process ran from it; the second subject then used a fresh directory of
the same base name, `C:\Temp\azureauth-real-host-20261016`, with no `-n` suffix.

**Second subject `8d9be2708c4bedaff059a37a2f69765c29a81766` (runtime observation).**

- **Environment.** Windows 11 Enterprise x64 build 26300 (10.0.26300.9711) in an active
  Remote Desktop session of the designated user; WSL 3.0.3.0, Ubuntu 26.04 under WSL 2 as
  the second caller. Both callers ran the same `<root>\run\Authentication.Cli.exe`;
  account state, WAM and UI belonged to the Windows session. MSAL and Broker 4.83.1,
  NativeInterop 0.20.3, SDK 10.0.402, runtime 10.0.13, MSVC 14.51.36231, Windows SDK
  10.0.26100.0, PowerShell 7.6.7.
- **Initial state.** Personal (Microsoft account) and work (organizational) roles both
  existed with unknown prior broker state. Requests used the `visual-studio-legacy-wam`
  example Profile (SHA-256 `b7b26fb3bcedeca62087dc3818e858dd9184ca37dbc9eb0abcbd310a839a2c75`),
  Public Cloud, `--tenant common` for both roles (no work tenant GUID was supplied) and
  the Azure DevOps default scope. Application files were separate; WAM sessions and
  caches received ordinary updates and are retained.
- **B1.** Owner-exempted machine-local restore workaround, as for the first subject; this
  is not a public-restore result. `--locked-mode` with new empty package and HTTP caches:
  exit 0. Lock closure verified for 26 of 26 lock-file packages by content hash; 3
  implicit packages not lock-verified: `Microsoft.NETCore.App.Host.win-x64`,
  `Microsoft.NETCore.App.Runtime.win-x64` and
  `Microsoft.NETCore.App.Runtime.NativeAOT.win-x64`, all 10.0.12.
- **B2 to B4.** Build exit 0 with 0 warnings. Publish exit 0; one `vctip.exe` from the
  pinned MSVC directory remained and was terminated; no other survivor. Validator
  restore exit 0 resolving 0 libraries (one NU1900 warning that vulnerability data was
  unreachable), build exit 0; `ResultValidation.dll` SHA-256
  `e7280e7ff4c99b0c6ce0ab8382b117021e99d8e86d027b70163f3c1d68cceed2`.
- **Published files** (bytes, SHA-256), copied unchanged to `<root>\run`:

  | File | Bytes | SHA-256 |
  | --- | --- | --- |
  | `Authentication.Cli.exe` | 8,928,256 | `E8558EAF5857E5910B0FA43C320C7F583755FA56C41B66F7306A26D0F5C6326A` |
  | `msalruntime.dll` | 2,949,656 | `9DF30B54B7AF974A072B1D55FEE3590A5562C77EBC46F47016F0DD5199CD0C79` |
  | `Authentication.Cli.pdb` | 37,097,472 | `CCFB041FF472B327DC50F201DE307DA2E7A8DF49A263F50B047A19918456DB8A` |
  | `Authentication.Core.pdb` | 24,528 | `2231502EC2C5896D82015E5902F04606C09EF54E2441EF3D5DC2246AE5B5400C` |
  | `Authentication.Windows.pdb` | 34,804 | `D8DDDE1E7A4EDEE16871648D07B0A74CDBB5B7966EFF887018BC4525A6D72894` |

- **Imports** (`dumpbin /DEPENDENTS`). `Authentication.Cli.exe`: ADVAPI32, bcrypt,
  CRYPT32, IPHLPAPI, KERNEL32, ncrypt, ole32, Secur32, USER32, WS2_32 and
  `api-ms-win-crt-*` (heap, math, string, convert, stdio, runtime, locale).
  `msalruntime.dll`: CRYPT32, WININET, RPCRT4, OLEAUT32, bcrypt, SspiCli, ncrypt,
  USER32, GDI32, SHELL32, ole32 and `api-ms-win-core-*`/`api-ms-win-security-*` API
  sets. No non-Windows DLL is imported.
- **Artifact checks** (rows 3 and 4, charged N). From a new empty directory with
  `PATH=C:\Windows\System32`: `help` exit 0 with the unofficial first line;
  `authenticate --protocol 0` exit 1 with `invalid_request`.
- **S1.** Scenario runtimeconfig probe change 10.0.12 to 10.0.13, SHA-256 before
  `352468623ef7a48f919a73cf597426aa3ab99e935ac50dcae9e2c7ab96589cbf`, after
  `78c2412dcaa1787e533b89d2d9a81743e53b90f65e95077451665232b907d263`; no outer Job
  object. S1-1 (all categories including `WindowsHostTiming`): exit 0, 183 passed, 0
  failed, 0 skipped. S1-2 (direct PowerShell 7, single-argument filter): exit 0, exactly
  2 passed, 0 failed, 0 skipped. S1-3 (`--native-profile-cases`): exit 0; the entry
  reports no per-test counts. No surviving process and no latched safety stop.
- **Native loading.** Every real call reached a typed provider outcome; none reported a
  `dll_search` or `broker_initialization` indication. This establishes that
  `msalruntime.dll` loaded from the application directory with its System32 imports on
  this host; it does not establish deployment on another host or without the
  development tools installed here.

**Real calls.** Each row was appended before its call started; outcomes were filled
afterwards. Launchers printed only the evidence allowlist. Readiness was a fresh owner
answer relayed by the coordinator immediately before each interactive-capable call (for
#13, #18 and #20 the answer was given before the immediately preceding `N` call, which
started and ended within seconds with no other preparation). "PASS" applies the protocol's
pass rule; P7 uses expected `InteractionRequired`, so its `Success/Silent` shows as
not passed and is dispositioned below.

| # | Case | Role | Caller | Unit | Start (UTC) | Outcome and exits | I left | N left |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | A1 artifact help | none | native | N | 2026-10-16T03:35:30Z | exit 0, unofficial first line, 0.85 s, no survivor | 24 | 39 |
| 2 | A2 artifact protocol 0 | none | native | N | 2026-10-16T03:35:38Z | exit 1, invalid_request on stdout, 0.05 s, no survivor | 24 | 38 |
| 3 | A1 artifact help | none | native | N | 2026-10-16T03:54:52Z | exit 0, unofficial first line, 0.82 s, no survivor | 24 | 37 |
| 4 | A2 artifact protocol 0 | none | native | N | 2026-10-16T03:54:59Z | exit 1, invalid_request on stdout, 0.05 s, no survivor | 24 | 36 |
| 5 | P7 | personal | native | N | 2026-10-16T04:04:54Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":false,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; NOT PASSED; 4.32 s; notice=False; overrun=False; survivors=0 | 24 | 35 |
| 6 | P1 | personal | native | I | 2026-10-16T04:11:44Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 1.29 s; notice=False; overrun=False; survivors=0 | 23 | 35 |
| 7 | P2 | personal | native | N | 2026-10-16T04:12:14Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 1.37 s; notice=False; overrun=False; survivors=0 | 23 | 34 |
| 8 | P3 | personal | native | I | 2026-10-16T04:13:09Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Interactive","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 34.64 s; notice=True; overrun=False; survivors=0 | 22 | 34 |
| 9 | P4 | personal | native | I | 2026-10-16T04:15:06Z | product exit 1; validator exit 0 {"Outcome":"Cancelled","Route":"None","Passed":true,"ProtocolValid":true,"MetadataValid":false,"PersistenceUnconfirmed":false,"PersistenceFailed":false}; PASS; 7.51 s; notice=True; overrun=False; survivors=0 | 21 | 34 |
| 10 | P6 | personal | native | I | 2026-10-16T04:16:05Z | product exit 1; validator exit 0 {"Outcome":"Timeout","Route":"None","Passed":true,"ProtocolValid":true,"MetadataValid":false,"PersistenceUnconfirmed":false,"PersistenceFailed":false}; PASS; 30.08 s; notice=True; overrun=False; survivors=0 | 20 | 34 |
| 11 | P1 | personal | wsl | I | 2026-10-16T04:17:46Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 0.53 s; notice=False; overrun=false; survivors=0 | 19 | 34 |
| 12 | P2 | personal | wsl | N | 2026-10-16T04:18:40Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 1.68 s; notice=False; overrun=false; survivors=0 | 19 | 33 |
| 13 | P3 | personal | wsl | I | 2026-10-16T04:18:46Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Interactive","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 80.65 s; notice=True; overrun=false; survivors=0 | 18 | 33 |
| 14 | P4 | personal | wsl | I | 2026-10-16T04:21:33Z | product exit 1; validator exit 0 {"Outcome":"Cancelled","Route":"None","Passed":true,"ProtocolValid":true,"MetadataValid":false,"PersistenceUnconfirmed":false,"PersistenceFailed":false}; PASS; 4.71 s; notice=True; overrun=false; survivors=0 | 17 | 33 |
| 15 | P5 | personal | wsl | I | 2026-10-16T04:22:53Z | product exit 1; validator exit 0 {"Outcome":"Cancelled","Route":"None","Passed":true,"ProtocolValid":true,"MetadataValid":false,"PersistenceUnconfirmed":false,"PersistenceFailed":false}; PASS; 10.9 s; notice=True; overrun=false; survivors=0 | 16 | 33 |
| 16 | P6 | personal | wsl | I | 2026-10-16T04:23:54Z | product exit 1; validator exit 0 {"Outcome":"Timeout","Route":"None","Passed":true,"ProtocolValid":true,"MetadataValid":false,"PersistenceUnconfirmed":false,"PersistenceFailed":false}; PASS; 30.15 s; notice=True; overrun=false; survivors=0 | 15 | 33 |
| 17 | P7 | work | native | N | 2026-10-16T04:27:25Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":false,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; NOT PASSED; 1.89 s; notice=False; overrun=False; survivors=0 | 15 | 32 |
| 18 | P1 | work | native | I | 2026-10-16T04:27:33Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 0.92 s; notice=False; overrun=False; survivors=0 | 14 | 32 |
| 19 | P2 | work | native | N | 2026-10-16T04:28:08Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 1 s; notice=False; overrun=False; survivors=0 | 14 | 31 |
| 20 | P3 | work | native | I | 2026-10-16T04:28:11Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Interactive","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 7.33 s; notice=True; overrun=False; survivors=0 | 13 | 31 |
| 21 | P4 | work | native | I | 2026-10-16T04:28:58Z | product exit 1; validator exit 0 {"Outcome":"Cancelled","Route":"None","Passed":true,"ProtocolValid":true,"MetadataValid":false,"PersistenceUnconfirmed":false,"PersistenceFailed":false}; PASS; 3.2 s; notice=True; overrun=False; survivors=0 | 12 | 31 |
| 22 | P1 | work | wsl | I | 2026-10-16T04:30:03Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 0.5 s; notice=False; overrun=false; survivors=0 | 11 | 31 |
| 23 | P2 | work | wsl | N | 2026-10-16T04:30:08Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Silent","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 0.44 s; notice=False; overrun=false; survivors=0 | 11 | 30 |
| 24 | P3 | work | wsl | I | 2026-10-16T04:31:19Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Interactive","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 5.48 s; notice=True; overrun=false; survivors=0 | 10 | 30 |

**Dispositions and operator observations** (owner yes/no answers relayed by the
coordinator):

- **P7 not reached** for both roles (#5, #17): existing state already permitted silent
  use; not repeated and no state changed to reach it.
- **Silent calls** (#6, #7, #11, #12, #18, #19, #22, #23): no window appeared where the
  owner was asked (#6, #11, #18, #22).
- **P3** (#8, #13, #20, #24): WAM shown, designated account chosen, no consent prompt,
  strict validation passed. See F1 for the personal role.
- **P4** (#9, #14, #21): WAM shown, owner cancelled on the WAM surface, no leftover window.
- **P5** (#15): after the owner confirmed WAM was shown, the launcher closed the sole
  lifetime writer at 04:23:03Z; the product ended `Cancelled/None` about one second later.
- **P6** (#10, #16): `Timeout/None` at about 30 s, within the 40 s bound.
- **Owner-skipped, no capacity charged.** Work-role P6 (native and WSL): no role-dependent
  behavior; timeout covered by personal native and WSL. Work-role WSL P4 and P5:
  cancellation precedes account selection; covered by personal WSL P4/P5 and work native
  P4.
- **Finding F1 (runtime observation; UX defect candidate).** With `force-interactive`
  and this MSA-passthrough Profile, the personal role needed two surfaces on both callers
  (#8 native, #13 WSL). The first, the native WAM account picker, listed both roles. After
  the personal role was picked, a second web-style account page listed only the work
  role, marked as connected to Windows, plus "Use another account"; the operator chose
  that and typed the personal account. The work role completed in one window (#20, #24).
  Final strict validation passed in every case. Cause not established. That it relates to
  the forced path passing neither account nor login hint (source finding:
  `MsalSessionFactory.BuildInteractiveRequest`) into the `organizations` MSA-passthrough
  flow is an **inference**.
- **Finding F2 (runtime observation).** A WAM window remained after the product ended in
  all three non-human terminations observed: product timeout (#10, #16) and lifetime-pipe
  cancellation (#15). The operator closed it. Human cancellation (#9, #14, #21) left no
  window. This matches the design, which forwards cancellation but neither waits for nor
  forces dismissal of external surfaces, and the earlier Slice's EOF observation.
- **Broker title (runtime observation).** The WAM account picker's subtitle showed the
  fixed broker title "Unofficial hcoona/microsoft-authentication-cli", so the configured
  broker title was presented on this host. The pre-interaction stderr notice line
  appeared in every `force-interactive` call and in no silent-route call.
- **CORE-01 (inference).** Each of the 14 validated successes (#5 to #8, #11 to #13,
  #17 to #20, #22 to #24) passed the coordinator's fail-closed correlation check, so the
  MSAL result returned the sent correlation ID and the check did not reject a real broker
  success. Broker-level echo is not established; no ID was recorded.
- **Telemetry.** `--telemetry stderr` projected only fixed stage events. Stage status was
  `unset` for inner stages; the request span was `ok` for success and `error` for
  cancellation and timeout. No `error.type` or mechanism indication appeared.
- **Not observed.** Fresh-state first use, consent denial, an explicit work tenant GUID,
  deadline expiry before WAM, concurrent calls and any other host. Existing-state results
  establish none of those.

**Consumption and cleanup.** 14 I and 10 N were used in total (including the 4 artifact
runs), leaving 10 I and 30 N. No call overlapped, overran its bound or left a product
process. No account, consent, cache or remote state changed beyond ordinary token
acquisition. `<root>` was deleted after recording. The local launchers, `roles.json`,
Profile, ledger and machine-local restore configuration are retained until the Wave entry
ends. WAM sessions, caches and the restore credential cache are retained; deleting local
files reverses no provider-side change.

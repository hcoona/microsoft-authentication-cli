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

**Amendment (2026-10-16, F1 confirmation).** Finding F1 was corrected by
[PR #492](https://github.com/hcoona/microsoft-authentication-cli/pull/492) (merge
`3477534`): the forced call now carries the requested email as login hint. Execution
rebinds under [Corrected Builds](#corrected-builds) to a third subject defined in Source
below and runs only the cases in [F1 Confirmation](#f1-confirmation-third-subject).

**Amendment (2026-10-16, F3).** The F1 confirmation stopped after call #27 under its
yes/no-only rule; the repository owner has dispositioned that stop (see [Results](#results)).
The third subject stays bound and is not rebuilt. This amendment adds Q4 and Q5, admits a
fixed credential-method vocabulary, resumes the two remaining confirmation calls and
defines a forced bound-account variant under [F3 Investigation](#f3-investigation). The
Wave limits are now 48 I and 64 N.

**Amendment (2026-10-16, variant).** The experiment-only variant subject defined under
[F3 Investigation](#f3-investigation) is the commit
`389f85a94f9a6da15c8bc4bc5f66abb88f09cc5c` on the dedicated branch
`experiment/forced-bound-account`, whose parent is the third subject. Its independent
review concluded "No material findings." This amendment records that hash and satisfies
the variant gate. Variant calls bind this amendment's merge commit under Protocol
revision. In #29 (work native P3) the owner answered Q1 no; the executor recorded a
forced-mode defect and stopped all real calls under F1 Confirmation, and its Results are
appended separately. The repository owner dispositioned that stop (chat, 2026-10-16,
quoted in the pull request adding this amendment): run the variant first, each of its
three cases once, to see whether it meets all of "interactive UI must appear", "no second
page" and "no defaulted security key", then decide the product change. The stop
therefore applies only to the third subject; the variant runs under
[F3 Investigation](#f3-investigation) as revised here.

## Subject and Inputs

- **Source.** The second subject (`8d9be27`) and the third subject (`0eb257a`) were each
  bound under the former rule: this protocol's merge commit on `main-v2`, or a later
  `main-v2` commit whose copy of this file is unchanged. The third subject,
  `0eb257ae71adc948202698b2914391185ba68d68`, contains `3477534`, the merge of PR #492;
  it stays bound in its retained `<root>` and is not rebuilt. The F3 variant subject is
  defined under [F3 Investigation](#f3-investigation) and is
  `389f85a94f9a6da15c8bc4bc5f66abb88f09cc5c`. Only a new subject is
  materialized, with
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
window; Q1 to Q5 of F1 Confirmation; whether UI appeared) and, after a Q5 yes, the
defaulted and chosen credential method, each exactly one of `security key`,
`Windows Hello`, `password`, `authenticator` or `other`. Trace IDs, token-shape fields, provider text and screenshots are excluded.

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

## F1 Confirmation (Third Subject)

- **Preparation.** Before B1, reconcile the local ledger to 10 I and 30 N remaining
  (otherwise stop). Then repeat B1 to B4, the native artifact checks (two N units) and S1
  in a new `<root>`; S1-1 covers the changed `MsalCompositionScenarios`. B1 uses the
  owner's standalone machine-local restore exemption
  ([PR #487 closure](https://github.com/hcoona/microsoft-authentication-cli/pull/487#issuecomment-6207448294),
  [PR #491 disposition](https://github.com/hcoona/microsoft-authentication-cli/pull/491#issuecomment-6208285632))
  instead of the nuget.org-only rule; the owner's
  [PR #494 disposition](https://github.com/hcoona/microsoft-authentication-cli/pull/494#issuecomment-6222226699)
  extends it to every subject built on this host, including this third subject. This
  protocol neither grants nor changes that
  exemption; no feed identifier is recorded, the result is not a public-restore result,
  and implicit runtime packages keep the not-lock-verified limitation.
- **Cases.** Only P3 (`force-interactive`), in order: personal native, personal WSL,
  work native; 3 I. No other case runs. With the artifact checks, at most 3 I and 2 N
  are used from the shared limits. The fresh readiness answer is given immediately before
  each call, with no other counted call in between.
- **Acceptance (owner decision).** A call is accepted only when the validator pass rule
  holds and the owner answers yes to both: WAM presented its interactive UI (a UI
  pre-filled from the hint is acceptable); the designated account completed sign-in on
  it. For the personal role the owner also answers whether the second provider surface
  of F1 appeared; expected no. A yes records F1 as not confirmed corrected for that role
  and caller; it alone does not make the call unaccepted. If WAM completed without
  presenting its interactive UI, record a defect of the forced mode, stop all real calls
  and do not accept the call. A call not accepted for another reason follows Repeats.
  The F1 conclusion covers only the observed role and caller combinations.
- **Questions.** After each interactive-capable call the executor asks: Q1, did WAM present its interactive
  UI (a pre-filled account counts as yes)? Q2, did the designated account complete
  sign-in on it? Q3 (personal role), did the second provider page of F1 appear? Q4, did a
  consent or permission prompt or any unexpected window appear? Q5 (every role), did
  the provider default to a credential method the operator did not want, so that the
  operator had to cancel that step and choose another? A Q4 yes follows the consent rule
  under Order and plan. A Q3 or Q5 yes is recorded as evidence only: it does not make a
  call unaccepted, is not an unexpected outcome, does not stop calls and is not a reason
  to repeat.
- **Yes/no only.** The executor asks only these yes/no questions and records only yes or
  no, except one fixed category: after a Q5 yes, the executor offers the closed options
  below, separately for the defaulted and the chosen credential method, and the operator
  picks one of each without describing them; each is recorded as exactly one of `security key`,
  `Windows Hello`, `password`, `authenticator` or `other`. Any other description is
  provider text. The stop condition for raw provider text applies without exception: if
  the owner or a relay describes or quotes provider UI text, the executor records none of it in
  the ledger, Results, launcher output or its own messages, stops all real calls and
  preserves state.

## F3 Investigation

- **Protocol revision.** #28 and #29 bind the merge commit of this F3 amendment on
  `main-v2`, or a later `main-v2` commit whose copy of this file is unchanged; the
  executor records its full hash in the ledger before #28 and in Results. Variant calls
  bind, in the same way, the merge commit of the amendment that records the variant hash;
  its full hash is recorded before the variant's B1.
- **Resumed confirmation.** On the third subject, without repeating B1 to S1: #28
  personal WSL P3, then #29 work native P3, each under F1 Confirmation with Q1 to Q5.
  Before #28 the executor checks the third subject's recorded values in the local ledger
  (`<root>`, byte size and SHA-256 of every file in `<root>\run`, and the Profile and
  validator SHA-256) against the files and records the check in the ledger; a missing value, a missing `<root>` or any mismatch stops real calls, and
  rebuilding then requires a new reviewed amendment. The third `<root>` is deleted under
  Retention and Cleanup only after #29 is recorded. The values are copied unchanged into
  Results in the pull request that records #28 and #29; that append does not change the
  protocol revision #28 and #29 bound.
- **Variant subject (experiment only).** A commit on the dedicated branch
  `experiment/forced-bound-account` whose parent is the third subject and whose only
  change is: when `force-interactive` finds exactly one discovered account matching the
  requested email, the adapter passes that account and `BuildInteractiveRequest` calls
  `WithAccount` and no `WithLoginHint`; with no matching account the adapter fails
  before calling WAM (after the coordinator has opened its hidden owned parent and
  printed the notice line), expected `InternalFailure/None`, exit 1, `error.type`
  `invalid_operation`; more than one matching account returns `AccountAmbiguous` before
  interaction through the unchanged coordinator (`RequestCoordinator.AcquireAsync`).
  Either is recorded as not reached, charged 1 I, not repeated and outside Repeats, but
  only when that exact outcome is observed and Q1 is no; otherwise it is a variant
  defect and stops variant calls. The variant review checks that the implementation
  yields these outcomes; the forced `MsalCompositionScenarios` are updated to match. It
  never merges into `main-v2` and is not a product correction. Source finding (pinned
  RuntimeBroker, cited in the Windows design): a bound account enters
  `AcquireTokenInteractivelyAsync` for that account instead of `SignInInteractivelyAsync`.
  Whether WAM then presents UI is the question under test.
- **Variant gate.** The variant is not a correction of the `main-v2` product; it is the
  experiment-only variant subject authorized by Wave outcome (3). It runs only after the
  variant commit is independently reviewed and a reviewed amendment to this file records
  its full hash. #28 and #29 do not wait for this gate.
- **Variant commit and review.** The variant commit is
  `389f85a94f9a6da15c8bc4bc5f66abb88f09cc5c` (parent
  `0eb257ae71adc948202698b2914391185ba68d68`), changing only
  `MsalAuthenticationProvider.cs` and `MsalSessionFactory.cs` in
  `src/Authentication.Windows` and the matching `MsalCompositionScenarios` and an
  `InteractionScenarios` comment. A reviewer who neither authored nor implemented it
  checked the parent, that the change is limited to the behavior under Variant subject
  (including the no-match and ambiguous-match outcomes) and that the non-forced path and
  coordinator are unchanged; conclusion: "No material findings." The Windows solution
  built with 0 warnings and the Linux scenarios passed; `Authentication.Windows.Scenarios`
  were only compiled on Linux and run first as S1 of the variant procedure.
- **Decision question** (Wave outcome (3)). Does the variant meet the owner's three
  criteria: interactive UI appears (Q1 yes; a no records that this path does not satisfy
  the forced-interaction requirement), no second provider page of F1 for the personal role
  (Q3 no), and no provider-defaulted credential method the operator must cancel (Q5 no;
  after a yes, the fixed vocabulary)? Q2 and Q4 are also asked. Variant answers are
  labeled as outcome (3) evidence only and are not mapped as `main-v2` validation.
- **Variant procedure.** In a new `<root>`, materialize the variant with `git archive`,
  then B1 to B4 (under the same restore exemption), the native artifact checks (2 N) and
  S1; S1 must pass before any variant call. Cases, all `force-interactive` with the P3
  validator expectations (`Success/Interactive`, 0): personal native, personal WSL, work
  native; 3 I. Observations: Q1 to Q5 for every variant call, Q3 recorded as not
  applicable for the work role. Unlike F1 Confirmation, a Q1 no in any variant case
  records only that the variant does not satisfy the requirement and does not stop the
  remaining variant cases, because that is the question under test. Every other stop
  condition (raw provider text, an unexpected account or prompt, token exposure and the
  rest of Stop Conditions and the yes/no-only rule) is unchanged; other unexpected
  outcomes follow Repeats.
- **Planned use and buffer.** Before #28, 33 I and 52 N remained under the Wave's 48 I and
  64 N; #28 and #29 used 2 I, leaving 31 I and 52 N. Planned for the variant: 3 I and the
  2 N artifact runs, each repeatable at most once under Repeats, so the worst case is 6 I
  and 4 N, leaving at least 25 I and 48 N. Before the variant's B1, reconcile the local
  ledger to 31 I and 52 N remaining (otherwise stop).
- **Scope.** F3 conclusions cover only the observed role, caller and subject. Variant
  evidence is recorded and labeled separately under its own subject, is not mapped as
  `main-v2` validation, and does not by itself authorize a product behavior change; any
  such change requires a separate owner decision.

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

**Third subject `0eb257ae71adc948202698b2914391185ba68d68` (runtime observation;
summary).** B1 to B4, the native artifact checks and S1 passed (S1-1 185 of 185). Calls
#25 and #26 were the artifact runs (2 N): `help` exit 0, its first-line check affected
by an operator defect and not repeated; `authenticate --protocol 0` exit 1 with
`invalid_request`. #27 personal native P3 (1 I): product exit 0, `Success/Interactive`,
validator pass, 35.2 s, no surviving process; owner answers Q1 yes, Q2 yes, Q3 no, Q4 no.
Q4 was not among this protocol's questions then; the executor added it from the earlier
operator-observation practice, and it is now part of the protocol. Used 15 I and 12 N in
total; 9 I and 28 N remained under the former limits. `<root>` is
`C:\Temp\azureauth-real-host-20261016` (the second subject's `<root>` of that name had
been deleted); after the stop it was retained unchanged with the launchers,
`roles.json`, Profile and ledger. The executor copies rows #25 to #27 and the recorded
hashes unchanged from the local ledger.

- **Stop and disposition.** After #27 the owner described the credential-method steps,
  and the executor stopped under the yes/no-only rule. The repository owner dispositioned
  that stop (chat, 2026-10-16, quoted in the pull request adding this amendment): the
  description contained no sensitive information, may be relayed to the executor, and
  needs investigation. It is an owner-authorized categorical description, not a leak of
  provider text; no provider UI wording is recorded.
- **Candidate finding F3 (operator observation).** For the personal role in
  `force-interactive` with the login hint, the credential method defaulted to a security
  key, Windows Hello was not offered, and the operator had to cancel that step and choose
  Windows Hello. The owner also states that before the F1 correction, without the hint,
  the call did not go directly to a security key; this is a later recollection, not a
  yes/no record made at the time. Cause not established.

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
  is not a public-restore result and departs from the protocol's nuget.org-only restore
  rule; the owner's [disposition](https://github.com/hcoona/microsoft-authentication-cli/pull/491#issuecomment-6208285632) states that
  the standalone exemption covers this second subject. `--locked-mode` with new empty package and HTTP caches:
  exit 0. Lock closure verified for 26 of 26 lock-file packages by content hash; 3
  implicit packages not lock-verified: `Microsoft.NETCore.App.Host.win-x64`,
  `Microsoft.NETCore.App.Runtime.win-x64` and
  `Microsoft.NETCore.App.Runtime.NativeAOT.win-x64`, all 10.0.12.
  Their provenance against nuget.org is unverified; they feed the self-contained
  Native AOT artifact, so the artifact hashes, imports and loading evidence below are
  bounded by that limit.
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
answer relayed by the coordinator immediately before each interactive-capable call, with
one **protocol deviation**: for #13, #18 and #20 the answer was given before the
immediately preceding `N` call (#12, #17, #19), and each I call started 3 to 8 seconds
after that call's start. No other preparation occurred in between and no unexpected
prompt was reported; no effect on the outcomes was observed. "PASS" applies the protocol's
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
- **Not executed by owner decision, no capacity charged.** Work-role P6 (native and WSL)
  and work-role WSL P4 and P5. The protocol's plan has no skip route; the owner decision
  and rationale are recorded in the [owner disposition](https://github.com/hcoona/microsoft-authentication-cli/pull/491#issuecomment-6208285632), which accepts the
  Wave's work-role EOF and deadline items as partially satisfied. That these cases add no
  role-dependent behavior beyond personal native and WSL P4, P5 and P6 and work native P4
  is an **inference**, not an observation; F1 shows the forced path can differ by role.
- **Finding F1 (runtime observation; UX defect candidate).** For `force-interactive` with
  this MSA-passthrough Profile, owner yes/no answers for the personal role (#8 native, #13
  WSL): WAM shown yes; a second provider surface shown yes; personal account offered for
  direct selection on it no; account chosen yes, after the operator entered it manually.
  Work role (#20, #24): second surface no. Strict validation passed in every case. Cause
  not established. A relation to the forced path passing neither account nor login hint
  (source finding: `MsalSessionFactory.BuildInteractiveRequest`) into the
  `organizations` MSA-passthrough flow is an **inference**.
- **Finding F2 (runtime observation).** A WAM window remained after the product ended in
  all three non-human terminations observed: product timeout (#10, #16) and lifetime-pipe
  cancellation (#15). The operator closed it. Human cancellation (#9, #14, #21) left no
  window. This matches the design, which forwards cancellation but neither waits for nor
  forces dismissal of external surfaces, and the earlier Slice's EOF observation.
- **Broker title (runtime observation).** Owner answer: configured broker title presented
  on the WAM account picker, yes. The pre-interaction stderr notice line appeared in every
  `force-interactive` call and in no silent-route call.
- **Evidence-handling deviation and missed stop condition.** Free-form operator
  descriptions of the provider surfaces behind F1 and the title, including provider UI
  wording, were relayed through the coordinator chat into agent traces between #8 (ended
  about 04:13:44Z) and #9 (04:15:06Z). The protocol's stop condition for raw provider
  text entering a trace or record therefore fired at that point and was not honored. It
  fired again when quoted provider strings from the owner's screenshots were written into
  the local ledger between #13 and #14 (04:21:33Z). Calls #9 to #24 were executed past
  that stop condition. The relayed text contained no token, email, tenant or other
  identifier; the screenshots were not shared with the executor; the quotes were removed
  from the local ledger and never committed. Only the yes/no projection above is
  recorded. The repository owner's
  [disposition](https://github.com/hcoona/microsoft-authentication-cli/pull/491#issuecomment-6208392178)
  accepts calls #9 to #24 as evidence; text already in chat and agent traces is retained
  there and must not enter the repository.
- **CORE-01 (inference).** Each of the 14 validated successes (#5 to #8, #11 to #13,
  #17 to #20, #22 to #24) passed the coordinator's fail-closed correlation check, so the
  MSAL result returned the sent correlation ID and the check did not reject a real broker
  success. Broker-level echo is not established; no ID was recorded.
- **Telemetry.** `--telemetry stderr` projected only fixed stage events. Stage status was
  `unset` for inner stages; the request span was `ok` for success and `error` for
  cancellation and timeout. No `error.type` or mechanism indication appeared.
- **Not observed.** Work-role WSL WAM cancellation, work-role WSL lifetime-pipe EOF, the
  work-role original deadline (native and WSL), fresh-state first use, consent denial,
  an explicit work tenant GUID, deadline expiry before WAM, concurrent calls and any
  other host. Existing-state results establish none of those.

**Consumption and cleanup.** 14 I and 10 N were used in total (including the 4 artifact
runs), leaving 10 I and 30 N. No call overlapped, overran its bound or left a product
process. No account, consent, cache or remote state changed beyond ordinary token
acquisition. `<root>` was deleted after recording. The local launchers, `roles.json`,
Profile and ledger are retained until the Wave entry ends. Outside the protocol's
retention list and under the restore exemption, the machine-local restore configuration
is retained until then and the restore credential cache is retained. WAM sessions and
caches are retained; deleting local
files reverses no provider-side change.

**Third subject `0eb257ae71adc948202698b2914391185ba68d68`: B1 to S1 and calls #25 to #29
(runtime observation).** This completes the summary above. #25 to #27 bound the F1
Confirmation revision `0eb257a` (protocol file SHA-256
`6d9651135e34cb0ed930993606e8237ab235e8e6b859cc0f69e437fe56be592a`); #28 and #29 bound
the F3 amendment merge `268ea4b0548f07a81ccd029e932af6f98afb6957`, recorded in the
ledger before #28. This append does not change either revision.

- **Environment.** As for the second subject: Windows 11 Enterprise x64 build 26300
  (10.0.26300.9711), WSL 3.0.3.0 with Ubuntu 26.04 under WSL 2, PowerShell 7.6.7, SDK
  10.0.402, only .NET 10 runtime 10.0.13, MSVC 14.51.36231, Windows SDK 10.0.26100.0,
  MSAL and Broker 4.83.1, NativeInterop 0.20.3. Same `visual-studio-legacy-wam` example
  Profile, Public Cloud, `--tenant common` for both roles and the Azure DevOps default
  scope. The designated session was disconnected at preflight; B1 to B4 and the artifact
  checks ran then, and S1 was deferred until the owner connected and the session was
  active (a conservative choice; the protocol does not require an active session for S1).
  The session was active before each of #27 to #29.
- **Initial state.** Both roles existed; their broker state carried the second subject's
  ordinary updates (both had reached silent use) and was not further characterized.
- **Source.** `<root>` `C:\Temp\azureauth-real-host-20261016`, a fresh directory (the
  second subject's `<root>` of that name had been deleted); `git archive` of the bound
  commit produced 170 files, equal to its tree, with `src\nuget.config` unchanged.
- **B1.** A first invocation failed in 0.6 s because the local step wrapper passed the
  argument list as one string; no restore ran and no package or `obj` directory was
  created. The rerun used the owner's machine-local restore exemption (cited under F1
  Confirmation) with `--locked-mode` and new empty package and HTTP caches: exit 0,
  14.8 s. Lock closure was verified for 26 of 26 lock-file packages by content hash; the
  same 3 implicit 10.0.12 runtime packages as for the second subject were not
  lock-verified and no other package was present. This is not a public-restore result,
  and the second subject's provenance limit on the Native AOT artifact applies unchanged.
- **B2 to B4.** Build exit 0, 0 warnings. Publish exit 0; one `vctip.exe` from the pinned
  MSVC directory remained and was terminated; no other survivor. B4 was first run with
  the machine-local restore configuration instead of `src\nuget.config` (operator
  deviation; 0 libraries resolved) and then repeated as specified: restore exit 0
  resolving 0 libraries with one NU1900 warning, build exit 0. `ResultValidation.dll`
  SHA-256 `e7280e7ff4c99b0c6ce0ab8382b117021e99d8e86d027b70163f3c1d68cceed2` after both
  passes, equal to the second subject's.
- **Published files** (bytes, SHA-256), copied unchanged to `<root>\run`:

  | File | Bytes | SHA-256 |
  | --- | --- | --- |
  | `Authentication.Cli.exe` | 8,928,256 | `09B575567A13C77AC59B19C464880CBA45F13740D048072A2B008BF4EED95729` |
  | `msalruntime.dll` | 2,949,656 | `9DF30B54B7AF974A072B1D55FEE3590A5562C77EBC46F47016F0DD5199CD0C79` |
  | `Authentication.Cli.pdb` | 37,097,472 | `132AF6A399FEAA3D80F0F577FA6269F93610A49698F92674191B10AC4379EAD6` |
  | `Authentication.Core.pdb` | 24,528 | `2231502EC2C5896D82015E5902F04606C09EF54E2441EF3D5DC2246AE5B5400C` |
  | `Authentication.Windows.pdb` | 34,848 | `1765AC9343F96AACA2ABD25E7A6F215F427B7C6E752FE41E18FE497F63031DDC` |

- **Imports** (`dumpbin /DEPENDENTS`). The same DLL name sets as the second subject for
  both files; no non-Windows DLL is imported.
- **Artifact checks** (#25, #26, charged N). `authenticate --protocol 0` exit 1 with
  `invalid_request`. `help` exit 0, but the local checker expected the first line to
  start with `Unofficial` while the product's first line, asserted by the bound commit's
  `ProcessScenarios`, starts with `AzureAuth Unofficial V2`; the output was not
  retained, so #25 establishes exit 0 only. This is an operator checker defect; #25 was
  not repeated, and S1-2's `RootHelpCompletesWithoutAuthentication` asserts those lines
  against the same executable. The checker wrote "FIRST LINE MISMATCH" into #25's outcome
  cell; the executor rewrote that cell to the wording below after the call.
- **S1.** Same runtimeconfig probe change and SHA-256 values as the second subject; no
  outer Job object; each run used its own new empty `TEMP`. S1-1 (all categories,
  including `WindowsHostTiming` and the changed `MsalCompositionScenarios`): exit 0,
  185 passed, 0 failed, 0 skipped. S1-2 (direct PowerShell 7 command, single-argument
  filter): exit 0, exactly 2 passed. S1-3: exit 0; no per-test counts. No surviving
  process and no latched safety stop.
- **Retained `<root>` check before #28.** `<root>` was present; `<root>\run` held exactly
  the five files above with matching bytes and SHA-256; the validator hash matched. The
  local ledger had recorded no Profile SHA-256 for the third subject, only that it was
  unchanged, so the executor stopped before #28 as the F3 amendment requires for a
  missing value. The repository owner's
  [ruling](https://github.com/hcoona/microsoft-authentication-cli/pull/497#issuecomment-6224331392)
  set the recorded value to the second subject's Profile SHA-256
  `b7b26fb3bcedeca62087dc3818e858dd9184ca37dbc9eb0abcbd310a839a2c75`; the retained
  Profile matched it, and calls resumed.
- **Ledger reconciliation under the new limits.** Before #28, rows #1 to #27 reconciled to
  15 I and 12 N used, leaving 33 I and 52 N under 48 I and 64 N. #25 to #27 show
  remaining counts under the former 24 I and 40 N; from #28 the counts use the new
  limits. The local launchers' reconciliation constants were updated accordingly; no row
  was edited for this change.

Rows #25 to #29, copied from the local ledger (#25's outcome cell as rewritten above).
Each row was appended before its call; a fresh owner readiness answer, relayed by the
coordinator, immediately preceded each of #27 to #29 with no other counted call in
between:

| # | Case | Role | Caller | Unit | Start (UTC) | Outcome and exits | I left | N left |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 25 | A1 artifact help | none | native | N | 2026-10-16T18:44:11Z | exit 0, first line not established (checker defect, see note), 1.35 s, no survivor | 10 | 29 |
| 26 | A2 artifact protocol 0 | none | native | N | 2026-10-16T18:44:16Z | exit 1, invalid_request on stdout, 0.05 s, no survivor | 10 | 28 |
| 27 | P3 | personal | native | I | 2026-10-16T19:28:25Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Interactive","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 35.21 s; notice=True; overrun=False; survivors=0 | 9 | 28 |
| 28 | P3 | personal | wsl | I | 2026-10-16T20:45:01Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Interactive","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 65.79 s; notice=True; overrun=false; survivors=0 | 32 | 52 |
| 29 | P3 | work | native | I | 2026-10-16T20:48:12Z | product exit 0; validator exit 0 {"Outcome":"Success","Route":"Interactive","Passed":true,"ProtocolValid":true,"MetadataValid":true,"PersistenceUnconfirmed":true,"PersistenceFailed":false}; PASS; 3.31 s; notice=True; overrun=False; survivors=0 | 31 | 52 |

**Dispositions and operator observations** (owner answers relayed by the coordinator):

- **#27 personal native P3: accepted.** Q1 yes, Q2 yes, Q3 no, Q4 no. Q5 was not yet
  asked; the F3 candidate finding above records the owner-authorized description for
  this call.
- **#28 personal WSL P3: accepted.** Q1 yes, Q2 yes, Q3 no, Q4 no, Q5 yes; defaulted
  credential method `security key`, chosen `Windows Hello`.
- **#29 work native P3: not accepted; defect of the forced mode.** Q1 no, Q4 no. The
  owner answered Q2 and Q5 as not applicable because no interactive surface was shown;
  they are recorded as not applicable, not as yes or no. Q3 is not applicable to the work
  role. The product returned `Success/Interactive` with a passing validator and an
  `interactive_acquisition` stage of 1,551 ms. Under F1 Confirmation, WAM completing
  without presenting its interactive UI is recorded as a defect of the forced mode; all
  real calls stopped, and #29 was not repeated. The variant of F3 Investigation was not
  started (no branch, build or call).
- **F1 (runtime observation).** The second provider page did not appear for the personal
  role on the corrected subject, native (#27) or WSL (#28). This covers only those two
  combinations on this host and existing state.
- **F3 candidate (operator observation).** With the login hint, the personal role's
  forced call defaulted to a security key and the operator reselected Windows Hello: by
  owner description after #27 (see above) and by the fixed-category Q5 answers for #28.
  Not observed for the work role, which showed no interactive surface. Cause not
  established.
- **Forced-mode defect (runtime observation and inference).** Observation: for the work
  role, native caller and existing state, the corrected forced call completed without
  WAM presenting interactive UI (#29). Source finding: at the bound commit,
  `MsalSessionFactory.BuildInteractiveRequest` passes only `WithLoginHint` for
  `force-interactive` (no `WithAccount`, no prompt option), and its comment notes that
  MSAL documents the hint as avoiding account-selection dialogs and that a skipped UI
  would be a defect pending real-host confirmation. That the hint caused the skip is an
  **inference**; the work-role WSL caller was not observed on this subject. Before the
  correction, the second subject's work-role P3 calls without a hint (#20, #24) presented
  WAM.
- **CORE-01 (inference).** #27 to #29 passed the coordinator's fail-closed correlation
  check, as for the second subject; no ID was recorded. #29 nonetheless is not accepted.
- **Telemetry.** Only fixed stage events; the pre-interaction notice line appeared in
  all three forced calls; no `error.type` or mechanism indication appeared.

**Consumption and retention.** The third subject used 3 I and 2 N; 17 I and 12 N were
used in total, leaving 31 I and 52 N under 48 I and 64 N. No call overlapped, overran its
bound or left a product process. No account, consent, cache or remote state changed
beyond ordinary token acquisition. Deviation from Retention and Cleanup: `<root>` was
not deleted after #29 was recorded. At the coordinator's direction it is retained
unchanged for a possible comparison with the variant, until the variant's results are
recorded or the Wave entry ends, whichever comes first; it is then deleted under
Retention and Cleanup and the deletion is recorded. It holds the materialized source;
the package and NuGet HTTP caches restored under the owner's machine-local restore
exemption (no feed identifier recorded); the build, publish, validator and run outputs;
the step logs and local step wrapper scripts; the synthetic S1 scenario output under
`tmp`; and empty per-call and artifact-check directories. No product process runs from
it. The local launchers, `roles.json`, Profile, ledger, the machine-local restore
configuration and WAM sessions and caches are retained as before; deleting local files
reverses no provider-side change.

# Windows MSAL Account and Token Metadata Protocol

## Question and Authority

Under [Issue #35](https://github.com/hcoona/microsoft-authentication-cli/issues/35), determine
whether the designated personal Microsoft account is visible through MSAL's explicit
Windows account-discovery option, whether a unique exact email match permits silent
acquisition for the Azure DevOps scope, and which authoritative result fields are
available after a permitted WAM interaction. A later silent invocation checks reuse of
existing broker state without an application cache file.

The accepted [Delivery Wave](../../delivery-wave.md) and
[experiment policy](../experiment-safety.md) govern execution. This file owns the bounded
procedure and its sanitized execution history. Git supplies its accepted revision; a PR
or an unmerged edit does not authorize a run. The
[V1 baseline](../v1-public-contract-baseline.md#architecture-reuse-and-remaining-deltas)
owns public-source findings. This protocol is neither a V2 implementation nor a selected
Client Profile, host architecture, or support promise.

No protected-resource request is made. Acquiring a token does not establish Azure DevOps
resource authorization, intended third-party registration reuse, or all of RECHECK-007.
There is no corporate-account comparison, resource write, PAT, registration/tenant
administration, cache migration, plaintext cache, or fallback mechanism in this probe.

## Subject and Environment

Use only the five source/configuration files in
[`tools/probes/windows-msal`](../../../tools/probes/windows-msal/Program.cs) from the exact
accepted protocol revision. The project builds a Windows Forms research executable with
one operator-started operation per process. The launcher is a narrow sequential helper
for this protocol, not a generic experiment runner or an authorization checker.

| Input | Bound value |
| --- | --- |
| Windows host | Current owner-designated Windows 11 25H2 x64 host, build 26200.9168, interactive desktop session |
| Initiating environment | Current WSL 2 Ubuntu 26.04 x64 environment, kernel `6.18.33.1-microsoft-standard-WSL2`; source transfer and process launch only |
| Toolchain | Existing Windows .NET SDK 8.0.425; Windows Desktop runtime 8.0.31; PowerShell 5.1 |
| Target | `net8.0-windows`, x64, Release; no installation or PATH change |
| MSAL and broker package | `Microsoft.Identity.Client` and `.Broker` 4.83.1 |
| Native interop | `Microsoft.Identity.Client.NativeInterop` 0.20.3, matching the V1 0.9.6 direct pin |
| Managed package pins | `Microsoft.IdentityModel.Abstractions` 8.14.0; `System.Diagnostics.DiagnosticSource` 6.0.1; `System.Runtime.CompilerServices.Unsafe` 6.0.0; `System.ValueTuple` 4.5.0 |
| Client | Microsoft-owned Visual Studio client `872cd9fa-d31f-45e0-9eab-6e460a02d1f1`, an experiment input only |
| Authority and scope | `https://login.microsoftonline.com/common`; `499b84ac-1321-427f-aa17-267ca6975798/.default` |
| Broker options | Windows WAM; `ListOperatingSystemAccounts = true`; no MSA passthrough option; real owned parent window |
| Selected account | One owner-authorized personal Microsoft account; exact email entered locally by the operator, never in command arguments or records |
| Application state | New in-memory MSAL cache for every invocation; no MSAL Extensions or application cache file |
| Existing OS state | Authorized current broker/session state; prior use and visibility are recorded as known or unknown, never assumed clean |

The host/toolchain versions above came from read-only host metadata during planning on
2026-09-10 UTC, not an authentication observation. Before execution, confirm they still
match, the operator is present, and the selected account is available to the operator.
An unknown existing-state history is permitted but limits conclusions. Another machine,
account role, version set, or effects boundary requires a reviewed protocol amendment;
previous consumption remains charged.

The public package pages document the declared dependencies for these versions:
[MSAL](https://www.nuget.org/packages/Microsoft.Identity.Client/4.83.1),
[broker](https://www.nuget.org/packages/Microsoft.Identity.Client.Broker/4.83.1), and
[native interop](https://www.nuget.org/packages/Microsoft.Identity.Client.NativeInterop/0.20.3).
Preparation must record the resolved package inventory and lock-file hash. An unexpected
package/version or an unavailable pin stops preparation; do not silently upgrade it.

## Locations and Effects

Use `%LOCALAPPDATA%\AzureAuthResearch\windows-msal` on the designated Windows host. Keep
`source-<accepted-commit>` for the exact five-file source copy, `packages`, `http-cache`,
`cli-home`, `attempts.jsonl`, `active.lock`, and numbered `attempt-<n>` directories below
that root. Build output stays under the source copy. Do not reuse an unrelated existing
root or overwrite a result file. This is ordinary owner-controlled local storage, not a
same-user adversary sandbox.

Before creating a source copy, establish that this root has either no prior history or
the recoverable history recorded below. Obtain the files with `git archive` from the
accepted commit and compare each copied file's SHA-256 with that Git version. Copying
public source is not an authentication attempt. Source changes require another accepted
revision; do not patch the live copy to make a failed build or acquisition pass.

Preparation downloads only the exact public NuGet packages through `api.nuget.org` and
its normal package CDN endpoints, using the supplied cleared source configuration.
Use dedicated package/CLI caches; do not access a private feed or copy existing package
credentials. The launcher disables .NET CLI telemetry, development-certificate creation,
global-tool PATH registration, workload notifications, and build-server reuse. Record
any preparation failure without treating this small probe build as a new V1 public-build
experiment or replaying Issue #1.

The probe uses documented MSAL/WAM APIs. In-memory enumeration may see other accounts;
only a unique exact email match is passed to silent acquisition. No OS-default sentinel,
alias inference, hidden account binding, or account removal is used. For an interactive
attempt, the operator must choose the designated account and control sign-in and consent.
Unexpected account use or UI is a stop condition, even if a provider has already updated
a session. A login hint is not a guarantee of account identity; the result is checked.

Authentication may reach the declared Microsoft identity authority and Microsoft's
normal WAM authentication endpoints, including personal-account sign-in surfaces.
Ordinary selected-account broker/session updates are permitted. No Azure DevOps API or
other protected-resource call is made. MSAL logging is discarded with PII and default
platform logging disabled; the probe has no telemetry exporter. Existing OS/broker
telemetry and session lifecycle remain platform-owned.

All authentication happens on Windows. WSL receives only source/build metadata, process
completion, the sanitized journal, and outcome flags. Do not inspect the email control,
screenshot authentication UI, capture tokens/codes, export broker diagnostics, or transport
a token back to WSL. Browser fallback is declined by the custom-web-UI callback; no
browser launcher, callback listener, or device-code flow is provided.

## Finite Attempts and Procedure

All actions are sequential under the launcher's local exclusive lock. The limits below
are cumulative across revisions, retries, failed starts, and manual operation. No script
or operator may reset them by deleting state or using another directory or machine.
The accepted protocol history and local journal must agree before another attempt.

| Action | Maximum attempts | Per-attempt bound | Expected observation |
| --- | --- | --- | --- |
| `prepare` | 2 | Restore 120 seconds, build 120 seconds, synthetic self-check 15 seconds; up to 10 seconds to stop each owned process | Public restore/build succeeds and selector/output self-check passes, with no authentication or account-store access |
| `inspect` | 1 | Process 120 seconds; launcher 135 seconds plus at most 10 seconds for termination | WAM available or unavailable; zero/one/multiple visible accounts and exact matches; missing-email flag; no acquisition |
| `silent` | 2 | Same bound as inspect | First attempt before interaction; second only after an email-matched interactive result; each resolves a real account afresh |
| `interactive` | 1 | Process 360 seconds; launcher 375 seconds plus at most 10 seconds for termination | Operator-controlled WAM interaction and provider metadata, or a bounded failure |

Maximum acquisition calls are three: two silent and one interactive. Each broker action
has at most one enumeration and one acquisition call. Preparation has no broker call.
The process bounds include time spent waiting for local email entry. No automatic retry
or automatic silent-to-interactive transition is permitted.

1. Verify the accepted Wave, protocol commit, exact source copy, environment, prior
   consumption, and source/dependency findings. Reconcile any failed launcher start that
   occurred before it could write its journal, adding its consumed action and outcome
   before continuing. Unknown capacity stops execution.
2. Run `prepare` using the command below. Review only sanitized build results, the exact
   package inventory/lock hash, and `self-check-passed`. All seven package pins and the
   expected target/runtime must match before a broker action. A second preparation
   attempt is allowed only for an understood transient failure, with unchanged source.
3. When the operator confirms availability of the designated account and is ready at the
   Windows desktop, run `inspect`. Enter the email locally. This can report absence; it
   does not prove that an account is absent from every OS or service store.
4. Run the first `silent` attempt with the same account. A missing or ambiguous account
   produces a bounded outcome without acquisition. If a strictly matched result is
   returned, stop this initial sequence; do not sign in again solely to consume a slot.
5. Only after an ordinary account-not-visible or interaction-required outcome, and with
   the operator ready to choose the selected account, run `interactive`. Do not proceed
   on ambiguity, unexpected UI, unavailable broker, uncertain termination, or unknown
   failure. These require interpretation or protocol amendment, not broader fallback.
6. If interaction returns a result with the exact requested email, run the second
   `silent` attempt in a fresh process. Otherwise stop and retain the limitation.
7. Record every attempt and its sanitized outcome below through independent evidence
   review. Include failed starts, termination/retention, existing-state limitations, and
   remaining limits. A normal research exit is not a V2 success-contract result.

From a Windows PowerShell 5.1 session, in the verified source-copy directory:

```powershell
.\Invoke-Probe.ps1 -Action prepare -AcceptedRevision <accepted-40-character-commit>
```

Replace `prepare` with one authorized `inspect`, `silent`, or `interactive` action only
when its prerequisites above are satisfied. The source-copy directory must be
`%LOCALAPPDATA%\AzureAuthResearch\windows-msal\source-<accepted-commit>`. Do not include an
email in the command. An agent may launch this Windows script from WSL after performing
the same checks; user sign-in and consent remain local operator actions.

## Outcomes, Stops, and Retention

`result.json` contains a fixed observation object defined in `Program.cs`: mode/status,
broker availability, bucketed visible/matching counts, missing-email indication,
acquisition/result presence, token-presence flag, exact-returned-email flag, tenant
presence and equality to the public MSA tenant constant, scope-metadata presence,
requested-`.default` membership, and expiry validity. Unobserved booleans are false;
interpret them only with status and acquisition/result-presence fields. It contains no
account identifier, token bytes, provider exception text, or raw scopes. `.default`
membership and a nonempty scope list are observations, not proof of resource acceptance.

The JSON and journal are local operational evidence with fields fixed by the source;
the reviewed Markdown history below is the committed evidence carrier. Build logs can
contain local paths: inspect them only during preparation, sanitize any retained finding,
and do not commit raw logs, assets files, caches, or binaries. No authentication stdout,
stderr, screenshots, or UI dumps are evidence carriers.

On closing the probe window, timeout, cancellation, or failure, stop the current attempt.
The probe requests cancellation and exits; the launcher bounds the owned process's
lifetime. Confirm process exit and let the operator close any remaining WAM prompt.
Do not kill a shared OS broker or claim reversal of a completed provider session. An
unexpected prompt, wrong account, sensitive output, unavailable dependency, unconfirmed
termination, changed subject, or uncertain capacity stops further attempts. An unresolved
started journal entry must be reconciled before another run.

Retain the dedicated source/build/package and sanitized result artifacts for review;
do not automatically delete them. Preserve ordinary authorized OS authentication state.
Cleanup, if later needed, is limited to verified experiment-owned files after owned
processes have exited. Do not clear broker state, revoke consent, sign out, or modify an
upstream installation as cleanup.

## Execution History

No subject execution has occurred in this initial protocol proposal. Consumed capacity:
prepare 0/2; inspect 0/1; silent 0/2; interactive 0/1. The next attempt number is 1.
A later execution record replaces this initial statement with the actual accepted
revision, environment/dependency identities, ordered attempts, observations, termination,
retention, limitations, and remaining capacity; it does not reset the limits.

# Windows MSAL Account, Token, and Git Discovery Protocol

## Question and Authority

Under [Issue #35](https://github.com/hcoona/microsoft-authentication-cli/issues/35), determine
whether the designated personal Microsoft account is visible through MSAL's explicit
Windows account-discovery option, whether a unique exact email match permits silent
acquisition for the Azure DevOps scope, and which authoritative result fields are
available after a permitted WAM interaction. A later silent invocation checks reuse of
existing broker state without an application cache file. For the owner-designated Git
scenario, also test whether the resulting token is accepted by that single Azure DevOps
repository's read-only discovery endpoint on the corporate-account Windows host.

The accepted [Delivery Wave](../../delivery-wave.md) and
[experiment policy](../experiment-safety.md) govern execution. This file owns the bounded
procedure and its sanitized execution history. Git supplies its accepted revision; a PR
or an unmerged edit does not authorize a run. The
[V1 baseline](../v1-public-contract-baseline.md#architecture-reuse-and-remaining-deltas)
owns public-source findings. This protocol is neither a V2 implementation nor a selected
Client Profile, host architecture, or support promise.

Only the designated repository's initial Git discovery GET is permitted. Acquiring a
token alone does not establish resource acceptance; recognizing a discovery response
still does not establish a complete Git operation, intended third-party registration
reuse, or all of RECHECK-007.
There is no corporate-account comparison, resource write, PAT, registration/tenant
administration, cache migration, plaintext cache, or fallback mechanism in this probe.

## Subject and Environment

The subject uses the six source/configuration files in
[`tools/probes/windows-msal`](../../../tools/probes/windows-msal/Program.cs). Prepare the
Git-discovery amendment once from its accepted `main-v2` commit and record that exact
source revision, source hashes, dependency inventory, and new artifact identities before
any broker action. The metadata-only artifact at
`3658a64b7ecba7feeb698821bd0aede6ce18f8a6` remains historical evidence; do not use it for
the new resource scenario. Subsequent actions use the verified amended source/artifacts.
Read the current accepted Wave and protocol before every action; a retained source
revision does not preserve authority that later records remove. Record the current
protocol revision separately when it differs from the launcher's source `Revision`.
The project builds a Windows Forms research executable with
one operator-started operation per process. The launcher is a narrow sequential helper
for this protocol, not a generic experiment runner or an authorization checker. The
Python helper fetches the seven pinned public packages from WSL before Windows restores
them from a local feed. It performs no authentication or account-store access.

| Input | Bound value |
| --- | --- |
| Windows host | Current owner-designated Windows 11 25H2 x64 host, build 26200.9445, interactive desktop session |
| Initiating environment | Current WSL 2 Ubuntu 26.04 x64 environment, kernel `6.18.33.1-microsoft-standard-WSL2`, existing Python 3.13.15; public package retrieval, source transfer, and process launch |
| Toolchain | Existing Windows .NET SDK 8.0.425; Windows Desktop runtime 8.0.31; PowerShell 5.1 |
| Target | `net8.0-windows`, x64, Release; no installation or PATH change |
| MSAL and broker package | `Microsoft.Identity.Client` and `.Broker` 4.83.1 |
| Native interop | `Microsoft.Identity.Client.NativeInterop` 0.20.3, matching the V1 0.9.6 direct pin |
| Managed package pins | `Microsoft.IdentityModel.Abstractions` 8.14.0; `System.Diagnostics.DiagnosticSource` 6.0.1; `System.Runtime.CompilerServices.Unsafe` 6.0.0; `System.ValueTuple` 4.5.0 |
| Client | Microsoft-owned Visual Studio client `872cd9fa-d31f-45e0-9eab-6e460a02d1f1`, an experiment input only |
| Authority and scope | `https://login.microsoftonline.com/common`; `499b84ac-1321-427f-aa17-267ca6975798/.default` |
| Broker options | Windows WAM; `ListOperatingSystemAccounts = true`; no MSA passthrough option; real owned parent window |
| Selected account | One owner-designated personal Microsoft account; privately supplied exact email in the owned local form, never in command arguments or records |
| Resource | The one owner-designated checkout's existing `https://dev.azure.com` Git remote; exact URL remains private |
| Windows account context | Corporate/domain-account session as reported by the owner; exact join/compliance state is not measured; no corporate-account acquisition |
| Application state | New in-memory MSAL cache for every invocation; no MSAL Extensions or application cache file |
| Existing OS state | Authorized current broker/session state; prior use and visibility are recorded as known or unknown, never assumed clean |

The host/toolchain versions above came from read-only host metadata during planning on
2026-09-10 UTC, not an authentication observation. Before execution, confirm they still
match. Fetch and preparation have no authentication or account-store access and may
proceed without operator/account readiness when their other prerequisites are met. Before each `inspect`,
`silent`, or `interactive` action, additionally confirm that the operator is present and
the selected account is available to the operator. Readiness may cover a continuous
operator-attended sequence; renew it after an interruption. An unknown existing-state history is
permitted but limits conclusions. Another machine, account role, version set, or effects
boundary requires a reviewed protocol amendment; previous consumption remains charged.

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
that root. The one fetch uses `fetch-1` for its start/result records and `public-feed` for
the downloaded packages, accessed through the existing WSL mount of this Windows path.
Build output stays under the source copy. Do not reuse an unrelated existing root or
overwrite a result file. This is ordinary owner-controlled local storage, not a same-user
adversary sandbox.

Before creating a source copy, establish that this root has either no prior history or
the recoverable history recorded below. Establish a detached checkout of the accepted
commit in the initiating WSL environment. The fetch helper remains bound to its recorded
accepted source; its one attempt is consumed. From the new checkout, obtain the five
Windows files with `git archive HEAD` and compare
each copied file's SHA-256 with that Git version. A full repository checkout on Windows
is unnecessary. Copying public source is not an authentication attempt. Source changes
require another accepted revision; do not patch the live copy to make a failed build or
acquisition pass.

Fetch downloads only the seven exact public NuGet package archives from the HTTPS
`api.nuget.org/v3-flatcontainer` paths for the project pins; normal NuGet CDN delivery is
permitted. Python uses its default verified TLS context. Do not disable certificate
verification, alter Windows TLS/proxy settings, add a mirror, or supply credentials.
Record each archive's public package name/version, byte length, and SHA-512; these hashes
identify the transferred bytes and do not constitute a separate publisher attestation.
After a successful fetch, compare the seven files against that local manifest before
Windows preparation. Preserve incomplete artifacts on failure and stop; fetch has no
retry. No downloaded package is executed in WSL.

Windows restore uses only `..\public-feed` through the supplied cleared source
configuration. Use the dedicated package/CLI caches; do not access a private feed or
copy existing package credentials. The launcher disables .NET CLI telemetry,
development-certificate creation, global-tool PATH registration, workload notifications,
and build-server reuse. This transfer prepares a research subject; it does not select a
V2 package-delivery or authentication architecture. Record any preparation failure without
treating this small probe build as a new V1 public-build experiment or replaying Issue #1.

The probe uses documented MSAL/WAM APIs. In-memory enumeration may see other accounts;
only a unique exact email match is passed to silent acquisition. No OS-default sentinel,
alias inference, hidden account binding, or account removal is used. For an interactive
attempt, the operator must choose the designated account and control sign-in and consent.
Unexpected account use or UI is a stop condition, even if a provider has already updated
a session. A login hint is not a guarantee of account identity; the result is checked.

Authentication may reach the declared Microsoft identity authority and Microsoft's
normal WAM authentication endpoints, including personal-account sign-in surfaces.
Ordinary selected-account broker/session updates are permitted. Resource access is limited
to the discovery procedure below, with normal service-side access auditing. No Azure
DevOps administration API is called. MSAL logging is discarded with PII and default
platform logging disabled; the probe has no telemetry exporter. Existing OS/broker
telemetry and session lifecycle remain platform-owned.

All authentication and resource requests happen on Windows. WSL handles the declared
public source/packages, build metadata, process completion, sanitized journal, and outcome
flags. The designated checkout's remote and matching credential-routing configuration
may be read only to bind the single resource and requested account. Do not read project
contents or stored credentials, or invoke Git/GCM/AzureAuth credential helpers.

The operator may fill the two owned form controls, or the agent may prefill the
privately supplied email and designated remote using write-only UI Automation. Limit
automation to the verified owned probe process/window and controls `RequestedEmail`,
`DesignatedRemote`, and `StartProbe`; do not read their values or other account UI. The
agent may start the already requested attempt after these checks. Private input transport
from WSL to the local automation process may use an anonymous stdin pipe in memory, never
command arguments, source files, logs, or a clipboard. Input-control automation is not
authorization to operate WAM sign-in, account choice, MFA, unlock, or consent: those remain
operator actions. Do not screenshot authentication UI, capture tokens/codes, export broker
diagnostics, or transport a token back to WSL. Browser fallback is declined by the custom-web-UI callback; no
browser launcher, callback listener, or device-code flow is provided.

Permit at most one input-automation operation per broker action, without retry. Its
20-second wall-clock limit includes private input transport, owned-window discovery,
prefill, and start. A local controller must supervise that owned automation process;
on timeout, failure, or cancellation, terminate only that process and confirm its exit
within five more seconds. Confirm its normal exit before proceeding as well. Bound the
controller itself to 30 seconds. An automation failure also ends the probe attempt using
the existing cancellation/termination procedure; do not retry input manually to bypass
the limit. If start completion or process termination is uncertain, preserve the action's
consumption and stop. Standard process supervision suffices; do not inspect or terminate
unrelated applications or shared brokers.

## Designated Git Discovery

**Public-source basis, retrieved 2026-09-10 UTC:** Microsoft's
[Azure Repos authentication guidance](https://learn.microsoft.com/en-us/azure/devops/repos/git/auth-overview?view=azure-devops)
shows an Azure DevOps resource token in Git's Bearer Authorization header. This supports
the request form, not this account/client combination's eligibility. Git's
[v2.51.0 HTTP protocol, Smart Clients and Smart Server Response](https://github.com/git/git/blob/v2.51.0/Documentation/gitprotocol-http.adoc)
defines `GET <remote>/info/refs?service=git-upload-pack`, the advertisement content type,
and initial service announcement. No Git client or credential-helper invocation is needed
to observe this protocol boundary.

Bind both local inputs to the owner's nominated account and existing remote before each
action. The probe accepts only HTTPS `dev.azure.com` URLs with the Git repository path,
no userinfo, nondefault port, query, or fragment. It appends only the discovery suffix.
The URL validator does not identify the owner's repository; that is the operator/agent's
local binding check. Never substitute another target to rescue a failed request.

`inspect` makes one anonymous discovery GET after account enumeration, without credentials
or cookies. Each permitted token-acquisition action makes at most one Bearer discovery
GET, only after an exact returned-email match and a nonempty, unexpired token. No token is
sent when identity verification fails. A challenge does not trigger automatic credentials,
account fallback, PAT creation, retries, or redirects.

Each request has a 15-second deadline inside the action's existing process limit. The
Windows HTTP handler retains standard verified TLS, disables redirects/cookies/default
server and proxy credentials, bounds response headers to 16 KiB, and disables response
body draining. Read at most 34 response-body bytes, and only for HTTP 200 with content type
`application/x-git-upload-pack-advertisement`. Compare them in memory to the fixed
`001e# service=git-upload-pack\n0000` announcement; retain only a Boolean. Do not request
protocol v2, parse refs, read the remaining body, log headers/bodies, or request a pack.
The HTTP/OS implementation may buffer network data; this limit concerns application
inspection and retention, not proof of lower-layer buffer contents.

Retain HTTP status, challenge-presence, content-type/prefix match, authentication-used,
and fixed outcome categories. If the anonymous request already recognizes Git discovery,
the authenticated result cannot establish that the token was necessary. Recognized
Bearer discovery after an anonymous challenge is bounded evidence of token acceptance
for that target, not a full clone/fetch/push test or wider service authorization. Apart
from the ordinary anonymous baseline responses listed in step 3, unrecognized responses
and network failures retain that limitation and stop the sequence; do not inspect private
error bodies or expand the probe.

## Finite Attempts and Procedure

All actions are sequential; do not fetch while a Windows action is active. Windows
actions use the launcher's local exclusive lock. Fetch has one non-overwriting start
record under `fetch-1`; an existing or unresolved fetch record prohibits another fetch.
The limits below are cumulative across revisions, retries, failed starts, and manual
operation. No script or operator may reset them by deleting state or using another
directory or machine. Before each action, recover consumption from the accepted history
and subsequent local records. The accepted history is the recorded baseline; later
attempts consume additional capacity even before their evidence review is published.
A contradiction with that history, an unresolved start, or uncertain remaining capacity
stops execution. Publish the resulting ordered history through the review in step 7.

| Action | Maximum attempts | Per-attempt bound | Expected observation |
| --- | --- | --- | --- |
| `fetch` | 1 | 120 seconds for the WSL process; no retries; at most seven archives, 100 MiB each and 200 MiB total; confirm exit before proceeding | The seven pinned public packages and their SHA-512 manifest are available to Windows; no package execution or account-store access |
| `prepare` | 4 | Restore 120 seconds, build 120 seconds, synthetic self-check 15 seconds; up to 10 seconds to stop each owned process | Public restore/build succeeds and synthetic selector/URL/output self-check passes, with no authentication or account-store access |
| `inspect` | 1 | Process 120 seconds; launcher 135 seconds plus at most 10 seconds for termination | WAM available or unavailable; zero/one/multiple visible accounts and exact matches; missing-email flag and one anonymous Git discovery baseline; no acquisition |
| `silent` | 2 | Same bound as inspect | First attempt before interaction; second only after an email-matched interactive result; each resolves a real account afresh |
| `interactive` | 1 | Process 360 seconds; launcher 375 seconds plus at most 10 seconds for termination | Operator-controlled WAM interaction and provider metadata, or a bounded failure |

Maximum acquisition calls are three: two silent and one interactive. Each broker action
has at most one enumeration and one acquisition call. Preparation has no broker or resource call. Git discovery has at most three requests
across the sequence: one anonymous and at most two authenticated requests. If the first
silent action succeeds, stop without interaction; otherwise only a successful interaction
and its follow-up silent action can each send one authenticated request. Count a request
as consumed when attempted, including timeout/failure. Derive consumption from the ordered
action/results below; unknown request consumption stops further execution.
The process bounds include time spent waiting for local email and remote entry. No automatic retry
or automatic silent-to-interactive transition is permitted.

1. Verify the accepted Wave, protocol commit, exact source copy, environment, prior
   consumption, and source/dependency findings. Reconcile any failed launcher start that
   occurred before it could write its journal, adding its consumed action and outcome
   before continuing. Unknown capacity stops execution.
2. The one fetch and three preparation attempts below remain consumed. Verify the retained
   seven-package feed against its existing manifest, then use the one additional
   preparation attempt for the accepted Git-discovery subject. No new dependency fetch,
   package upgrade, or installation is permitted. Record the new source/dependency and
   artifact hashes, runtime configuration, and `self-check-passed` result before any
   account operation. Missing or changed artifacts stop execution; no capacity remains
   for an unreviewed replacement build after this fourth preparation.
3. With the operator ready at the Windows desktop, run `inspect` with the bound account
   and remote. It records account visibility and the anonymous discovery baseline. Absence
   does not prove absence from every OS/service store. Ordinary anonymous HTTP 401, 403,
   404, or a declined redirect is a baseline observation; recognized anonymous discovery
   limits what later token acceptance can establish. A network failure or another
   unrecognized response stops further attempts.
4. Run the first `silent` attempt with the same account and remote. A missing or ambiguous
   account produces a bounded outcome without acquisition. If it returns a strictly
   matched result, record its discovery outcome and stop the initial sequence; do not
   sign in again solely to consume a slot.
5. Only after an ordinary account-not-visible or interaction-required outcome, and with
   the operator ready to choose the selected account, run `interactive`. Do not proceed
   on ambiguity, unexpected UI, unavailable broker, uncertain termination, or unknown
   failure. These require interpretation or protocol amendment, not broader fallback.
6. If interaction returns an exact requested-email match, a nonempty unexpired token, and
   recognized Git discovery, run the second `silent` attempt in a fresh process. Otherwise
   stop and retain the limitation. This tests later process reuse of existing OS state;
   it does not prove fresh-state behavior or a separate consumer's behavior.
7. Record every attempt and sanitized outcome below through independent evidence review,
   including failed starts, request consumption, termination/retention, operator actions,
   existing-state limitations, and remaining limits. A normal research exit is not a V2
   success-contract result.

For the amended subject, substitute its verified accepted 40-character source commit
for `<accepted-source-commit>`, use the corresponding source-copy directory under
`%LOCALAPPDATA%\AzureAuthResearch\windows-msal`, and invoke Windows PowerShell 5.1:

```powershell
.\Invoke-Probe.ps1 -Action prepare -AcceptedRevision <accepted-source-commit>
```

After preparation verification, use each `inspect`, `silent`, or `interactive` action
only in the sequence and conditions above. Do not include an email or resource URL in
commands. An agent may launch this Windows script from WSL after the same checks; local
input may use the owned-form procedure above and user authentication remains manual.

## Outcomes, Stops, and Retention

`result.json` contains a fixed observation object defined in `Program.cs`: mode/status,
broker availability, bucketed visible/matching counts, missing-email indication,
acquisition/result presence, token-presence flag, exact-returned-email flag, tenant
presence and equality to the public MSA tenant constant, scope-metadata presence,
requested-`.default` membership, expiry validity, and the fixed resource fields described
above. Unobserved booleans are false and the unobserved HTTP status is zero;
interpret them only with status and acquisition/result-presence fields. It contains no
account identifier, resource URL, token bytes, provider exception text, raw headers/body,
or raw scopes. `.default`
membership and a nonempty scope list are observations, not proof of resource acceptance.

The JSON and journal are local operational evidence with fields fixed by the source;
the reviewed Markdown history below is the committed evidence carrier. Build logs can
contain local paths: inspect them only during preparation, sanitize any retained finding,
and do not commit raw logs, assets files, caches, or binaries. No authentication stdout,
stderr, screenshots, or UI dumps are evidence carriers.

On fetch timeout the Python watchdog exits the fetch process; on operator cancellation,
interrupt that owned Python process and confirm exit. It launches no child process. A
missing fetch result remains unresolved; do not retry or use its incomplete feed. On
closing the probe window, timeout, cancellation, or failure, stop the current attempt.
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

Current cumulative baseline before the Git-discovery amendment executes: fetch 1/1,
prepare 3/4, inspect 0/1, silent 0/2, interactive 0/1, discovery requests 0/3. The next
Windows attempt is 4 (`prepare`). The sections below preserve consumption and conclusions
at their respective historical revisions; they do not grant extra runs.

## Execution History

### First Preparation: Public Index Unavailable

Runtime observation on 2026-09-10 UTC, under the protocol accepted by
[PR #40](https://github.com/hcoona/microsoft-authentication-cli/pull/40), revision
`ed9d51e134db51c5e75e393db10894854e944e43`. The original host was Windows 11 25H2 x64,
build 26200.9168; initiating WSL/kernel and Windows SDK/runtime matched that revision.
The .NET welcome output independently reported SDK 8.0.425. The accepted source was in a
detached WSL checkout, and all five Windows files matched its SHA-256 values. The dedicated
Windows research root had no prior history before this attempt.

| Attempt | Action | Start UTC | End UTC | Outcome |
| --- | --- | --- | --- | --- |
| 1 | `prepare` | 2026-09-10 08:06:57.0755476 | 2026-09-10 08:07:06.8044423 | `step-failed`; restore returned `NU1301` for the public NuGet service index |

Restore reported failure after 6.53 seconds, within its 120-second bound. The launcher
confirmed process exit and recorded the end before returning failure. Build and
synthetic self-check did not run; there is no probe binary or `result.json`. No account
was selected, MSAL/WAM invoked, authentication UI shown, or resource request made.
Account-state and broker-version observations are therefore not applicable. This failure
does not test the MSAL API design or establish package unavailability.

The failed restore produced an empty resolved-library inventory. Its partial
`packages.lock.json` has SHA-256
`add2d0ea7db517668ed65a2fe6be37b50cdde8e7f97eda130b50f5c93272c7e8`;
it is failure evidence, not an accepted seven-package lock. Source/configuration, CLI
state, partial restore artifacts, the sanitized journal, and local build logs remain in
the dedicated Windows root. No deletion, installation change, or account cleanup was
performed by this experiment.

Read-only follow-up on 2026-09-10 UTC found that WSL could retrieve the public NuGet index
with HTTP 200, while Windows .NET Framework and curl reported TLS handshake failures
(`SecureChannelFailure` and `SEC_E_ILLEGAL_MESSAGE`). No proxy environment variable or
system proxy was used for that endpoint. Restricting the public curl request to TLS 1.2
did not resolve it. These later observations do not establish the exact cause of the
earlier restore failure. No certificate or system network setting was changed.

The same follow-up found Windows build 26200.9445 and the original SDK/runtime still
installed; the WSL/kernel version was unchanged. The temporary WSL checkout no longer
existed, while the Windows source and attempt records remained recoverable and the five
source files still matched revision `ed9d51e`. A new accepted detached checkout is
required for further preparation. The bound environment above reflects the newly
observed patch level; the original attempt's environment remains recorded here.

### Public Package Fetch and Second Preparation

Runtime observations on 2026-09-10 UTC under the amendment accepted by
[PR #41](https://github.com/hcoona/microsoft-authentication-cli/pull/41), revision
`4b7ec2e9928d3259f5e1475a89b54546452e2565`. Preflight confirmed Windows 11 25H2 x64
build 26200.9445, PowerShell 5.1, Windows SDK 8.0.425 and Core/Desktop runtime 8.0.31,
with the declared WSL/kernel and Python 3.13.15. A new detached checkout and five-file
Windows copy were verified against that accepted revision. The first preparation's
start/end records were recovered; no fetch record or local feed existed before fetch.
The Windows action lock was available, and the actions ran sequentially.

| Action | Start UTC | End UTC | Outcome |
| --- | --- | --- | --- |
| `fetch` 1 | 2026-09-10 18:07:42.010712 | 2026-09-10 18:07:43.648896 | `packages-fetched`, exit 0; seven archives, 25,337,689 bytes |
| Windows attempt 2, `prepare` | 2026-09-10 18:08:14.6809236 | 2026-09-10 18:08:22.7272071 | `step-failed`; restore reported success, then the launcher stopped before build |

The fetch emitted no stdout/stderr. All archive names, versions, byte lengths, and
SHA-512 values matched the fetch manifest before preparation and remained unchanged
when reviewed afterward:

| Package | Version | Bytes | Archive SHA-512 |
| --- | --- | --- | --- |
| `microsoft.identity.client` | 4.83.1 | 4,391,519 | `692ae5e6b961a2ef71b747a9877f7a7f0460a03f9fb2edc0fa7e4d457a5419a0f564afae53c6296b7e75e0ab2b1c61b3f621a9d56e99945bb047b02dcfe9a2bd` |
| `microsoft.identity.client.broker` | 4.83.1 | 90,323 | `9923928bde2049ed3ec125f871eb37f125a2bb28d20e0d5ebdf59d1a7cb1f37858f4c7d818dd25fd72f1fa7ae96a01a1320d1a21bb3ba3a1379d3fe37463f2ec` |
| `microsoft.identity.client.nativeinterop` | 0.20.3 | 20,066,978 | `e8d30c22acc6c14d91f09c9e8204278357f2500a11e1e7befb1443f0e806a9dd5522938d37733bfe3de11a1c4e30ccea4755f80fcd1f9de6d8c87a88910ae5cd` |
| `microsoft.identitymodel.abstractions` | 8.14.0 | 115,275 | `175ef8bf78b63f3c327e680d5cf7721d74f29e96460e686b22b4e67c264fb036a7a9bea1473f4a5b487337ab7a560c861b51ed1aa744777f303362262b01a8b4` |
| `system.diagnostics.diagnosticsource` | 6.0.1 | 384,347 | `80a0f9bf3a7afdb28d9f00e1f301feeacb39c34fe4ac8f55a392377e2e018fb546fc3fc56e2fe4336dea222b7ab3f4bab58a0b8d86eb18c71951ef2e1c752789` |
| `system.runtime.compilerservices.unsafe` | 6.0.0 | 84,343 | `d4057301be4ec4936f24b9ce003b5ec4d99681ab6d9b65d5393dd38d04cdec37784aaa12c1a8b50ac3767ed878dae425749490773fec01e734f93cf1045822b3` |
| `system.valuetuple` | 4.5.0 | 204,904 | `fa00ebb5045d12c51274f64411c551981beceb1266a8606a4731063109b95ea1f15939197bf3d2ba899db61e593dc39bfce876908bba34286823525093ae3d8e` |

Windows restore reported success after 2.8 seconds. The resolved-library inventory
contains exactly those seven name/version pairs. `packages.lock.json` has SHA-256
`6653224a1478ae1ef1a6d62c32c188b1408502ce4fcc2f4730f32673e23f3e77`.
Archive hashes identify fetched bytes; the lock-file hash identifies NuGet's separate
resolution record. Neither is a platform-support or authentication result.

Only restore stdout/stderr files exist for this attempt. There is no build log,
compiled probe, or self-check result. The launcher confirmed the owned restore process's
exit and recorded an end, then returned failure to the caller. Its exact post-restore
exception and numeric child exit code were not retained. Thus successful restore output
and resolution are observed; successful launcher completion or compilation is not.
No MSAL/WAM call, account selection, authentication UI, token acquisition, or protected
resource request occurred.

**Source finding and correction basis, retrieved 2026-09-10 UTC:**
[PowerShell issue #5421](https://github.com/PowerShell/PowerShell/issues/5421) describes
Windows PowerShell 5.1 process objects returned by `Start-Process` with stream redirection
reporting a null `ExitCode` after a separate wait. Its published workaround obtains the
process handle before waiting. The launcher used that affected API pattern and treated
any value other than zero as failure. This is a plausible explanation for the observed
stop, not a retrospectively measured null exit code. The narrow correction caches the
owned handle before the bounded wait and explicitly stops if an exit code is unavailable.
It preserves bounded termination and does not infer success from missing process data.

Retain the accepted source copies, seven public archives and manifest, dedicated caches,
restore outputs, lock, and sanitized start/end records. No cleanup, account-state change,
TLS bypass, global network modification, or extra download was performed. Both Windows
preparation attempts remain consumed; accepting the correction does not erase them.

### Completed Windows Preparation

Runtime observation on 2026-09-10 UTC under the correction accepted by
[PR #42](https://github.com/hcoona/microsoft-authentication-cli/pull/42), protocol and
source revision `3658a64b7ecba7feeb698821bd0aede6ce18f8a6`. Preflight confirmed the
same declared Windows build 26200.9445, x64 architecture, SDK 8.0.425, Core/Desktop
runtime 8.0.31, WSL/kernel, and Python 3.13.15. Both earlier preparation attempts and
the one completed fetch were recovered before starting. The seven retained archives
still matched their recorded byte lengths and SHA-512 values; no package was fetched
again. A new detached checkout and five-file Windows copy matched the accepted revision.

| Attempt | Action | Start UTC | End UTC | Outcome |
| --- | --- | --- | --- | --- |
| 3 | `prepare` | 2026-09-10 18:29:10.6148856 | 2026-09-10 18:29:18.5918142 | `prepared-and-self-checked`; launcher exit 0 |

Restore reported success after 215 milliseconds. The resolved inventory is exactly the
seven package name/version pairs recorded above, and the lock SHA-256 remains
`6653224a1478ae1ef1a6d62c32c188b1408502ce4fcc2f4730f32673e23f3e77`.
Windows Release compilation succeeded in 4.83 seconds with zero warnings and zero
errors. The generated runtime configuration selects Microsoft.NETCore.App and
Microsoft.WindowsDesktop.App 8.0.31 with `rollForward: Disable`.

| Prepared artifact under `bin/Release/net8.0-windows` | Bytes | SHA-256 |
| --- | --- | --- |
| `WindowsMsalProbe.exe` | 151,552 | `ada362907899479ec36f09a16b49b355952d50d4ffefe70f26a763ce428cdf32` |
| `WindowsMsalProbe.dll` | 19,968 | `7f7b1f2422f2fb6b4df0a4fbd36ccf10526d36901b0c9b413dc4945172642c54` |

The research process returned `Mode = self-check` and `Status = self-check-passed`.
Visible-account and exact-match fields remain `not-observed`; acquisition/result flags
are false because this synthetic selector/output check invokes no account or token API.
Those default fields are not an observation that WAM is unavailable or that no account
exists. The launcher confirmed process completion and recorded the normal end; its
stdout/stderr were empty, and build/restore stderr files were empty. All five source
files still matched the accepted revision after execution.

This establishes successful preparation and the synthetic self-check on the declared
host. It does not establish account visibility, token acquisition, interactive prompt
behavior, cancellation effectiveness during authentication, or broker reuse. No account
was selected, login UI shown, or protected resource accessed. RECHECK-007 eligibility
and the other recorded platform/Profile limitations remain unresolved.

Retain the verified prepared directory, dependency caches/feed, and local sanitized
records. No account-state cleanup, sign-out, consent change, or installation change was
performed. Remaining broker actions use the prepared identity above after checking the
current accepted protocol and operator readiness. An evidence-only update does not
require rebuilding an unchanged retained subject.

Consumed capacity: fetch 1/1; prepare 3/3; inspect 0/1; silent 0/2; interactive 0/1.
The next Windows attempt number is 4. No broker action has been executed.

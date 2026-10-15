# Windows MSAL Account, Token, and Git Discovery Evidence

This is a completed experiment record for
[Issue #35](https://github.com/hcoona/microsoft-authentication-cli/issues/35), retained as
evidence cited by current records. It authorizes no execution. The Delivery Wave grant it
ran under was completed and removed. The full protocol, operator procedure, package
pins and hashes, launcher and probe recipes, attempt accounting, source pins and complete
execution history remain at the
[pinned revision](https://github.com/hcoona/microsoft-authentication-cli/blob/242cd292a10ee5626e783f42349e570c2e5a19a1/docs/research/experiments/windows-msal-account-metadata.md).
The probe source is retained at the
[same revision](https://github.com/hcoona/microsoft-authentication-cli/tree/242cd292a10ee5626e783f42349e570c2e5a19a1/tools/probes/windows-msal).
The [experiment policy](../experiment-safety.md) governs any future experiment; another
run requires a new accepted protocol and authorization.

The investigation asked whether a designated personal Microsoft account is visible
through MSAL's explicit Windows account discovery, whether a unique exact email match
permits silent and interactive acquisition for the Azure DevOps scope, which result
fields are available, whether a later process reuses existing broker state, and whether
the token is accepted by one owner-designated Azure DevOps repository's read-only Git
discovery endpoint. The [V1 baseline](../v1-public-contract-baseline.md) owns the
public-source findings that consume these observations. This record is neither a V2
implementation nor a selected Client Profile, host architecture or support promise.

## Current Disposition: MSA Acquisition and Reuse Observed

**Runtime observation:** The GCM-informed configuration completed preparation, attended
interactive acquisition and its conditional fresh-process silent follow-up. Both account
actions returned the exact requested email and a nonempty, unexpired token. Both
authenticated Git discovery requests returned HTTP 200 with the expected content type and
fixed service prefix. During interaction, the operator identified WAM and manually
switched the apparent Security Key selection to Windows Hello PIN. The
[completed observation](#gcm-informed-msa-acquisition-and-silent-reuse) records the
details.

**Limits:** This establishes the bounded requested-personal-account path on the
designated existing Windows host and Git target with this exact configuration. It does
not isolate the cause of the earlier broker error, establish fresh-state or
cross-consumer behavior, select a Client Profile, or establish intended external
registration reuse or broader support. The sequence is complete and its limits are
exhausted.

## Probe Configuration

The research probe was a small `net8.0-windows` x64 Windows Forms executable that ran one
operator-started operation per process. Each operation used a new in-memory MSAL cache,
with no MSAL Extensions or application cache file, and the existing OS broker state.

| Input | Value |
| --- | --- |
| Windows host | Owner-designated Windows 11 25H2 x64 host in an interactive desktop session with a corporate-account Windows session, as reported by the owner; join and compliance state were not measured |
| Dependencies | `Microsoft.Identity.Client` and `.Broker` 4.83.1; `Microsoft.Identity.Client.NativeInterop` 0.20.3, fetched as public packages and restored from a local feed |
| Client | Microsoft-owned Visual Studio client `872cd9fa-d31f-45e0-9eab-6e460a02d1f1`, an experiment input only |
| Scope | `499b84ac-1321-427f-aa17-267ca6975798/.default` |
| Broker options | Windows WAM; `ListOperatingSystemAccounts = true`; a real owned parent window |
| Selected account | One owner-designated personal Microsoft account, matched by exact email; never recorded |
| Resource | One owner-designated `https://dev.azure.com` Git remote; never recorded |

Earlier sequences used the `https://login.microsoftonline.com/common` authority without
MSA passthrough. The final GCM-informed sequence used the `organizations` authority with
`MsaPassthrough = true`. For its silent follow-up only, when the uniquely matched
account's home tenant was the public MSA home tenant, the probe applied MSAL
`WithTenantId` with the public Microsoft MSA transfer tenant
`f8cdef31-a31e-4b4a-93e4-5f571e91255a`. It recorded only whether that rule applied.

Account selection passed only a unique exact email match to MSAL `WithAccount`. With no
match, the unchanged logic used `WithLoginHint`. The returned email was checked against
the request. There was no OS-default sentinel, alias inference, account fallback,
browser fallback or device-code flow.

The probe's Git discovery was a single `GET <remote>/info/refs?service=git-upload-pack`.
It used a Bearer token only after an exact returned-email match and a nonempty, unexpired
token. Redirects, cookies and default credentials were disabled. Only HTTP status,
challenge presence and a Boolean comparison of the first 34 response bytes against the
fixed `001e# service=git-upload-pack\n0000` announcement were retained. This follows
Microsoft's
[Azure Repos authentication guidance](https://learn.microsoft.com/en-us/azure/devops/repos/git/auth-overview?view=azure-devops)
and Git's
[v2.51.0 HTTP protocol](https://github.com/git/git/blob/v2.51.0/Documentation/gitprotocol-http.adoc).
Recognized discovery is bounded evidence of token acceptance for that target, not a
complete clone, fetch or push.

Sanitized results kept fixed booleans, bucketed account counts and, for failures, only
the MSAL error code, `IsRetryable`, service status, UI-required classification and the
named broker status and code. No token bytes, account or tenant identifiers, remote URL,
raw scopes, exception text, headers, bodies or broker diagnostics were retained.

## Execution History

The first preparation failed when Windows restore could not reach the public NuGet
index; the cause was not established. Public packages were then fetched through WSL into
a local feed. A Windows PowerShell 5.1
process exit-code defect in the launcher stopped one more preparation. Later preparations
built the probe and passed a synthetic self-check that made no account or resource call.
The account sequences below are the evidence current records cite. Earlier subjects
retain their own evidence limits.

### Account Visibility and Unresolved Acquisition Failure

**Runtime observation, 2026-09-10 UTC:** Three actions each reported broker
availability, multiple visible accounts, exactly one exact email match and no
missing-email indication. An anonymous Git discovery request observed HTTP 302 with a
`WWW-Authenticate` header and no recognized Git advertisement. Silent acquisition for
the matched account returned `interaction-required`. The permitted interactive action
returned the probe's coarse `provider-rejected` category, its mapping for
`MsalServiceException`, without an `AuthenticationResult`. No authenticated discovery
request or reuse follow-up ran.

**Limits:** Exact account discovery worked in this existing state. The coarse category
does not identify the underlying service error, configuration issue, account eligibility
or operator action, and finer fields were not captured. Do not infer categorical MSA
rejection or a registration-support conclusion. Successful result metadata,
authenticated discovery and later reuse remained unobserved. Detailed operator UI steps
were unavailable.

### Diagnostic Subject Preparation and Acquisition

**Runtime observation, 2026-09-10 UTC:** A diagnostic subject added the structured
failure fields above and passed its synthetic self-check, including exclusion of
synthetic private markers. One interactive action then reported broker availability,
multiple visible accounts, no missing-email indication and zero exact matches, so the
unchanged logic used `WithLoginHint` rather than `WithAccount`. It reached the probe's
360-second process deadline as `process-timeout` without an `AuthenticationResult`
or authenticated resource request. The structured failure recorded kind `client`,
`authentication_canceled`, broker status `UserCanceled`, broker code 0, no service
status and `IsRetryable = false`.

**Inference and limits:** The
[pinned MSAL mapping](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/WamAdapters.cs#L69-L74)
converts `UserCanceled` to a client cancellation, which is consistent with the deadline
cancellation. It does not establish manual cancellation, remote rejection or why
acquisition had not completed. The cause of the changed exact-match count is unknown,
and this action does not explain the first sequence's failure.

### Attended Preparation and Structured Broker Failure

**Runtime observation, 2026-09-11 UTC:** After preparation, the agent announced
readiness and waited for the owner's explicit readiness response. One interactive action
then found one exact match among multiple visible accounts and used `WithAccount`. About
20.6 seconds after launch, it returned `acquisition-failed` without an
`AuthenticationResult` or resource request. The structured failure recorded kind
`service-or-broker`, `unknown_broker_error`, broker status `Unexpected`, broker code
`2147786073` (`0x80049D59`), service status 0 and `IsRetryable = false`. The owner
saw the probe form, apparent automatic filling and submission, and then a brief surface
that appeared to be WAM before the windows closed.

**Limits:** Service status 0 is the reported default, not an observed HTTP response. The
[pinned MSAL default mapping](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/d5d7de6b103f0d9dd7bca9bf13cbb9f3da37bc9f/src/client/Microsoft.Identity.Client.Broker/WamAdapters.cs#L116-L120)
accounts for the generic category; it does not identify the cause of this broker code or
establish remote rejection. Matching the first sequence's category does not prove the
same cause. The owner was uncertain about the brief surface's identity, and no sign-in,
MFA or consent step was reported.

### GCM-Informed MSA Acquisition and Silent Reuse

**Runtime observation, 2026-09-11 UTC:** After preparation and the explicit readiness
handoff, the interactive action used the `organizations` authority and
`MsaPassthrough = true` with the same client, scope, exact account checks and owned
parent. After its strict result and discovery checks passed, the conditional silent
action ran in a fresh process with a new in-memory cache, resolved the unique account
afresh and applied the MSA transfer-tenant rule.

| Observation | Interactive | Silent |
| --- | --- | --- |
| Broker available; visible accounts; exact matches | true; multiple; one | true; multiple; one |
| Acquisition started; provider result returned | true; true | true; true |
| Token present; unexpired | true; true | true; true |
| Exact returned email | true | true |
| Tenant present; equals public MSA home tenant | true; false | true; false |
| Silent MSA transfer rule applied | false | true |
| Scope metadata present; requested `.default` reported | true; true | true; true |
| Structured failure | null | null |
| Authenticated resource request; HTTP status; challenge | true; 200; false | true; 200; false |
| Discovery content type and fixed prefix matched | true | true |

The interactive and silent processes completed about 48.5 and 29.2 seconds after their
start records. The operator identified WAM, reported that Security Key appeared initially
selected and manually chose Windows Hello PIN, followed by apparent success. No factor
value was collected.

**Inference and limits:** This exact existing-state configuration returned the requested
personal account's token and recognized authenticated Git discovery, then repeated those
postconditions through fresh-process silent acquisition without an application cache
file. It does not isolate a single option's causal effect, explain the earlier
`0x80049D59`, or prove that `common` is unsupported. It also does not establish a
clean first-use path, cross-consumer interoperability, a complete Git operation or
intended external reuse of the Microsoft-owned registration. The tenant equality flag
does not reveal the token tenant. No operator UI observation exists for the silent
action, so it is not an independently observed no-UI guarantee.

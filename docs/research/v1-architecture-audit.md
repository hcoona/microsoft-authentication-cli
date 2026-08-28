# AzureAuth V1 Architecture Audit

## Status and Scope

This audit records public evidence supporting the v2 direction. It evaluates AzureAuth
v1 as a deterministic, multi-account, machine-facing authentication substrate rather than
only as a human-operated token CLI.

Audited references:

- `main` at
  [`de20930c34b3b86c8a0ed7bbdeeca3f662dae918`](https://github.com/AzureAD/microsoft-authentication-cli/commit/de20930c34b3b86c8a0ed7bbdeeca3f662dae918)
- tag
  [`0.9.5`](https://github.com/AzureAD/microsoft-authentication-cli/tree/0.9.5)
- tag
  [`0.9.6`](https://github.com/AzureAD/microsoft-authentication-cli/tree/0.9.6)
- public issues and Microsoft documentation cited below

This record contains no internal project evidence or unpublished downstream observations.

## Summary

AzureAuth v1 has useful projects, interfaces, MSAL mechanisms, cache integration, ADO
specialization, and cross-platform packaging. Its central weakness is not absence of
layers; it is an under-specified request, policy, and result model.

The v1 design is reasonable for a human asking a CLI to obtain a token using a broad set
of acceptable fallbacks. It is not a sufficient foundation for a caller requiring exact
identity, explicit interaction policy, ordered acquisition, one deadline, host-aware UI,
and typed machine failures.

Assessment for that target use case: **2.3/5**.

| Area | Score | Publicly observable reason |
| --- | ---: | --- |
| Responsibility boundaries | 3/5 | Projects and test seams exist, but command, policy, storage, and presentation remain coupled. |
| Caller-intent preservation | 2/5 | Client, tenant, and scopes pass through; order, interaction, deadline, and host intent do not. |
| Account correctness | 1/5 | Domain suffix filtering, lossy ambiguity, OS-account widening, and no result postcondition. |
| Flow architecture | 2/5 | Deterministic fixed sequence, but broker combines silent and interactive policy stages. |
| Platform and host model | 2/5 | Broad platform support, but no explicit WSL model and weak UI-parent discovery. |
| Cache and security | 3/5 | Secure-first integration with an implicit headless plaintext fallback. |
| Failure and output contract | 2/5 | Token output is separate from logs, but failures and result metadata are collapsed. |
| Testability | 3/5 | Useful interfaces and unit tests, without release-gating real broker and WSL matrices. |
| Release and maintenance | 2/5 | Self-contained pinned artifacts, but stale release records and weak dependency canaries. |

## Finding 1: Flow Order and Interaction Policy Are Conflated

`--mode` values are combined as flags by
[`AuthMode.Combine`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthMode.cs#L124-L133).
The caller's order is therefore lost.

[`AuthFlowFactory`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/AuthFlowFactory.cs#L38-L87)
then imposes a fixed cache, IWA, broker, web, and device sequence.

[`Broker.GetTokenInnerAsync`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L78-L116)
attempts silent acquisition and then interactive WAM inside one flow. The caller cannot
request broker-aware silent acquisition while prohibiting the interactive half of that
same mechanism.

This is the architectural basis of the missing strict no-interaction contract discussed
in [issue #464](https://github.com/AzureAD/microsoft-authentication-cli/issues/464).

## Finding 2: Account Selection Is a Preference, Not a Postcondition

The CLI documents `--domain` as a preferred-domain filter, not a strict selector.

[`PCAWrapper.TryToGetCachedAccountAsync`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L150-L180):

- filters usernames with a raw suffix comparison;
- returns the same `null` outcome for no account, no match, or multiple matches;
- does not produce a typed ambiguity result.

On Windows,
[`Broker.ResolveAccountAsync`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L119-L142)
widens that `null` outcome to `PublicClientApplication.OperatingSystemAccount`.

The claims retry overload in
[`PCAWrapper`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L111-L134)
applies claims without preserving an account argument.

There is no final account postcondition. This is the central subject of
[issue #465](https://github.com/AzureAD/microsoft-authentication-cli/issues/465).

## Finding 3: The Result Boundary Discards Required Facts

[`PCAWrapper.TokenResultOrNull`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L209-L216)
reduces `AuthenticationResult` to the access token and correlation ID. The provider
account, tenant, scopes, token type, and other acquisition metadata are not preserved as
authoritative result fields.

[`PublicClientAuth`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/PublicClientAuth.cs#L54-L81)
further reduces the public outcome to token or `null`.

[`CommandAad`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Commands/CommandAad.cs#L384-L424)
maps most failures to exit code `1`. A machine caller cannot distinguish account absence,
interaction required, user cancellation, mechanism unavailability, network failure,
timeout, cache failure, or internal failure.

Microsoft recommends treating access tokens as opaque:
[Access tokens in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens).
Strict account selection must therefore be enforced at the MSAL result boundary rather
than reconstructed from token claims.

## Finding 4: Host Context and WSL Are Under-Specified

On Windows, broker UI ownership is derived from `GetConsoleWindow()` and
`GetAncestor(...)` in
[`Broker`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L193-L240).
There is no caller-supplied parent-window contract or typed result for an unusable host.

Microsoft documents that `GetConsoleWindow` can return `NULL` and that pseudoconsole
hosting can expose a non-displayed compatibility window:
[GetConsoleWindow](https://learn.microsoft.com/en-us/windows/console/getconsolewindow).

The source has no distinct WSL host model. A Linux binary is treated as Linux; a Windows
binary launched through WSL interop still receives no explicit Linux-caller-to-Windows-UI
context. See the public WSL request in
[issue #460](https://github.com/AzureAD/microsoft-authentication-cli/issues/460).

Current MSAL versions also document a native Linux broker route for WSL, with significant
WSL, package, and keyring prerequisites:
[Using MSAL.NET with WSL](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/linux-dotnet-sdk-wsl).
V2 must evaluate that route explicitly rather than inherit an accidental host model.

## Finding 5: Timeout and Cancellation Do Not Form One Deadline

The named mutex provides useful prompt serialization, but lock wait and authentication do
not share one caller-defined deadline.

[`Locked.Execute`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/Locked.cs#L43-L84)
uses synchronous waiting.

[`TaskExecutor.CompleteWithin`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/TaskExecutor.cs#L27-L54)
can return after requesting cancellation without proving that the underlying operation
has stopped.

[`AuthFlowExecutor`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/AuthFlowExecutor.cs#L98-L144)
has separate polling and timeout behavior. The public contract cannot guarantee that a
timed-out request leaves no prompt or background operation.

## Finding 6: Cache Policy Contains an Implicit Security Decision

[`PCACache`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L49-L105)
uses MSAL Extensions and attempts secure platform persistence.

On headless Linux, failure to use the secure store can select an unprotected file cache.
Permission hardening is best effort rather than a caller-visible policy decision. See
[`PCACache`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L85-L95)
and
[`LinuxHelper`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/LinuxHelper.cs#L40-L85).

Issue [#398](https://github.com/AzureAD/microsoft-authentication-cli/issues/398)
records secure-store availability problems. V2 must make fallback policy explicit.

## Finding 7: Real Broker and Dependency Regressions Need Release Canaries

The source provides useful interfaces and unit tests, but no public release-gating matrix
was found for real WAM, macOS broker, browser, device-code, WSL, multiple-account, claims,
and cancellation states.

Between 0.9.5 and 0.9.6, public project references show a substantial MSAL update and a
native interop dependency change:

- [`0.9.5 MSALWrapper.csproj`](https://github.com/AzureAD/microsoft-authentication-cli/blob/21258ff3a2cbb01d6891243114a55abe9ae3587e/src/MSALWrapper/MSALWrapper.csproj)
- [`0.9.6 MSALWrapper.csproj`](https://github.com/AzureAD/microsoft-authentication-cli/blob/8ef1b8b00782bf20a51de078289819a79c3cba70/src/MSALWrapper/MSALWrapper.csproj)

The existing broker source already retries interactive acquisition after
`MsalUiRequiredException`. A changed dependency could therefore expose duplicate
interaction behavior that older versions did not trigger. This is a hypothesis, not a
proven public root cause.

No public issue or source fix was found that establishes a complete Windows repeated-
interaction regression and resolution for 0.9.6. V2 must reproduce dependency-sensitive
behavior directly before drawing a stronger conclusion.

## Finding 8: The Upstream Build Is Not Yet a Public V2 Foundation

The audited upstream
[`nuget.config`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/nuget.config)
clears package sources and selects an authenticated Office Azure Artifacts feed.

[`AzureAuth.csproj`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/AzureAuth.csproj)
references `Microsoft.Office.Lasso`.

SOURCE-VERIFIED: the source declares a private-feed build dependency. VALIDATE-RUNTIME:
a clean anonymous public restore must establish exactly which packages are unavailable
and which responsibilities must be replaced. V2 implementation must not depend on
private Microsoft build infrastructure.

## Structural Debt Versus Isolated Defects

| Area | Classification |
| --- | --- |
| Ordered strategy and interaction policy | Structural: mechanism flags substitute for a policy model. |
| Strict account selection | Structural, with additional suffix-match and claims-retry defects. |
| Typed result and failure semantics | Structural public-contract gap. |
| Parent-window and WSL behavior | Missing host-context abstraction plus implementation defects. |
| Deadline and cancellation | Structural execution-contract gap. |
| Linux cache fallback | Embedded policy decision requiring explicit product ownership. |
| Individual duplicate cache attempts or environment checks | Repairable implementation defects. |

## V1 Component Disposition

| V1 component | V2 disposition |
| --- | --- |
| `AuthMode` and `Combine()` | Replace. |
| `AuthParameters` | Replace with a complete request contract. |
| `PublicClientAuth.Token` | Replace with asynchronous typed orchestration. |
| `AuthFlowFactory` and `AuthFlowExecutor` | Replace. |
| Composite `Broker` | Split; selectively reuse mechanism code. |
| `CachedAuth`, `Web`, and `DeviceCode` | Reuse concepts behind v2 mechanism contracts. |
| IWA | Open decision requiring a supported-scenario justification. |
| `IPCAWrapper` and `PCAWrapper` | Reuse the seam; replace the result shape and claims behavior. |
| `PCACache` | Reuse platform knowledge; replace policy, namespace, and fallback semantics. |
| `TaskExecutor` | Replace. |
| Named lock | Reuse the coordination concept with asynchronous deadline-aware behavior. |
| `TokenResult` and manual JSON | Replace with a versioned protocol. |
| Attempt diagnostics | Reuse the local observability concept with fork-owned identity and redaction. |
| ADO PAT components | Defer to a separate product-specific decision. |
| Upstream build and release plumbing | Replace with publicly operable, fork-owned infrastructure. |

## Reusable Assets

The audit supports selective reuse of:

- MSAL and broker integration concepts;
- `IPCAWrapper`-style test seams, expanded to preserve full results;
- system-browser and device-code mechanisms;
- broker-aware silent acquisition;
- secure platform-storage integration after policy review;
- cross-process prompt coordination after deadline redesign;
- ADO PAT components if a later product decision retains them;
- self-contained platform packaging knowledge.

## Conclusion

The v1 orchestration core should not define v2. Reusing mechanism-level code remains
economical, but every reused component must sit behind v2 identity, interaction, host,
deadline, cache, and result contracts.

Confidence is high for static source findings and public history, medium for inferred
runtime consequences, and intentionally limited for dependency-regression hypotheses
that lack a public reproduction.

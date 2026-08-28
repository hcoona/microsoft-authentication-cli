# Evidence Register

## Purpose

This register prevents mutable public information and runtime hypotheses from being
promoted into durable project facts. It is an index, not a replacement for the linked
source or research record.

## Immutable Source Baseline

| Subject | Evidence | Classification |
| --- | --- | --- |
| Audited upstream baseline | [`de20930c34b3b86c8a0ed7bbdeeca3f662dae918`](https://github.com/AzureAD/microsoft-authentication-cli/commit/de20930c34b3b86c8a0ed7bbdeeca3f662dae918) | SOURCE-VERIFIED |
| V1 mode combination | [`AuthMode.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthMode.cs#L124-L133) | SOURCE-VERIFIED |
| Fixed flow ordering | [`AuthFlowFactory.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/AuthFlowFactory.cs#L38-L87) | SOURCE-VERIFIED |
| Composite silent and interactive broker | [`Broker.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L78-L142) | SOURCE-VERIFIED |
| Lossy account filtering | [`PCAWrapper.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L150-L180) | SOURCE-VERIFIED |
| MSAL result metadata discarded | [`PCAWrapper.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCAWrapper.cs#L209-L216) | SOURCE-VERIFIED |
| Console-derived WAM parent | [`Broker.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/AuthFlow/Broker.cs#L193-L240) | SOURCE-VERIFIED |
| Headless Linux plaintext cache fallback | [`PCACache.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/MSALWrapper/PCACache.cs#L79-L150) | SOURCE-VERIFIED |
| Upstream restore uses authenticated Office feed | [`nuget.config`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/nuget.config) | SOURCE-VERIFIED |
| CLI depends on `Microsoft.Office.Lasso` | [`AzureAuth.csproj`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/AzureAuth.csproj) | SOURCE-VERIFIED |
| Upstream Azure DevOps client and scope | [`Ado/Constants.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Ado/Constants.cs) | SOURCE-VERIFIED |

## Standards and Platform Guidance

| Subject | Evidence | Classification |
| --- | --- | --- |
| Native public-client and impersonation model | [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) | SOURCE-VERIFIED |
| Access tokens treated as opaque | [Microsoft identity-platform access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens) | SOURCE-VERIFIED |
| Application-object ownership and configuration | [Apps and service principals](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals) | SOURCE-VERIFIED |
| Azure DevOps Entra OAuth and documented MSA limitation | [Azure DevOps Entra OAuth](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/entra-oauth) | SOURCE-VERIFIED, RECHECK-UPSTREAM |
| WAM parent-window requirement | [Acquire tokens with WAM](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-wam) | SOURCE-VERIFIED |
| WSL native broker prerequisites | [MSAL.NET with WSL](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/linux-dotnet-sdk-wsl) | SOURCE-VERIFIED |
| Console-window limitations | [`GetConsoleWindow`](https://learn.microsoft.com/en-us/windows/console/getconsolewindow) | SOURCE-VERIFIED |

## Mutable Upstream Records

These records must be rechecked before a milestone that depends on their status:

| Subject | Record | Classification |
| --- | --- | --- |
| Silent-only acquisition | [Issue #464](https://github.com/AzureAD/microsoft-authentication-cli/issues/464) | RECHECK-UPSTREAM |
| Strict account selection | [Issue #465](https://github.com/AzureAD/microsoft-authentication-cli/issues/465) | RECHECK-UPSTREAM |
| WSL broker-backed acquisition | [Issue #460](https://github.com/AzureAD/microsoft-authentication-cli/issues/460) | RECHECK-UPSTREAM |
| Remote browser and callback behavior | [Issues #459](https://github.com/AzureAD/microsoft-authentication-cli/issues/459) and [#461](https://github.com/AzureAD/microsoft-authentication-cli/issues/461) | RECHECK-UPSTREAM |
| Linux broker implementation | [PR #462](https://github.com/AzureAD/microsoft-authentication-cli/pull/462) | RECHECK-UPSTREAM |
| Secure-store availability | [Issue #398](https://github.com/AzureAD/microsoft-authentication-cli/issues/398) | RECHECK-UPSTREAM |

## Hypotheses Requiring Experiments

| Hypothesis | Required evidence | Classification |
| --- | --- | --- |
| A changed MSAL or native-broker dependency exposed repeated interactive behavior between 0.9.5 and 0.9.6. | Controlled source/dependency matrix on real Windows WAM hosts. | HYPOTHESIS, VALIDATE-RUNTIME |
| Console-derived parent handles cause hidden or poorly owned WAM UI when a Windows binary is launched from WSL. | Host matrix covering Console, Windows Terminal, IDE terminals, and WSL interop. | HYPOTHESIS, VALIDATE-RUNTIME |
| Native WSL broker is suitable for the intended operating envelope. | Repeated tests with supported WSL versions, package prerequisites, keyring states, and account states. | VALIDATE-RUNTIME |
| The upstream Visual Studio client currently supplies the required Azure DevOps behavior for each intended MSA and Entra scenario. | Client-by-account-type-by-resource matrix, plus recheck of public owner guidance. | VALIDATE-RUNTIME, RECHECK-UPSTREAM |
| Upstream source cannot restore anonymously without replacing or making private dependencies public. | Fresh public runner restore, build, and package experiment. | VALIDATE-RUNTIME |

## Fork Decisions

The following are project decisions rather than upstream facts:

- rebuild the policy and orchestration core;
- preserve public-client IDs as configurable external dependencies;
- use no upstream telemetry identity;
- maintain independent operational namespaces;
- keep downstream credential-provider protocols outside this repository;
- make no current v1 compatibility or support commitment.

The governing ADRs, not this index, are authoritative.

# Client Application Identity

This architecture view defines how v2 treats OAuth public-client application
registrations. It does not claim ownership of any Microsoft registration or freeze a
client-profile contract.

## Public Does Not Mean Ownerless

Native desktop applications are OAuth public clients. A distributed application cannot
keep a shared client secret confidential, and the client ID is therefore an identifier,
not a credential.

RFC 8252 nevertheless distinguishes public identification from proof of client identity
and explicitly discusses client impersonation:

- [Registration of Native App Clients](https://www.rfc-editor.org/rfc/rfc8252.html#section-8.4)
- [Client Authentication](https://www.rfc-editor.org/rfc/rfc8252.html#section-8.5)
- [Client Impersonation](https://www.rfc-editor.org/rfc/rfc8252.html#section-8.6)

In Microsoft Entra ID, a client ID identifies an application object whose owner controls
supported account types, redirect configuration, API permissions, branding, consent, and
lifecycle. See
[Apps and service principals in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals).

Consequently:

- a client ID must never be treated as a secret;
- technical ability to send a client ID does not transfer ownership of its application
  registration;
- behavior enabled by a Microsoft-owned registration remains an external dependency;
- audit, consent, and policy systems can attribute activity to that application identity.

## Upstream Azure DevOps Compatibility Identity

At the audited upstream baseline, the Azure DevOps specialization uses:

- **Client ID:** `872cd9fa-d31f-45e0-9eab-6e460a02d1f1`
- **Azure DevOps scope:** `499b84ac-1321-427f-aa17-267ca6975798/.default`

The upstream source identifies the client ID as the Visual Studio 2019 and earlier public
client:

- [`src/AzureAuth/Ado/Constants.cs`](https://github.com/AzureAD/microsoft-authentication-cli/blob/de20930c34b3b86c8a0ed7bbdeeca3f662dae918/src/AzureAuth/Ado/Constants.cs)

This fork does not own or control that registration. V2 may provide an explicitly named
compatibility profile that uses it, but the profile must state that:

- it is a Microsoft-owned external dependency;
- this fork provides no availability or behavior commitment for it;
- use does not imply Microsoft sponsorship or upstream support;
- failure or changed behavior must be surfaced rather than hidden by identity fallback.

## Azure DevOps and Microsoft Accounts

Current Azure DevOps guidance states that Microsoft Entra applications do not natively
support Microsoft account users for the Azure DevOps resource. The upstream source proves
that AzureAuth uses a Microsoft-owned Visual Studio client; it does not by itself prove
the current MSA behavior, intended reuse, or support status of that registration for this
fork. Those properties require rechecking and runtime validation.

See
[Build Azure DevOps integrations with Microsoft Entra OAuth apps](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/entra-oauth).

This makes client-application identity a functional input, not a replaceable cosmetic
constant.

## Architecture Model

1. The authentication core accepts explicit client-application configuration.
2. The core does not embed a client secret for a native public-client flow.
3. Product or compatibility profiles are separate from the mechanism core.
4. A profile records the client ID, authority policy, expected account types, scopes,
   ownership statement, known limitations, per-platform redirect URIs, broker
   registration requirements, and any signing or bundle identity constraints.
5. Microsoft-owned compatibility registrations are configurable and visibly identified.
6. A strict request fails if the selected profile cannot satisfy its account or resource
   requirements.
7. No result may imply that this fork owns, represents, or is supported by the
   registration owner.

## Activation Boundaries

- Every experiment must be authorized by a downstream Issue and name the client profile
  it uses under [`experiment-safety.md`](../research/experiment-safety.md).
- Current Azure DevOps account-type guidance and reproducible behavior must be resolved
  through [`RECHECK-007`](../research/rechecks.yaml) before selecting or enabling an
  Azure DevOps compatibility profile.
- No externally owned profile may become a default or public compatibility option until
  it satisfies the gate in
  [`compatibility-and-migration.md`](../product/compatibility-and-migration.md).
- Cache and configuration identity must be selected in
  [`operational-identities.yaml`](../governance/operational-identities.yaml) before a
  client profile persists state.

These boundaries do not authorize implementation. The applicable downstream Issue and
repository-owner decision remain required.

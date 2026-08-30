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
compatibility profile that uses it. Product identity, support, strict-result, and fallback
behavior are governed by
[`V2-REQ-003`](../product/requirements/product-boundary.md#v2-req-003-unofficial-product-identity),
[`V2-REQ-022`](../product/requirements/strategy-interaction-and-host.md#v2-req-022-strict-identity-postcondition),
[`V2-REQ-023`](../product/requirements/strategy-interaction-and-host.md#v2-req-023-classified-fallback),
and decision
[`0003`](../decisions/0003-treat-client-registration-as-an-external-dependency.md).

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

Required configurability and visible ownership are defined by
[`V2-REQ-042`](../product/requirements/cache-security-and-operational-identity.md#v2-req-042-client-registration-as-configuration).
Strict request and fallback behavior are defined by `V2-REQ-022` and `V2-REQ-023`
above.

## Governing Evidence and Gates

Experiments, mutable Azure DevOps account guidance, compatibility activation, and
persisted operational identity are governed respectively by:

- [`experiment-safety.md`](../research/experiment-safety.md);
- [`RECHECK-007`](../research/rechecks.yaml);
- the external-client-profile gate in
  [`compatibility-and-migration.md`](../product/compatibility-and-migration.md);
- [`operational-identities.yaml`](../governance/operational-identities.yaml).

# 0003: Treat Client Registration as an External Dependency

- **Status:** Accepted
- **Date:** 2026-08-28

## Context

OAuth native applications are public clients. Their client IDs are public identifiers,
not secrets. A client ID nevertheless refers to an application registration whose owner
controls account types, redirect and broker configuration, permissions, consent,
branding, and lifecycle.

The upstream Azure DevOps path uses a Microsoft-owned Visual Studio public-client
registration. Public Azure DevOps guidance also states that an ordinary Microsoft Entra
application cannot natively support Microsoft-account users for the Azure DevOps
resource. These facts do not prove the current behavior, intended reuse, or support status
of the Visual Studio registration for this fork.

## Decision

Treat client application identity as explicit configuration.

V2 may provide a named Azure DevOps compatibility profile using the existing
Microsoft-owned public-client ID, but:

- the fork does not claim ownership or support for that registration;
- the profile is separate from the authentication core;
- the client ID remains configurable;
- identity or capability changes fail visibly;
- user-facing material does not imply Microsoft sponsorship.

Default enablement or distribution of that profile remains blocked until its account,
resource, consent, audit, and branding behavior is publicly reviewed and validated for
the intended hosts.

## Consequences

- Reusing the identifier is not treated as handling a secret.
- The compatibility profile has an external availability and governance dependency.
- An independently owned client registration may have different MSA and Azure DevOps
  capabilities.
- Cache namespace and migration must include client application identity.
- Public distribution and opt-in behavior remain open decisions.

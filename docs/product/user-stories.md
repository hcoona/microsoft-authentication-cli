# Product User Stories

This record owns user context and motivation for requirements work. It does not define
normative behavior, realization choices, validation procedures, or current support.
Those concerns belong to [requirements](requirements/),
[architecture](../architecture/overview.md), [validation](../validation/strategy.md), and
[research](../research/v1-public-contract-baseline.md).

## Primary Journey: Personal Azure DevOps Git Access

> As a developer working with a personal Azure DevOps Git repository while my Windows WAM
> default account is a corporate work account, I want the Git credential adapter to
> request an Azure DevOps access token from the AzureAuth Unofficial V2 authentication
> engine for the personal Microsoft account email selected for that repository, so that
> Git operations do not silently authenticate as the corporate account and can reuse valid
> authentication state without prompting when it is available.

The developer has selected a personal account for this repository, not whichever account
happens to be the operating-system default. Repeated Git operations make wrong-account
success and unnecessary prompts particularly disruptive.

The external adapter identifies Azure DevOps, selects a Client Profile, and supplies the
account email and Azure DevOps scope as consumer knowledge. Repository bindings, remote
parsing, Git credential protocol, and any PAT lifecycle remain outside the authentication
engine under [decision 0004](../decisions/0004-keep-the-authentication-engine-separate-from-consumers.md).

This is the primary first-release blocking journey. Its acceptance evidence belongs to
the [primary-journey validation gate](../validation/strategy.md#primary-journey-gate).
The WAM context explains the wrong-default risk; it does not select WAM as the required
implementation or establish that any Client Profile or platform supports this journey.

## Requirements Consumers

- [Request, identity, and authority](requirements/request-identity-and-authority.md):
  the adapter's explicit intent and strict account/target selection.
- [Strategy, interaction, and host](requirements/strategy-interaction-and-host.md):
  selected-account silent-first acquisition, bounded interaction, and terminal validation.
- [Result and process protocol](requirements/result-and-process-protocol.md):
  the machine calling contract, privacy, and supported-protocol compatibility.
- [State and operational identity](requirements/cache-security-and-operational-identity.md):
  safe reuse, recovery, and independent identities.

These are routes to the behavioral authority, not a second set of acceptance criteria.

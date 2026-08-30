# Request, Identity, and Authority Requirements

## V2-REQ-010: Versioned Request

Every machine request must declare a protocol version and fail safely when the major
version is unsupported.

## V2-REQ-011: Explicit Application and Authority

A request or selected profile must identify the client application, authority host,
tenant policy, and requested scopes or resource.

## V2-REQ-011A: Trusted Authority

An authority must be selected from an explicitly supported Microsoft Entra cloud or a
trusted client profile and must pass MSAL authority validation. Arbitrary caller-supplied
authority hosts and disabling authority validation are prohibited unless a separate
accepted decision defines the trust model.

## V2-REQ-012: Stable Account Constraint

A strict account constraint must use a provider-native stable identifier where available.
Username and domain may be used only as discovery or display hints.

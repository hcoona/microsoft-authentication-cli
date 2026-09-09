# Result and Process-Protocol Requirements

## V2-REQ-030: Versioned Result and Exit Status

Every terminal authentication result emitted by V2 must use a versioned structured
protocol that represents both success and failure. When a complete result is emitted,
the process exit status must be zero for success and one documented nonzero value shared
by all failures. The payload must carry the specific outcome, and the exit status must
not contradict it.

A success with a persistence warning remains success. Operating-system termination or
incomplete or malformed output is not a normally emitted typed failure. The concrete
nonzero value and serialized schema are not selected here.

## V2-REQ-031: Complete Success Metadata

A successful result must return one access token and preserve its token type,
provider-reported expiration time, provider-observed account email, actual tenant and
authority, provider-reported scope metadata, acquisition mechanism, and interaction
classification. Correlation metadata must be included when available. Public account
metadata must identify the account by its provider-observed email, without exposing
stable provider account identifiers.

Expiration is metadata, not a guarantee that the token remains valid for the duration of
a downstream operation. V2 defines no minimum remaining token lifetime.

## V2-REQ-032: Caller-Action Failure Taxonomy

The first version must distinguish invalid requests, required interaction, account
ambiguity, identity-validation failure, cancellation, denial, mechanism unavailability,
temporary unavailability, timeout, and internal failure. Provider and platform exception
types must not define the public taxonomy. Additional causes, including consent
requirements and the origin of transient failures, must be conveyed as safe reason
details rather than parallel top-level outcomes.

The outcome vocabulary is `success`, `invalid_request`, `interaction_required`,
`account_ambiguous`, `identity_validation_failed`, `cancelled`, `denied`,
`mechanism_unavailable`, `temporarily_unavailable`, `timeout`, and `internal_failure`.
There is no separate account-not-found, interaction-blocked, consent, claims-challenge,
cache, or integrity outcome. Serialization field names are not frozen by this vocabulary.

## V2-REQ-033: Opaque Access Tokens

Identity correctness must not depend on parsing access-token claims. Access tokens must
be treated as opaque bearer material.

## V2-REQ-034: Output Discipline

For an authentication invocation, stdout must be reserved for one terminal result in the
versioned structured protocol, including invalid-request outcomes. Human prompts, usage
text, and diagnostics must use separate, explicitly designated channels. The first
version must not provide alternative raw-token, header, or human-status output modes.

Non-authentication help entry points are outside the authentication stdout protocol.

## V2-REQ-035: Authentication Material Containment

Only a validated success result may expose an access token to the caller. Refresh tokens,
ID tokens, authorization codes, and reusable authentication artifacts must not be
returned. Authentication secrets must be confined to the authorized success field and
the provider, operating-system, or owned user-interaction channels required for
authentication. They must not appear in command-line arguments, logs, telemetry, or
V2-generated diagnostic, exception, or crash output.

## V2-REQ-036: Account Email Privacy

V2 must exclude raw request and provider-observed account emails, and stable identifiers
derived from them, from its diagnostics, logs, exception output, and telemetry.
Necessary authentication processing and secure authentication state may retain the
email. The command-line request and structured success result may carry the email as
required by their respective contracts.

This does not promise to hide command-line arguments from local process inspection.

## V2-REQ-037: Supported Protocol Compatibility

An update of AzureAuth Unofficial V2 must preserve the published request and result
contract of every protocol major version it continues to support, including accepted
argument meanings, defined result fields and outcomes, and exit-status semantics.
Breaking contract changes require a different protocol major version. This does not
promise indefinite support for an older protocol or compatibility with official
AzureAuth.

This preserves the calling contract of an unchanged adapter while its protocol major
remains supported. Protocol versioning is distinct from the V2 product-generation name.

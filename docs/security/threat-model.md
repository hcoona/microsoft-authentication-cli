# Preliminary Threat Model

## Scope

This threat model applies to the planned delegated public-client authentication engine.
It is preliminary and must be revised before implementation contracts are frozen.

The goal is to protect authentication intent, token material, account metadata, cache
state, machine protocols, and user interaction within a normal developer workstation
threat model.

The project does not claim to protect secrets after the current operating-system user
session, administrator, kernel, or authentication broker is fully compromised.

## Security Design Tradeoffs

Evaluate a mitigation against a concrete scenario, protected asset, credible attacker or
failure, and the trust boundary it crosses. Compare the risk reduction with implementation
complexity, ongoing maintenance, and operational cost. Prefer the smallest mechanism that
satisfies the accepted security requirements; speculative attack chains outside this
workstation threat model do not justify unlimited application hardening.

Within the stated threat model, rely on the documented protections of the operating
system, maintained authentication libraries, broker, and platform-secure storage. Review
the application's configuration and use of those contracts rather than building a second
implementation of their security guarantees. Missing or contradictory capability
evidence remains an integration question, not a reason to assume a stronger guarantee.

If the required trust or safety conditions cannot be established, fail closed at the
affected boundary using the existing result taxonomy. Bound recovery and cleanup to
state the engine owns and the effects it is authorized to perform. Do not broaden access,
repair unrelated account state, or invent additional services to handle an extreme case.
This preserves the requirements' permitted cache-miss recovery and validated success
with a persistence warning; those outcomes do not expose an unvalidated token.

Cost is not permission to weaken an accepted requirement. If a required journey cannot
be realized under these assumptions at reasonable cost, present the limitation and
tradeoff for repository-owner disposition. A broader threat model, reduced security
guarantee, or expanded product boundary needs an explicit accepted decision.

## Protected Assets

- Access tokens, refresh-token cache material, authorization codes, and device codes.
- Request and provider-observed account emails, internal provider account metadata, and
  token/resource-tenant identity.
- Client application and authority configuration.
- Interaction-policy decisions and acquisition-stage order.
- Secure reusable-state integrity, recovery, and persistence-warning accuracy.
- Machine-readable stdout and diagnostic stderr boundaries.
- Release artifacts, dependencies, update metadata, and imported upstream source.

## Trust Boundaries

- Calling process to CLI protocol boundary.
- CLI process to MSAL and native broker.
- Process to browser, device-code terminal, or other interactive surface.
- WSL process to Linux broker or Windows helper.
- Process to platform secure storage.
- Process to network identity and resource endpoints.
- Build and release environment to distributed artifacts.
- Fork source to Microsoft-owned application registrations and upstream code.

## Credible Threats and Governing Authorities

| Threat | Governing authority |
| --- | --- |
| A cached or operating-system default account silently overrides the requested account, or a same-email ambiguity is hidden by a persistent binding. | [`V2-REQ-012`](../product/requirements/request-identity-and-authority.md#v2-req-012-required-email-account-constraint), [`V2-REQ-020`](../product/requirements/strategy-interaction-and-host.md#v2-req-020-pre-resolved-account-for-silent-acquisition), and [`V2-REQ-022`](../product/requirements/strategy-interaction-and-host.md#v2-req-022-strict-result-identity) |
| A nominally silent request opens authentication or secure-state unlock UI. | [`V2-REQ-014`](../product/requirements/strategy-interaction-and-host.md#v2-req-014-explicit-per-request-interaction-permission), [`V2-REQ-021`](../product/requirements/strategy-interaction-and-host.md#v2-req-021-no-interaction-guarantee), and [`V2-REQ-025`](../product/requirements/strategy-interaction-and-host.md#v2-req-025-no-orphaned-work) |
| Ambiguous failure causes unsafe fallback to another identity or mechanism. | [`V2-REQ-023`](../product/requirements/strategy-interaction-and-host.md#v2-req-023-classified-fallback), [`V2-REQ-024`](../product/requirements/strategy-interaction-and-host.md#v2-req-024-request-bounded-claims-handling), and [`V2-REQ-032`](../product/requirements/result-and-process-protocol.md#v2-req-032-caller-action-failure-taxonomy) |
| A token or code leaks through arguments, logs, telemetry, crash output, or protocol noise. | [`V2-REQ-034`](../product/requirements/result-and-process-protocol.md#v2-req-034-output-discipline) and [`V2-REQ-035`](../product/requirements/result-and-process-protocol.md#v2-req-035-authentication-material-containment) |
| Email or a stable email-derived hash creates a diagnostic or telemetry identity trail. | [`V2-REQ-036`](../product/requirements/result-and-process-protocol.md#v2-req-036-account-email-privacy) |
| Another local user reads or modifies reusable state, unsafe state is consumed, or storage silently falls back to plaintext. | [`V2-REQ-040`](../product/requirements/cache-security-and-operational-identity.md#v2-req-040-secure-authentication-state) and [`V2-REQ-041`](../product/requirements/cache-security-and-operational-identity.md#v2-req-041-safe-reusable-state-recovery-and-concurrency) |
| Reuse across consumers confuses account, tenant, client, resource, or security contexts, or OS sign-in is mistaken for permission to use an opaque default. | [`V2-REQ-041`](../product/requirements/cache-security-and-operational-identity.md#v2-req-041-safe-reusable-state-recovery-and-concurrency), [`V2-REQ-020`](../product/requirements/strategy-interaction-and-host.md#v2-req-020-pre-resolved-account-for-silent-acquisition), and [`V2-REQ-022`](../product/requirements/strategy-interaction-and-host.md#v2-req-022-strict-result-identity) |
| Authentication work outlives cancellation or timeout. | [`V2-REQ-015`](../product/requirements/strategy-interaction-and-host.md#v2-req-015-common-deadline) and [`V2-REQ-025`](../product/requirements/strategy-interaction-and-host.md#v2-req-025-no-orphaned-work) |
| A WSL-launched prompt is hidden, unowned, or attached to the wrong desktop. | [`V2-REQ-016`](../product/requirements/strategy-interaction-and-host.md#v2-req-016-self-contained-interactive-authentication) and [`V2-REQ-021`](../product/requirements/strategy-interaction-and-host.md#v2-req-021-no-interaction-guarantee) |
| A Microsoft-owned client ID is mistaken for an owned credential or support contract. | [`V2-REQ-042`](../product/requirements/cache-security-and-operational-identity.md#v2-req-042-client-registration-as-configuration) and decision [`0003`](../decisions/0003-treat-client-registration-as-an-external-dependency.md) |
| A caller directs discovery or authentication to an attacker-controlled authority. | [`V2-REQ-011A`](../product/requirements/request-identity-and-authority.md#v2-req-011a-trusted-authority) |
| Home-tenant identity is mistaken for the requested resource tenant, or token parsing fabricates scope satisfaction. | [`V2-REQ-019`](../product/requirements/request-identity-and-authority.md#v2-req-019-tenant-selection), [`V2-REQ-027`](../product/requirements/request-identity-and-authority.md#v2-req-027-scope-satisfaction), and [`V2-REQ-033`](../product/requirements/result-and-process-protocol.md#v2-req-033-opaque-access-tokens) |
| Telemetry sends without explicit configuration or changes the authentication outcome. | [`V2-REQ-043`](../product/requirements/cache-security-and-operational-identity.md#v2-req-043-no-upstream-telemetry-reuse) and [`V2-REQ-046`](../product/requirements/cache-security-and-operational-identity.md#v2-req-046-optional-telemetry-semantics) |
| Dependency or upstream changes alter broker or cache behavior. | [Dependency Upgrade Matrix](../validation/strategy.md#dependency-upgrade-matrix) and [Release Gates](../validation/strategy.md#release-gates) |
| Unofficial artifacts overwrite or impersonate upstream AzureAuth. | [`V2-REQ-003`](../product/requirements/product-boundary.md#v2-req-003-unofficial-product-identity), [`V2-REQ-044`](../product/requirements/cache-security-and-operational-identity.md#v2-req-044-independent-distribution-identity), and decision [`0005`](../decisions/0005-establish-independent-operational-identity.md) |

## Security Policy References

Cache and operational-identity behavior is normative only in
[`cache-security-and-operational-identity.md`](../product/requirements/cache-security-and-operational-identity.md).
Protocol and diagnostic behavior is normative only in
[`result-and-process-protocol.md`](../product/requirements/result-and-process-protocol.md).
This threat model records why those requirements are security-relevant; it does not
restate them as an independent policy.

The explicit email in a command-line request is visible to local process inspection;
email privacy is a diagnostic and telemetry boundary, not a promise to conceal process
arguments. Non-enumerated same-email accounts and provider alias metadata remain
visibility limits, not justification for ambient-account fallback. The
[secure-store desk finding](../research/v1-public-contract-baseline.md#recheck-006-secure-store-availability)
is reported evidence, not proof that V2 recovery works on a platform.

## Security Validation Priorities

The normative release evidence requirements are defined by
[`validation/strategy.md`](../validation/strategy.md). Security review prioritizes its
strict-account, interaction, cancellation, cache, WSL, authority, output, dependency, and
artifact-isolation scenarios because they exercise the threats above.

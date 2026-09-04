# Preliminary Threat Model

## Scope

This threat model applies to the planned delegated public-client authentication engine.
It is preliminary and must be revised before implementation contracts are frozen.

The goal is to protect authentication intent, token material, account metadata, cache
state, machine protocols, and user interaction within a normal developer workstation
threat model.

The project does not claim to protect secrets after the current operating-system user
session, administrator, kernel, or authentication broker is fully compromised.

## Protected Assets

- Access tokens, refresh-token cache material, authorization codes, and device codes.
- Stable account identifiers, tenant identifiers, and account bindings.
- Client application and authority configuration.
- Interaction-policy decisions and acquisition-stage order.
- Cache integrity, logout state, and v2 cache-version migration state.
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
| A cached or operating-system default account silently overrides the requested account. | [`V2-REQ-012`](../product/requirements/request-identity-and-authority.md#v2-req-012-stable-account-constraint), [`V2-REQ-020`](../product/requirements/strategy-interaction-and-host.md#v2-req-020-selected-account-silent-first), and [`V2-REQ-022`](../product/requirements/strategy-interaction-and-host.md#v2-req-022-strict-identity-postcondition) |
| A nominally silent request opens WAM, a browser, or a device-code prompt. | [`V2-REQ-014`](../product/requirements/strategy-interaction-and-host.md#v2-req-014-independent-interaction-policy), [`V2-REQ-021`](../product/requirements/strategy-interaction-and-host.md#v2-req-021-no-interaction-guarantee), and [`V2-REQ-025`](../product/requirements/strategy-interaction-and-host.md#v2-req-025-no-orphaned-work) |
| Ambiguous failure causes unsafe fallback to another identity or mechanism. | [`V2-REQ-023`](../product/requirements/strategy-interaction-and-host.md#v2-req-023-classified-fallback), [`V2-REQ-024`](../product/requirements/strategy-interaction-and-host.md#v2-req-024-claims-challenge-preservation), and [`V2-REQ-032`](../product/requirements/result-and-process-protocol.md#v2-req-032-typed-failure-taxonomy) |
| A token or code leaks through arguments, logs, telemetry, crash output, or protocol noise. | [`V2-REQ-034`](../product/requirements/result-and-process-protocol.md#v2-req-034-output-discipline) and [`V2-REQ-035`](../product/requirements/result-and-process-protocol.md#v2-req-035-secret-channel-containment) |
| Another local user reads or modifies cache data, or secure storage silently falls back to plaintext. | [`V2-REQ-040`](../product/requirements/cache-security-and-operational-identity.md#v2-req-040-secure-storage-by-default) and [`V2-REQ-041`](../product/requirements/cache-security-and-operational-identity.md#v2-req-041-versioned-cache-semantics) |
| Authentication work outlives cancellation or timeout. | [`V2-REQ-015`](../product/requirements/strategy-interaction-and-host.md#v2-req-015-common-deadline) and [`V2-REQ-025`](../product/requirements/strategy-interaction-and-host.md#v2-req-025-no-orphaned-work) |
| A WSL-launched prompt is hidden, unowned, or attached to the wrong desktop. | [`V2-REQ-016`](../product/requirements/strategy-interaction-and-host.md#v2-req-016-explicit-host-context) and [`V2-REQ-021`](../product/requirements/strategy-interaction-and-host.md#v2-req-021-no-interaction-guarantee) |
| A Microsoft-owned client ID is mistaken for an owned credential or support contract. | [`V2-REQ-042`](../product/requirements/cache-security-and-operational-identity.md#v2-req-042-client-registration-as-configuration) and decision [`0003`](../decisions/0003-treat-client-registration-as-an-external-dependency.md) |
| A caller directs discovery or authentication to an attacker-controlled authority. | [`V2-REQ-011A`](../product/requirements/request-identity-and-authority.md#v2-req-011a-trusted-authority) |
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

## Security Validation Priorities

The normative release evidence requirements are defined by
[`validation/strategy.md`](../validation/strategy.md). Security review prioritizes its
strict-account, interaction, cancellation, cache, WSL, authority, output, dependency, and
artifact-isolation scenarios because they exercise the threats above.

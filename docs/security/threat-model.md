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
- Cache integrity, logout state, and migration state.
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

## Credible Threats and Required Controls

| Threat | Required control |
| --- | --- |
| A cached or operating-system default account silently overrides the requested account. | Resolve a stable account ID and validate the returned MSAL account and tenant. |
| A nominally silent request opens WAM, a browser, or a device-code prompt. | Enforce interaction independently from mechanism and fail before creating UI. |
| Ambiguous failure causes unsafe fallback to another identity or mechanism. | Use typed outcomes and explicit terminal versus retryable policy. |
| A token or code leaks through arguments, logs, telemetry, crash output, or protocol noise. | Transport secrets only through protected process memory and schema-controlled output; redact all diagnostics. |
| Another local user reads or modifies cache data. | Use platform secure storage, restrictive permissions, integrity checks, and atomic writes. |
| Secure storage is unavailable and the implementation silently falls back to plaintext. | Fail closed unless an explicit, separately accepted policy permits a bounded fallback. |
| Multiple processes create duplicate prompts or corrupt shared cache state. | Use request-appropriate cross-process coordination under the common deadline. |
| Cancellation or timeout returns while v2-owned acquisition work remains active. | Propagate cancellation, stop owned tasks, listeners, locks, and controllable prompts, and invalidate any externally owned browser flow. |
| A WSL-launched prompt is hidden, unowned, or attached to the wrong desktop. | Model WSL explicitly and require a validated host and parent-window strategy. |
| A Microsoft-owned client ID is mistaken for an owned credential or support contract. | Treat it as public external configuration, record ownership, and permit explicit replacement. |
| A caller directs discovery or authentication to an attacker-controlled authority. | Select authorities from supported Entra clouds or trusted profiles and retain MSAL authority validation. |
| Dependency or upstream changes alter broker or cache behavior. | Pin versions, record provenance, test real platform/account states, and review imports. |
| Unofficial artifacts overwrite or impersonate upstream AzureAuth. | Separate names, namespaces, signing, installation, telemetry, and update channels. |

## Cache Policy

The default cache policy must:

- prefer broker-owned or platform secure storage;
- partition state by relevant client, authority, tenant, and account dimensions;
- use cross-process coordination and atomic updates;
- detect and report corruption safely;
- define logout and account-removal behavior;
- version persisted state and document migration;
- avoid plaintext fallback unless a later decision defines the operating envelope,
  permissions, user notice, and acceptance criteria.

Cache compatibility with v1 is not assumed.

## Protocol and Diagnostic Policy

- Tokens, authorization codes, and secrets must never appear in command arguments.
- Machine stdout contains only the versioned result selected by the caller.
- Human prompts and diagnostics use explicitly owned channels.
- Error messages expose safe classifications, not raw broker, cache, tenant-policy, or
  token content.
- Test fixtures use synthetic values that cannot be mistaken for usable credentials.
- Remote telemetry is absent unless a future decision defines and owns it.

## Security Validation Priorities

Before a supported release, validation must include:

- strict-account mismatch and ambiguity;
- no-interaction behavior under every enabled mechanism;
- prompt cancellation, timeout, and concurrent callers;
- cache permissions, corruption, and migration;
- WSL host and UI ownership;
- authority-host and cloud-profile validation;
- stdout/stderr contamination and redaction;
- dependency upgrades affecting MSAL and native broker behavior;
- artifact provenance and installation isolation.

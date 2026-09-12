# Authentication Engine Threat Model

## Scope

This threat model applies to the delegated public-client authentication architecture and
the [concrete Windows Slice design](../designs/windows-ado-authentication.md). Its
application controls remain planned until implementation and validation; design review
does not mark them effective on a real platform.

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

The [request lifecycle view](../architecture/request-lifecycle.md#request-context-and-trust)
allocates application and dependency responsibilities across these boundaries. This
threat model owns their security assumptions and mitigation tradeoffs.

- Calling process to CLI protocol boundary.
- Explicit caller-managed local Profile file to the immutable request configuration.
- CLI process to MSAL and native broker.
- Process to browser, device-code terminal, or other interactive surface.
- WSL calling process to the explicitly selected Windows CLI through interoperability.
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

### Concrete Windows Slice

The selected design adds a nonsecret Profile-file input and specializes the existing
caller/CLI boundary with optional stdin-lifetime cancellation. The caller deliberately
selects the executable and local Windows Profile path. The engine reads one bounded
snapshot, validates the trusted cloud/client/tenant/integration constraints, and does not
search for configuration, follow a configuration URL, or import upstream state. Ordinary
Windows file permissions protect configuration within the stated same-user trust model;
signing or encrypting a public Profile file would not protect against the excluded
compromised current user and is not required.

WAM supplies reusable-state protection and integrity through its API. The Slice has no
app-owned token file, cache callback, cross-process lock, account binding, or repair
operation. Missing durable-write confirmation is represented accurately as a success
warning. No new persistence service or independent proof of broker internals is needed.

The owned Windows parent exists only for permitted interaction. WAM controls its own
credential/MFA/consent UI; the engine supplies an HWND and login hint, validates the final
result, forwards cancellation, and invalidates late completion. Provider prompt choice
is not an application security control. Unknown or terminal failures cannot activate a
PAT, alternate registration, browser, or account fallback.

The selected Native AOT design replaces the managed desktop host with finite static Win32
interop inside the same process. Explicit ABI/layout, callback lifetime, creating-thread
window destruction and nonblocking cancellation are review obligations; the unmanaged
boundary must not leak exceptions or accept a late success. Standard accessible controls
display bounded plain text and collect no credentials. Process DLL search must exclude
the current directory and ambient `PATH`, retaining only the application directory and
System32 before provider initialization. Validate the actual broker loader and every
required native asset under those restrictions; Native AOT alone supplies no dependency
integrity or DLL-loading guarantee. A conflict makes the affected target unavailable.

The native TMT model's process, UI, broker, caller, Profile and data flows do not change:
these are internal host and deployment mitigations of its existing execution, tampering,
disclosure and availability threats. The
[synthetic evidence](../research/experiments/windows-native-aot.md#diagnostic-round-05-results)
supports the bounded loader/allocation/observable-cleanup premise; it does not mark
product controls effective. The publishing choice is resolved at the design level.
The native model and its candidate dispositions remain unchanged, and complete-application,
Profile and security acceptance gates remain applicable.

The optional lifetime pipe gives a cooperating caller a concrete cancellation signal.
Its contract depends on ordinary writer-handle closure, not Linux-to-Windows signal
translation. Without that channel, the original deadline bounds a lost caller. A blocked
output pipe or uncooperative dependency may require process termination and incomplete
output. The caller must recognize that as transport failure. A one-second local shutdown
allowance cannot resume authentication or extend its deadline. This is the bounded
fail-closed response to the actual transport limitation, without an additional daemon.

Only the validated result contains a token. Fixed stderr indications and optional local
telemetry use an allowlist, have bounded buffering, and carry no email or authentication
material. Network telemetry is not selected. Externally owned Visual Studio registration
branding, consent, audit attribution, and availability remain explicit dependency limits
under the candidate Profile gate. The Slice scenario matrix tests these application
boundaries; actual company-account, .NET 10, first-use, WSL cancellation, and feed behavior
are not established by the existing personal-account probe.

The normative release evidence requirements are defined by
[`validation/strategy.md`](../validation/strategy.md). Security review prioritizes its
strict-account, interaction, cancellation, cache, WSL, authority, output, dependency, and
artifact-isolation scenarios because they exercise the threats above.

Research using existing account or broker state follows the
[experiment policy](../research/experiment-safety.md#environment-and-effects). Its accepted
protocol bounds observations, ordinary authentication updates, operator interaction, and
safe retention or cleanup. Using an existing environment neither changes the product
threat model nor authorizes access to unrelated state.

## TMT Analysis and Disposition

The checked-in [native model](authentication-engine.tm7) is the executable data-flow
input and candidate-disposition record for
[Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool).
This Markdown record owns the security assumptions, interpretation, and requirement
routing. The native model does not create a second product policy.

The model covers one CLI process containing the engine and MSAL, its caller, explicit
caller-managed Profile file, OS broker, user-interaction facility, platform-secure
reusable state, identity service, local diagnostic sink, and optional telemetry endpoint.
It has two boundary containers and 17 directed flows. MSAL is an in-process dependency;
a broker is an external OS facility.
The workstation boundary and CLI process/API boundary distinguish network trust from
local process and dependency responsibilities. They do not assert that every local
same-user process is a separately protected OS security principal. The secure-state role
does not select a V2 cache format or imply access to a broker's private store.

In the [selected WSL deployment](../architecture/overview.md#deployment-wsl-caller-and-windows-cli),
the existing caller is in WSL and the CLI process, broker, and eligible state are on
Windows. The caller/CLI flows model the request, optional lifetime pipe, and token
crossing that boundary; the Profile-to-engine flow supplies the selected configuration
snapshot. No forwarding process is introduced. WSL interoperability is
an operating-system dependency inside the workstation trust base. Executable selection,
output confidentiality, Windows UI ownership, and bounded process completion remain
relevant threats. The model records the design boundaries; it does not establish that an
implemented cross-host path is secure.

The generic interaction, state, and telemetry roles retain the wider architecture's
trust boundaries. In the concrete Windows Slice they specialize to WAM-owned interaction
and state, and local stderr telemetry; browser/device-code and network telemetry remain
unselected. They do not add components to the selected deployment. Resource access,
Git/package protocols, and credential translation remain with the caller. Build/release
threats remain in the narrative model above because they have a separate lifecycle from
this runtime diagram. No real account, tenant, token, or authentication observation is
stored in the model.

### Tool and Reproduction

On **2026-09-11 UTC**, the native model was opened and analyzed with installed Windows
TMT **7.3.51110.1** using **SDL TM Knowledge Base (Core) 4.1.0.11**. Both desktop Analysis
View and the tool's native model API generated the same candidate count. The embedded knowledge
base comes from Microsoft's
[public default template at `0ece9c7`](https://github.com/microsoft/threat-modeling-templates/blob/0ece9c71b6f3710b10d497bd1ef63e57805e7c3e/default.tb7).
The tool generated **96 candidates**. Analysis is a design review aid, not an
authentication experiment, implementation test, or proof of platform security.

Prefer a supported command-line analyzer when available. The official getting-started
and feature documentation consulted for this version did not identify one. This review
therefore used 32-bit Windows PowerShell in STA mode to load the installed TMT model,
view-model, and local-storage assemblies, initialize WPF, and open a separate model copy
with `ObjectModel(LocalFile, false)`. `ModelLoadHasIssues` was false;
`GenerateThreats()` and `ProcessModelImmediately(FullModel)` produced and reconciled all
96 candidates, followed by native `SaveAs` to a separate output. This is a version-specific
native API workflow, not a supported public CLI contract. The pull request records the
reproduction commands, input hash, tool/template versions, and observed counts.

Desktop reproduction remains possible by opening `authentication-engine.tm7` and switching
to Analysis View. The file embeds its template; importing an Azure template or regenerating
from Markdown is unnecessary. Review candidate justification and status in the native file
alongside the requirements linked above. Keep machine-specific author metadata out of
committed dispositions. Template upgrades may change the candidate set and require review;
zero findings is not an acceptance target. A Windows installation or analyzer job is not
required for every unrelated CI change.

### Candidate Dispositions

All 96 candidates have a scenario-specific or threat-family justification in the native
file. **76 are `NeedsInvestigation` and 20 are `NotApplicable`; none is marked `Mitigated`.**
`NeedsInvestigation` records planned application controls, dependency configuration, or
verification obligations. It does not mean that 76 new architectural feasibility
questions or observed vulnerabilities were found. Product implementation has not begun.

| Candidate group | Design disposition and verification focus |
| --- | --- |
| Spoofing and input tampering | Preserve explicit intent, select a real account, validate provider identity/tenant/scopes, use trusted authority and broker APIs, and bind completion to the request. Test wrong-default and unverifiable-success scenarios. |
| Token/state disclosure and store corruption | Use OS process boundaries, maintained OAuth/TLS integration, and platform-secure storage; preserve secret-free diagnostics, V2 state identity, and safe corruption recovery. No second OS-security subsystem or plaintext fallback. |
| Interrupted flows, process failure, and inaccessible storage | Bound work by the original deadline, classify failures, reject late results, and distinguish validated success from unconfirmed persistence. Optional telemetry failure cannot change the authentication result. |
| Execution-flow and privilege threats | Keep request parsing and policy explicit, use maintained dependency parsers, and introduce no privileged helper or impersonation service. Full compromise of the OS session/kernel/broker remains outside the declared threat model. |
| OAuth response CSRF candidates | Preserve the maintained OAuth implementation's state, PKCE, and redirect validation where applicable, plus V2-owned completion and final result validation. Do not implement a parallel OAuth verifier. |
| Generic nonrepudiation candidates (`R6`/`R7`, 16 items) | Not applicable: the engine promises typed results and sanitized diagnostics, not signed delivery receipts or an identity-rich audit ledger. Persistence-status accuracy remains applicable under the separate storage candidate. |
| CSRF on a CLI request or broker API result (IDs 11 and 28) | Not applicable to these non-browser-cookie endpoints. Their input-validation and spoofing concerns remain applicable under other candidates. |
| Profile disclosure through a spoofed receiver or weak store ACL (IDs 88 and 91) | Not applicable to confidentiality of deliberately nonsecret registration metadata. Profile integrity, executable selection, and authenticated output remain covered by applicable spoofing and tampering candidates. |
| Profile source substitution, parsing, interruption, and execution-flow threats (IDs 89 and 92–96) | Validate one bounded immutable local-file snapshot using a closed data-only schema; rely on Windows permissions within the stated trust model. Reject invalid or unavailable configuration without ambient search, partial defaults, executable extensions, account fallback, or state repair. Preserve request-owned account, scopes, interaction permission, and deadline. |

Generic template attribute defaults are question prompts, not observations that a
platform lacks TLS, memory protection, or secure storage. Dispositions evaluate the
actual flow and the declared dependency trust rather than mechanically adopting each
suggested control.

### Scenario Review Beyond STRIDE Generation

The template does not fully express strict full-email selection, no-interaction
permission, or validated-success/persistence-warning semantics. Review those directly
against the primary journey and the
[UML lifecycle](../architecture/request-lifecycle.md), including:

- a corporate OS default differing from the requested personal account;
- a silent request encountering authentication or secure-store unlock UI;
- a provider result with missing or mismatched identity metadata;
- a valid result with unconfirmed persistence, without waiting indefinitely or leaving
  V2-controlled work running;
- a late completion after cancellation or timeout;
- consumer changes that preserve authentication context and should reuse eligible state.

The [V1-to-V2 delta assessment](../research/v1-public-contract-baseline.md#architecture-reuse-and-remaining-deltas)
provides the dependency baseline for these checks. TMT cannot establish the specific
personal-account/Azure DevOps registration eligibility, first-use account visibility, or
real host cancellation behavior. Those focused integration questions retain their
existing evidence routes; the model does not enlarge them into a general hardening or
experiment program.

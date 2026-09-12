# Windows Azure DevOps Authentication Slice

This record owns the concrete Windows request implementation design and the protocol 1
command-line/process semantics. The linked JSON Schemas own serialized field shapes.
Requirements remain authoritative for required behavior; the
[architecture](../architecture/overview.md) owns system-wide boundaries. This is a
design record, not an activated Client Profile, executable, or support claim. The Native
AOT publishing disposition below retains an explicit preimplementation compatibility gap.

## Selected Boundary and Dependencies

A WSL caller explicitly launches one Windows executable for one authentication request.
The same request design covers a selected personal Microsoft account and a selected work
account. Git and Azure Artifacts use the caller-supplied Azure DevOps scope; repository,
organization, feed, and package operations stay with the caller. The engine returns the
original delegated access token. The [PAT prohibition](../product/requirements/product-boundary.md#v2-req-005-no-personal-access-tokens)
applies to every operation, configuration, and failure path.

| Choice | Concrete design and reason |
| --- | --- |
| Runtime and UI candidate | C# on .NET 10 LTS, `net10.0-windows`, `win-x64`; SDK 10.0.401 and runtime 10.0.12. A small in-process Win32 window replaces the Windows Forms host in the candidate design below. It requires no Windows Desktop managed framework. |
| Authentication dependencies | `Microsoft.Identity.Client` and `Microsoft.Identity.Client.Broker` 4.83.1, with `Microsoft.Identity.Client.NativeInterop` 0.20.3. Preserve the existing probe's authentication dependency baseline while changing the managed host. |
| Provider | Windows WAM only. One real-account discovery, at most one selected-account silent call, and at most one permitted interactive call. No application-level network retry or second provider. |
| State | Broker-owned reusable state; a fresh in-memory MSAL application per invocation. No MSAL Extensions cache helper, serialized MSAL cache, shadow refresh-token store, engine account binding, or cross-process lock. |
| Host | Windows 11 x64 in an active interactive user session, with WAM available. WSL 2 callers use normal Windows executable interoperability. Service, impersonated, disconnected desktop, and native Linux hosts are outside this Slice. |
| Distribution | Executable basename, installer, signing, and update channel remain release identities under the [registry](../governance/operational-identities.yaml). `<windows-cli>` below denotes the caller-selected executable, not a new installed command. |

The [dependency assessment](../research/v1-public-contract-baseline.md#windows-slice-dependency-and-host-contracts)
binds these choices to public source. .NET 10 compatibility is a design inference from
published framework contracts, not an observation from the .NET 8 probe. Future upgrades
must use the existing dependency review/validation matrix. No restore, build, or new
authentication experiment is part of accepting this design.

### Native AOT Target Disposition

The one executable and RID in this Slice have an **unresolved publishing choice** under
[V2-REQ-055](../product/requirements/quality-build-and-validation.md#v2-req-055-native-aot-publishing).
The preferred candidate is Native AOT with the Win32 host described here. No non-AOT
exception is accepted. Public contracts establish a plausible route, but do not yet
establish the complete pinned Broker/NativeInterop loading path under Native AOT. Keep
production publishing unselected and do not call the Slice implementation-ready until
that essential premise has a reviewed disposition. This is a concrete design and next
validation obligation, not permission to implement or publish it in the current Wave.

The [bounded synthetic investigation](../research/experiments/windows-native-aot.md#retained-native-artifact-runtime-results)
restored the exact .NET 10 graph, produced an x64 native EXE, and subsequently executed
that retained artifact on the Windows host through WSL. The positive case created MSAL
configuration and entered the upstream NativeInterop configuration-allocation path with
its module in the application directory. Missing-library and working-directory/PATH-decoy
cases both failed to load the module as expected. All three controllers completed normally.
The tested synthetic allocation/import and restricted-search premise is now supported
by runtime evidence for this artifact and host.

The historical publish-controller stop and unavailable AOT/trim warnings remain unresolved;
the runtime cases do not recover that evidence. Full provider/WAM/UI behavior, complete
native cleanup, wrong-architecture rejection and the actual application remain unvalidated.
The preferred host, production-publishing disposition and absence of a non-AOT exception
remain unchanged; these synthetic results do not make the whole design implementation-ready.

The [readiness supplement](../research/experiments/windows-native-aot.md#readiness-results)
subsequently restored the exact graph and produced another native x64 EXE with the
selected provider surface rooted for compilation. Its publish subject exited zero, but
one owned Job member remained and was terminated; final quiescence was confirmed. The
controller stopped before saving publish diagnostics. Its survivor identity and warning
status remain unknown, and no new runtime case ran. This is an experiment-lifecycle and
evidence blocker, not an observed compiler error or a publishing selection. The separately
bounded recovery must resolve those missing observations before the disposition changes.

The [public AOT assessment](../research/v1-public-contract-baseline.md#windows-native-aot-assessment)
distinguishes the following alternatives:

| Alternative | Disposition and reason |
| --- | --- |
| Existing Windows Forms host | Cannot be selected as a supported Native AOT route: Native AOT requires trimming, and Microsoft disables supported Windows Forms trimming because of built-in COM dependencies. Keeping this host would require a justified non-AOT exception; it is not necessary merely to own an HWND. |
| WPF replacement | Its documented trimming limitation does not resolve the blocker. |
| Small Win32 host with static interop | Preferred candidate: the required parent, public branding, completion and cancellation controls need only Win32 window APIs, an owned message loop, and statically known callbacks. This removes the managed desktop-framework blocker without another process or provider. |
| Larger UI framework or direct broker rewrite | No present UI requirement justifies another framework's dependency surface or replacing the supported MSAL integration with direct broker internals. Neither is needed to assess the smaller candidate. |
| Same Win32 host with ordinary self-contained JIT publishing | Future comparison baseline, not an accepted fallback or exception. Consider it only if the exact remaining AOT blocker cannot reasonably be remediated, with the requirement's evidence and reassessment obligations. |

The candidate project would enable `PublishAot` in its own project, retaining AOT/trim
analysis during development. It would not apply that property to the historical probe,
use blanket warning suppression, add dynamic plugins, or equate ReadyToRun/trimming with
Native AOT. Use source-generated P/Invoke for the finite owned Win32 API surface and
static `UnmanagedCallersOnly` callbacks with explicit ABI/layout. Built-in COM, runtime
code generation, reflection-based activation, and C++/CLI are not part of this host.

Read Profile JSON with a bounded `Utf8JsonReader`/explicit field reader, retaining the
existing duplicate-key, unknown-field, version, depth, and semantic validation. Write
result/event JSON from the existing field allowlists with `Utf8JsonWriter`; never serialize
arbitrary provider objects. These choices do not change the schemas or loosen input
validation. MSAL's own .NET 8 asset uses its generated JSON context; the separate Broker
asset targets .NET Standard 2.0 and does not inherit that AOT annotation automatically.

The public NativeInterop 0.20.3 package supplies a .NET 9 managed asset and `win-x64`
`msalruntime.dll`. The future resolved dependency graph must confirm the selected assets,
their public provenance, and all native transitive requirements. Do not assume the older
.NET Standard loader issue applies to the newer asset, or that package metadata proves
the newer loader works. Retain the three authentication pins while assessing this route.

Native assets belong in the application deployment directory with their notices. Before
provider initialization, constrain process DLL search to the application directory and
System32 with supported Windows loader controls; reject user-configured native paths.
Do not rely on the working directory, ambient `PATH`, development installations, runtime
extraction, or `Assembly.Location`. Do not enable direct P/Invoke for the broker library:
Native AOT's default binding and OS direct binding have different search semantics. The
exact upstream loader, its dependencies, and the process search restriction must be
validated together; an incompatible loader keeps the candidate unavailable rather than
silently weakening search rules or copying private runtime internals.

A future authorized publish protocol must pin the Windows x64 public native build chain
(Visual Studio C++ tools, Windows SDK, and `link.exe`), SDK/runtime inputs, resolved
NuGet graph, and publish properties before execution. Microsoft's documented Windows
prerequisite is Visual Studio 2022 or later with Desktop development with C++ and its default
components; this record does not select a floating installed compiler. No compiler is
installed by this design revision. Artifact closure must include the native broker and
OS prerequisites; an AOT executable does not imply one-file deployment or no OS dependency.
Debug symbols have a separate diagnostic/release treatment and are included when
comparing total development and distribution costs.

Resolve the remaining premise through the least costly separately authorized public
source or bounded synthetic publish/loading evidence. If that fails, investigate precise
supported dependency or host changes before proposing a scoped exception. Actual WAM,
account, UI and cancellation behavior still require the existing later Windows scenario
evidence even after a successful publish. The historical .NET 8 probe is unchanged.

### C4 Deployment View

This view answers which process owns authentication, configuration, and cancellation.
Blue nodes are engine-owned; gray nodes are caller or platform dependencies.

```mermaid
flowchart LR
    subgraph workstation["Developer workstation [Deployment node]"]
        subgraph wsl["WSL 2 distribution [Execution environment]"]
            caller["Git or package adapter<br/>[External system instance]"]
        end
        subgraph windows["Windows interactive user session [Execution environment]"]
            cli["Windows CLI + MSAL<br/>[Container instance: .NET 10 process]<br/>Native AOT candidate; compatibility unresolved"]
            profile[("Explicitly selected Profile file<br/>[External data store: caller-managed JSON]")]
            ui["Win32 parent and completion UI<br/>[Component in the CLI process]"]
            wam["WAM and protected reusable state<br/>[External OS system]"]
        end
    end
    identity["Microsoft identity platform<br/>[External system]"]
    resource["Azure DevOps Git / Artifacts<br/>[External system]"]
    caller <-->|Arguments, result, stderr, exit<br/>Optional stdin lifetime pipe| cli
    profile -->|One bounded read| cli
    cli -->|Permission-gated parent window| ui
    cli <-->|Real accounts, token operations, cancellation| wam
    wam <-->|Authentication and issuance| identity
    cli -->|Authority discovery through MSAL| identity
    caller -->|Direct token presentation and service operations| resource
    classDef owned fill:#1168bd,color:#fff,stroke:#0b4884
    classDef external fill:#e5e7eb,color:#111827,stroke:#6b7280
    class cli,ui owned
    class caller,profile,wam,identity,resource external
```

## Protocol 1 Command-Line Contract

Invoke `<windows-cli> authenticate` followed by the arguments below. Options and enum
values are case-sensitive. Use separate option and value arguments; short aliases,
`--name=value`, positional targets, response files, and repeated scalar options are
invalid. Windows argument quoting is the caller's responsibility; the engine consumes
the resulting argument vector without invoking another shell.

| Argument | Meaning |
| --- | --- |
| `--protocol 1` | Required protocol major. No implicit version. |
| `--profile <absolute-Windows-file-path>` | Required selection of one Profile document, not inline client configuration. |
| `--account-email <full-email>` | Required strict account constraint. |
| `--scope <qualified-scope>` | Required, repeatable for permissions on exactly one resource. |
| `--interaction non-interactive-only\|interactive-if-needed` | Required permission for the entire request. |
| `--tenant common\|<tenant-GUID>` | Optional; normalize under the selected Profile's tenant policy. |
| `--timeout-seconds <integer>` | Optional, 1 through 600 inclusive; default 120. One monotonic deadline measured from managed entry, including Profile reading and validation. |
| `--cancel-on-stdin-close` | Optional valueless lifetime flag. Use a dedicated caller-owned pipe whose writer remains open until completion or cancellation. EOF or pipe failure cancels the request. Stdin is never an authentication request or credential channel. |
| `--telemetry off\|stderr` | Optional, default `off`. Enables only the bounded local event stream described below; it does not configure network export. |

The [request schema](../../contracts/v1/request.schema.json) describes the parsed argument
projection for validators and synthetic cases; it is not a stdin-JSON API. Defaults are
applied only after syntax validation. Duplicate scopes are rejected rather than silently
rewritten. Unknown options, absent required options, malformed values, unsupported
versions, and conflicts with a Profile produce `invalid_request` before provider work.
No environment variable supplies request intent or Profile selection.

`help` and root `--help` are non-authentication entry points and may print help to stdout.
Every attempted authentication invocation, including malformed ones, uses the terminal
result contract. An unsupported or absent version returns a protocol 1 `invalid_request`
envelope with a safe reason; it does not echo the unsupported input. This bootstrap
failure envelope remains recognizable independently of later supported major versions.

### Scope and Email Normalization

Accept a nonempty full email with one `@` and no whitespace/control characters, up to
320 characters. Preserve spelling and compare the whole string using ordinal
case-insensitive equality. Do not strip aliases, fold dots, rewrite domains, apply
Unicode normalization, or create an account-kind selector.

Each scope must contain an explicit resource prefix and a final permission segment.
Split at the last `/`: the prefix must be a GUID or an absolute application-ID URI with
an authority, no userinfo, query, or fragment; the last segment must be nonempty. This
covers the Azure DevOps GUID prefix and URI resources such as `api://<application-id>`
without a resource catalog. Reject unqualified permissions and identity-protocol scopes
as caller resource targets. MSAL may add its own OAuth protocol scopes internally.
Require the same resource prefix in all requested scopes using ordinal equality; do not
guess equivalence between different resource spellings. `/.default` must be the only
scope. For dynamic scopes, compare full provider-reported scope strings using ordinal
equality, allowing extra granted scopes. Missing coverage fails closed. For `/.default`,
validate the request/result association for the same resource and operation rather than
expecting its literal spelling in returned permissions.

These are deterministic core rules with table-driven unit-test value. They do not parse
access tokens or infer service authorization.

## Profile Contract and Ownership

The [Profile schema](../../contracts/v1/client-profile.schema.json) owns configuration
fields. A Profile has its own `schemaVersion`, name, client ID, Public Cloud selection,
tenant policy, integration kind, and explicit registration ownership/support metadata.
Protocol major and Profile schema version are separate version spaces. The current
reader accepts version 1 only and rejects unknown fields and duplicate JSON keys.

`--profile` is the sole lookup mechanism. Open that file once, read at most 64 KiB as
strict UTF-8 JSON, validate it, and retain an immutable in-memory snapshot for the request.
The path must be an absolute drive-qualified path on a local fixed Windows volume;
relative, drive-relative, UNC, device, and Linux paths are invalid. No environment or home
expansion, directory search, URL retrieval, symlink-management policy, or Profile writer
is introduced. The caller owns file provisioning, permissions, update, and deletion;
the engine never modifies the file. Trust ordinary OS access control within the current
user threat model. A read error is `invalid_request` with a safe configuration reason;
an expired deadline remains `timeout`. Do not report raw paths or file contents.

Configuration is public and nonsecret, but its integrity matters. The explicit file
selection and strict semantic checks prevent accidental use of an unrelated registration.
The engine does not search upstream locations or import upstream configuration. WSL
callers convert their chosen file path to Windows form before invocation. This explicit
caller-managed file requires no engine-owned configuration namespace or persistent
configuration service.

The two integration values filter compatible provider behavior without choosing an
acquisition order:

- `windows-wam`: ordinary public-client WAM integration, with no MSA passthrough.
- `visual-studio-legacy-wam`: Public Cloud only, client ID exactly
  `872cd9fa-d31f-45e0-9eab-6e460a02d1f1`, multitenant policy, and the legacy mapping
  already defined by the [client-identity architecture](../architecture/client-application-identity.md#provider-mapping).
  Only this integration enables the provider's legacy MSA passthrough option.

Both derive the broker redirect URI as `ms-appx-web://microsoft.aad.brokerplugin/<client-id>`.
Authority validation is enabled, multi-cloud behavior is disabled, and the trusted cloud
host is `login.microsoftonline.com`. Profiles cannot supply arbitrary hosts, redirect
code, secrets, scopes, cache modes, ordering, deadline defaults, prompt preferences,
telemetry destinations, or PAT behavior. Unsupported integrations fail admission.

### Visual Studio Legacy Candidate

The named example in the Profile schema is the concrete candidate definition. It is
schema documentation, not an installed/enabled Profile. An implementation must not
silently materialize or select it. Any eventual provisioned file uses the same parser
and explicit path selection as a user-created file.

Microsoft owns the registration. AzureAuth and GCM publicly use it; this fork has no
upstream endorsement, support commitment, or control over account eligibility, consent,
policy, or availability. Authentication, consent, and audit records can identify the
Visual Studio application rather than this fork. The owned UI must identify the fork,
display the Profile name and external owner as bounded plain text, and explain that the
provider controls the ensuing sign-in/consent display. It must not impersonate Visual
Studio or promise a particular Security Key, PIN, or MFA choice.

State sharing under this registration is intentional only through WAM APIs and compatible
account, tenant, client, resource, and Windows-user context. It does not authorize reading
Visual Studio, AzureAuth, or GCM serialized caches. No app-owned persisted state exists
to collide with those products. Changing Profile names alone neither changes the OAuth
client identity nor creates a new broker cache partition.

Before activation/distribution, the existing
[external Profile gate](../product/compatibility-and-migration.md#externally-owned-client-profile-gate)
still needs bounded personal/work-account, host/redirect, consent/audit/branding, strict
result, and reuse evidence. Registration rejection returns the existing failure outcome;
there is no alternate registration, PAT, or SelfDescribing fallback. Those acceptance
obligations are distinct from selecting this candidate's concrete design.

## Cohesive Request Implementation

Use one executable and one request coordinator. The CLI parser/serializer, Windows host,
and MSAL adapter are dependency boundaries; pure account, tenant, scope, and terminal
outcome rules are ordinary functions. Do not create a service/container/plugin framework
for these responsibilities. A provider seam and a host/clock seam suffice for scenario
validation; the number of conceptual architecture boxes is not a class count.

### Admission and Provider Setup

1. Establish the monotonic request start, bounded deadline, cancellation latch, and one
   terminal-result gate. Parse and validate the arguments and Profile before any account
   discovery or authentication. Honor cancellation during admission.
2. Normalize tenant policy once. A fixed Profile uses its fixed GUID and rejects a
   conflicting selector. Multitenant omission becomes `common`; an explicit GUID remains
   an exact resource-tenant constraint throughout.
3. Construct a fresh `PublicClientApplication` using the chosen Profile and trusted
   cloud, with Windows broker enabled and `ListOperatingSystemAccounts = true`.
   Use no persistent cache callbacks, MSAL logging callback, default OS account sentinel,
   `cp1`, PoP, or username/password API. Keep provider PII/default logging disabled.
4. Check broker availability. The pinned availability API is obsolete but still present;
   confine that compatibility dependency to the adapter. Install a rejecting
   `ICustomWebUI` before any interactive call so an MSAL fallback cannot open a browser
   if broker availability changes. Do not implement an OAuth exchange in that callback.
5. Use the concrete `ClientApplicationBase.GetAccountsAsync(CancellationToken)` overload,
   which exists even though the interface's older overload omits cancellation. Thread
   the original request cancellation token into it and every token operation.

Profile/client identity is bound by the application instance and its request-local
operation context. It is not inferred from token text. Every candidate carries that
context back to the coordinator; a callback for another or ended operation is discarded.

### Resolution, Acquisition, and Failure Classification

Use MSAL's returned real accounts as the visible account set. Do not consult upstream
files, OS-account sentinels, a previous chosen-account binding, or a different source
after ambiguity. Count exact full-email matches: zero permits interaction only if the
host/Profile can perform it, one permits silent acquisition with that `IAccount`, and
more than one is terminal `account_ambiguous`. Missing account email is not a match.

For a unique real account, call `AcquireTokenSilent(scopes, account)` before considering
interaction. Preserve the normalized tenant constraint separately from the provider
route. Under the legacy integration and `common` only, a resolved MSA home-account tenant
selects the public transfer tenant `f8cdef31-a31e-4b4a-93e4-5f571e91255a` for silent use;
the initial authority is `organizations` with passthrough. An explicit resource GUID
always wins and is never replaced. This mapping comes from the existing architecture,
not from an email suffix or a new account-kind request.

Only no match or a classified `MsalUiRequiredException` can advance to the one interactive
call. With permission, establish the owned UI first, pass the requested email as login
hint, and use the same account when uniquely resolved. Forward an opaque claims challenge
only when it came from this request's silent exception. No caller claims payload,
cross-process continuation, automatic interactive retry, or browser/device-code path is
provided. MSAL/WAM may perform their own documented protocol steps within the original
cancellation/deadline boundary.

| Observation | Coordinator outcome/action |
| --- | --- |
| Admission or Profile semantic error | `invalid_request`; no provider call. |
| No visible match or provider interaction requirement | `interaction_required`, or the one compatible interactive call when permitted. |
| Multiple exact visible matches | `account_ambiguous`; no silent call or picker. |
| Broker unavailable, unsupported session, or rejected web fallback | `mechanism_unavailable`; no alternate mechanism. |
| Caller cancellation, owned-window close, or provider user cancellation | `cancelled`; no retry. The local cancellation/deadline latch determines its own origin before interpreting a provider cancellation code. |
| Recognized provider denial, including OAuth `access_denied` or AADSTS65004 | `denied`; no retry. Do not classify all service exceptions as denial. |
| Recognized network/service transient or provider `IsRetryable` hint | `temporarily_unavailable`; no application retry in this Slice. |
| Required result postcondition absent or mismatched | `identity_validation_failed`; discard the candidate token and stop. |
| Original deadline reached before complete validation | `timeout`; invalidate late completion. |
| Unrecognized provider/native failure or application defect | `internal_failure`; no fallback or raw exception export. |

Map codes through an explicit bounded table using structured provider codes/statuses,
never message substring parsing. Safe reason strings identify categories such as
`invalid_profile`, `consent_required`, `broker_unavailable`, `provider_denied`,
`provider_transient`, `metadata_missing`, or `provider_failure`; they never contain
arbitrary provider text. An interactive call that again requires interaction terminates
as `interaction_required`. State-related interaction requirements follow the same
permission policy; an unexplained broker failure does not authorize account deletion,
cache repair, or retries.

### UML Request Sequence

```mermaid
sequenceDiagram
    participant Caller as WSL caller
    participant CLI as Windows request coordinator
    participant UI as Owned Windows UI
    participant MSAL as Request-local MSAL application
    participant WAM as Windows broker and state
    Caller->>CLI: authenticate + explicit protocol/Profile/account/scopes/permission
    CLI->>CLI: Validate admission#59; establish original deadline
    CLI->>MSAL: GetAccountsAsync(original cancellation token)
    MSAL->>WAM: Discover eligible real accounts
    WAM-->>MSAL: Provider accounts
    MSAL-->>CLI: Visible account set
    CLI->>CLI: Count strict full-email matches
    alt Exactly one match
        CLI->>MSAL: AcquireTokenSilent(scopes, real account)
        MSAL->>WAM: Selected-account silent operation
        WAM-->>MSAL: Candidate or classified failure
        MSAL-->>CLI: Candidate or interaction-required
    else Ambiguous
        CLI-->>Caller: account_ambiguous#59; exit 1
    end
    opt No match or silent interaction requirement#59; permission allows interaction
        CLI->>UI: Create owned parent and completion context
        CLI->>MSAL: One interactive call with account/hint and same intent
        MSAL->>WAM: Interactive operation with owned HWND and cancellation
        WAM-->>MSAL: Candidate or failure
        MSAL-->>CLI: Candidate or typed provider observation
    end
    CLI->>CLI: Validate identity, tenant, client/context, scopes, and metadata
    CLI->>CLI: Classify already available persistence observation
    CLI->>UI: Close owned UI#59; invalidate acquisition completion
    CLI-->>Caller: One JSON result#59; success 0 or failure 1
    Note over Caller,WAM: Cancellation/deadline can terminate any pending path#59; external session changes are not rolled back
```

The diagram's success tail applies only to a candidate that passed validation. Ambiguity,
denial, cancellation, timeout, and invalid candidates do not continue to it.

### Authoritative Result and State Observations

Validate `AuthenticationResult.Account.Username`, `TenantId`, `Scopes`, `TokenType`,
`ExpiresOn`, nonempty access token, and operation context. Require the requested email,
the exact tenant when constrained, and the same client/cloud/resource context. Preserve
the provider's email spelling, tenant, token type, expiration, granted scopes, and
correlation GUID when nonempty. Reject already expired candidates; impose no additional
minimum remaining lifetime. Use provider metadata rather than parsing an access or ID
token in application code.

The public `authority` is the canonical Public Cloud authority URI formed from the
validated single-cloud operation and actual `TenantId`:
`https://login.microsoftonline.com/<actual-tenant-guid>`. It identifies the resulting
cloud/tenant, not a network trace, home-tenant claim, or the initial `common`,
`organizations`, or transfer routing alias. MSAL's public `AuthenticationResult` does
not expose a literal final endpoint URI; the contract does not invent one. A missing
actual tenant or unverifiable cloud association fails validation.

The adapter reports `wam` and whether the successful API operation was `silent` or
`interactive`. This describes the API used, not a claim about which MFA option the user
saw or whether an interactive API happened to complete without a visible prompt.

WAM owns persistence, locking, corruption handling, and account/session state. Use its
documented operations without inspecting its files or resetting accounts. A clean
interaction-required/miss indication may proceed through the normal permission gate;
an unusable or unverifiable candidate cannot succeed. There is no owned cache to repair.
The pinned public result has no per-request durable-write receipt, so successful results
carry `persistence_unconfirmed`. This warning does not claim persistence failed, disable
future reuse, or require a readback. Do no post-validation persistence I/O or waiting.

## Windows UI and Request Lifetime

The candidate uses a small Win32 window on an owned STA thread with a message loop only when
interaction is both needed and permitted. It supplies a stable nonzero HWND and explicit
cancel/close behavior. It does not ask for account email, passwords, URLs, or credentials;
those belong to the caller's request and provider UI. Parent WAM with that HWND, use the
specified login hint, and let WAM choose sign-in/MFA/consent methods. Failure to create the
owned parent makes the path unavailable before the interactive call.

The UI thread registers the window class and creates/destroys its HWND. Use standard
Windows text/button controls, keyboard navigation, accessible names and system visual
settings; show the bounded public branding/ownership text required above and an explicit
Cancel action. No custom credential form, embedded browser, COM automation or rich-text
rendering is needed. Accessibility and DPI/focus behavior remain host-validation cases.
Keep the window-procedure callback and request context alive through window destruction;
unmanaged callbacks must not unwind managed exceptions across the ABI boundary.

The coordinator awaits a ready HWND or a typed creation failure under the original
deadline before the one interactive call. Its asynchronous MSAL work must not block the
UI message pump with `.Result`, synchronous waits, or synchronous cross-thread window
messages. UI cancel/close signals the request cancellation latch. Terminal completion
invalidates the request context and posts owned-window closure to the creating thread;
that thread destroys its windows and quits its loop. A queued completion cannot recreate
UI or authorize success after cancellation. If creation, dispatch or destruction stalls,
the existing one-process shutdown watchdog remains the final bound.

### UML UI Ownership and Cancellation Sequence

```mermaid
sequenceDiagram
    participant C as Request coordinator
    participant U as Owned STA and Win32 message loop
    participant P as MSAL and WAM
    participant W as Process shutdown watchdog
    C->>U: Start only when interaction is needed and permitted
    U-->>C: Ready HWND or creation failure
    opt Ready before original deadline and request still active
        C->>P: One asynchronous interactive call with HWND and request token
        Note over U: Continue dispatching messages while provider work is pending
        alt Cancel, close, lifetime-pipe failure, or deadline
            U-->>C: Cancel/close notification when originating in UI
            C->>C: Latch cancellation/timeout and reject late success
            C->>P: Request cancellation
            C->>W: Enforce existing shutdown allowance
        else Candidate or failure completes
            P-->>C: Request-bound provider observation
            C->>C: Validate candidate and select terminal outcome
        end
        C->>U: Post closure with invalidated request context
        U->>U: Destroy HWND on creating thread and quit loop
        U-->>C: Closed
        Note over C,W: A stalled provider, UI, or output cannot extend process lifetime
    end
```

No visible window or prompt is created for a prohibited-interaction request. Broker
discovery and silent APIs are the eligible no-interaction operations; no opaque default
account call is used. The engine cannot promise that a malfunctioning OS is repaired by
application code. A dependency contract regression makes that combination ineligible.

The coordinator races provider completion against the original cancellation/deadline
latch. Cancellation sources are Windows console cancellation when delivered, owned UI
cancel/close, and EOF/failure on the optional lifetime pipe. With
`--cancel-on-stdin-close`, stdin must be a redirected pipe; reject a console or regular
file before provider work. The caller must retain the sole writer and avoid leaking it
to descendants. Data is not interpreted or logged; the reader only observes closure.
An already closed pipe cancels before authentication.

Without that flag, stdin is unused. WSL Linux signals and Linux parent-process death are
not assumed to become Windows cancellation notifications. A caller needing prompt
disconnect cancellation supplies the lifetime pipe; otherwise the finite CLI deadline
is the backstop, and a broken output pipe ends delivery when detected. Immediate detection
of an arbitrary Linux parent's death without a lifetime channel is explicitly unsupported.
Do not discover Linux process IDs, create listeners, or add a helper service to infer it.

On any terminal acquisition outcome, latch the outcome, reject later callbacks, cancel
the provider token, close owned UI, and stop initiating work. Deliver at most one result.
Caller cancellation observed before result commitment wins over a candidate success or
persistence warning. Deadline expiry before complete validation yields `timeout`;
incidental expiry after timely validation may use the requirements' success-or-timeout
latitude. Once delivery starts, a concurrent cancellation cannot rewrite a partial JSON
object: finish the selected result or terminate with incomplete output, never emit a
second object.

Anonymous-pipe I/O may block. Use dedicated bounded-lifetime I/O work and a process-level
shutdown watchdog, not an assumption that `WriteAsync` makes an anonymous pipe cancellable.
At cancellation or expiry, allow at most one second for local closure/result delivery;
no acquisition, retry, persistence wait, or renewed deadline occurs in this shutdown
interval. If owned cleanup or transport cannot finish, terminate the one process. OS
process termination releases its threads and handles; external WAM services remain OS
owned. A forced termination or incomplete write is a transport failure, not a fabricated
typed result. This is the exceptional fail-closed boundary, not a resident watchdog
process or a mechanism for making unsupported platforms work.

External broker windows/session changes are not forcibly rolled back. Forward cancellation
through MSAL, close the owned parent, invalidate completion, and write a fixed sanitized
completion/cancellation indication to stderr when available. Do not wait for the user to
dismiss an external surface before ending the CLI process.

### UML Terminal State View

```mermaid
stateDiagram-v2
    [*] --> Admission
    Admission --> Active: Valid arguments/Profile/host
    Admission --> Ending: Invalid request or cancellation
    Active --> Validated: Candidate passes all postconditions before deadline
    Active --> Ending: Failure, denial, cancellation, or timeout
    Validated --> Ending: Success with available persistence warning
    Validated --> Ending: Cancellation or permitted incidental timeout
    Ending --> Delivering: Latch outcome, invalidate callbacks, close owned UI
    Delivering --> Exited: Complete JSON and matching exit status
    Ending --> Exited: Shutdown watchdog or process termination
    Delivering --> Exited: Broken/blocked pipe or forced termination
    Exited --> [*]
```

## Result, Diagnostics, and Compatibility

The [result schema](../../contracts/v1/result.schema.json) defines one UTF-8 JSON object
followed by LF, with no BOM. Exit `0` means a complete `success` object; exit `1` is
shared by every complete typed failure. Failure objects contain no token or account
metadata. A success with `persistence_unconfirmed` still exits zero. Invalid/partial
JSON, process kill, absent output, or mismatched exit status is a caller-observed
transport/protocol failure and must not be converted into an engine outcome.

Build the result from an allowlist of fields, not by serializing an MSAL result or
exception. Only `accessToken` in a validated success may expose authentication material.
Do not emit refresh/ID tokens, claims, account IDs, raw exceptions, provider property bags,
or diagnostic email hashes. Keep stdout exclusively for that result.

Stderr carries bounded fixed human indications and, only with `--telemetry stderr`, local
JSON event lines containing `event`, `stage`, `outcome`, and elapsed milliseconds. Events
contain no token, email, path, Profile/client/account identifier, tenant, resource, scope,
claims, or provider text. This is optional local telemetry; network export and persistent
telemetry identifiers are not provided by this Slice. Bound pending diagnostic/event
output to 8 KiB, drop excess, never await a flush at result delivery, and ignore sink
failure without changing authentication or exit status. The process watchdog covers a
blocked diagnostic writer too. No upstream telemetry configuration is read.

Protocol 1 producers emit only the defined fields. Consumers must tolerate unknown
additional result fields but still validate the known outcome and required fields;
additive optional result metadata is compatible. Request and Profile readers reject
unknown inputs so typos cannot become silently ignored intent. Existing flags, defaults,
outcomes, and result meanings cannot be changed incompatibly while protocol 1 remains
supported. A breaking request/result change requires a new major; a breaking Profile
interpretation requires a new Profile schema version. No v1 AzureAuth compatibility is
implied, and no protocol is published as supported merely by merging this design.

## Validation and Explicit Unsupported Cases

The [Slice scenario basis](../validation/strategy.md#windows-slice-design-acceptance)
owns cases and required evidence. Contract examples are synthetic and demonstrate schema
shape only. Core normalization/selection/outcome rules receive unit tests; ordinary
orchestration is validated by scenario outcomes, provider calls, observed UI/lifetime,
and output effects rather than private class structure.

Unsupported in this Slice: native Linux/macOS authentication, WSL forwarding, non-Public
Cloud, Windows services/impersonation/disconnected sessions, ARM64, browser/device code,
PoP, confidential/workload credentials, PATs and derived-credential exchange, opaque OS
account selection, alias equivalence, stable account selectors, cross-process claims
continuation, shared-cache import/repair, logout/cache commands, duplicate-prompt
suppression, network telemetry export, Profile auto-discovery/activation, and immediate
Linux-parent-death detection without the lifetime pipe. Git clone and NuGet restore
remain downstream service tests, not operations of this engine.

Design acceptance requires complete contracts, scenario obligations, reviewed dependency
premises, and security/TMT consistency. Implementation, Profile activation, and platform
support each retain their later authorization and evidence gates. The existing personal
account probe is positive mechanism evidence for its .NET 8 host and state; it does not
replace future .NET 10, company-account, fresh-state, cancellation, or feed validation.

# Windows Slice Implementation Validation Evidence

This is a completed experiment record for
[Issue #108](https://github.com/hcoona/microsoft-authentication-cli/issues/108), retained as
evidence cited by current records. It authorizes no execution. The Delivery Wave grant it
ran under was completed and removed. The full protocol, call procedures, recipes,
allocations and accounting, source pins and execution history remain at the
[pinned revision](https://github.com/hcoona/microsoft-authentication-cli/blob/242cd292a10ee5626e783f42349e570c2e5a19a1/docs/research/experiments/windows-slice-validation.md).
Earlier controlled scenario results remain at the
[pre-cleanup revision](https://github.com/hcoona/microsoft-authentication-cli/blob/06ab8855e4fc4c3144852f4cadeb12086531c388/docs/research/experiments/windows-slice-validation.md).
The [experiment policy](../experiment-safety.md) governs any future experiment; another
run requires a new accepted protocol and authorization.

The [V1 baseline](../v1-public-contract-baseline.md) records the dated observations, exact
candidate hashes and accepted call revisions. The
[validation strategy](../../validation/strategy.md) owns the mapping from scenarios to
evidence, and the [Windows design](../../designs/windows-ado-authentication.md) owns the
parent selection. This record keeps only the observation methods and bounded conclusions
those records rely on.

## Common Observation Basis

All real calls used the designated Windows 11 x64 interactive user and, where stated, the
designated WSL2 Linux x64 caller. They used the existing owner-designated personal and
work roles, the experimental `visual-studio-legacy-wam` Profile, the Azure DevOps default
scope and existing broker state. Existing state is not clean first use, and ordinary
provider-managed session updates were permitted and retained.

- **Evidence channels.** Three channels stayed separate. Standard local OpenTelemetry
  stage events established observed request phases. Ordinary process handles and actual
  tool returns established process completion. Operator reports established visible WAM
  and human actions. Phase events and process exit do not prove visible UI, window
  attribution or provider-wide closure.
- **Result validation.** Token-bearing stdout was checked only on Windows, in memory, by
  the existing Windows-only result validator. It returned fixed protocol, outcome, route,
  identity and metadata conclusions. No token, result, account or tenant identifier,
  identifier hash, provider text or raw diagnostic entered Linux beyond bounded caller
  memory and pipes, agent output or Git.
- **Typed results.** A typed outcome required complete streams, a matching product exit
  and Windows-local validation. Product exit 2 or incomplete transport is a transport
  failure, not a typed result.
- **Limits.** These are existing-state observations on one host. They establish no
  durable persistence receipt, clean first use, another host's behavior, Profile
  distribution or support.

## Selected-Account Scenarios

**Method:** Real-account calls invoked the existing product directly as one ordinary
foreground Windows process per request. Observation used standard local telemetry and
Windows-local result validation, without a retained host, launcher, controller or custom
observer. Interaction was never forced to manufacture evidence: a validated
`InteractionRequired` ended a silent-first probe, and only a separately admitted
interactive call followed it.

**Runtime observation:** Native personal and work requests each obtained a validated
selected-account success and a fresh-process silent reuse (scenarios R1/R6 and R7/R8).
Actual WSL calls through ordinary interop then established complete result transport,
silent reuse and an initially closed lifetime pipe returning `Cancelled/None` with
exit 1 and no token. The baseline's selected-role observations record the dates, scopes
and candidates.

**Limits:** A silent route, no-interaction permission, telemetry or process exit alone
does not prove that no UI appeared. Reuse is fresh-process reuse of existing state, not a
durable-write receipt.

## Actual WSL Deadline Assessment

**Runtime observation:** Repeated one-second noninteractive WSL requests did not produce
a typed `Timeout`. They returned `MechanismUnavailable` with the fixed
`host_session_inactive` indication, or exit-2 transport failures. A diagnostic call
recorded a fixed `timeout` request completion after about one second while account
discovery had no observed completion, with product exit 2. A later personal
`interactive-if-needed` request on the corrected candidate returned validated
`Timeout/None`, exit 1, at its ordinary 120-second deadline. That observation
establishes an actual typed WSL timeout under the original deadline.

**Limits:** Caller intervals are not exact Windows entry or exit times. Phase events do
not establish which dependency was pending at expiry, the watchdog path or the cause of
an exit-2 failure. `host_session_inactive` establishes failure of the session's
Active-state gate, not its exact substate or physical cause. The operator did not watch
continuously during the timeout, so that call does not establish user cancellation or
visible WAM.

## Console Parent Feasibility

**Question:** Does an already installed PowerShell 7 process, launched from WSL, give a
console child an existing visible root parent that could serve as the WAM parent?

**Method:** Two credential-free foreground calls each ran once. WSL invoked Windows
PowerShell 5.1 x64 directly, and WSL invoked the installed PowerShell 7, which invoked the
same Windows PowerShell subject. A fixed script used `GetConsoleWindow`,
`GetAncestor(GA_ROOTOWNER)`, `IsWindow` and `IsWindowVisible` and emitted only eight
fixed Booleans. No authentication, account, Profile, cache, network or window creation was
involved.

**Runtime observation:** Neither launch shape gave the surrogate a console HWND or a
root-owner HWND. Both reports completed with exit 0 and empty stderr.

**Inference and limits:** Ordinary shell wrapping is not an established existing-console
parent source for this launch context. Windows PowerShell is a surrogate: the result is
not exact Native AOT product evidence, does not cover every WSL terminal, and does not
show that WAM requires a visible application window.

## Hidden Owned-Parent Candidate

**Question:** The [Windows design](../../designs/windows-ado-authentication.md) considered
keeping the existing owned top-level HWND hidden. Can that be done without a larger host
rewrite?

**Method:** An isolated experimental source omitted only the native show call in the owned
request host and set MSAL `BrokerOptions.Title` to
`Unofficial hcoona/microsoft-authentication-cli`. It kept the owned STA, message pump,
admission rechecks, cancellation latch and creating-thread cleanup.

**Synthetic observation:** Four existing credential-free Windows scenarios passed for the
hidden parent: readiness with immutable-Profile and thread checks, cancellation during
creation, internal close without caller cancellation, and completion waiting for actual
UI-thread exit.

**Runtime observation:** The first personal silent assessment returned
`MechanismUnavailable` without a retained reason. A diagnostic call identified
`host_session_inactive`. After the ordinary desktop connection action, a fresh
comparison returned `Success/Silent` and fresh-process `Success/Silent`, so the
conditional interactive case was skipped.

**Limits:** These results establish synthetic own-window lifecycle behavior and selected
request transport and reuse for the candidate. They neither validate nor reject
hidden-parent WAM presentation; the later
[interactive observation](#hidden-owned-parent-interactive-observation) addresses it.

## Windows Request Lifetime Dispatch Validation

**Synthetic observation:** After the request-lifetime dispatch correction, the corrected
visible-parent product was rebuilt and published as Windows x64 Native AOT. Twelve
existing credential-free Windows process scenarios passed: normal result despite broken
diagnostics, initially closed lifetime pipe, writer closure rejecting late success,
uncooperative deadline, six owned-host cancellation, fault, UI-thread and callback drain
cases, and two default HTTP cancellation and disposal cases.

**Limits:** Controlled providers and synthetic Profiles were used. These cases do not
establish real WAM cancellation, an actual WSL deadline, the cause of a real exit-2
failure or whole-Slice acceptance.

## Remaining WSL Lifetime and Action Cases

**Runtime observation:** On the selected visible-parent candidate, the work role
established three named cases:

- **Caller death without a lifetime pipe.** Caller-only SIGTERM ended the Linux caller
  with exit 143. An independently retained Windows process handle then observed native
  exit within the original bound. This establishes finite scoped Windows completion after
  caller death, not immediate signal delivery, a typed result or UI closure.
- **EOF during actual WAM.** After the operator confirmed an actual WAM surface, the
  caller closed its sole lifetime writer while the product was live. The result was
  validated `Cancelled/None`, exit 1, with no token. EOF did not close external WAM.
- **Human WAM cancellation.** The operator closed WAM, and the validated result was
  `Cancelled/None`, exit 1, with no token. This is WAM cancellation, not consent denial
  or owned-parent Cancel behavior.

Earlier attempts ended as alternatives, such as silent success, `host_session_inactive`,
timed-pipe cancellation without observed WAM, or failed observation. They remain
historical evidence at the pinned revision and do not satisfy these cases. One forced
interactive diagnostic returned fixed `error.type: broker_contract`, which established
the failure boundary rather than the offending parameter. One EOF attempt reached actual
WAM but failed acceptance when the result validator exited without conclusions; its
pinned runtime was then found absent, and the validator alone was bound to the installed
runtime without changing the product.

## Selected Visible-Parent UIA Observation

**Method:** A work-role WSL `force-interactive` call ran with a short PowerShell 5.1
STA script. Using standard Windows UI Automation, the script bound exactly one product
process and its one owned top-level window. It read only that window and its descendants
and could invoke the owned Cancel only when the parent and Cancel were enabled and on
screen. A prior manual-report attempt had ended in a timeout without physical evidence.

**Runtime observation:** The owned parent was found and its title matched. While WAM was
shown, the parent was disabled as WAM's modal owner, focus was not in the product, and
the owned Cancel was not actionable, so the script took no action. The operator cancelled
on WAM's own surface. The result was validated `Cancelled/None`, exit 1, with complete
transport and completion. The [owner's public report](https://github.com/hcoona/microsoft-authentication-cli/issues/108#issuecomment-6176150339)
adds that a private logical-DPI rendering showed the title, Profile, registration
owner, provider-control notice and Cancel without clipping, and that the window was
DPI-unaware at 96 DPI on a 192-DPI monitor.

**Inference and limits:** The notice told users to choose an owned Cancel that WAM
disabled while its prompt was shown. This one observation informed the owner's parent
selection decision. Owned Cancel, notice layout through UIA, keyboard navigation, focus
between the parent and WAM, physical readability and assistive-technology behavior were
not accepted or observed.

## Hidden Owned-Parent Interactive Observation

**Method:** A work-role WSL `force-interactive` call ran the merged hidden-parent
product. A read-only UI Automation check bound the product process and reported only
whether a product-owned top-level window was exposed. It read nothing from WAM and took
no action. The operator received the public unofficial project, Profile and owner context
beforehand.

**Runtime observation:** No product-owned top-level window was exposed, and the operator
saw no product window. WAM appeared, and the operator cancelled it on WAM's own surface a
few seconds later. The validated result was `Cancelled/None` with no token and product
exit 1, all created processes ended normally, and no residual window remained. The exact
pre-interaction notice line was written to stderr.

**Limits:** UI Automation shows that no product window was exposed, not that none
existed. The stderr notice shows delivery to the caller, not that a user saw it. The
operator did not report the WAM title or focus. Hidden-parent lifetime-pipe EOF and
deadline were not observed; accepted lifetime evidence is reused.

## Locked-State Non-Interactive Observation

**Method:** On this Remote Desktop host, a disconnected session is the locked state. It
shows the lock screen and has no input desktop. A Boolean-only check confirmed that
exactly one session of the current user was disconnected. A work-role WSL
`non-interactive-only` call then ran the hidden-parent candidate without a lifetime
pipe.

**Runtime observation:** The product returned validated `MechanismUnavailable/None` with
no token, the fixed `host_session_inactive` indication and exit 1, after only Profile
reading and account discovery and with no interactive stage. After reconnecting, the
operator saw no WAM, product window or unlock prompt.

**Limits:** On this host, a noninteractive request from a disconnected session is
rejected at local admission without a product, WAM or unlock surface. Broker behavior
under a connected lock screen or an expired credential was not observed.

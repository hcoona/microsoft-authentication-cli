# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Real-Host Validation and Threat-Model Re-Review (2026-10-15)

**Outcome:** For the current `main-v2` product, (1) obtain bounded real-host evidence on
the designated machine for the items listed below, recorded in a new accepted research
record and mapped in the validation strategy; and (2) re-review the native threat-model
candidate dispositions in `docs/security/threat-model.md` and
`docs/security/authentication-engine.tm7` against the implemented Slice. Release gates
stay tracked in [Issue #482](https://github.com/hcoona/microsoft-authentication-cli/issues/482);
this entry claims no release readiness or support.

Real-host evidence items:

- run the Windows scenario project (`tests/Authentication.Windows.Scenarios`) on the
  Windows host, including its host-timing scenarios;
- publish the Native AOT Windows x64 executable on the Windows host and check its native
  dependency loading under application-directory/System32 search;
- with that executable, native Windows and WSL-launched calls for the personal and work
  roles: silent-first success, fresh-process silent reuse, `non-interactive-only` with
  interaction required, `force-interactive` success, human WAM cancellation, caller
  lifetime-pipe EOF and the original deadline; each success also confirms whether the
  provider echoes the request correlation ID (CORE-01).

**Accepted inputs:** Windows 11 x64 interactive user on the designated host, its WSL2 Linux
x64 environment, .NET SDK 10.0.402 already installed on both, the installed Visual Studio
C++ toolchain and Windows SDK, MSAL/Broker 4.83.1 and NativeInterop 0.20.3, the
experimental `visual-studio-legacy-wam` Profile and the Azure DevOps default scope.

**Owner risk decision:** The repository owner accepts using the existing personal and work
accounts on that host, whose actual selectors stay local and are never committed.
Provider-managed sessions, broker state and caches may receive their ordinary
authentication updates and are retained. Each interactive case needs the owner at the
desktop for that call. A successful WSL-launched call returns the access token through
stdout to the trusted Linux caller's bounded process memory and ordinary interop pipes;
the owner accepts that exposure, while captured output, logs and agent traces still
exclude the token.

**Limits (circuit breakers, owner-raised twice):** At most 48 interactive-capable calls and 64
`non-interactive-only` product calls in total, counting failed and interrupted starts.
A call is interactive-capable when its interaction permission allows UI
(`interactive-if-needed` or `force-interactive`, including its cancellation, EOF and
deadline cases), whether or not UI appears. Synthetic scenario runs, builds and
publishes are not counted but stay within ordinary local resources. No automatic retry.
A case that existing account state cannot reach without an excluded state change is
recorded as not reached, never simulated.

**Delegated work:** Prepare, independently review and merge a research protocol before any
real call; build, publish and run on the host within it; record sanitized evidence;
update the validation strategy, Windows design and threat model with the results;
correct product defects and design records that the evidence exposes, with their tests,
inside this entry; re-review and re-disposition TMT candidates. A corrected build is a
new subject: rebind it through a reviewed protocol amendment before further real calls,
sharing the same limits.
The owner also authorizes one experiment-only product variant subject: forced
interaction that binds the discovered account and supplies no login hint, built from a
dedicated experiment branch that is never merged into main-v2, executed only under a
reviewed protocol amendment and sharing the same limits.

**Exclusions:** No account addition or removal, sign-out, consent revocation, cache
clearing or import, administrator consent, registration change, authenticated service
request beyond token acquisition, or remote mutation. No new dependency, SDK or runtime
version, no Profile activation or distribution, no release, signing or installer. No
tokens, account or tenant identifiers, raw provider diagnostics or screenshots with
private data in committed records, logs or chat.

**External effects:** Token acquisition against Microsoft Entra for the two existing
accounts with ordinary session/cache updates; public package restore; ordinary CI.

**Completion:** Remove this entry through a reviewed Wave change once both outcomes merge,
the call limits are exhausted, or the owner ends it.

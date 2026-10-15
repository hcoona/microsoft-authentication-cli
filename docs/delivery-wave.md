# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Review Remediation (2026-10-15)

**Outcome:** Resolve [Issue #474](https://github.com/hcoona/microsoft-authentication-cli/issues/474)
by completing exactly the items in its "Accepted remediation set", as recorded in the
Issue body updated at 2026-10-15T04:28:23Z (body SHA-256
`4991ce2b6da5c458294b9610beeaee1a05c28c707dcd34e39484d66381f735c2`). Later Issue edits
do not change this outcome.

**Delegated work:** Amend the requirements, architecture, design, threat-model,
validation and governance records the dispositions name; retire or compact completed
experiment records and migrate their consumers, links and controls to current
authorities; change the CLI, core and Windows adapter source and their scenario tests;
add a CI job that restores, builds and runs the platform-neutral
`tests/Authentication.Scenarios` project on Linux. Locally restore, build and run that
project and build the Windows projects with the pinned .NET SDK 10.0.402 from
NuGet.org without credentials. Apply the applicable control, review and independent
triage procedures.

**Owner decision:** Ordinary credential-free local restore, build and synthetic
scenario-test runs for this remediation, using the pinned SDK, NuGet.org and the existing
local package cache, are development validation rather than experiments under the
[experiment policy](research/experiment-safety.md); they need no separate protocol and
support no public-restore or real-platform claim.

**Exclusions:** No real-account, WAM, broker, interactive or Windows-host execution;
no Windows CI runner; no dependency, SDK or runtime change; no change to a concrete
Profile's selection or content or to a client registration (CORE-06/WIN-02 validation
tightening of Profile schema fields is in scope); no release, signing or distribution
identity.

**External effects:** None beyond repository changes, public package restore and
ordinary CI.

**Completion:** Remove this entry through a reviewed Wave change once the remediation
merges or the owner ends it.

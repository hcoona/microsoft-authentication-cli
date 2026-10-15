# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Review Remediation (2026-10-15)

**Outcome:** Resolve [Issue #474](https://github.com/hcoona/microsoft-authentication-cli/issues/474):
remediate the independently triaged findings of the 2026-10-15 multi-agent design and
implementation review according to the repository-owner dispositions recorded there.

**Delegated work:** Amend the requirements, architecture, design, threat-model,
validation and governance records the dispositions name; retire or compact completed
experiment records and migrate their consumers, links and controls to current
authorities; change the CLI, core and Windows adapter source and their scenario tests;
add a CI job that restores, builds and runs the platform-neutral
`tests/Authentication.Scenarios` project on Linux. Locally restore, build and run that
project and build the Windows projects with the pinned .NET SDK 10.0.402 from
NuGet.org without credentials. Apply the applicable control, review and independent
triage procedures.

**Exclusions:** No real-account, WAM, broker, interactive or Windows-host execution;
no Windows CI runner; no dependency, SDK, runtime, Profile or registration change; no
release, signing or distribution identity.

**External effects:** None beyond repository changes, public package restore and
ordinary CI.

**Completion:** Remove this entry through a reviewed Wave change once the remediation
merges or the owner ends it.

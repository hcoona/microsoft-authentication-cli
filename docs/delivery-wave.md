# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Engineering-Principle Review Remediation (2026-10-19)

**Outcome:** Items T1, P1, D1 and E1 to E7 of the "Accepted remediation set" in
[Issue #533](https://github.com/hcoona/microsoft-authentication-cli/issues/533), following
the repository-owner dispositions recorded in the Issue body as last edited at
2026-10-19T18:15:52Z (body SHA-256
`c312f850e360774f5f1fe976ec547368ad0e1f1b6888f698f82e5d7260bbcaa7`). Later Issue edits
do not change this outcome.

**Owner decision:** The repository owner approved this entry on 2026-10-19 and
delegated merging of this entry and of its implementing pull requests to the
implementation agent after independent review and triage. P1 amends the experiment
policy as the Issue records; it receives the governance-amendment review and the owner's
disposition in its pull request. Credential-free restore, build and synthetic scenario
runs on a contributor host or a GitHub-hosted runner, under the accepted
[development validation](research/experiment-safety.md#development-validation)
definition, are development validation and not experiments.

**Delegated work:** change `src/Authentication.Windows/MsalBoundary.cs`,
`src/Authentication.Core/RequestCoordinator.cs`, both scenario test projects' tests and
comments, the experiment policy, `CONTRIBUTING.md`, the validation strategy, the
Windows design, the request lifecycle, the threat model, the V1 public-contract baseline
and the Windows Slice validation record as those items require; apply the applicable
control, review and independent triage procedures.

**Exclusions:**

- No contract schema, result value, reason vocabulary or provider failure-mapping change.
- No real-account, WAM UI, broker sign-in, token acquisition or interactive execution on
  any host, and no Windows host run; Windows scenarios run only in CI.
- No change to `docs/security/authentication-engine.tm7`.
- No new record family or control.
- No SDK, runtime or NuGet package version change.
- No release, signing or distribution.
- No triage result outside the listed items is remediated.

**External effects:** None beyond repository changes, public package restore, tool
downloads verified by `mise.lock` or a uv lock, ordinary CI on GitHub-hosted runners,
and temporary build output.

**Completion:** Remove this entry through a reviewed Wave change once the items merge
or the owner ends it.

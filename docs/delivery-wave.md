# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

The three entries below share one owner decision, stated once here, and the work
carrier [Issue #523](https://github.com/hcoona/microsoft-authentication-cli/issues/523).
Each outcome is exactly the items its entry names from that Issue's "Accepted
remediation set", following the repository-owner dispositions recorded in the Issue
body as last edited at 2026-10-18T06:47:23Z (body SHA-256
`0f5addab2d1cdf27ecffb457630a696136cc42ae83d5a3cf9a6e52dc826a549d`). Later Issue edits
do not change these outcomes.

**Shared owner decision:** The repository owner approved all three entries on
2026-10-18. The following are development validation, not experiments under the
[experiment policy](research/experiment-safety.md):

- ordinary credential-free restore, build, Pkl evaluation and synthetic scenario runs,
  using the pinned SDK, NuGet.org and the existing local package cache, on a contributor
  host, the owner's Windows host or a GitHub-hosted runner;
- deterministic Windows API checks in those scenarios that read the current process or
  thread state, or that create the following under a fresh temporary root: temporary
  files, junctions, child processes, console process groups, and hidden windows owned
  by the test process and destroyed before it exits;
- the existing non-broker MSAL interactive scenario, under all of these conditions:
  - its HTTP client factory is a synthetic handler that returns canned responses and
    fails the test on any unexpected request;
  - it reaches `RejectingWebUi` without opening a browser, any window other than those
    owned by the test process, or any operator surface;
  - it uses no account or credential.

  Under those conditions the call is not token acquisition or interactive execution
  for the exclusions below;
- validation of `docs/security/authentication-engine.tm7` in Microsoft Threat Modeling
  Tool 7, as its record family requires, under all of these conditions:
  - it launches the tool already installed on the owner's Windows host, on the owner's
    interactive desktop, then opens, analyzes and saves a copy of the model under a
    fresh temporary root;
  - UI Automation reads and acts only on windows of the TMT process that the run
    started, identified by process ID, and stops if another window is in the foreground;
  - screenshots capture only the bounds of a TMT window while it is in the foreground
    and not overlapped, and the run stops if another window overlaps it;
  - screenshots are stored under the temporary root for private review, are never
    committed or published, and are deleted before the implementing pull request
    merges;
  - the run declines any update prompt;
  - if TMT does not close within 60 seconds after the close request, the run ends
    only the TMT process it started, identified by process ID.

These runs need no separate protocol and support no public-restore, real-platform or
support claim.

**Shared exclusions:**

- No real-account, WAM UI, broker sign-in, token acquisition or interactive execution on
  any host, and no network contact with an identity or authority-discovery endpoint.
- No TMT installation or update and no deliberate change to TMT settings. A repository
  change to the model comes only from reviewed text edits or from a save in the tool
  whose diff is reviewed.
- No tool-installation observation.
- No change to the result value `cancelled` or to the protocol name.
- No Profile selection or content, client registration, or operational-identity
  selection change.
- No SDK, runtime or NuGet package version change.
- No release, signing or distribution.
- No false-positive triage result from Issue #523 is remediated.

**Shared external effects:** None beyond:

- repository changes;
- public package restore;
- tool downloads verified by `mise.lock` or a uv lock;
- ordinary CI on GitHub-hosted runners;
- temporary files, processes and hidden windows owned by the development validation
  above;
- the TMT process and its windows on the owner's interactive desktop, closed after
  validation, TMT's own recent-file and application-data writes, and any update check
  the installed tool makes on its own, with any update prompt declined.

### W1: Result Delivery, Privacy and Request Parsing (2026-10-18)

**Outcome:** Issue #523 items R1 to R6.

**Delegated work:** amend V2-REQ-030, V2-REQ-036 and V2-REQ-046; change the Windows
design, request lifecycle, architecture overview, threat model, native threat model,
validation strategy, contract schema descriptions and the `public-contracts`
record-family concern as those items require; change the Core, Windows adapter and CLI
source and both scenario test projects; apply the applicable control, review and
independent triage procedures.

**Exclusions:** No contract field, outcome value or reason vocabulary change. R1
changes only which exit status accompanies an already complete result. R6 changes no
failure mapping; if a mapping change becomes necessary, stop and request a Wave
amendment.

**Completion:** Remove this entry through a reviewed Wave change once the items merge
or the owner ends it.

### W2: Governance, Record Authority and Experiment Policy (2026-10-18)

**Outcome:** Issue #523 items G1 to G12.

**Delegated work:** amend the governance and record-system policies, `controls.yaml`,
`record-families.yaml` and their schemas, `AGENTS.md`, `CONTRIBUTING.md`, the
experiment policy, the recheck registry, the compatibility policy, `project.md`,
V2-REQ-044, the product and architecture records, the threat model, native threat model
and the real-host validation record as those items require; change `hk.pkl`,
`.gitattributes`, `.editorconfig`, the CI workflow and the record checker; renormalize
the four package lock files to LF with no content change; apply the applicable control,
review and independent triage procedures. Each governance amendment receives explicit
repository-owner disposition in its pull request.

**Owner risk decision (G9 cleanup):** Remove the experiment-owned machine-local NuGet
configuration file from the owner's Windows host, under the experiment directory that
the real-host validation used. The user-wide credential-provider token cache is
pre-existing user state shared with unrelated work. It is neither read nor removed, and
the record says so.

**External effects:** In addition to the shared list, only the G9 removal above.

**Exclusions:** No new record family. No new control unless an item requires it and its
governance review accepts it.

**Completion:** Remove this entry through a reviewed Wave change once the items merge
or the owner ends it.

### W3: Validation Evidence, Tests and Hygiene (2026-10-18)

**Outcome:** Issue #523 items E1 to E8.

**Prerequisites:** E1's host rerun starts only after W1 merges, at the `main-v2` commit
it records. E4 starts only after W2 merges.

**Delegated work:** correct the validation strategy, threat model, native threat model,
design and other records named by those items; change the Windows scenario test project
and its test configuration, the Core scenario tests, the record checker's uv lock,
`hk.pkl`, `mise.toml`, `mise.lock`, the CI workflow and contributor guidance as E4
and E6 require; run the `WindowsHostTiming` scenarios once, plus at most one rerun under
the validation strategy's host-timing classification, on the owner's Windows host as
development validation, and record the result; apply the applicable control, review and
independent triage procedures.

**Exclusions:** E1 claims only synthetic host-timing evidence for the recorded commit.
It makes no real-account, Native AOT or support claim. E6 uses desk evidence only.

**Completion:** Remove this entry through a reviewed Wave change once the items merge
or the owner ends it.

# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Review Remediation (2026-10-17)

**Outcome:** Resolve [Issue #509](https://github.com/hcoona/microsoft-authentication-cli/issues/509)
by completing exactly the items in its "Accepted remediation set", following the
repository-owner dispositions recorded in that Issue body as created at
2026-10-17T04:08:57Z (body SHA-256
`052aeb89a1c391742d7a51043174c5863f3049c8016e18397af0968a40290790`). Later Issue
edits do not change this outcome. The outcome also includes the owner-approved additions
below.

**Owner-approved additions:** The repository owner approved the following on
2026-10-17:

1. **CD-5 lock entry.** Complete CD-5 by setting `IsAotCompatible` on
   `Authentication.Core` and accepting the one implicit `Microsoft.NET.ILLink.Tasks`
   entry that the SDK adds to `src/Authentication.Core/packages.lock.json`. That entry
   must have the same version and content hash as the entry already locked in the
   Windows and CLI projects.
2. **Help-text line endings.** Resolve
   [Issue #514](https://github.com/hcoona/microsoft-authentication-cli/issues/514): the
   CLI help text is byte-identical whatever the checkout line-ending setting. This
   may add a line-ending rule for C# sources to `.gitattributes`, or build the help text
   with explicit line feeds, or both.
3. **TMT validation of the model.** Validate `docs/security/authentication-engine.tm7`
   in its native format, as required by the threat-model record family's review point.
   Open a copy of the merged file and analyze it in Microsoft Threat Modeling Tool 7,
   which is already installed on the owner's Windows host. Drive the tool through
   Windows UI Automation.

**Delegated work:** Within that set:

- amend the requirements, architecture, design, contract-schema descriptions,
  threat-model, validation, research and governance records it names;
- move or compact research evidence, and migrate its consumers, links, record families
  and controls;
- change the Core, Windows adapter and CLI source and both scenario test projects;
- change `.gitattributes` and the Core lock file as additions 1 and 2 allow;
- change the record checker, hk configuration, CI workflows, contributor guidance, and
  the dependency metadata or lock files that RG-7 and CI-1 to CI-3 name;
- add the Linux build of `Windows.slnx` and a GitHub-hosted `windows-latest` CI job
  that runs the synthetic Windows scenarios;
- apply the applicable control, review and independent triage procedures.

**Owner decision:** The following are development validation, not experiments under the
[experiment policy](research/experiment-safety.md):

- ordinary credential-free restore, build and synthetic scenario runs, using the pinned
  SDK, NuGet.org and the existing local package cache, on a contributor host or a
  GitHub-hosted runner;
- deterministic Windows API checks in those scenarios that read the current process or
  thread state, or that create the following under a fresh temporary root: temporary
  files, junctions, child processes, console process groups, and hidden windows owned
  by the test process and destroyed before it exits;
- the TMT validation in addition 3, under all of these conditions:
  - it launches the installed tool on the owner's interactive desktop, then opens,
    analyzes and saves a copy of the model under a fresh temporary root;
  - UI Automation reads and acts only on windows of the TMT process that the run
    started, identified by process ID, and stops if another window is in the foreground;
  - screenshots capture only the bounds of a TMT window while it is in the foreground
    and not overlapped, and the run stops if another window overlaps it;
  - screenshots are stored under the temporary root for private review, are never
    committed or published, and are deleted before the implementing pull request
    merges;
  - the run declines any update prompt;
  - if TMT does not close within 60 seconds after the close request, the run ends
    only the TMT process it started, identified by process ID;
- TS-2's non-broker MSAL interactive call, under all of these conditions:
  - its HTTP client factory is a synthetic handler that returns canned responses and
    fails the test on any unexpected request;
  - it reaches `RejectingWebUi` without opening a browser, any window other than those
    owned by the test process, or any operator surface;
  - it uses no account or credential.

  Under those conditions the call is not token acquisition or interactive execution
  for the exclusions below.

These runs need no separate protocol and support no public-restore or real-platform
claim.

**Exclusions:**

- No real-account, WAM UI, broker sign-in, token acquisition or interactive execution on
  any host, and no Windows host-timing claim from CI.
- No network contact with an identity endpoint or authority-discovery endpoint.
- No dependency, SDK or runtime version change, except one RG-7 change to the record
  checker:
  - remove its unused `jsonschema` dependency;
  - lock its remaining dependencies (`PyYAML` and `markdown-it-py`) at their
    currently pinned versions, and their transitive dependencies at the versions that
    resolve from those pins, with no upgrade.

  The `check-jsonschema` tool is unchanged. Addition 1's single lock entry is also
  permitted.
- No TMT installation or update, no deliberate change to TMT settings, and no
  committed or published screenshot. TMT's own recent-file and application-data writes
  are permitted and may remain. A
  repository change to the model comes only from reviewed text edits or from a save in
  the tool whose diff is reviewed.
- No change to a concrete Profile's selection or content, or to a client registration.
- No operational-identity registry selection.
- No release, signing or distribution.
- No change to the host-admission diagnostic vocabulary tracked in
  [Issue #508](https://github.com/hcoona/microsoft-authentication-cli/issues/508).

**External effects:** None beyond:

- repository changes;
- public package restore;
- ordinary CI on GitHub-hosted runners;
- processes and hidden windows owned by the test process;
- the TMT process and its windows on the owner's interactive desktop, closed after
  validation;
- TMT's own recent-file and application-data writes, and any update check the
  installed tool makes on its own, with any update prompt declined;
- temporary files under the runner or contributor temporary directory. Scenarios remove
  their junctions before completing, including on failure. Other temporary files may be
  left for ordinary temporary-directory cleanup.

**Completion:** Remove this entry through a reviewed Wave change once the remediation
merges or the owner ends it.

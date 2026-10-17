# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Toolchain Alignment (2026-10-17)

**Outcome:** One source of truth determines the toolchain:

- The .NET SDK is pinned once in `mise.toml` and `mise.lock`. `global.json` is generated
  from that pin through an Apple Pkl source and is never edited by hand.
- Every product, test and tool project runs on exactly the runtime bundled with that
  SDK, 10.0.13 for SDK 10.0.402, with roll-forward disabled. No project, script or
  workflow states the runtime patch version separately, and no environment override
  rolls the runtime forward. Generated lock files do not count as separate statements.
- `shellcheck` and `pkl` are pinned in `mise.toml` and locked in `mise.lock` for
  linux-x64, windows-x64, and each other platform already in the lock for which the
  tool publishes a release. The CI jobs that use them install them from the lock.

This runtime-patch upgrade is not a Dependency Upgrade Matrix evaluation under the
validation strategy. It claims only CI synthetic evidence and supports no real-host,
Native AOT or support claim for 10.0.13.

**Approval:** The repository owner approved this on 2026-10-17. The approach follows the
generated `global.json` pattern of
[hcoona/three](https://github.com/hcoona/three/blob/main/global.pkl): a version is
derived where it is consumed, rather than duplicated and then compared by tests.

**Delegated work:**

- change `mise.toml`, `mise.lock`, `global.json`, a new Pkl source, the MSBuild props
  and project files, the package lock files that the runtime-patch change regenerates,
  `hk.pkl`, the CI workflow and contributor guidance;
- add a check that `global.json` matches its Pkl source, as a new control registered in
  `controls.yaml` and run by `hk.pkl`, subject to its governance review;
- remove the runtime roll-forward overrides from the CI workflow and the Windows
  scenario process fixture;
- update the current-state statements in the validation strategy, the Windows design,
  `controls.yaml` and `CONTRIBUTING.md` that name the runtime patch, roll-forward or
  the toolchain source;
- apply the applicable control, review and independent triage procedures.

**Owner decision:** The same classification as the 2026-10-17 remediation applies.
Ordinary credential-free restore, build, Pkl evaluation and synthetic scenario runs,
on a contributor host or a GitHub-hosted runner, are development validation and not
experiments.

**Exclusions:**

- No real-account, WAM, broker or interactive execution, and no real-host or Native AOT
  publish claim for the new runtime patch. Existing real-host and Native AOT evidence
  remains bound to the source revisions, SDK, runtime and runtime packs that its
  records name. It is not reinterpreted as evidence for the 10.0.13 configuration.
- No SDK change; the SDK stays 10.0.402.
- The Native AOT target disposition changes only its runtime pin. The implementing pull
  request records the RECHECK-008 evaluation.
- No NuGet package change except `Microsoft.DotNet.ILCompiler`,
  `runtime.win-x64.Microsoft.DotNet.ILCompiler` and `Microsoft.NET.ILLink.Tasks` in the
  package lock files, and the implicit runtime packs, all moving from 10.0.12 to
  10.0.13.
- No new runtime-version consistency test. Consistency comes from derivation; only the
  generated-file check above is added.
- Historical research records are not rewritten.
- No release, signing or distribution.

**External effects:** None beyond:

- repository changes;
- tool downloads verified by `mise.lock`;
- NuGet package downloads, verified by the package lock files where they are locked;
- public runtime-pack downloads that no lock verifies;
- ordinary CI on GitHub-hosted runners;
- temporary build output.

**Completion:** Remove this entry through a reviewed Wave change once the alignment
merges or the owner ends it.

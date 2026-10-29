# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Windows 0.1.0-alpha Prereleases (2026-10-29)

**Outcome:** Add a GitHub release workflow that builds the `azureauth-unofficial`
portable package from `main-v2` on a GitHub-hosted Windows runner, and publish
`0.1.0-alpha` prereleases from it as GitHub prereleases of this repository.
Packaging is tracked in
[Issue #506](https://github.com/hcoona/microsoft-authentication-cli/issues/506); release
gates stay tracked in
[Issue #482](https://github.com/hcoona/microsoft-authentication-cli/issues/482). The
prereleases claim no support, production readiness, compatibility, clean-machine
deployment or satisfaction of the validation strategy's release gates.

**Owner decisions:** The repository owner approved this entry on 2026-10-29 and decides:

- Workflow: started manually (`workflow_dispatch`) and refused unless the ref is
  `refs/heads/main-v2`; runs on a GitHub-hosted `windows-latest` runner with the
  checksum-pinned SDK from `mise.lock`; runs the Windows scenario project, then
  `packaging/windows/package.ps1` without `-AllowNonPublicRelease` or
  `-DisableNuGetAudit`; creates a GitHub build-provenance attestation for both zips;
  and creates a **draft** prerelease. Only the job that creates the draft receives
  `contents: write`, and only the job that attests receives `id-token: write` and
  `attestations: write`.
- Release identity: tag `v<version>`, where `<version>` is the computed SemVer 2.0
  version without build metadata (for example `v0.1.0-alpha.42`), on the built commit.
  Assets: the package zip, the symbols zip and their `.sha256` files. Release notes link
  the package README, state the unofficial, unsigned and unsupported status and the
  bundled Visual Studio Profile's limits, and link the release review.
- Publication: the repository owner reviews each draft and publishes it manually as a
  prerelease; publication is the owner's release decision. No local verification of a
  downloaded draft is required; Mark-of-the-Web, SmartScreen and Smart App Control
  behavior is not evaluated or claimed.
- Scope: this entry covers every `0.1.0-alpha` prerelease. A version other than
  `0.1.0-alpha.{height}`, a non-prerelease, or a change to the release workflow's
  inputs, permissions or assets needs a new entry.
- Risk: the owner accepts publishing unsigned executables, the bundled Visual Studio
  Profile under decision 0003's prerelease exception, and the native and managed symbol
  files of each build, and that completed downloads cannot be recalled.

**Delegated work:**

1. Add `.github/workflows/release.yml` as above, with actions pinned by commit SHA as in
   the existing workflow, and full Git history for version computation.
2. Records: update the support and release posture in `docs/governance/project.md`; the
   `update-channel` and `package-name` selection evidence in
   `operational-identities.yaml` (tag scheme, symbols zip); the Windows design's
   package section; the validation strategy's CI section and release-readiness note; the
   package README and root README where they say no package has been published; and
   `CONTRIBUTING.md`.
3. Release review for each prerelease, before the owner publishes the draft: an
   independent research-evidence review at the `release` execution point that
   evaluates the whole recheck registry, checks that the draft's assets match the
   workflow run's outputs and attestation, and checks that the symbols and executable
   embed no user-identifying build path; independent triage of any finding; recorded as
   a comment on Issue #506 that the release notes link.
4. Correct defects in the workflow, the packaging script or the records that a run
   exposes, with tests where applicable.

**Exclusions:** No real-account authentication, WAM UI or experiment on any host. No
signing, installer, MSIX, WinGet, Scoop, automatic update, PATH or registry integration,
non-`win-x64` artifact, or upload outside this repository's GitHub Releases. No
authentication behavior, result contract, request protocol or Profile change. No SDK,
runtime or dependency change. No tag or release outside the `v0.1.0-alpha.*` series, and
no release from a ref other than `main-v2`.

**External effects:** GitHub Actions runs on GitHub-hosted runners with public package
restore and tool downloads verified by `mise.lock`; build-provenance attestations
recorded in this repository and, for this public repository, in the public Sigstore
transparency log; public tags and GitHub prereleases with their assets (the owner can
delete them, but completed downloads and transparency-log entries cannot be recalled).

**Completion:** Remove this entry through a reviewed Wave change when the owner ends the
`0.1.0-alpha` series or replaces it with a new entry.

# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Windows Portable Package, Local Build and Test (2026-10-29)

**Outcome:** Make the current `main-v2` Windows product buildable as an unsigned
`win-x64` portable zip through a repository packaging script, build that zip locally on
the designated host, and record bounded real-host evidence for the exact built archive
after extracting it into a fresh directory. Packaging is tracked in
[Issue #506](https://github.com/hcoona/microsoft-authentication-cli/issues/506); release
gates stay tracked in
[Issue #482](https://github.com/hcoona/microsoft-authentication-cli/issues/482). A later
entry adds the GitHub release workflow and publishes the first prerelease from it. This
entry claims no support, production readiness, compatibility, clean-machine deployment,
public-restore reproducibility, or satisfaction of the validation strategy's release
gates.

**Owner decisions:** The repository owner approved this entry on 2026-10-28 and decides:

- Operational identities: product, command, and package name `azureauth-unofficial`;
  executable `azureauth-unofficial.exe`; archive
  `azureauth-unofficial-<version>-win-x64.zip`. There is no default installation root:
  the user extracts the archive into a directory of their choice, and deleting that
  directory uninstalls it. Diagnostic identity: the existing source name
  `hcoona.microsoft-authentication-cli`. Update channel: manual download from this
  repository's GitHub Releases, with no automatic update. Signing identity: none; the
  prerelease line ships unsigned
  ([Issue #505](https://github.com/hcoona/microsoft-authentication-cli/issues/505)).
  Configuration, cache, lock, and telemetry identities remain unselected because the
  package adds no persistent configuration, cache, lock, or remote telemetry.
- Version: Nerdbank.GitVersioning computes the SemVer 2.0 version
  `0.1.0-alpha.{height}+{commit}`, with `main-v2` as the only public-release ref. Builds
  from another ref carry the tool's commit-ID prerelease suffix.
- Bundled Profile: the archive contains the existing Visual Studio legacy compatibility
  Profile as a file. It is selected only through an explicit `--profile` argument and
  has no default selection. For the prerelease line, the owner accepts that sign-in,
  consent, and audit records attribute activity to the Microsoft-owned Visual Studio
  application, that Microsoft provides no support or availability commitment, and that
  the remaining items of the externally owned Client Profile gate stay open. The package
  README states these limits. Item 3 records this decision in decision 0003, the
  compatibility policy, and the client-application identity view, limited to this
  bundled file in prerelease archives.
- Real-host risk: the owner accepts using the existing personal and work accounts on
  the designated host. Provider-managed sessions, broker state, and caches may receive
  ordinary authentication updates and are retained. Each interactive call needs the
  owner at the desktop.

**Accepted inputs:** current `main-v2` source; .NET SDK 10.0.402 with runtime 10.0.13;
MSAL/Broker 4.83.1 and NativeInterop 0.20.3; Nerdbank.GitVersioning 3.10.94 as a
build-only package; the designated Windows 11 x64 host with its existing development
tools and package cache, and its WSL2 environment; the Azure DevOps default scope.

**Delegated work:**

1. Product: rename the executable; add Nerdbank.GitVersioning; replace the `0.0.0`
   User-Agent and ActivitySource versions with the computed SemVer version without
   build metadata; set the Windows file version resource; add `--version`, which prints
   the full version; update lock files and tests; set `fetch-depth: 0` in the existing
   CI jobs that build.
2. Packaging: under `packaging/windows/`, add the Profile file, a README (unofficial
   notice, extraction, a WSL invocation example, Profile ownership, unsigned and
   SmartScreen notes, uninstall), and third-party license notices. Add one packaging
   script that refuses a dirty worktree, restores in locked mode, publishes Native AOT,
   enforces an archive-content allowlist, checks that native imports come only from
   system DLLs and API sets, and writes the zip and its SHA-256.
3. Records: update `operational-identities.yaml`, decision 0003, the compatibility
   policy, the client-application identity view, the Windows design (distribution,
   Profile, `--version`, version mapping), the validation strategy, the threat model
   where it describes distribution, the record-family catalog for new governed records,
   `CONTRIBUTING.md`, the root README, and `docs/README.md`. Do not change
   `authentication-engine.tm7` or any candidate disposition, meaning a candidate's state
   or its justification text; if one needs to change, stop for a Wave amendment. The
   identity, Profile, decision 0003, and compatibility policy updates merge before or
   together with items 1 and 2, and before the item 4 protocol relies on them.
4. Real-host test: merge an independently reviewed protocol, then build the archive on
   the designated host from a recorded `main-v2` commit, extract it into a fresh
   directory, run help and version checks, and make native Windows and WSL calls for both
   roles. The cases form a coverage set: silent success, fresh-process silent reuse,
   `non-interactive-only` with interaction required, and `force-interactive` success.
   The protocol selects the combinations within the limits. A case that existing state
   does not reach is recorded as not reached and never simulated. Record whether Windows
   blocked the unsigned executable; this archive was never downloaded and has no
   Mark-of-the-Web, so the observation says nothing about a downloaded archive, and the
   README's SmartScreen notes rely on public Microsoft documentation. Record sanitized
   results in a research record and evaluate RECHECK-007 and RECHECK-008.
5. Corrections: fix packaging defects, and product defects that do not change
   authentication behavior, the result contract, or the request protocol, with tests.
   A defect that needs such a change stops the test and requires a new entry. Each
   corrected archive is a new subject, rebound through a reviewed protocol amendment and
   sharing the same limits.

**Limits:** At most 10 non-interactive and 3 interactive product calls in total across
all candidate archives, counting failed and interrupted starts. An interactive call is
any call whose interaction permission allows UI, whether or not UI appears; every other
product call is non-interactive. No automatic retry. Help and version checks, synthetic
scenario runs, builds, and packaging are not counted.

**Exclusions:** No GitHub release workflow, tag, GitHub Release, or upload or other
publication of a locally built archive. No installer, MSIX, WinGet, PATH, registry or
shell integration, signing, automatic update, non-`win-x64` artifact, Git credential
helper or other adapter, persistent configuration, cache or lock, or telemetry export.
No authentication behavior, result contract, or request protocol change other than
`--version`. No SDK, runtime, or MSAL upgrade, and no additional Profile. No account
addition or removal, sign-out, consent revocation, or cache clearing. No tokens, account
or tenant identifiers, raw provider diagnostics, or private screenshots in committed
records, logs, or chat.

**External effects:** Token acquisition against Microsoft Entra for the two existing
accounts with ordinary broker updates; public package restore; ordinary CI on
GitHub-hosted runners; one extraction directory on the host, deleted after the test.

**Completion:** Remove this entry through a reviewed Wave change once the packaging
changes and test evidence merge, the call limits are exhausted, or the owner ends it.

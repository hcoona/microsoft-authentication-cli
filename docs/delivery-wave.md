# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Engineering-Principle Review Follow-Up (2026-10-19)

**Outcome:** Items L1 to L5, S1 to S7, V1 to V5 and C1 to C5 of the "Accepted
remediation set" in
[Issue #538](https://github.com/hcoona/microsoft-authentication-cli/issues/538), following
the repository-owner dispositions recorded in the Issue body as created at
2026-10-19T21:50:19Z (body SHA-256
`d5ef37948a12fe7b7f67a047ca4efe24ee2cc59ef9c3d8df30f48ebb534f2dfb`). Later Issue edits
do not change this outcome.

**Owner decision:** The repository owner approved this entry on 2026-10-19. As the Issue
records, the implementation agent may merge the implementing pull request after
independent review and triage. L1, L2, L4, L5 and S1 change governance records, controls
or catalogs; they receive the governance-amendment review and the owner's disposition in
that pull request. L1 reverses the earlier retention of the public-build evidence chain.
Credential-free restore, build, Pkl evaluation and synthetic scenario runs on a
contributor host or a GitHub-hosted runner, under the accepted
[development validation](research/experiment-safety.md#development-validation)
definition, are development validation and not experiments.

**Delegated work:** delete the records, schemas, record families, control, portal rows,
policy exception and checker code that L1 and L2 name; change
`docs/research/v1-architecture-audit.md`, `docs/governance/record-system.md`,
`docs/governance/record-families.yaml`, `docs/governance/controls.yaml`,
`docs/README.md`, `tools/check_repository_records.py` and its uv lock, a new commit
message check script, `hk.pkl`, `mise.toml`, `.editorconfig`,
`.github/workflows/check.yml`, `CONTRIBUTING.md`, the threat model, the Windows
design, the client-application identity view, the validation strategy, the Windows
adapter source and both scenario test projects as those items require; apply the
applicable control, review and independent triage procedures. After merge, close
#12 as superseded.

**Exclusions:**

- No contract schema change, including its examples; if an existing example fails L3's
  validation, stop and request a Wave amendment.
- No result value, reason vocabulary or provider failure-mapping change.
- No change to `docs/security/authentication-engine.tm7`.
- No new record family. L5 is the only new control.
- No real-account, WAM UI, broker sign-in, token acquisition, or real interactive or
  broker authentication on any host, and no Windows host run; Windows scenarios run only
  in CI.
- No SDK, runtime, NuGet package, hk or other tool version change.
- No release, signing or distribution.

**External effects:** None beyond repository changes, closing #12, public package
restore, tool downloads verified by `mise.lock` or a uv lock, ordinary CI on
GitHub-hosted runners, and temporary build output.

**Completion:** Remove this entry through a reviewed Wave change once the items merge
or the owner ends it.

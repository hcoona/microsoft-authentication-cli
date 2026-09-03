# Contributing to AzureAuth Unofficial V2

**AzureAuth Unofficial V2** is an unofficial, pre-release fork. Contributions must remain
within the current project boundary and work authorization.

## Before Starting

1. Read the [project record index](docs/README.md).
2. Determine authorization from the target branch's accepted
   [`docs/project-state.md`](docs/project-state.md), normally the copy on `main-v2`.
3. Confirm that the change's activity class, boundary, and accepted prerequisites fit the
   work-authorization envelope.
4. Treat a working-branch change to that file as a proposal that cannot authorize
   additional work before merge.
5. Read the applicable Issue when one carries advance owner disposition, coordination,
   dependencies, an experiment, or stage-gate evidence. Otherwise, use the pull request
   as the bounded work carrier.
6. Read the canonical product, architecture, research, security, and validation records
   relevant to the change.

Do not add private company information, credentials, tokens, private account details, or
unpublished downstream evidence.

## Work Carriers and Concurrency

Use a separate Issue when work requires advance owner disposition, spans multiple pull
requests or contributors, coordinates dependencies, executes an experiment, or
contributes evidence to a stage gate. A bounded, low-risk, single-PR change inside the
accepted envelope may use the pull request itself as its work carrier.

An Issue or Milestone may plan future work but does not authorize execution outside the
accepted envelope. Starting or completing an ordinary in-envelope Issue does not require
a project-state update.

Independent in-envelope work may proceed concurrently. Work remains ordered when it
depends on an unaccepted result or changes the same canonical authority under conflicting
assumptions. Under the [roadmap](docs/roadmap.md), implementation of an accepted slice
may overlap requirements or architecture work for a later slice, but each slice must
pass its own lifecycle gates in order. If the target branch materially changes a
relied-on prerequisite or shared canonical authority, pause dependent work and refresh
its gate evidence, validation, and review before merge.

## Local Checks

Install the pinned repository toolchain and hooks:

```sh
mise install --locked
mise run hooks:install
```

The locked toolchain is supported on platforms represented for every required tool in
`mise.lock`. The pinned hk release has no Intel macOS binary; use CI or another supported
development host on Intel macOS.

The pre-commit hook runs the local fast set through hk. Run the complete CI-equivalent
set before requesting review:

```sh
mise run check
```

The hook fails closed while any unstaged or untracked path remains. Stage the final
intended snapshot or temporarily set other work aside before committing so repository-wide
path-based checks inspect the same tree Git will record.

## Pull Requests

A pull request should:

- state the repository outcome if merged;
- link the accepted project-state envelope, any applicable Issue, and governing records;
- define its scope and material non-goals;
- identify any record-system impact;
- distinguish evidence from inference and decision;
- provide the smallest validation that supports the claimed change;
- describe material security or external effects.

Not every change needs an Issue, decision record, design record, or documentation update.
Use them only when their repository policies or the work's coordination needs require
them.

## Review Routing

Before merge:

1. Consult [`docs/governance/controls.yaml`](docs/governance/controls.yaml) and run or
   request every control required by the change and its execution point.
2. Evaluate every fired entry in
   [`docs/research/rechecks.yaml`](docs/research/rechecks.yaml), even when no research file
   changed before the trigger.
3. For governance amendments, use the accepted target-branch versions of `AGENTS.md`, the
   governance policies, `controls.yaml`, and the applicable review Skill as the review
   authority. Treat proposed versions as review subjects until merge.
4. Send each material review finding to a reviewer independent of the originating
   review, change author, and implementation agent for triage before remediation or
   dismissal.
5. Obtain repository-owner disposition when an applicable control, unresolved finding,
   or owner-decision finding requires it.
6. Record the review, triage, recheck, and owner-disposition evidence in the pull request.

## Commits

Use Conventional Commits. Keep each commit focused on one human-reviewable semantic
concern and include a nonempty body and final footer block.

## Upstream Source

Follow [`UPSTREAM.md`](UPSTREAM.md) when copying or substantially deriving upstream
source. Preserve required copyright and license notices and record the exact source
commit.

## License

By contributing, you agree that your contribution is provided under the MIT License in
[`LICENSE.txt`](LICENSE.txt).

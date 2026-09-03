# Contributing to AzureAuth Unofficial V2

**AzureAuth Unofficial V2** is an unofficial, pre-release fork. Contributions must remain
within the current project boundary and work authorization.

## Before Starting

1. Read the [project record index](docs/README.md).
2. Determine authorization from the target branch's accepted
   [`docs/delivery-wave.md`](docs/delivery-wave.md), normally the copy on `main-v2`.
3. Confirm that one current entry authorizes the bounded advancement and that its
   accepted inputs, exclusions, and external-effects boundary fit the work.
4. Treat a working-branch change to that file as a proposal that cannot authorize
   additional work before merge.
5. Read the applicable Issue when work needs separate proposal, dependency, or progress
   coordination. Otherwise, use the pull request as the bounded work carrier.
6. Read the canonical product, architecture, research, security, and validation records
   relevant to the change.

Do not add private company information, credentials, tokens, private account details, or
unpublished downstream evidence.

## Work Carriers and Concurrency

Use a separate Issue when work spans multiple pull requests or contributors, coordinates
dependencies or progress, or benefits from separate proposal discussion. A bounded
single-PR change may use the pull request itself as its work carrier when its accepted
Wave entry already contains sufficient scope.

An Issue, Milestone, branch, pull request, comment, label, or unmerged Wave edit does not
grant or enlarge work authorization.

An explicitly repository-owner-approved pull request limited to adding, changing,
deleting, or replacing Delivery Wave entries may be prepared and reviewed without an
existing entry. Newly proposed work begins only after that change merges.

Independent authorized work may proceed concurrently. Work remains ordered when it
depends on an unaccepted result or changes the same canonical authority under conflicting
assumptions. Implementation requires accepted Slice requirements, applicable
architecture and contracts, a validation basis, explicit unsupported cases, and every
applicable domain precondition. Another authorized Slice may concurrently remain in
requirements or architecture work. If the target branch materially changes a relied-on
prerequisite or shared canonical authority, pause dependent work and refresh its gate
evidence, validation, and review before merge.

Before an experiment runs, its accepted Wave entry must bound the outcome and maximum
effects and its accepted protocol must define environment, isolation, observations,
repetition bounds, stop conditions, and cleanup. Repeated executions inside those bounds
do not require another owner approval. A material effects boundary requires the owner
risk decision defined by the experiment policy.

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
- link the accepted Delivery Wave entry, any applicable Issue, and governing records;
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

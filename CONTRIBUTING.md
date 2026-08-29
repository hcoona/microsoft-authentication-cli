# Contributing

This repository is an unofficial, pre-release fork. Contributions must remain within the
current project boundary and work authorization.

## Before Starting

1. Read the [project record index](docs/README.md).
2. Read [`docs/project-state.md`](docs/project-state.md).
3. Confirm that `docs/project-state.md` explicitly authorizes the work and, when it
   designates an active downstream Issue, that the work remains within that Issue.
4. Read the canonical product, architecture, research, security, and validation records
   relevant to the change.

Do not add private company information, credentials, tokens, private account details, or
unpublished downstream evidence.

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

The hook fails closed when a staged file also has unstaged edits. Stage the final intended
file content or temporarily set its unstaged edits aside before committing so path-based
checks inspect the same bytes Git will record.

## Pull Requests

A pull request should:

- state the repository outcome if merged;
- link the applicable Issue and governing records;
- define its scope and material non-goals;
- identify any record-system impact;
- distinguish evidence from inference and decision;
- provide the smallest validation that supports the claimed change;
- describe material security or external effects.

Not every change needs an Issue, decision record, design record, or documentation update.
Use them only when their repository policies require them.

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

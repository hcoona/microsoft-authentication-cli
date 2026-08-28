# Contributing

This branch is in a pre-implementation design phase. Contributions should improve the
public evidence, requirements, decisions, or validation plan unless
`docs/project-state.md` explicitly activates implementation work.

Before contributing:

1. Read `AGENTS.md` and the required records it identifies.
2. Confirm that the work is the current permitted task or is backed by an accepted
   decision.
3. Keep the change within delegated public-client authentication.
4. Use public sources only; do not add private company information, credentials, tokens,
   account details, or unpublished downstream evidence.

## Pull Requests

A pull request should:

- explain the problem and the bounded change;
- identify the governing project-state item or decision;
- state material non-goals;
- distinguish evidence from inference;
- describe identity, interaction, cache, output, host, and security effects;
- identify copied or derived upstream source and its exact commit;
- include the smallest validation that proves the claimed behavior.

Do not claim official Microsoft status, upstream support, production readiness, v1
compatibility, or ownership of a Microsoft application registration.

## Commits

Use Conventional Commits with a nonempty body and footer. Keep each commit focused on one
reviewable semantic concern.

## License

By contributing, you agree that your contribution is provided under the MIT License in
`LICENSE.txt`. Preserve upstream notices in copied or substantially derived material.

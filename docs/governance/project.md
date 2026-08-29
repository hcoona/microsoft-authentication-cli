# Project Governance

## Unofficial Status

`main-v2` is an unofficial fork line. It is not an official Microsoft Authentication CLI
release and has no upstream support, compatibility, service-level, release, or
security-response commitment.

The MIT License permits modification and redistribution subject to its notice. It does
not establish trademark rights, application-registration ownership, service entitlement,
or Microsoft sponsorship.

## Naming and Branding

The GitHub repository name is inherited from the fork relationship. A distributed v2
product must use an independently selected executable, package, installation, cache,
configuration, diagnostic, signing, and update identity.

Until those identities are selected:

- do not publish a binary as an official AzureAuth release;
- do not reuse upstream logos, signing identities, release badges, telemetry identities,
  or update channels;
- retain a prominent unofficial notice in public user-facing material.

## Support and Compatibility

The repository currently provides no published v2 release, production-readiness claim,
compatibility commitment, or service-level objective.

A future support claim must identify the exact release, platform, account state, client
application, mechanism, dependency set, and validation evidence to which it applies.

## Public Record Boundary

Committed rationale must use public source, public standards and documentation, public
Issues or pull requests, or reproducible sanitized experiments.

Do not commit credentials, private identities, internal company information, private
conversations, or unpublished downstream observations. If private information motivates
work, restate the public technical question and collect publishable evidence before using
it as repository rationale.

## Governance Authority

The repository owner decides product scope, risk acceptance, governance changes, and
whether a release is published.

Contributors and agents may propose changes and provide review evidence. Automated checks
and Agent Skills implement bounded controls; they do not make owner decisions.

Changes to governance follow [`governance-system.md`](governance-system.md).

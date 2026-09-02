# AzureAuth Unofficial V2 Project Governance

## Public Project Identity

**AzureAuth Unofficial V2** is the canonical public display name for this repository
project and its `main-v2` line. `Unofficial` is part of the name and must be retained when
an audience-facing entry point names the project.

The GitHub repository remains `hcoona/microsoft-authentication-cli` because its slug is
inherited from the fork relationship. That owner-qualified path identifies the source
repository; it is not the project display name.

The public display name does not select a future distributed product or any operational
identity. Those selections remain governed by
[`operational-identities.yaml`](operational-identities.yaml).

## Unofficial Status

**AzureAuth Unofficial V2** is an unofficial fork project. Its `main-v2` line is not an
official Microsoft Authentication CLI release and has no upstream support, service-level,
release, or security-response commitment.

The MIT License permits modification and redistribution subject to its notice. It does
not establish trademark rights, application-registration ownership, service entitlement,
or Microsoft sponsorship.

## Naming and Branding

The public display name does not authorize `AzureAuth`, `azureauth`, or a Microsoft
publisher namespace as an operational identifier. A distributed v2 product must use an
independently selected executable, package, installation, cache, configuration,
diagnostic, signing, and update identity.

Until those identities are selected:

- do not publish a binary as an official AzureAuth release;
- do not reuse upstream logos, signing identities, release badges, telemetry identities,
  or update channels;
- retain a prominent unofficial notice in public user-facing material.

## Support and Release

The repository currently provides no published v2 release, production-readiness claim,
or service-level objective.

A future support claim must identify the exact release, platform, account state, client
application, mechanism, dependency set, and validation evidence to which it applies.

Current compatibility and migration commitments are defined only in
[`compatibility-and-migration.md`](../product/compatibility-and-migration.md).

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

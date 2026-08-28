# Governance and Product Boundaries

## Unofficial Status

`main-v2` is an unofficial fork line. It is not an official Microsoft Authentication CLI
release and has no upstream support, compatibility, release, or security-response
commitment.

The MIT License permits modification and redistribution subject to preservation of its
notice. The license does not establish trademark rights, application-registration
ownership, service entitlement, or Microsoft sponsorship.

## Naming and Branding

The GitHub repository name is inherited from the fork relationship. The v2 executable,
package, installation, and product names remain undecided.

Until a naming decision is accepted:

- do not publish a binary named as an official AzureAuth release;
- do not reuse upstream logos, icons, signing identity, or release badges;
- do not describe the fork as endorsed, supported, or released by Microsoft;
- retain a prominent unofficial notice in user-facing material.

Modified versions must not cause confusion or imply Microsoft sponsorship. See the
[Microsoft Trademark and Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks).

## Namespace Separation

Before any distributable build, v2 must independently define:

- executable and package names;
- installation directories;
- cache files, keychain entries, and mutex or lock names;
- configuration and environment-variable prefixes;
- protocol identifiers and schema names;
- telemetry and diagnostic identities;
- signing and update channels;
- user-agent and version strings.

Sharing any v1 namespace requires an explicit compatibility and migration decision.
The provisional collision inventory is in [`namespaces.md`](namespaces.md).

## Telemetry

V2 sends no remote telemetry by default. The fork must not reuse an upstream Microsoft
Application Insights token, registry configuration, ingestion endpoint, or product
identity.

Local diagnostics may be designed separately, subject to the threat model and complete
secret redaction. Remote telemetry requires a new accepted decision covering ownership,
notice, data classification, retention, user control, and operational purpose.

## Compatibility and Support

The project currently provides:

- no SLA;
- no compatibility commitment;
- no published release;
- no production-readiness statement;
- no guarantee that a Microsoft-owned client registration will remain available;
- no promise to merge or continuously track upstream.

Claims may be added only after the corresponding implementation and validation evidence
exists.

## Public Record Boundary

Committed documentation must rely on public source, standards, documentation, issues, and
reproducible experiments. Do not publish internal company information, private
conversations, private identities, credentials, or unpublished downstream observations.

If a private observation motivates work, restate the public technical question and
collect publishable evidence before using it as repository rationale.

## Release Posture

No release should be published until:

- the product and namespace identity is resolved;
- the request/result contract is versioned;
- the supported platform and account matrix is explicit;
- security and validation gates pass;
- client-application dependencies are documented;
- installation and update paths cannot overwrite an upstream installation;
- artifacts have an independently controlled provenance and signing story.

The implementation build must also be reproducible on clean public infrastructure. The
audited upstream baseline clears public NuGet sources in favor of an authenticated Office
feed and references `Microsoft.Office.Lasso`; those dependencies must not be inherited
without a publicly reviewable replacement or distribution basis.

# AzureAuth Unofficial V2 Project Records

This index routes human readers to the primary canonical project and domain records. It
is navigation, not an independent authority.

## Current Work

| Audience | Authoritative subject | Canonical record |
| --- | --- | --- |
| Contributors, agents, and repository owner | Current bounded work authorization | [`delivery-wave.md`](delivery-wave.md) |

## Product and Engineering

| Audience | Authoritative subject | Canonical record |
| --- | --- | --- |
| Product owner, maintainers, and contributors | Product purpose and directional boundary | [`product/vision.md`](product/vision.md) |
| Product maintainers, implementers, and reviewers | Product scope, supported scenarios, and exclusions | [`product/requirements/product-boundary.md`](product/requirements/product-boundary.md) |
| Product maintainers, implementers, and reviewers | Request identity, authority selection, and account constraints | [`product/requirements/request-identity-and-authority.md`](product/requirements/request-identity-and-authority.md) |
| Product maintainers, implementers, and reviewers | Strategy ordering, interaction policy, and host integration | [`product/requirements/strategy-interaction-and-host.md`](product/requirements/strategy-interaction-and-host.md) |
| Product maintainers, implementers, and reviewers | Result shape, process behavior, and compatibility protocol | [`product/requirements/result-and-process-protocol.md`](product/requirements/result-and-process-protocol.md) |
| Product maintainers, implementers, and reviewers | Cache, security, and independent operational identity | [`product/requirements/cache-security-and-operational-identity.md`](product/requirements/cache-security-and-operational-identity.md) |
| Product maintainers, implementers, and reviewers | Quality, build, packaging, and validation constraints | [`product/requirements/quality-build-and-validation.md`](product/requirements/quality-build-and-validation.md) |
| Product owners and release planners | Compatibility promises, migration rules, and support gates | [`product/compatibility-and-migration.md`](product/compatibility-and-migration.md) |
| Architects and implementers | Component boundaries, dependency direction, and target runtime views | [`architecture/overview.md`](architecture/overview.md) |
| Architects and security reviewers | OAuth client-registration ownership and profile structure | [`architecture/client-application-identity.md`](architecture/client-application-identity.md) |
| Security reviewers and implementers | Threats, trust boundaries, and required mitigations | [`security/threat-model.md`](security/threat-model.md) |
| Test and release maintainers | Evidence required for validation and support claims | [`validation/strategy.md`](validation/strategy.md) |
| Architects, maintainers, and reviewers | Establishing `main-v2` as an orphan line | [`decisions/0001-establish-main-v2.md`](decisions/0001-establish-main-v2.md) |
| Architects, maintainers, and reviewers | Rebuilding the authentication core | [`decisions/0002-rebuild-the-authentication-core.md`](decisions/0002-rebuild-the-authentication-core.md) |
| Architects, maintainers, and reviewers | Treating client registration as an external dependency | [`decisions/0003-treat-client-registration-as-an-external-dependency.md`](decisions/0003-treat-client-registration-as-an-external-dependency.md) |
| Architects, maintainers, and reviewers | Separating the authentication engine from consumers | [`decisions/0004-keep-the-authentication-engine-separate-from-consumers.md`](decisions/0004-keep-the-authentication-engine-separate-from-consumers.md) |
| Architects, maintainers, and reviewers | Establishing an independent operational identity | [`decisions/0005-establish-independent-operational-identity.md`](decisions/0005-establish-independent-operational-identity.md) |

## Research and Upstream

| Audience | Authoritative subject | Canonical record |
| --- | --- | --- |
| Architects and research reviewers | Evidence for not using the v1 core as the v2 foundation | [`research/v1-architecture-audit.md`](research/v1-architecture-audit.md) |
| Experiment authors and reviewers | Experiment authorization, isolation, safety, and evidence rules | [`research/experiment-safety.md`](research/experiment-safety.md) |
| Public-build evidence maintainers and reviewers | Fixed solution targets, source dependencies, and build-stage applicability | [`research/public-build-source-baseline.json`](research/public-build-source-baseline.json) |
| Public-build evidence maintainers and reviewers | Fixed source-level Lasso usage manifest | [`research/public-build-lasso-reference-manifest.json`](research/public-build-lasso-reference-manifest.json) |
| Public-build evidence consumers and reviewers | Recorded WSL2-Linux-x64 public-build runtime evidence and its reproducibility contract | [`research/experiments/public-build-wsl2-linux-x64-dotnet-8-0-424.json`](research/experiments/public-build-wsl2-linux-x64-dotnet-8-0-424.json) |
| Public-build evidence maintainers and reviewers | Retained public-only dependency inputs admitted by the current singleton receipt | [`AdoPat`](research/experiments/assets/public-build-wsl2-linux-x64-dotnet-8-0-424-public-only-target-adopat-net8-0.project.assets.json), [`MSALWrapper`](research/experiments/assets/public-build-wsl2-linux-x64-dotnet-8-0-424-public-only-target-msalwrapper-net8-0.project.assets.json), and [`TestHelper`](research/experiments/assets/public-build-wsl2-linux-x64-dotnet-8-0-424-public-only-target-testhelper-net8-0.project.assets.json) |
| Research and release reviewers | Mutable public facts and their recheck triggers | [`research/rechecks.yaml`](research/rechecks.yaml) |
| Maintainers and upstream-source consumers | Upstream baseline and import policy | [`../UPSTREAM.md`](../UPSTREAM.md) |

## Governance

| Audience | Authoritative subject | Canonical record |
| --- | --- | --- |
| Rule authors, control maintainers, and reviewers | Creation, amendment, enforcement, and retirement of governance rules | [`governance/governance-system.md`](governance/governance-system.md) |
| Record authors, maintainers, and reviewers | Repository record authority, lifecycle, format, and enforcement | [`governance/record-system.md`](governance/record-system.md) |
| Record-system automation and reviewers | Current and scheduled record-family routing | [`governance/record-families.yaml`](governance/record-families.yaml) |
| Contributors, automation, and reviewers | Controls that implement governing policies | [`governance/controls.yaml`](governance/controls.yaml) |
| Contributors and public readers | Project identity, unofficial status, and public-record boundary | [`governance/project.md`](governance/project.md) |
| Packaging and runtime maintainers | Independent executable, package, cache, configuration, and release identities | [`governance/operational-identities.yaml`](governance/operational-identities.yaml) |
| Human contributors | Contribution and review workflow | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |
| Security reporters | Vulnerability reporting process | [`../SECURITY.md`](../SECURITY.md) |

## Workflow and Machine Contracts

| Audience | Authoritative subject | Canonical record |
| --- | --- | --- |
| Change authors and reviewers | Pull-request evidence and disposition prompts | [Pull-request template](../.github/pull_request_template.md) |
| Record-system automation | Record-family catalog schema | [`record-families.schema.json`](../schemas/governance/record-families.schema.json) |
| Control automation | Control catalog schema | [`controls.schema.json`](../schemas/governance/controls.schema.json) |
| Packaging and runtime automation | Operational-identity registry schema | [`operational-identities.schema.json`](../schemas/governance/operational-identities.schema.json) |
| Research automation | Mutable-source recheck schema | [`rechecks.schema.json`](../schemas/research/rechecks.schema.json) |
| Public-build source-audit automation | Public-build source-baseline schema | [`public-build-source-baseline.schema.json`](../schemas/research/public-build-source-baseline.schema.json) |
| Public-build source-audit automation | Public-build Lasso-reference schema | [`public-build-lasso-reference-manifest.schema.json`](../schemas/research/public-build-lasso-reference-manifest.schema.json) |
| Public-build evidence automation | Retained `project.assets.json` evidence schema | [`public-build-assets-evidence.schema.json`](../schemas/research/public-build-assets-evidence.schema.json) |
| Public-build evidence automation and reviewers | Strict-JSON recorded public-build evidence and historical lifecycle contract | [`public-build-experiment-bundle.schema.json`](../schemas/research/public-build-experiment-bundle.schema.json) |

The root [`README.md`](../README.md) is the public landing page. The root
[`AGENTS.md`](../AGENTS.md) is an AI-agent interface and is not human onboarding
documentation.

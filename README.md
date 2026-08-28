# Authentication CLI v2

> [!IMPORTANT]
> This is an unofficial, pre-implementation v2 line derived from
> [Microsoft Authentication CLI](https://github.com/AzureAD/microsoft-authentication-cli).
> It is not an official Microsoft Authentication CLI release and is not supported by
> the upstream maintainers. The software is provided as-is under the MIT License.

`main-v2` is an orphan branch established to redesign the authentication core without
carrying forward accidental compatibility constraints from the v1 implementation.
There is no production implementation or release on this branch yet.

## Vision

Build a deterministic command-line authentication engine for delegated Microsoft Entra
public-client token acquisition. A caller must be able to state:

- which application, authority, scopes, account, and tenant it requires;
- which acquisition stages may run, and in which order;
- whether any user interaction is permitted;
- the deadline and host context for the operation.

The result must preserve the actual account and tenant selected by MSAL, identify the
mechanism that ran, and return a typed failure when the request cannot be honored.

The v2 effort will reuse proven mechanism-level work where appropriate, but it will not
extend the v1 flag-based orchestration model.

## Current State

- **Phase:** Phase 1 - empirical baseline
- **Implementation:** none
- **Default development branch:** `main-v2`
- **Upstream baseline under review:** `de20930c34b3b86c8a0ed7bbdeeca3f662dae918`
- **Compatibility:** no v1 CLI or behavioral compatibility commitment
- **Support:** no SLA, release, or production-readiness commitment

The authoritative current status and next permitted work are in
[`docs/project-state.md`](docs/project-state.md).

## Start Here

Read these records in order before proposing or implementing a change:

1. [`AGENTS.md`](AGENTS.md)
2. [`docs/HANDOFF.md`](docs/HANDOFF.md)
3. [`docs/project-state.md`](docs/project-state.md)
4. [`docs/vision.md`](docs/vision.md)
5. [`docs/architecture.md`](docs/architecture.md)
6. [`docs/client-application-identity.md`](docs/client-application-identity.md)
7. [`docs/threat-model.md`](docs/threat-model.md)
8. [`docs/research/v1-architecture-audit.md`](docs/research/v1-architecture-audit.md)
9. [`docs/validation-strategy.md`](docs/validation-strategy.md)
10. [`docs/roadmap.md`](docs/roadmap.md)

Repository provenance and source-import rules are documented in
[`UPSTREAM.md`](UPSTREAM.md). Accepted architectural decisions are recorded under
[`docs/decisions/`](docs/decisions/).

## Scope

The v2 core is for delegated public-client authentication. It is not intended to become:

- a Git credential manager;
- a general Azure SDK credential chain;
- a daemon or GUI;
- a raw OAuth, WAM, or browser implementation;
- an implicit service-principal, managed-identity, or workload-identity selector;
- a compatibility clone of every AzureAuth v1 command.

Azure DevOps PAT lifecycle and other product-specific features are outside the v2 core
and require separate decisions.

Downstream credential-provider products and their Git, NuGet, Python, npm, or other host
adapters are separate consumers. Their architecture and configuration do not belong in
this repository.

## License and Product Identity

The upstream source is available under the MIT License; see [`LICENSE.txt`](LICENSE.txt).
The repository retains the GitHub fork relationship for provenance, but this orphan
branch has independent history.

Microsoft-owned public-client application registrations are public identifiers, not
secrets. They are nevertheless externally owned configuration and are not assets of this
fork. See [`docs/client-application-identity.md`](docs/client-application-identity.md).

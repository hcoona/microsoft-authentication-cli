# Authentication CLI v2

> [!IMPORTANT]
> This is an unofficial, pre-release fork of
> [Microsoft Authentication CLI](https://github.com/AzureAD/microsoft-authentication-cli).
> It is not an official Microsoft release and is not supported by the upstream
> maintainers. The software is provided as-is under the MIT License.

`main-v2` is an orphan development line for a deterministic command-line authentication
engine for delegated Microsoft Entra public-client token acquisition.

The caller must be able to state its client application, authority, scopes, account and
tenant constraints, permitted acquisition stages, interaction policy, deadline, and host
context. A successful result must preserve and validate the identity selected by the
provider; a failed request must return a safe, typed outcome.

There is no production implementation or v2 release on this branch.

## Scope

The v2 core owns delegated public-client authentication and its machine-facing process
contract. It does not implicitly own:

- Git or other host credential protocols;
- a general Azure SDK credential chain;
- service-principal, managed-identity, or workload-identity selection;
- a daemon or graphical interface;
- Azure DevOps PAT lifecycle;
- v1 command, cache, environment-variable, or fallback compatibility.

Downstream credential providers remain separate consumers.

## Documentation

Start with the [project record index](docs/README.md). Current work authorization is in
[`docs/project-state.md`](docs/project-state.md).

Human contributors should read [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports
must follow [`SECURITY.md`](SECURITY.md).

## Upstream and License

The repository retains its GitHub fork relationship, but `main-v2` has independent
history. [`UPSTREAM.md`](UPSTREAM.md) records the audited upstream baseline and source
import policy.

The source is available under the [MIT License](LICENSE.txt).

# Operational Namespace Registry

## Status

No final v2 product or namespace names have been selected. This registry records
inherited identifiers that must not be reused accidentally.

Attribution and migration code may refer to old identifiers. Normal v2 runtime,
installation, logout, cleanup, and telemetry must not own or mutate them without an
accepted compatibility decision.

## Inherited Identifiers

| Area | Upstream identifiers or patterns | V2 rule |
| --- | --- | --- |
| Product and command | `AzureAuth`, `azureauth`, `microsoft.authentication.azureauth` | Choose a distinct product, command, and package identity before distribution. |
| .NET namespaces | `Microsoft.Authentication.AzureAuth`, `Microsoft.Authentication.MSALWrapper`, `Microsoft.Authentication.AdoPat` | New implementation must not publish fork-owned assemblies under a Microsoft publisher namespace. |
| Installation | `%LOCALAPPDATA%\Programs\AzureAuth`, `~/.azureauth`, `/usr/bin/azureauth`, `/usr/lib/azureauth` | Install side by side under a fork-owned root. |
| Configuration | `AZUREAUTH_*`, `OEAUTH_MSAL_DISABLE_CACHE`, `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AzureAuth` | Define an independent prefix and vendor path. Do not read old settings implicitly. |
| MSAL cache | `%LOCALAPPDATA%\.IdentityService`, `Microsoft.Developer.IdentityService`, category `azureauth`, `com.microsoft.identity.tokencache`, `.azureauth` | Define explicit v2 cache ownership. Intentional broker SSO is not permission to mutate upstream serialized stores. |
| PAT storage | `azureauth-ado-pat.lock`, `azureauth-pat.cache`, Microsoft-labelled Keychain and keyring values | Use distinct names if PAT support is later accepted. |
| Telemetry | `AZUREAUTH_APPLICATION_INSIGHTS_INGESTION_TOKEN`, upstream registry keys, event namespace `azureauth` | Do not consume or emit under upstream telemetry configuration. |
| Release identity | Upstream archive, package, installer, maintainer, signing, and update names | Define independent artifact provenance and update channels. |
| Client application | Visual Studio public-client ID and Microsoft defaults | Represent only in an explicit compatibility profile with an ownership statement. |

## Namespace Selection Gate

Before packaging or persistent state is implemented, record:

- chosen value;
- owning component;
- storage or protocol location;
- schema/version behavior;
- collision test;
- migration or import behavior;
- cleanup and uninstall ownership.

No broad cleanup operation may infer ownership from a shared parent directory or name
prefix.

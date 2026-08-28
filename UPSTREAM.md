# Upstream Provenance

## Source

- **Repository:** <https://github.com/AzureAD/microsoft-authentication-cli>
- **Upstream branch:** `main`
- **Audited baseline:** `de20930c34b3b86c8a0ed7bbdeeca3f662dae918`
- **Tag `0.9.5`:** `21258ff3a2cbb01d6891243114a55abe9ae3587e`
- **Tag `0.9.6`:** `8ef1b8b00782bf20a51de078289819a79c3cba70`
- **Baseline revalidated:** 2026-08-28
- **License:** MIT

The GitHub repository remains a fork of the upstream repository, but `main-v2` is an
orphan line with independent Git history. The reset is intended to prevent v1
compatibility and file layout from becoming implicit v2 requirements. It does not hide
or replace upstream provenance.

## Import Policy

Do not merge `upstream/main` into `main-v2`.

## Imported Source Inventory

No production source file has been imported into `main-v2`.

| V2 path | Upstream path | Upstream commit | Disposition |
| --- | --- | --- | --- |
| `LICENSE.txt` | `LICENSE.txt` | `de20930c34b3b86c8a0ed7bbdeeca3f662dae918` | Preserved MIT license and copyright notice. |

An upstream change may be imported only when:

1. it provides a mechanism, security fix, test, or operational behavior needed by an
   accepted v2 requirement;
2. the exact upstream commit and imported files are recorded in the change;
3. copyright and license notices are preserved;
4. the code is adapted to v2 contracts rather than reintroducing v1 orchestration;
5. platform, security, and behavioral validation accompanies the import.

Every copied or substantially derived file must retain the notices required by the MIT
License. Imported code remains subject to independent review; upstream origin is not
evidence that it satisfies v2 invariants.

## Update Policy

The fork does not promise continuous synchronization with upstream. Security and
mechanism-level fixes should be evaluated promptly, but every import must remain
intentional and reviewable.

Recheck upstream issues, pull requests, releases, dependency changes, and security fixes
before each implementation or release milestone. Record the review and its disposition
in this file or a future append-only upstream review ledger.

Use the local `upstream` remote for source comparison:

```text
origin   https://github.com/hcoona/microsoft-authentication-cli.git
upstream https://github.com/AzureAD/microsoft-authentication-cli.git
```

Do not publish internal or nonpublic evidence when explaining why an upstream change is
or is not imported.

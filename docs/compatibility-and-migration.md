# Compatibility and Migration Policy

## Current Commitment

V2 has no current promise of compatibility with v1 commands, output, environment
variables, configuration, cache data, installation paths, or fallback behavior.

Compatibility is a bounded adapter concern, not a constraint on the v2 core.

## Side-by-Side First

Any future v2 artifact must:

- use a distinct executable and installation root;
- use independent configuration, cache, lock, telemetry, and update namespaces;
- avoid placing an `azureauth` compatibility shim by default;
- leave upstream installation and state untouched during install, login, logout, upgrade,
  downgrade, uninstall, and cleanup.

## Migration Rules

No automatic token-cache takeover is permitted.

A future importer, if accepted, must:

- run only through an explicit command;
- support a dry run;
- identify every source record it proposes to read;
- leave source data unchanged;
- import nonsecret configuration separately from credentials;
- translate account aliases to stable v2 account records only after verification;
- refuse a client-ID or authority mismatch unless a specific migration rule exists;
- be repeatable and interruptible;
- support rollback without overwriting upstream state;
- never import upstream telemetry configuration or device identifiers.

PAT import is not part of a general migration. If PAT support is accepted, migration
requires a separate security decision and should prefer issuing a new minimally scoped
credential.

## Compatibility Adapter Gate

A v1 compatibility adapter may be accepted only when:

- the supported commands, flags, aliases, output fields, exit codes, and environment
  variables are enumerated;
- each input maps deterministically to a v2 request;
- changed behavior is documented;
- ambiguous or unsafe behavior fails rather than silently widening policy;
- compatibility output is isolated from the native v2 protocol;
- deprecation and removal rules are defined.

Until that gate is met, scripts must not assume that `main-v2` is a drop-in replacement.

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

V2 provides no importer for v1 configuration, aliases, account records, token caches,
credentials, PATs, telemetry configuration, or device identifiers. The product must not
read, modify, delete, or take over upstream state as migration. Users must configure v2
independently and reauthenticate.

## Externally Owned Client Profile Gate

A profile that uses a client application not owned by this repository may be accepted
only when:

- public evidence identifies the owner and the intended or unsupported reuse boundary;
- the required account, resource, authority, host, redirect, and broker combinations have
  bounded validation;
- default selection, explicit user opt-in, and failure behavior are decided;
- cache and configuration partitioning prevent silent identity collisions;
- public documentation states ownership, support, and availability limits.

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

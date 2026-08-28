# Experiment Safety Protocol

## Scope

This protocol applies before running an upstream or v2 authentication binary, restore,
build, cache, installer, or migration experiment.

Phase 1 experiments may observe real platform behavior, but they must not contaminate
personal production state, rely silently on private credentials, or publish sensitive
evidence.

## Required Isolation

### Source and Build

- Use a detached checkout pinned to the recorded upstream commit or tag.
- Record the exact source commit and dependency versions.
- Test public restore with an empty package cache and no inherited package-source
  credentials.
- Do not use a cached private package to claim that a public build works.
- Keep build output and package caches outside upstream or v2 production install paths.
- Record every nonpublic feed, package, service connection, or signing dependency found.

### User and Credential State

- Use dedicated, authorized test identities and tenants where practical.
- Do not embed personal account names, tenant details, screenshots, tokens, or policy
  output in committed evidence.
- Use a disposable operating-system profile, home directory, container, VM, or explicitly
  isolated cache and configuration root.
- Never point an experiment at an upstream production cache, keychain, keyring, registry
  value, PAT store, or installation path unless the experiment explicitly studies that
  store and has a read-only plan.
- Never copy refresh-token caches into the repository or session artifacts.

### Interaction and Telemetry

- Disable upstream remote telemetry through its documented controls before execution.
- When the behavior of the telemetry switch itself is under test, isolate network access
  and record only sanitized endpoint and field observations.
- Record which interactive surface is expected before running the experiment.
- Ensure the operator can identify and close WAM, browser, device-code, or terminal
  prompts created by the test.
- Do not run interactive experiments in CI or unattended sessions.

### Network and Resource Effects

- Prefer token acquisition and read-only resource probes.
- Do not create, delete, push, publish, revoke, or mutate remote resources unless that
  side effect is the explicit experiment subject.
- Do not create PATs as an incidental fallback.
- Bound every operation with a documented timeout and cleanup procedure.

## Required Experiment Record

Every committed result must state:

- source commit;
- v2 commit, if applicable;
- MSAL and native-broker versions;
- operating system, architecture, WSL version, and host type;
- sanitized account-state shape;
- client profile, authority class, scopes, and requested policy;
- cache and configuration isolation;
- telemetry and network controls;
- expected UI and typed result;
- observed UI and result;
- cleanup performed;
- reproduction count and known variability;
- evidence classification: SOURCE-VERIFIED, HYPOTHESIS, or VALIDATE-RUNTIME.

## Stop Conditions

Stop the experiment if:

- a real token, code, credential, or private account detail would be recorded;
- a prompt appears in an unexpected session or cannot be identified;
- the process accesses an unplanned cache, keychain, keyring, registry path, or
  installation;
- a restore succeeds only because inherited credentials or package caches are present;
- cleanup ownership is unclear;
- continuing would mutate an unrelated remote resource.

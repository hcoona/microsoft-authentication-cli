# Vision

## Status

This document defines the intended product boundary for the v2 effort. It is directional,
not a frozen command-line or library contract.

## Problem

Microsoft Authentication CLI v1 successfully wraps MSAL mechanisms, but its public model
is optimized for a human asking for a token rather than a machine requiring a
deterministic authentication outcome.

A machine caller cannot reliably express or verify all of the following:

- the exact account that must be used;
- a strict tenant or authority postcondition;
- the order of silent and interactive acquisition stages;
- a guarantee that no interactive surface will be created;
- one deadline covering locks, broker work, browser work, and fallback;
- a structured distinction between interaction required, cancellation, denial,
  unavailability, timeout, and internal failure.

The v2 effort exists to make those properties explicit.

## Vision

Provide a small, deterministic command-line authentication engine for delegated
Microsoft Entra public-client token acquisition.

The engine should:

- preserve caller intent from request through MSAL execution and result validation;
- identify accounts by stable provider identifiers rather than username suffixes;
- separate acquisition mechanism from interaction policy;
- execute an explicit, ordered strategy;
- model Windows, WSL, Linux, and macOS host capabilities deliberately;
- preserve MSAL account, tenant, scope, expiry, correlation, and mechanism metadata;
- provide versioned machine output and typed failures;
- remain safe to embed in credential providers and other command-line tools;
- reuse maintained MSAL and broker integrations rather than implement OAuth or platform
  brokers directly.

## Design Principles

1. **Identity is a postcondition.** A successful request must prove that the returned
   result satisfies its account, tenant, authority, and client constraints.
2. **No interaction means no interaction.** Silent-only execution must not create WAM,
   browser, device-code, terminal, or other user-facing prompts.
3. **Policy is data.** Ordered stages and fallback rules must not be inferred from an
   unordered flag set or global environment state.
4. **Tokens are opaque.** Identity and authorization metadata must come from the
   authentication result, not from depending on access-token claim layouts.
5. **Host context is explicit.** Platform and process-host capabilities are inputs, not
   accidental consequences of operating-system detection.
6. **Failure is information.** Callers must receive a safe, typed reason that supports a
   deliberate next action.
7. **Mechanisms are replaceable.** MSAL, brokers, browser launchers, cache stores, and
   product-specific adapters sit behind narrow contracts.
8. **Security follows a bounded threat model.** Do not add unbounded hardening, but do
   not silently weaken explicit identity, interaction, storage, or output guarantees.

## Intended Uses

- Local developer tools that require delegated Microsoft Entra access tokens.
- Credential-provider processes that need deterministic silent versus interactive
  behavior.
- Diagnostics and explicit login workflows that must report the selected identity.
- Public-client applications that need a versioned command-line boundary around MSAL.

Downstream credential providers remain separate products. V2 supplies authentication
outcomes; it does not own their host protocols, configuration, or credential
materialization.

## Non-Goals

The v2 core will not, by default:

- implement Git credential-helper semantics;
- reproduce Azure CLI or Azure Identity credential chains;
- select service principals, managed identities, or workload identities implicitly;
- run as a long-lived token daemon;
- provide a graphical interface;
- implement OAuth, WAM, browser engines, or secure storage primitives from scratch;
- promise compatibility with every v1 command or environment variable;
- treat Azure DevOps PAT lifecycle as part of the generic authentication core;
- promise that a Microsoft-owned public-client registration will remain available.

Any expansion beyond these boundaries requires a separate accepted decision.

## Success Criteria

The first supported v2 release requires:

- a reviewed and versioned request/result contract;
- strict selected-account silent acquisition;
- explicit no-interaction enforcement;
- at least one interactive mechanism with validated result identity;
- bounded cancellation and cross-process prompt coordination;
- secure cache behavior with no silent plaintext fallback;
- clean stdout/stderr separation and complete secret redaction;
- release-gating tests for every supported platform and interaction mode;
- an explicit client-application identity and ownership statement;
- documented unsupported cases that fail closed.

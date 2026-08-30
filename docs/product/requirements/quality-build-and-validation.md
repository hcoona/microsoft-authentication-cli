# Quality, Build, and Validation Requirements

## V2-REQ-050: Public Evidence

This identifier is reserved to preserve stable references established by issue #2 and
must not be reused. Its former text combined repository evidence policy, now owned by
[`project.md`](../../governance/project.md), with support-claim validation, now owned by
[`strategy.md`](../../validation/strategy.md). It defines no independent product
behavior.

## V2-REQ-051: Real Platform Validation

Supported broker, browser, device-code, cache, and WSL behavior must be validated on the
real operating-system and account-state combinations declared as supported.

## V2-REQ-052: Dependency Upgrade Isolation

MSAL, native broker, cache, and platform dependency upgrades must be independently
testable, pinnable, and reversible.

## V2-REQ-053: Public Build Chain

V2 implementation and release builds must restore, build, test, and package from publicly
retrievable dependencies and fork-owned infrastructure. They must not require Microsoft
private feeds, private service connections, or upstream signing systems.

## V2-REQ-054: Isolated Experiments

Build, authentication, cache, installer, and migration experiments must follow the
experiment-safety policy. Public-build claims must be tested without inherited
credentials or package caches, and authentication experiments must not mutate unrelated
user or upstream state.

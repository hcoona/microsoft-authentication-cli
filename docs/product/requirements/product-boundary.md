# Product-Boundary Requirements

## V2-REQ-001: Delegated Public-Client Scope

V2 must provide delegated Microsoft Entra public-client token acquisition. It must not
implicitly select confidential-client, service-principal, managed-identity, or
workload-identity flows.

## V2-REQ-002: No Implicit Product Expansion

Git credential protocols, Azure DevOps PAT lifecycle, a daemon, a GUI, and general SDK
credential chaining must remain outside the core unless separately accepted.

Downstream credential-provider products and host-tool adapters must remain separate
consumers of the v2 authentication protocol.

## V2-REQ-003: Unofficial Product Identity

Every user-facing surface must identify the project as unofficial and must not imply an
official Microsoft release, upstream support, or ownership of a Microsoft application
registration.

## V2-REQ-004: One Authentication Request Per Process

Each native authentication process must handle one machine request and terminate after
its terminal outcome. A daemon, persistent multi-request service, and batch or
multiplexed authentication protocol remain outside native v2.

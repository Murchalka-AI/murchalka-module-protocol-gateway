# ADR-0001: Generic gateway boundary

Status: Accepted

## Decision

The gateway owns listeners, route namespace resolution, authentication presence checks, limits, backpressure, streaming transport, cancellation, health, and audit-safe correlation. Protocol modules own serializers, discovery, protocol authentication semantics, and mapping to bounded internal capabilities.

Routes are discovered only through Runtime-granted handler dependencies. Route collisions fail closed. No request can name or enumerate an arbitrary Runtime capability.

# Generic Protocol Gateway

Installable, protocol-neutral Phase 8 gateway. It owns bounded external HTTP/SSE routes and dispatches only to Runtime-granted `protocol.gateway.handler` capabilities. It never parses MCP or A2A messages and never exposes the Runtime capability registry.

The default endpoint is `http://127.0.0.1:5088`. Anonymous access is denied by default and can be enabled only for an explicit loopback endpoint. Remote deployments must terminate TLS with client certificates or provide a bearer credential that the selected protocol module validates. Route additions, removals, dependency revocation, peer disconnect, deadline, and module disable invalidate active work immediately.

Canonical `vX.Y.Z` tags validate the repository and publish signed immutable bundles for Linux and macOS on x64 and arm64. Windows remains a CI build target, but process-module bundles are intentionally not published until the Runtime provides an equivalent fail-closed Windows sandbox.

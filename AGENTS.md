# Contributor guidance

- Keep the gateway protocol-neutral; MCP, A2A, and future protocol semantics belong to independent modules.
- Bind loopback by default and fail closed when peer authentication is unavailable.
- Dispatch only to Runtime-granted `protocol.gateway.handler` providers.
- Keep one declared type per C# file, align namespaces with paths, and document public APIs in English.
- Bound every payload, deadline, stream, and concurrency path and cancel active work on disable or revocation.
- Run formatting, Release build, tests, conformance, packaging, and Runtime verification before release.

using Murchalka.ModuleProtocol.Contracts;

namespace Murchalka.ProtocolGateway.Runtime;

internal sealed record ProtocolRouteEndpoint(
    string RouteNamespace,
    int MaximumPayloadBytes,
    int MaximumConcurrency,
    int MaximumStreams,
    TimeSpan Timeout,
    IReadOnlySet<string> Authentication,
    IReadOnlySet<string> Transports,
    DependencyEndpoint Dependency);

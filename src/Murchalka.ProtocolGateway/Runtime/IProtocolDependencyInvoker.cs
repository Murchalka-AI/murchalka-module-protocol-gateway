using System.Text.Json;

namespace Murchalka.ProtocolGateway.Runtime;

internal interface IProtocolDependencyInvoker
{
    Task<IReadOnlyList<ProtocolRouteEndpoint>> GetRoutesAsync(CancellationToken cancellationToken);

    ValueTask<byte[]> LeaseSecretAsync(string name, string purpose, CancellationToken cancellationToken);

    ValueTask<JsonElement> InvokeAsync(
        ProtocolRouteEndpoint endpoint,
        JsonElement payload,
        string correlationId,
        DateTimeOffset deadline,
        CancellationToken cancellationToken);
}

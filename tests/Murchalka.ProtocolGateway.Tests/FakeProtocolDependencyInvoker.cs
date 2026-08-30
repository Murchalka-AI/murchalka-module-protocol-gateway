using System.Text.Json;
using Murchalka.ProtocolGateway.Runtime;

namespace Murchalka.ProtocolGateway.Tests;

internal sealed class FakeProtocolDependencyInvoker : IProtocolDependencyInvoker
{
    private readonly IReadOnlyList<ProtocolRouteEndpoint> _routes;
    private readonly IReadOnlyDictionary<string, byte[]> _secrets;

    public FakeProtocolDependencyInvoker(IReadOnlyList<ProtocolRouteEndpoint> routes, IReadOnlyDictionary<string, byte[]>? secrets = null)
    {
        _routes = routes;
        _secrets = secrets ?? new Dictionary<string, byte[]>();
    }

    public JsonElement? LastPayload { get; private set; }

    public Task<IReadOnlyList<ProtocolRouteEndpoint>> GetRoutesAsync(CancellationToken cancellationToken) => Task.FromResult(_routes);

    public ValueTask<byte[]> LeaseSecretAsync(string name, string purpose, CancellationToken cancellationToken)
    {
        _ = purpose;
        cancellationToken.ThrowIfCancellationRequested();
        return _secrets.TryGetValue(name, out var value)
            ? ValueTask.FromResult(value.ToArray())
            : ValueTask.FromException<byte[]>(new InvalidOperationException("No test secret is configured."));
    }

    public ValueTask<JsonElement> InvokeAsync(ProtocolRouteEndpoint endpoint, JsonElement payload, string correlationId, DateTimeOffset deadline, CancellationToken cancellationToken)
    {
        LastPayload = payload.Clone();
        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new { statusCode = 200, contentType = "application/json", body = new { ok = true } }));
    }
}

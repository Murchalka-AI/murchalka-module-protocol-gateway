namespace Murchalka.ProtocolGateway.Gateway;

internal sealed class ProtocolRouteLimitState : IDisposable
{
    public ProtocolRouteLimitState(int maximumConcurrency, int maximumStreams)
    {
        Requests = new SemaphoreSlim(maximumConcurrency, maximumConcurrency);
        Streams = new SemaphoreSlim(maximumStreams, maximumStreams);
    }

    public SemaphoreSlim Requests { get; }
    public SemaphoreSlim Streams { get; }

    public void Dispose()
    {
        Requests.Dispose();
        Streams.Dispose();
    }
}

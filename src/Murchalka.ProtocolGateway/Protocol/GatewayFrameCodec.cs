using System.Buffers.Binary;
using System.Text.Json;
using Murchalka.ModuleProtocol.Json;

namespace Murchalka.ProtocolGateway.Protocol;

internal static class GatewayFrameCodec
{
    private const int MaximumFrameBytes = 16 * 1024 * 1024;

    public static async ValueTask WriteAsync<T>(Stream stream, string kind, T payload, CancellationToken cancellationToken)
    {
        var content = JsonSerializer.SerializeToUtf8Bytes(new { kind, payload }, ProtocolJson.Options);
        if (content.Length > MaximumFrameBytes) throw new InvalidDataException("Module Protocol frame exceeds the maximum size.");
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(prefix, content.Length);
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<GatewayFrame> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(prefix);
        if (length is <= 0 or > MaximumFrameBytes) throw new InvalidDataException("Module Protocol frame length is invalid.");
        var content = new byte[length];
        await stream.ReadExactlyAsync(content, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<GatewayFrame>(content, ProtocolJson.Options) ?? throw new InvalidDataException("Module Protocol frame is invalid.");
    }

    public static T PayloadAs<T>(GatewayFrame frame) => frame.Payload.Deserialize<T>(ProtocolJson.Options) ?? throw new InvalidDataException($"Frame '{frame.Kind}' payload is invalid.");
}

using System.Net;
using System.Text.Json;

namespace Murchalka.ProtocolGateway.Gateway;

internal sealed record ProtocolGatewayOptions(
    Uri Endpoint,
    bool AllowAnonymousLoopback,
    string? TlsCertificateSecret,
    string? TlsCertificatePasswordSecret,
    int MaximumPayloadBytes,
    int MaximumConcurrency,
    int MaximumStreams,
    int RequestsPerMinute,
    TimeSpan RequestTimeout)
{
    public static ProtocolGatewayOptions Parse(JsonElement configuration)
    {
        var endpoint = new Uri(configuration.GetProperty("endpoint").GetString() ?? throw new InvalidDataException("Gateway endpoint is missing."), UriKind.Absolute);
        if (!IPAddress.TryParse(endpoint.Host, out var address)) throw new InvalidDataException("Gateway endpoint host must be an explicit IP address.");
        if (endpoint.Scheme == Uri.UriSchemeHttp && !IPAddress.IsLoopback(address)) throw new InvalidDataException("Plain HTTP is restricted to an explicit loopback endpoint.");
        if (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps) throw new InvalidDataException("Gateway endpoint must use HTTP or HTTPS.");
        if (!string.IsNullOrEmpty(endpoint.UserInfo) || endpoint.AbsolutePath != "/" || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment))
            throw new InvalidDataException("Gateway endpoint must be an uncredentialed origin without a path, query, or fragment.");
        var certificateSecret = ReadNullableString(configuration, "tlsCertificateSecret");
        var passwordSecret = ReadNullableString(configuration, "tlsCertificatePasswordSecret");
        if (endpoint.Scheme == Uri.UriSchemeHttps && certificateSecret is null) throw new InvalidDataException("HTTPS gateway endpoints require tlsCertificateSecret.");
        if (endpoint.Scheme == Uri.UriSchemeHttp && (certificateSecret is not null || passwordSecret is not null)) throw new InvalidDataException("TLS secrets are accepted only for HTTPS gateway endpoints.");
        return new ProtocolGatewayOptions(
            endpoint,
            configuration.GetProperty("allowAnonymousLoopback").GetBoolean(),
            certificateSecret,
            passwordSecret,
            configuration.GetProperty("maximumPayloadBytes").GetInt32(),
            configuration.GetProperty("maximumConcurrency").GetInt32(),
            configuration.GetProperty("maximumStreams").GetInt32(),
            configuration.GetProperty("requestsPerMinute").GetInt32(),
            TimeSpan.FromSeconds(configuration.GetProperty("requestTimeoutSeconds").GetInt32()));
    }

    private static string? ReadNullableString(JsonElement configuration, string property) =>
        configuration.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()
            : null;
}

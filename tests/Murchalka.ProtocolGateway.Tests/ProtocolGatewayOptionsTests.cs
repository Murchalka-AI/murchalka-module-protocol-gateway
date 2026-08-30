using System.Text.Json;
using Murchalka.ProtocolGateway.Gateway;

namespace Murchalka.ProtocolGateway.Tests;

/// <summary>Verifies fail-closed external listener configuration.</summary>
public sealed class ProtocolGatewayOptionsTests
{
    /// <summary>Rejects clear-text listeners outside explicit loopback addresses.</summary>
    [Fact]
    public void RemotePlainHttpIsRejected()
    {
        var configuration = Configuration("http://0.0.0.0:5088", null);

        Assert.Throws<InvalidDataException>(() => ProtocolGatewayOptions.Parse(configuration));
    }

    /// <summary>Rejects HTTPS configuration without a brokered certificate reference.</summary>
    [Fact]
    public void HttpsWithoutCertificateSecretIsRejected()
    {
        var configuration = Configuration("https://127.0.0.1:5088", null);

        Assert.Throws<InvalidDataException>(() => ProtocolGatewayOptions.Parse(configuration));
    }

    private static JsonElement Configuration(string endpoint, string? certificateSecret) => JsonSerializer.SerializeToElement(new
    {
        endpoint,
        allowAnonymousLoopback = false,
        tlsCertificateSecret = certificateSecret,
        tlsCertificatePasswordSecret = (string?)null,
        maximumPayloadBytes = 4096,
        maximumConcurrency = 4,
        maximumStreams = 2,
        requestsPerMinute = 60,
        requestTimeoutSeconds = 5
    });
}

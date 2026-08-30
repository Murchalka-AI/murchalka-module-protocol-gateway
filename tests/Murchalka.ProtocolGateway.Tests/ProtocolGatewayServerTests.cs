using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Murchalka.ProtocolGateway.Gateway;

namespace Murchalka.ProtocolGateway.Tests;

/// <summary>Verifies the lifecycle of the loopback protocol listener.</summary>
public sealed class ProtocolGatewayServerTests
{
    /// <summary>Verifies that listener startup and shutdown are bounded and complete.</summary>
    [Fact]
    public async Task ListenerStartsAndStopsAsync()
    {
        var invoker = new FakeProtocolDependencyInvoker([]);
        await using var server = new ProtocolGatewayServer(invoker);
        var configuration = JsonSerializer.SerializeToElement(new
        {
            endpoint = "http://127.0.0.1:15089",
            allowAnonymousLoopback = false,
            tlsCertificateSecret = (string?)null,
            tlsCertificatePasswordSecret = (string?)null,
            maximumPayloadBytes = 4096,
            maximumConcurrency = 4,
            maximumStreams = 2,
            requestsPerMinute = 60,
            requestTimeoutSeconds = 5
        });

        await server.StartAsync(configuration, TestContext.Current.CancellationToken);
        await server.StopAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>Verifies that HTTPS obtains its certificate only through secret leases and completes a TLS handshake.</summary>
    [Fact]
    public async Task HttpsListenerUsesLeasedEphemeralCertificateAsync()
    {
        const string password = "phase8-test";
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        var invoker = new FakeProtocolDependencyInvoker([], new Dictionary<string, byte[]>
        {
            ["tls-pfx"] = certificate.Export(X509ContentType.Pfx, password),
            ["tls-password"] = Encoding.UTF8.GetBytes(password)
        });
        await using var server = new ProtocolGatewayServer(invoker);
        var configuration = JsonSerializer.SerializeToElement(new
        {
            endpoint = "https://127.0.0.1:15090",
            allowAnonymousLoopback = false,
            tlsCertificateSecret = "tls-pfx",
            tlsCertificatePasswordSecret = "tls-password",
            maximumPayloadBytes = 4096,
            maximumConcurrency = 4,
            maximumStreams = 2,
            requestsPerMinute = 60,
            requestTimeoutSeconds = 5
        });
        using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
        using var client = new HttpClient(handler);

        await server.StartAsync(configuration, TestContext.Current.CancellationToken);
        using var response = await client.GetAsync("https://127.0.0.1:15090/health", TestContext.Current.CancellationToken);
        await server.StopAsync(TestContext.Current.CancellationToken);

        Assert.True(response.IsSuccessStatusCode);
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Murchalka.ModuleProtocol.Contracts;
using Murchalka.ProtocolGateway.Gateway;
using Murchalka.ProtocolGateway.Runtime;

namespace Murchalka.ProtocolGateway.Tests;

/// <summary>Verifies authentication and bounded dispatch at the external gateway boundary.</summary>
public sealed class ProtocolRequestHandlerTests
{
    /// <summary>Verifies explicitly enabled anonymous loopback access and bounded route dispatch.</summary>
    [Fact]
    public async Task AnonymousLoopbackDispatchesOnlyToResolvedRoute()
    {
        var invoker = new FakeProtocolDependencyInvoker([Route(new HashSet<string>(StringComparer.Ordinal) { "none" })]);
        using var handler = new ProtocolRequestHandler(invoker, Options(allowAnonymousLoopback: true));
        var context = Context("mcp");

        await handler.HandleAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal("none", invoker.LastPayload?.GetProperty("authentication").GetProperty("scheme").GetString());
    }

    /// <summary>Verifies that missing peer authentication fails closed.</summary>
    [Fact]
    public async Task MissingAuthenticationIsRejected()
    {
        var invoker = new FakeProtocolDependencyInvoker([Route(new HashSet<string>(StringComparer.Ordinal) { "bearer" })]);
        using var handler = new ProtocolRequestHandler(invoker, Options(allowAnonymousLoopback: false));
        var context = Context("mcp");

        await handler.HandleAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Null(invoker.LastPayload);
    }

    /// <summary>Verifies that a validated client certificate is projected as bounded mTLS identity metadata.</summary>
    [Fact]
    public async Task ClientCertificateUsesMutualTlsAuthentication()
    {
        var invoker = new FakeProtocolDependencyInvoker([Route(new HashSet<string>(StringComparer.Ordinal) { "mtls" })]);
        using var handler = new ProtocolRequestHandler(invoker, Options(allowAnonymousLoopback: false));
        var context = Context("mcp");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=phase8-client", key, HashAlgorithmName.SHA256);
        context.Connection.ClientCertificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));

        await handler.HandleAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal("mtls", invoker.LastPayload?.GetProperty("authentication").GetProperty("scheme").GetString());
        context.Connection.ClientCertificate.Dispose();
    }

    /// <summary>Verifies that the per-peer request budget fails closed after it is exhausted.</summary>
    [Fact]
    public async Task RateLimitRejectsExcessRequests()
    {
        var invoker = new FakeProtocolDependencyInvoker([Route(new HashSet<string>(StringComparer.Ordinal) { "none" })]);
        using var handler = new ProtocolRequestHandler(invoker, Options(allowAnonymousLoopback: true, requestsPerMinute: 1));
        var first = Context("mcp");
        var second = Context("mcp");

        await handler.HandleAsync(first);
        await handler.HandleAsync(second);

        Assert.Equal(StatusCodes.Status200OK, first.Response.StatusCode);
        Assert.Equal(StatusCodes.Status429TooManyRequests, second.Response.StatusCode);
    }

    /// <summary>Verifies bounded streaming reads even when a peer omits Content-Length.</summary>
    [Fact]
    public async Task ChunkedOversizedPayloadIsRejected()
    {
        var invoker = new FakeProtocolDependencyInvoker([Route(new HashSet<string>(StringComparer.Ordinal) { "none" })]);
        using var handler = new ProtocolRequestHandler(invoker, Options(allowAnonymousLoopback: true));
        var context = Context("mcp");
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"value\":\"" + new string('x', 5000) + "\"}"));
        context.Request.ContentLength = null;

        await handler.HandleAsync(context);

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.Null(invoker.LastPayload);
    }

    private static DefaultHttpContext Context(string route)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Method = HttpMethods.Post;
        context.Request.RouteValues["route"] = route;
        context.Request.RouteValues["path"] = string.Empty;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{}"));
        context.Request.ContentLength = 2;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static ProtocolRouteEndpoint Route(IReadOnlySet<string> authentication) => new(
        "mcp", 4096, 4, 2, TimeSpan.FromSeconds(5), authentication, new HashSet<string>(["http"]),
        new DependencyEndpoint("protocol-handlers", new ModuleId("dev.murchalka.protocol-mcp"), SemanticVersion.Parse("0.5.0"),
            new CapabilityId("protocol.mcp.route"), SemanticVersion.Parse("1.0.0"), new InstanceId("instance-mcp"),
            new Uri("murchalka://runtime/capabilities/protocol.mcp.route/instance-mcp"), "binding:test"));

    private static ProtocolGatewayOptions Options(bool allowAnonymousLoopback, int requestsPerMinute = 60) =>
        new(new Uri("http://127.0.0.1:5088"), allowAnonymousLoopback, null, null, 4096, 4, 2, requestsPerMinute, TimeSpan.FromSeconds(5));
}

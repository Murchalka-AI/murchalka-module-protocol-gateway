using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Murchalka.ProtocolGateway.Runtime;

namespace Murchalka.ProtocolGateway.Gateway;

internal sealed class ProtocolGatewayServer : IAsyncDisposable
{
    private readonly IProtocolDependencyInvoker _dependencies;
    private WebApplication? _application;
    private X509Certificate2? _certificate;

    public ProtocolGatewayServer(IProtocolDependencyInvoker dependencies) => _dependencies = dependencies;

    public async Task StartAsync(System.Text.Json.JsonElement configuration, CancellationToken cancellationToken)
    {
        if (_application is not null) return;
        var options = ProtocolGatewayOptions.Parse(configuration);
        var certificate = await LoadCertificateAsync(options, cancellationToken).ConfigureAwait(false);
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { Args = [] });
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrelCore().ConfigureKestrel(server => server.Listen(IPAddress.Parse(options.Endpoint.Host), options.Endpoint.Port, listener =>
        {
            if (certificate is not null)
            {
                listener.UseHttps(new HttpsConnectionAdapterOptions
                {
                    ServerCertificate = certificate,
                    ClientCertificateMode = ClientCertificateMode.AllowCertificate,
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                });
            }
        }));
        builder.Services.AddRouting();
        builder.Services.AddSingleton(_dependencies);
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<ProtocolRequestHandler>();
        var application = builder.Build();
        application.Use(async (context, next) =>
        {
            context.Response.Headers.XContentTypeOptions = "nosniff";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            await next(context).ConfigureAwait(false);
        });
        application.MapGet("/health", () => Results.Ok(new { status = "ready" }));
        application.MapGet("/protocols", async (IProtocolDependencyInvoker invoker, CancellationToken token) =>
            Results.Ok(new { routes = (await invoker.GetRoutesAsync(token).ConfigureAwait(false)).Select(value => value.RouteNamespace) }));
        application.MapMethods("/protocols/{route}/{**path}", ["GET", "POST", "PUT", "PATCH", "DELETE"], async context =>
            await context.RequestServices.GetRequiredService<ProtocolRequestHandler>().HandleAsync(context).ConfigureAwait(false));
        application.MapMethods("/protocols/{route}", ["GET", "POST", "PUT", "PATCH", "DELETE"], async context =>
            await context.RequestServices.GetRequiredService<ProtocolRequestHandler>().HandleAsync(context).ConfigureAwait(false));
        try
        {
            await application.StartAsync(cancellationToken).ConfigureAwait(false);
            _certificate = certificate;
            _application = application;
        }
        catch
        {
            await application.DisposeAsync().ConfigureAwait(false);
            certificate?.Dispose();
            throw;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_application is null) return;
        await _application.StopAsync(cancellationToken).ConfigureAwait(false);
        await _application.DisposeAsync().ConfigureAwait(false);
        _application = null;
        _certificate?.Dispose();
        _certificate = null;
    }

    public async ValueTask DisposeAsync()
    {
        if (_application is not null) await _application.DisposeAsync().ConfigureAwait(false);
        _certificate?.Dispose();
    }

    private async Task<X509Certificate2?> LoadCertificateAsync(ProtocolGatewayOptions options, CancellationToken cancellationToken)
    {
        if (options.TlsCertificateSecret is null) return null;
        var pfx = await _dependencies.LeaseSecretAsync(options.TlsCertificateSecret, "protocol-gateway-tls", cancellationToken).ConfigureAwait(false);
        byte[]? passwordBytes = null;
        try
        {
            passwordBytes = options.TlsCertificatePasswordSecret is null
                ? null
                : await _dependencies.LeaseSecretAsync(options.TlsCertificatePasswordSecret, "protocol-gateway-tls-password", cancellationToken).ConfigureAwait(false);
            var password = passwordBytes is null ? null : Encoding.UTF8.GetString(passwordBytes);
            // Windows Schannel cannot use an in-memory-only private key for TLS credentials.
            // DefaultKeySet creates a temporary OS-backed key that is removed when the certificate is disposed.
            var keyStorage = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
                ? X509KeyStorageFlags.DefaultKeySet
                : X509KeyStorageFlags.EphemeralKeySet;
            return X509CertificateLoader.LoadPkcs12(pfx, password, keyStorage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
            if (passwordBytes is not null) CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}

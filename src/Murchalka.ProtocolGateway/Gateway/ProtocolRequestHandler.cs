using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Murchalka.ProtocolGateway.Runtime;

namespace Murchalka.ProtocolGateway.Gateway;

internal sealed class ProtocolRequestHandler : IDisposable
{
    private static readonly HashSet<string> ForwardedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "accept", "content-type", "last-event-id", "mcp-protocol-version", "mcp-session-id", "a2a-version"
    };

    private readonly IProtocolDependencyInvoker _dependencies;
    private readonly ProtocolGatewayOptions _options;
    private readonly SemaphoreSlim _globalConcurrency;
    private readonly ConcurrentDictionary<string, ProtocolRouteLimitState> _routeLimits = new(StringComparer.Ordinal);
    private readonly ProtocolRateLimiter _rateLimiter;

    public ProtocolRequestHandler(IProtocolDependencyInvoker dependencies, ProtocolGatewayOptions options)
    {
        _dependencies = dependencies;
        _options = options;
        _globalConcurrency = new SemaphoreSlim(options.MaximumConcurrency, options.MaximumConcurrency);
        _rateLimiter = new ProtocolRateLimiter(options.RequestsPerMinute);
    }

    public void Dispose()
    {
        _globalConcurrency.Dispose();
        foreach (var limits in _routeLimits.Values) limits.Dispose();
        _routeLimits.Clear();
    }

    public async Task HandleAsync(HttpContext context)
    {
        var routeNamespace = context.Request.RouteValues["route"] as string ?? string.Empty;
        var correlationId = ReadCorrelationId(context);
        context.Response.Headers["X-Correlation-Id"] = correlationId;
        try
        {
            var route = (await _dependencies.GetRoutesAsync(context.RequestAborted).ConfigureAwait(false))
                .SingleOrDefault(value => string.Equals(value.RouteNamespace, routeNamespace, StringComparison.Ordinal));
            if (route is null)
            {
                await WriteErrorAsync(context, StatusCodes.Status404NotFound, "protocol-route-not-found", "The protocol route is not active.").ConfigureAwait(false);
                return;
            }

            if (!_rateLimiter.TryAcquire(RateKey(context)))
            {
                context.Response.Headers.RetryAfter = "60";
                await WriteErrorAsync(context, StatusCodes.Status429TooManyRequests, "protocol-rate-limit-exceeded", "The peer exceeded the protocol request rate limit.").ConfigureAwait(false);
                return;
            }

            var authentication = Authenticate(context, route);
            var maximumPayload = Math.Min(_options.MaximumPayloadBytes, route.MaximumPayloadBytes);
            if (context.Request.ContentLength is > 0 && context.Request.ContentLength > maximumPayload)
            {
                await WriteErrorAsync(context, StatusCodes.Status413PayloadTooLarge, "protocol-payload-too-large", "The request exceeds the route payload limit.").ConfigureAwait(false);
                return;
            }

            using var body = await ReadPayloadAsync(context.Request, maximumPayload, context.RequestAborted).ConfigureAwait(false);
            var deadline = DateTimeOffset.UtcNow.Add(route.Timeout < _options.RequestTimeout ? route.Timeout : _options.RequestTimeout);
            var requestId = Guid.NewGuid().ToString("N");
            var payload = JsonSerializer.SerializeToElement(new
            {
                operation = "handle",
                requestId,
                method = context.Request.Method,
                path = context.Request.RouteValues["path"] as string ?? string.Empty,
                query = context.Request.QueryString.Value ?? string.Empty,
                headers = context.Request.Headers.Where(value => ForwardedHeaders.Contains(value.Key)).ToDictionary(value => value.Key.ToLowerInvariant(), value => value.Value.ToString()),
                authentication,
                payload = body.RootElement,
                acceptsStream = context.Request.GetTypedHeaders().Accept?.Any(value => value.MediaType.Value == "text/event-stream") == true
            });
            var effectiveStreams = Math.Min(route.MaximumStreams, _options.MaximumStreams);
            var routeLimitKey = $"{route.RouteNamespace}:{route.MaximumConcurrency}:{effectiveStreams}";
            var routeLimits = _routeLimits.GetOrAdd(routeLimitKey, _ => new ProtocolRouteLimitState(route.MaximumConcurrency, effectiveStreams));
            using var requestDeadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            requestDeadline.CancelAfter(deadline - DateTimeOffset.UtcNow);
            var globalSlot = false;
            var requestSlot = false;
            var streamSlot = false;
            try
            {
                await _globalConcurrency.WaitAsync(requestDeadline.Token).ConfigureAwait(false);
                globalSlot = true;
                await routeLimits.Requests.WaitAsync(requestDeadline.Token).ConfigureAwait(false);
                requestSlot = true;
                if (context.Request.GetTypedHeaders().Accept?.Any(value => value.MediaType.Value == "text/event-stream") == true)
                {
                    streamSlot = routeLimits.Streams.Wait(0);
                    if (!streamSlot)
                    {
                        await WriteErrorAsync(context, StatusCodes.Status429TooManyRequests, "protocol-stream-limit-exceeded", "The route stream limit has been reached.").ConfigureAwait(false);
                        return;
                    }
                }
                var response = await _dependencies.InvokeAsync(route, payload, correlationId, deadline, context.RequestAborted).ConfigureAwait(false);
                if (response.TryGetProperty("streamId", out var streamIdElement) && streamIdElement.ValueKind == JsonValueKind.String)
                {
                    await StreamAsync(context, route, streamIdElement.GetString()!, response, correlationId, deadline).ConfigureAwait(false);
                    return;
                }

                await WriteResponseAsync(context, response, context.RequestAborted).ConfigureAwait(false);
            }
            finally
            {
                if (streamSlot) routeLimits.Streams.Release();
                if (requestSlot) routeLimits.Requests.Release();
                if (globalSlot) _globalConcurrency.Release();
            }
        }
        catch (UnauthorizedAccessException exception)
        {
            context.Response.Headers.WWWAuthenticate = "Bearer, MutualTLS";
            await WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "protocol-authentication-required", exception.Message).ConfigureAwait(false);
        }
        catch (ProtocolDependencyException exception)
        {
            await WriteErrorAsync(context, StatusCodes.Status502BadGateway, exception.Code, exception.Message).ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            await WriteErrorAsync(context, StatusCodes.Status400BadRequest, "protocol-payload-invalid", exception.Message).ConfigureAwait(false);
        }
        catch (InvalidDataException exception)
        {
            await WriteErrorAsync(context, StatusCodes.Status413PayloadTooLarge, "protocol-payload-too-large", exception.Message).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // The peer disconnected. Cancellation is propagated through the current dependency invocation or stream cleanup.
        }
        catch (OperationCanceledException)
        {
            await WriteErrorAsync(context, StatusCodes.Status504GatewayTimeout, "protocol-deadline-exceeded", "The protocol request deadline elapsed.").ConfigureAwait(false);
        }
    }

    private async Task StreamAsync(
        HttpContext context,
        ProtocolRouteEndpoint route,
        string streamId,
        JsonElement initial,
        string correlationId,
        DateTimeOffset deadline)
    {
        context.Response.StatusCode = initial.TryGetProperty("statusCode", out var status) ? status.GetInt32() : StatusCodes.Status200OK;
        context.Response.ContentType = "text/event-stream";
        context.Response.Headers.Connection = "keep-alive";
        var cursor = 0L;
        try
        {
            while (!context.RequestAborted.IsCancellationRequested)
            {
                var next = await _dependencies.InvokeAsync(
                    route,
                    JsonSerializer.SerializeToElement(new { operation = "stream.next", streamId, cursor }),
                    correlationId,
                    deadline,
                    context.RequestAborted).ConfigureAwait(false);
                if (next.TryGetProperty("events", out var events))
                {
                    foreach (var item in events.EnumerateArray())
                    {
                        var sequence = item.GetProperty("sequence").GetInt64();
                        if (sequence != cursor) throw new InvalidDataException("Protocol stream sequence is invalid.");
                        var eventName = item.GetProperty("kind").GetString() ?? "message";
                        await context.Response.WriteAsync($"id: {sequence}\nevent: {eventName}\ndata: {item.GetProperty("payload").GetRawText()}\n\n", context.RequestAborted).ConfigureAwait(false);
                        cursor++;
                    }
                    await context.Response.Body.FlushAsync(context.RequestAborted).ConfigureAwait(false);
                }

                if (next.TryGetProperty("completed", out var completed) && completed.GetBoolean()) return;
                await Task.Delay(TimeSpan.FromMilliseconds(100), context.RequestAborted).ConfigureAwait(false);
            }
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await _dependencies.InvokeAsync(route, JsonSerializer.SerializeToElement(new { operation = "cancel", streamId }), correlationId, DateTimeOffset.UtcNow.AddSeconds(2), cleanup.Token).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is ProtocolDependencyException or OperationCanceledException)
            {
                // Stream cancellation is best-effort after dependency revocation or process shutdown.
            }
        }
    }

    private object Authenticate(HttpContext context, ProtocolRouteEndpoint route)
    {
        if (context.Connection.ClientCertificate is { } certificate && route.Authentication.Contains("mtls"))
            return new { scheme = "mtls", subject = certificate.Subject, credential = certificate.Thumbprint };
        var authorization = context.Request.Headers.Authorization.ToString();
        if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) && authorization.Length > 7 && route.Authentication.Contains("bearer"))
            return new { scheme = "bearer", subject = (string?)null, credential = authorization[7..] };
        if (_options.AllowAnonymousLoopback && route.Authentication.Contains("none") && context.Connection.RemoteIpAddress is { } address && IPAddress.IsLoopback(address))
            return new { scheme = "none", subject = "peer:loopback", credential = (string?)null };
        throw new UnauthorizedAccessException("The route requires an accepted peer authentication scheme.");
    }

    private static async Task<JsonDocument> ReadPayloadAsync(HttpRequest request, int maximumPayloadBytes, CancellationToken cancellationToken)
    {
        if (request.ContentLength == 0) return JsonDocument.Parse("{}");
        var capacity = request.ContentLength is > 0 ? Math.Min(maximumPayloadBytes, (int)request.ContentLength.Value) : 0;
        using var bounded = new MemoryStream(capacity);
        var buffer = new byte[8192];
        while (true)
        {
            var read = await request.Body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > maximumPayloadBytes) throw new InvalidDataException("The request exceeds the route payload limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
        return bounded.Length == 0
            ? JsonDocument.Parse("{}")
            : JsonDocument.Parse(bounded.ToArray(), new JsonDocumentOptions { MaxDepth = 64 });
    }

    private static async Task WriteResponseAsync(HttpContext context, JsonElement response, CancellationToken cancellationToken)
    {
        context.Response.StatusCode = response.TryGetProperty("statusCode", out var status) ? status.GetInt32() : StatusCodes.Status200OK;
        context.Response.ContentType = response.TryGetProperty("contentType", out var contentType) ? contentType.GetString() : "application/json";
        if (response.TryGetProperty("headers", out var headers))
        {
            foreach (var header in headers.EnumerateObject())
            {
                if (header.NameEquals("Mcp-Session-Id") || header.NameEquals("A2A-Task-Id")) context.Response.Headers[header.Name] = header.Value.GetString();
            }
        }
        if (response.TryGetProperty("body", out var body)) await context.Response.WriteAsync(body.GetRawText(), cancellationToken).ConfigureAwait(false);
    }

    private static Task WriteErrorAsync(HttpContext context, int status, string code, string message)
    {
        if (context.Response.HasStarted) return Task.CompletedTask;
        context.Response.StatusCode = status;
        return context.Response.WriteAsJsonAsync(new { code, message });
    }

    private static string ReadCorrelationId(HttpContext context)
    {
        var value = context.Request.Headers["X-Correlation-Id"].ToString();
        return value.Length is > 0 and <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.')
            ? value
            : Guid.NewGuid().ToString("N");
    }

    private static string RateKey(HttpContext context)
    {
        var credential = context.Connection.ClientCertificate?.Thumbprint ?? context.Request.Headers.Authorization.ToString();
        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));
        return $"{context.Connection.RemoteIpAddress}:{digest}";
    }
}

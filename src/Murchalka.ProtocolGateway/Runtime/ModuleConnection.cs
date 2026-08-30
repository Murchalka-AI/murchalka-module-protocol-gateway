using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Murchalka.ModuleProtocol.Contracts;
using Murchalka.ModuleProtocol.Json;
using Murchalka.ProtocolGateway.Gateway;
using Murchalka.ProtocolGateway.Protocol;

namespace Murchalka.ProtocolGateway.Runtime;

internal sealed class ModuleConnection : IProtocolDependencyInvoker, IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly ModuleId _moduleId;
    private readonly InstanceId _instanceId;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly SemaphoreSlim _routeRefreshGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<ResultEnvelope>> _pending = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<ControlResult>> _pendingSecrets = new(StringComparer.Ordinal);
    private readonly ProtocolGatewayServer _server;
    private ConfigurationSnapshot _configuration;
    private DependencyEndpointsSnapshot _dependencies;
    private IReadOnlyList<ProtocolRouteEndpoint>? _routes;
    private bool _active;
    private bool _disposed;

    private ModuleConnection(
        Stream stream,
        ModuleId moduleId,
        InstanceId instanceId,
        ConfigurationSnapshot configuration,
        DependencyEndpointsSnapshot dependencies)
    {
        _stream = stream;
        _moduleId = moduleId;
        _instanceId = instanceId;
        _configuration = configuration;
        _dependencies = dependencies;
        _server = new ProtocolGatewayServer(this);
    }

    public static async Task<ModuleConnection> ConnectAsync(CancellationToken cancellationToken)
    {
        var moduleId = new ModuleId(Required("MURCHALKA_MODULE_ID"));
        var instanceId = new InstanceId(Required("MURCHALKA_INSTANCE_ID"));
        var proofKey = Convert.FromBase64String(Required("MURCHALKA_PROOF_KEY"));
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(Required("MURCHALKA_SOCKET")), cancellationToken).ConfigureAwait(false);
            var stream = new NetworkStream(socket, ownsSocket: true);
            var hello = new ModuleHello(
                moduleId,
                SemanticVersion.Parse(Required("MURCHALKA_MODULE_VERSION")),
                Required("MURCHALKA_BUNDLE_DIGEST"),
                instanceId,
                [1],
                Required("MURCHALKA_ARTIFACT_ID"),
                ModuleTarget.Runtime,
                Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                Required("MURCHALKA_CAPABILITIES_DIGEST"),
                Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
            await GatewayFrameCodec.WriteAsync(stream, "moduleHello", hello, cancellationToken).ConfigureAwait(false);
            var challenge = GatewayFrameCodec.PayloadAs<RuntimeChallenge>(await GatewayFrameCodec.ReadAsync(stream, cancellationToken).ConfigureAwait(false));
            if (challenge.ModuleNonce != hello.Nonce || challenge.ExpiresAt <= DateTimeOffset.UtcNow || challenge.SelectedProtocolVersion != 1)
                throw new InvalidDataException("Runtime challenge is invalid.");
            var transcript = string.Join('\n', "murchalka-module-proof-v1", hello.ModuleId.Value, hello.ModuleVersion.ToString(), hello.BundleDigest,
                hello.InstanceId.Value, hello.ArtifactId, hello.DeclaredCapabilitiesDigest,
                challenge.SelectedProtocolVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), challenge.ModuleNonce, challenge.RuntimeNonce);
            var proof = new ModuleProof(moduleId, instanceId, challenge.RuntimeNonce, challenge.ModuleNonce,
                Convert.ToBase64String(HMACSHA256.HashData(proofKey, Encoding.UTF8.GetBytes(transcript))));
            CryptographicOperations.ZeroMemory(proofKey);
            await GatewayFrameCodec.WriteAsync(stream, "moduleProof", proof, cancellationToken).ConfigureAwait(false);
            var configuration = GatewayFrameCodec.PayloadAs<ConfigurationSnapshot>(await GatewayFrameCodec.ReadAsync(stream, cancellationToken).ConfigureAwait(false));
            _ = await GatewayFrameCodec.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
            var dependencies = GatewayFrameCodec.PayloadAs<DependencyEndpointsSnapshot>(await GatewayFrameCodec.ReadAsync(stream, cancellationToken).ConfigureAwait(false));
            await GatewayFrameCodec.WriteAsync(stream, "moduleReady", new ModuleReady(moduleId, instanceId, hello.DeclaredCapabilitiesDigest, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
            return new ModuleConnection(stream, moduleId, instanceId, configuration, dependencies);
        }
        catch
        {
            socket.Dispose();
            CryptographicOperations.ZeroMemory(proofKey);
            throw;
        }
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        try
        {
            while (!linked.IsCancellationRequested)
            {
                var frame = await GatewayFrameCodec.ReadAsync(_stream, linked.Token).ConfigureAwait(false);
                switch (frame.Kind)
                {
                    case "control":
                        _ = CompleteControlAsync(GatewayFrameCodec.PayloadAs<ControlMessage>(frame), linked.Token);
                        break;
                    case "invocation":
                        await HandleStatusInvocationAsync(GatewayFrameCodec.PayloadAs<InvocationEnvelope>(frame), linked.Token).ConfigureAwait(false);
                        break;
                    case "capabilityResult":
                        var result = GatewayFrameCodec.PayloadAs<ResultEnvelope>(frame);
                        if (_pending.TryRemove(result.InvocationId, out var completion)) completion.TrySetResult(result);
                        break;
                    case "secretLeaseResult":
                        var secretResult = GatewayFrameCodec.PayloadAs<ControlResult>(frame);
                        if (_pendingSecrets.TryRemove(secretResult.OperationId, out var secretCompletion)) secretCompletion.TrySetResult(secretResult);
                        break;
                    default:
                        throw new InvalidDataException($"Unexpected protocol frame '{frame.Kind}'.");
                }
            }
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
    }

    private async Task CompleteControlAsync(ControlMessage control, CancellationToken cancellationToken)
    {
        try
        {
            if (!await HandleControlAsync(control, cancellationToken).ConfigureAwait(false)) await _lifetime.CancelAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception)
        {
            try
            {
                await WriteAsync("controlResult", new ControlResult(control.OperationId, false, "control-failed", exception.Message, null), CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception) { }
        }
    }

    public async Task<IReadOnlyList<ProtocolRouteEndpoint>> GetRoutesAsync(CancellationToken cancellationToken)
    {
        if (!_active) return [];
        if (Volatile.Read(ref _routes) is { } cached) return cached;
        await _routeRefreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_routes is not null) return _routes;
            var discovered = new List<ProtocolRouteEndpoint>();
            foreach (var endpoint in Volatile.Read(ref _dependencies).Endpoints.Where(value => value.RequirementId == "protocol-handlers"))
            {
                var description = await InvokeEndpointAsync(
                    endpoint,
                    JsonSerializer.SerializeToElement(new { operation = "describe" }),
                    Guid.NewGuid().ToString("N"),
                    DateTimeOffset.UtcNow.AddSeconds(10),
                    cancellationToken).ConfigureAwait(false);
                discovered.Add(ParseRoute(description, endpoint));
            }

            var collision = discovered.GroupBy(value => value.RouteNamespace, StringComparer.Ordinal).FirstOrDefault(group => group.Count() > 1);
            if (collision is not null) throw new InvalidDataException($"Protocol route namespace '{collision.Key}' has multiple providers and requires an administrative binding.");
            _routes = discovered.OrderBy(value => value.RouteNamespace, StringComparer.Ordinal).ToArray();
            return _routes;
        }
        finally
        {
            _routeRefreshGate.Release();
        }
    }

    public ValueTask<JsonElement> InvokeAsync(
        ProtocolRouteEndpoint endpoint,
        JsonElement payload,
        string correlationId,
        DateTimeOffset deadline,
        CancellationToken cancellationToken) =>
        InvokeEndpointAsync(endpoint.Dependency, payload, correlationId, deadline, cancellationToken);

    public async ValueTask<byte[]> LeaseSecretAsync(string name, string purpose, CancellationToken cancellationToken)
    {
        var operationId = Guid.NewGuid().ToString("N");
        var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        var completion = new TaskCompletionSource<ControlResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingSecrets.TryAdd(operationId, completion)) throw new InvalidOperationException("Secret lease operation identifier collision.");
        try
        {
            await WriteAsync("secretLeaseRequest", new GatewaySecretLeaseRequest(operationId, name, purpose, deadline), cancellationToken).ConfigureAwait(false);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(deadline - DateTimeOffset.UtcNow);
            var result = await completion.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            if (!result.Succeeded || result.Details is null) throw new ProtocolDependencyException(result.ErrorCode ?? "secret-lease-failed", result.ErrorMessage ?? "Secret lease failed.");
            var lease = result.Details.Value.Deserialize<GatewaySecretLease>(ProtocolJson.Options) ?? throw new InvalidDataException("Secret lease payload is invalid.");
            if (lease.OperationId != operationId || lease.Name != name || lease.ExpiresAt <= DateTimeOffset.UtcNow) throw new InvalidDataException("Secret lease identity or expiry is invalid.");
            return Convert.FromBase64String(lease.Value);
        }
        finally
        {
            _pendingSecrets.TryRemove(operationId, out _);
        }
    }

    private async ValueTask<JsonElement> InvokeEndpointAsync(
        DependencyEndpoint endpoint,
        JsonElement payload,
        string correlationId,
        DateTimeOffset deadline,
        CancellationToken cancellationToken)
    {
        if (!_active) throw new ProtocolDependencyException("module-inactive", "Protocol Gateway is not active.");
        var invocation = new InvocationEnvelope(
            Guid.NewGuid(), endpoint.Capability, endpoint.CapabilityVersion, endpoint.ProviderInstance, _moduleId,
            null, new InvocationScope(null, null, null, null, null, null), ProtocolPurpose(payload), endpoint.AuthorizationReference,
            correlationId, correlationId, null, deadline, null, "protocol.gateway.handler.request@1", payload, null);
        var completion = new TaskCompletionSource<ResultEnvelope>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(invocation.InvocationId, completion)) throw new InvalidOperationException("Invocation identifier collision.");
        try
        {
            await WriteAsync("capabilityInvocation", invocation, cancellationToken).ConfigureAwait(false);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(deadline - DateTimeOffset.UtcNow);
            var result = await completion.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            if (result.Status == InvocationStatus.Succeeded && result.Payload is { } response) return response;
            throw new ProtocolDependencyException(result.Error?.Code ?? "protocol-handler-failed", result.Error?.Message ?? "Protocol handler failed.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested || deadline <= DateTimeOffset.UtcNow)
        {
            await TrySendCancellationAsync(invocation.InvocationId,
                cancellationToken.IsCancellationRequested ? "caller-cancelled" : "deadline-exceeded").ConfigureAwait(false);
            throw;
        }
        finally
        {
            _pending.TryRemove(invocation.InvocationId, out _);
        }
    }

    private async ValueTask TrySendCancellationAsync(Guid invocationId, string reason)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await WriteAsync("capabilityCancellation", new { invocationId, reason }, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException or OperationCanceledException) { }
    }

    private async Task<bool> HandleControlAsync(ControlMessage control, CancellationToken cancellationToken)
    {
        if (control.Kind == ControlMessageKind.HealthProbe)
        {
            await WriteAsync("health", new ModuleHealth(_active ? ModuleHealthStatus.Ready : ModuleHealthStatus.NotReady, DateTimeOffset.UtcNow, _active ? [] : ["inactive"]), cancellationToken).ConfigureAwait(false);
            return true;
        }

        if (control.Deadline <= DateTimeOffset.UtcNow)
        {
            await WriteAsync("controlResult", new ControlResult(control.OperationId, false, "deadline-exceeded", "Control deadline elapsed.", null), cancellationToken).ConfigureAwait(false);
            return true;
        }

        if (control.Kind == ControlMessageKind.ReloadConfiguration)
            _configuration = control.Payload.Deserialize<ConfigurationSnapshot>(ProtocolJson.Options) ?? throw new InvalidDataException("Configuration snapshot is invalid.");
        else if (control.Kind == ControlMessageKind.UpdateBindings)
        {
            var replacement = control.Payload.Deserialize<DependencyEndpointsSnapshot>(ProtocolJson.Options) ?? throw new InvalidDataException("Dependency snapshot is invalid.");
            var removed = _dependencies.Endpoints.Where(current => current.RequirementId == "protocol-handlers" &&
                !replacement.Endpoints.Any(candidate => SameEndpoint(current, candidate))).ToArray();
            foreach (var endpoint in removed)
            {
                try
                {
                    _ = await InvokeEndpointAsync(endpoint, JsonSerializer.SerializeToElement(new { operation = "revoke" }),
                        Guid.NewGuid().ToString("N"), control.Deadline, cancellationToken).ConfigureAwait(false);
                }
                catch (ProtocolDependencyException) { }
            }
            _dependencies = replacement;
            Volatile.Write(ref _routes, null);
        }
        else if (control.Kind == ControlMessageKind.Activate)
        {
            await _server.StartAsync(_configuration.Values, cancellationToken).ConfigureAwait(false);
            _active = true;
        }
        else if (control.Kind is ControlMessageKind.Drain or ControlMessageKind.Stop)
        {
            _active = false;
            Volatile.Write(ref _routes, null);
            await _server.StopAsync(cancellationToken).ConfigureAwait(false);
            foreach (var completion in _pending.Values) completion.TrySetCanceled(cancellationToken);
        }

        await WriteAsync("controlResult", new ControlResult(control.OperationId, true, null, null, null), cancellationToken).ConfigureAwait(false);
        return control.Kind != ControlMessageKind.Stop;
    }

    private async Task HandleStatusInvocationAsync(InvocationEnvelope invocation, CancellationToken cancellationToken)
    {
        ResultEnvelope result;
        if (!_active || invocation.Payload is null)
        {
            result = Failure(invocation.InvocationId, "module-inactive", ErrorCategory.Unavailable, "Protocol Gateway is unavailable.");
        }
        else
        {
            var endpoint = ProtocolGatewayOptions.Parse(_configuration.Values).Endpoint;
            var routes = (await GetRoutesAsync(cancellationToken).ConfigureAwait(false)).Select(value => value.RouteNamespace).ToArray();
            result = new ResultEnvelope(invocation.InvocationId, InvocationStatus.Succeeded,
                JsonSerializer.SerializeToElement(new { endpoint, active = true, routes }), null, null, [], [], invocation.IdempotencyKey);
        }

        await WriteAsync("result", result, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask WriteAsync<T>(string kind, T payload, CancellationToken cancellationToken)
    {
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await GatewayFrameCodec.WriteAsync(_stream, kind, payload, cancellationToken).ConfigureAwait(false); }
        finally { _writeGate.Release(); }
    }

    private static ProtocolRouteEndpoint ParseRoute(JsonElement value, DependencyEndpoint endpoint)
    {
        var limits = value.GetProperty("limits");
        var timeout = TimeSpan.FromSeconds(limits.GetProperty("timeoutSeconds").GetInt32());
        return new ProtocolRouteEndpoint(
            value.GetProperty("routeNamespace").GetString() ?? throw new InvalidDataException("Protocol route namespace is missing."),
            limits.GetProperty("maximumPayloadBytes").GetInt32(),
            limits.GetProperty("maximumConcurrency").GetInt32(),
            limits.GetProperty("maximumStreams").GetInt32(),
            timeout,
            value.GetProperty("authentication").EnumerateArray().Select(item => item.GetString() ?? string.Empty).ToHashSet(StringComparer.Ordinal),
            value.GetProperty("transports").EnumerateArray().Select(item => item.GetString() ?? string.Empty).ToHashSet(StringComparer.Ordinal),
            endpoint);
    }

    private static ResultEnvelope Failure(Guid invocationId, string code, ErrorCategory category, string message) =>
        new(invocationId, InvocationStatus.Failed, null, new ProtocolError(code, category, false, message, null), null, [], [], null);

    private static string ProtocolPurpose(JsonElement payload)
    {
        if (!payload.TryGetProperty("operation", out var operation)) return "external-protocol-request";
        return operation.GetString() switch
        {
            "describe" => "protocol-route-discovery",
            "stream.next" => "protocol-stream-progress",
            "cancel" => "protocol-stream-cancellation",
            "revoke" => "protocol-route-revocation",
            _ => "external-protocol-request"
        };
    }

    private static string Required(string name) => Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"Required environment variable '{name}' is missing.");

    private static bool SameEndpoint(DependencyEndpoint left, DependencyEndpoint right) =>
        left.RequirementId == right.RequirementId && left.ProviderModule == right.ProviderModule && left.ProviderInstance == right.ProviderInstance &&
        left.Capability == right.Capability && left.CapabilityVersion == right.CapabilityVersion && left.AuthorizationReference == right.AuthorizationReference;

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        await _server.DisposeAsync().ConfigureAwait(false);
        _stream.Dispose();
        _writeGate.Dispose();
        _routeRefreshGate.Dispose();
        _lifetime.Dispose();
        foreach (var completion in _pending.Values) completion.TrySetCanceled();
        foreach (var completion in _pendingSecrets.Values) completion.TrySetCanceled();
    }
}

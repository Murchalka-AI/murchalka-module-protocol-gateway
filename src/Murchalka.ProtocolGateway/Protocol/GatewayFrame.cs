using System.Text.Json;

namespace Murchalka.ProtocolGateway.Protocol;

internal sealed record GatewayFrame(string Kind, JsonElement Payload);

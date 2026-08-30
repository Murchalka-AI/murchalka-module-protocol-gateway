namespace Murchalka.ProtocolGateway.Runtime;

internal sealed record GatewaySecretLeaseRequest(string OperationId, string Name, string Purpose, DateTimeOffset Deadline);

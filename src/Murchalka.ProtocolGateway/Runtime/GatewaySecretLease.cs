namespace Murchalka.ProtocolGateway.Runtime;

internal sealed record GatewaySecretLease(string OperationId, string LeaseId, string Name, long Revision, string Value, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);

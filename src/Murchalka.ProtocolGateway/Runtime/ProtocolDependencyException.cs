namespace Murchalka.ProtocolGateway.Runtime;

internal sealed class ProtocolDependencyException : Exception
{
    public ProtocolDependencyException(string code, string message) : base(message) => Code = code;

    public string Code { get; }
}

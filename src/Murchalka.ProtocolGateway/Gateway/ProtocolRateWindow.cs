namespace Murchalka.ProtocolGateway.Gateway;

internal sealed class ProtocolRateWindow
{
    public ProtocolRateWindow(long minute) => Minute = minute;

    public long Minute { get; set; }
    public int Count { get; set; }
}

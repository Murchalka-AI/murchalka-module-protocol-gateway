using System.Collections.Concurrent;

namespace Murchalka.ProtocolGateway.Gateway;

internal sealed class ProtocolRateLimiter
{
    private readonly ConcurrentDictionary<string, ProtocolRateWindow> _windows = new(StringComparer.Ordinal);
    private readonly int _maximumPerMinute;

    public ProtocolRateLimiter(int maximumPerMinute) => _maximumPerMinute = maximumPerMinute;

    public bool TryAcquire(string key)
    {
        var minute = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
        var window = _windows.GetOrAdd(key, _ => new ProtocolRateWindow(minute));
        lock (window)
        {
            if (window.Minute != minute)
            {
                window.Minute = minute;
                window.Count = 0;
            }
            if (window.Count >= _maximumPerMinute) return false;
            window.Count++;
        }
        if (_windows.Count > 4096)
            foreach (var pair in _windows.Where(value => value.Value.Minute < minute - 1)) _windows.TryRemove(pair.Key, out _);
        return true;
    }
}

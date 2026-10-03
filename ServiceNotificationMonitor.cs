using System.Text.Json;

namespace AntiStealer;

internal sealed class ServiceNotificationMonitor : IDisposable
{
    private readonly string _feedPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "AntiStealer", "notifications.jsonl");
    private readonly Action<UserNotification> _received;
    private System.Threading.Timer? _timer;
    private long _offset;
    private int _polling;

    public ServiceNotificationMonitor(Action<UserNotification> received) => _received = received;

    public void Start()
    {
        try { _offset = File.Exists(_feedPath) ? new FileInfo(_feedPath).Length : 0; }
        catch { _offset = 0; }
        _timer ??= new System.Threading.Timer(_ => Poll(), null, 500, 750);
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _polling, 1) != 0)
            return;
        try
        {
            if (!File.Exists(_feedPath))
                return;
            using var stream = new FileStream(_feedPath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length < _offset)
                _offset = 0;
            stream.Position = _offset;
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                try
                {
                    var notification = JsonSerializer.Deserialize<UserNotification>(line);
                    if (notification is not null)
                        _received(notification);
                }
                catch { }
            }
            _offset = stream.Position;
        }
        catch { }
        finally { Volatile.Write(ref _polling, 0); }
    }

    public void Dispose() => _timer?.Dispose();
}

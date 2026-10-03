namespace AntiStealer;

internal sealed class ProtectionServiceHost : IDisposable
{
    private readonly ProtectionEngine _engine = new();
    private readonly AuditMonitor _audit;
    private readonly DriverPortClient _driver;

    public ProtectionServiceHost()
    {
        _audit = new AuditMonitor(_engine);
        _driver = new DriverPortClient((pid, path) =>
            _engine.HandleSensitiveAccess(pid, path, "minifilter до открытия файла"));
        _engine.Detected += OnDetected;
        _engine.TamperDetected += OnTamper;
        _engine.StatusChanged += status => ServiceLog.Write("Engine: " + status);
    }

    public void Start()
    {
        ServiceLog.Write("AntiStealer.Service starting");
        SensitivePathAuditConfigurator.Apply();
        _audit.Start();
        _engine.Start();
        _driver.Start();
        ServiceLog.Write("AntiStealer.Service running");
    }

    public void SignalScan() => _engine.SignalScan();

    private static void OnDetected(DetectionEvent detection)
    {
        var title = "УГРОЗА ЗАБЛОКИРОВАНА";
        var message = $"{detection.ProcessName}: интернет отключён. Нажми, чтобы открыть подробности.";
        NotificationFeedWriter.Publish(new UserNotification
        {
            Kind = "detection",
            Title = title,
            Message = message,
            Detection = detection
        });
        if (!InteractiveNotifier.IsUiPresent())
        {
            InteractiveNotifier.Warn(
                "AntiStealer: доступ к данным заблокирован",
                $"Братан, похоже, тебя обносят.\r\n\r\nПроцесс: {detection.ProcessName}\r\nФайл: {detection.FilePath}\r\nПричина: {detection.Reasons}\r\nСтатус: {detection.Status}");
        }
    }

    private static void OnTamper(string message)
    {
        NotificationFeedWriter.Publish(new UserNotification
        {
            Kind = "tamper",
            Title = "ЗАЩИТА ВОССТАНОВЛЕНА",
            Message = message
        });
        if (!InteractiveNotifier.IsUiPresent())
            InteractiveNotifier.Warn("AntiStealer восстановил защиту", message);
    }

    public void Dispose()
    {
        _driver.Dispose();
        _audit.Dispose();
        _engine.Dispose();
        ServiceLog.Write("AntiStealer.Service stopped");
    }
}

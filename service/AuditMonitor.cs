using System.Diagnostics.Eventing.Reader;

namespace AntiStealer;

internal sealed class AuditMonitor : IDisposable
{
    private readonly ProtectionEngine _engine;
    private EventLogWatcher? _watcher;

    public AuditMonitor(ProtectionEngine engine) => _engine = engine;

    public void Start()
    {
        try
        {
            const string query = "*[System[(EventID=4663 or EventID=4688 or EventID=5156 or EventID=4946 or EventID=4947 or EventID=4950)]]";
            _watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, query));
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;
            ServiceLog.Write("Security audit watcher enabled (4663/4688/5156/firewall)");
        }
        catch (Exception ex)
        {
            ServiceLog.Write("Security audit watcher unavailable: " + ex.Message);
        }
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs eventArgs)
    {
        if (eventArgs.EventException is not null)
        {
            ServiceLog.Write("Audit watcher error: " + eventArgs.EventException.Message);
            return;
        }

        using var record = eventArgs.EventRecord;
        if (record is null)
            return;

        try
        {
            var fields = AuditEventParser.ReadFields(record.ToXml());
            switch (record.Id)
            {
                case 4663:
                    if (fields.TryGetValue("ProcessId", out var pidText) &&
                        fields.TryGetValue("ObjectName", out var objectName) &&
                        AuditEventParser.TryParsePid(pidText, out var processId) &&
                        SensitiveTargetPolicy.IsSensitivePath(objectName))
                    {
                        _engine.HandleSensitiveAccess(processId, objectName, "аудит Windows 4663 после открытия файла");
                    }
                    break;
                case 4688:
                case 5156:
                case 4946:
                case 4947:
                case 4950:
                    _engine.SignalScan();
                    break;
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Write("Audit event parse failed: " + ex.Message);
        }
    }

    public void Dispose()
    {
        if (_watcher is null)
            return;
        _watcher.Enabled = false;
        _watcher.EventRecordWritten -= OnEvent;
        _watcher.Dispose();
    }
}

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace AntiStealer;

internal sealed class ProtectionEngine : IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<int, Candidate> _candidates = new();
    private readonly string _dataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntiStealer");
    private readonly AllowlistStore _allowlist;
    private readonly IntegrityGuard _integrityGuard;
    private readonly string _ownPath = Environment.ProcessPath ?? string.Empty;
    private readonly ConcurrentDictionary<string, string> _blockedPrograms = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _tamperAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _sensitiveAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly AutoResetEvent _scanSignal = new(false);
    private Task? _worker;
    private DateTimeOffset _lastFirewallCheck = DateTimeOffset.MinValue;
    private DateTimeOffset _lastIntegrityCheck = DateTimeOffset.MinValue;
    private int _firewallFailures;

    public event Action<DetectionEvent>? Detected;
    public event Action<string>? StatusChanged;
    public event Action<string>? TamperDetected;

    public ProtectionEngine()
    {
        Directory.CreateDirectory(_dataDirectory);
        _allowlist = new AllowlistStore(_dataDirectory);
        _integrityGuard = new IntegrityGuard(_dataDirectory);
        _integrityGuard.RegisterSelf(_ownPath);
        FirewallBlocker.RemoveForPath(_ownPath);
    }

    public void Start()
    {
        _worker ??= Task.Run(() => MonitorLoop(_stop.Token));
    }

    public void SignalScan() => _scanSignal.Set();

    public void RescanAll()
    {
        _candidates.Clear();
        StatusChanged?.Invoke("Повторная проверка всех активных процессов…");
    }

    public string TrustFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Файл не найден", filePath);
        _allowlist.Add(filePath);
        _integrityGuard.AcceptCurrentVersion(filePath);
        var hash = ProcessInspector.Sha256(filePath);
        StatusChanged?.Invoke($"Файл добавлен в доверенные по SHA-256: {Path.GetFileName(filePath)}");
        return hash;
    }

    public bool HandleSensitiveAccess(int processId, string targetPath, string source)
    {
        if (processId <= 4 || string.IsNullOrWhiteSpace(targetPath) || !SensitiveTargetPolicy.IsSensitivePath(targetPath))
            return true;

        ProcessFacts? facts = null;
        if (_candidates.TryGetValue(processId, out var known) && IsSameProcess(processId, known.Facts.StartTimeUtcTicks))
        {
            facts = known.Facts;
        }
        else
        {
            _candidates.TryRemove(processId, out _);
            try
            {
                using var process = Process.GetProcessById(processId);
                facts = ProcessInspector.Inspect(process, ProcessInspector.GetParentNames());
                if (facts is not null)
                    _candidates.TryAdd(processId, new Candidate { Facts = facts });
            }
            catch { }
        }

        if (facts is not null && (PathEquals(facts.FilePath, _ownPath) || _allowlist.Contains(facts.FilePath) ||
                                  SensitiveTargetPolicy.IsLegitimateOwner(targetPath, facts)))
            return true;

        var processPath = facts?.FilePath ?? $"PID:{processId}";
        var processName = facts?.ProcessName ?? "неизвестный процесс";
        var dedupeKey = $"{processId}|{processPath}|{targetPath}";
        var now = DateTimeOffset.Now;
        if (_sensitiveAlerts.TryGetValue(dedupeKey, out var previous) && now - previous < TimeSpan.FromMinutes(5))
            return false;
        _sensitiveAlerts[dedupeKey] = now;

        var ruleName = string.Empty;
        if (facts is not null)
        {
            try
            {
                ruleName = FirewallBlocker.Block(facts.FilePath);
                _blockedPrograms[ruleName] = facts.FilePath;
            }
            catch (Exception ex)
            {
                RaiseTamperAlert($"Обнаружен доступ к секретам, но сеть {processName} заблокировать не удалось: {ex.Message}");
            }
        }

        var detection = new DetectionEvent
        {
            ProcessId = processId,
            ProcessName = processName,
            FilePath = processPath,
            RemoteEndpoints = "сеть заблокирована до отправки данных",
            Reasons = $"{source}: попытка чтения защищённого хранилища {targetPath}",
            Risk = 300,
            FirewallRuleName = ruleName,
            Status = "Доступ к секретам запрещён; интернет заблокирован"
        };
        WriteEvent(detection);
        Detected?.Invoke(detection);
        return false;
    }

    public void Allow(DetectionEvent detection)
    {
        _allowlist.Add(detection.FilePath);
        _integrityGuard.AcceptCurrentVersion(detection.FilePath);
        FirewallBlocker.Remove(detection.FirewallRuleName);
        _blockedPrograms.TryRemove(detection.FirewallRuleName, out _);
        detection.Status = "Разрешено пользователем";
        WriteEvent(detection);
    }

    public void Terminate(DetectionEvent detection)
    {
        if (detection.ProcessId <= 0)
        {
            detection.Status = "Интернет заблокирован; процесс сейчас не запущен";
            WriteEvent(detection);
            return;
        }

        try
        {
            using var process = Process.GetProcessById(detection.ProcessId);
            process.Kill(true);
            process.WaitForExit(5000);
            detection.Status = "Процесс завершён, интернет заблокирован";
        }
        catch (Exception ex)
        {
            detection.Status = "Не удалось завершить: " + ex.Message;
        }
        WriteEvent(detection);
    }

    public void Quarantine(DetectionEvent detection)
    {
        Terminate(detection);
        try
        {
            if (!ProcessInspector.IsQuarantinable(detection.FilePath))
                throw new InvalidOperationException("системные папки нельзя помещать в карантин");

            var quarantineDir = Path.Combine(_dataDirectory, "Quarantine");
            Directory.CreateDirectory(quarantineDir);
            var destination = Path.Combine(
                quarantineDir,
                $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Path.GetFileName(detection.FilePath)}.blocked");
            File.Move(detection.FilePath, destination, false);
            File.WriteAllText(destination + ".json", JsonSerializer.Serialize(new
            {
                OriginalPath = detection.FilePath,
                QuarantinedAt = DateTimeOffset.Now,
                detection.Risk,
                detection.Reasons,
                Sha256 = ProcessInspector.Sha256(destination)
            }, new JsonSerializerOptions { WriteIndented = true }));
            detection.Status = "Завершён и помещён в карантин";
        }
        catch (Exception ex)
        {
            detection.Status = "Процесс остановлен; карантин не выполнен: " + ex.Message;
        }
        WriteEvent(detection);
    }

    private void MonitorLoop(CancellationToken cancellationToken)
    {
        StatusChanged?.Invoke("Защита активна");
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                InspectProcesses();
                EvaluateCandidates();
                MaintainSecurityControls();
                CleanupCandidates();
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke("Ошибка мониторинга: " + ex.Message);
            }

            if (WaitHandle.WaitAny([_scanSignal, cancellationToken.WaitHandle], 1500) == 1)
                break;
        }
    }

    private void InspectProcesses()
    {
        var parentNames = ProcessInspector.GetParentNames();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id == Environment.ProcessId)
                    continue;
                if (_candidates.TryGetValue(process.Id, out var known))
                {
                    if (IsSameProcess(process.Id, known.Facts.StartTimeUtcTicks))
                        continue;
                    _candidates.TryRemove(process.Id, out _);
                }

                var facts = ProcessInspector.Inspect(process, parentNames);
                if (facts is null || PathEquals(facts.FilePath, _ownPath) ||
                    _allowlist.Contains(facts.FilePath) || TrustedToolsPolicy.IsBuiltInTrustedTool(facts))
                    continue;

                var candidate = new Candidate { Facts = facts };
                _candidates.TryAdd(process.Id, candidate);

                var integrityFinding = _integrityGuard.Observe(facts);
                if (integrityFinding is not null)
                {
                    EmitIntegrityDetection(integrityFinding, process.Id);
                    candidate.Detected = true;
                }
            }
        }
    }

    private void EvaluateCandidates()
    {
        var connections = NativeNetwork.GetOutboundConnections();
        foreach (var pair in _candidates)
        {
            var candidate = pair.Value;
            if (candidate.Detected || !connections.TryGetValue(pair.Key, out var endpoints))
                continue;

            var assessment = RiskScorer.Assess(candidate.Facts, endpoints.Count > 0);
            if (!assessment.ShouldBlock)
                continue;

            string ruleName;
            try
            {
                ruleName = FirewallBlocker.Block(candidate.Facts.FilePath);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke("Не удалось заблокировать " + candidate.Facts.ProcessName + ": " + ex.Message);
                continue;
            }

            candidate.Detected = true;
            _blockedPrograms[ruleName] = candidate.Facts.FilePath;
            var detection = new DetectionEvent
            {
                ProcessId = candidate.Facts.ProcessId,
                ProcessName = candidate.Facts.ProcessName,
                FilePath = candidate.Facts.FilePath,
                RemoteEndpoints = string.Join(", ", endpoints.Take(5)),
                Reasons = string.Join("; ", assessment.Reasons),
                Risk = assessment.Score,
                FirewallRuleName = ruleName
            };
            WriteEvent(detection);
            Detected?.Invoke(detection);
        }
    }

    private void MaintainSecurityControls()
    {
        var now = DateTimeOffset.Now;
        if (now - _lastFirewallCheck >= TimeSpan.FromSeconds(5))
        {
            _lastFirewallCheck = now;
            try
            {
                foreach (var message in FirewallGuard.CheckAndRepair())
                    RaiseTamperAlert(message);
                _firewallFailures = 0;

                foreach (var blocked in _blockedPrograms)
                {
                    if (FirewallBlocker.Exists(blocked.Key))
                        continue;
                    var restoredRule = FirewallBlocker.Block(blocked.Value);
                    _blockedPrograms.TryRemove(blocked.Key, out _);
                    _blockedPrograms[restoredRule] = blocked.Value;
                    RaiseTamperAlert($"Кто-то удалил блокирующее правило для {Path.GetFileName(blocked.Value)}. AntiStealer восстановил его.");
                }
            }
            catch (Exception ex)
            {
                _firewallFailures++;
                if (_firewallFailures == 2)
                    RaiseTamperAlert("Не удаётся проверить Windows Firewall. Возможно, служба остановлена или защита повреждена: " + ex.Message);
            }
        }

        if (now - _lastIntegrityCheck >= TimeSpan.FromSeconds(5))
        {
            _lastIntegrityCheck = now;
            foreach (var finding in _integrityGuard.CheckKnownFiles())
                EmitIntegrityDetection(finding, FindRunningProcess(finding.FilePath));
        }
    }

    private void EmitIntegrityDetection(IntegrityFinding finding, int processId)
    {
        string ruleName;
        try
        {
            ruleName = FirewallBlocker.Block(finding.FilePath);
            _blockedPrograms[ruleName] = finding.FilePath;
        }
        catch (Exception ex)
        {
            RaiseTamperAlert($"Подмена {finding.ProcessName} обнаружена, но сеть заблокировать не удалось: {ex.Message}");
            return;
        }

        var detection = new DetectionEvent
        {
            ProcessId = processId,
            ProcessName = finding.ProcessName,
            FilePath = finding.FilePath,
            RemoteEndpoints = "блок поставлен до проверки соединений",
            Reasons = finding.Reason,
            Risk = 200,
            FirewallRuleName = ruleName,
            Status = "Подмена EXE: интернет заблокирован"
        };
        WriteEvent(detection);
        Detected?.Invoke(detection);
    }

    private void RaiseTamperAlert(string message)
    {
        var now = DateTimeOffset.Now;
        if (_tamperAlerts.TryGetValue(message, out var previous) && now - previous < TimeSpan.FromMinutes(5))
            return;
        _tamperAlerts[message] = now;
        TamperDetected?.Invoke(message);
        try
        {
            File.AppendAllText(Path.Combine(_dataDirectory, "tamper.log"), $"{now:O} {message}{Environment.NewLine}");
        }
        catch { }
    }

    private static int FindRunningProcess(string filePath)
    {
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (string.Equals(process.MainModule?.FileName, filePath, StringComparison.OrdinalIgnoreCase))
                        return process.Id;
                }
                catch { }
            }
        }
        return 0;
    }

    private void CleanupCandidates()
    {
        foreach (var pair in _candidates)
        {
            if (!IsSameProcess(pair.Key, pair.Value.Facts.StartTimeUtcTicks) ||
                (!pair.Value.Detected && DateTimeOffset.Now - pair.Value.FirstSeen > TimeSpan.FromMinutes(10)))
                _candidates.TryRemove(pair.Key, out _);
        }
    }

    private static bool IsSameProcess(int processId, long startTimeUtcTicks)
    {
        if (startTimeUtcTicks == 0)
            return false;
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.StartTime.ToUniversalTime().Ticks == startTimeUtcTicks;
        }
        catch { return false; }
    }

    private void WriteEvent(DetectionEvent detection)
    {
        try
        {
            var line = JsonSerializer.Serialize(detection) + Environment.NewLine;
            File.AppendAllText(Path.Combine(_dataDirectory, "events.jsonl"), line);
        }
        catch { }
    }

    private static bool IsRunning(int processId)
    {
        try { using var process = Process.GetProcessById(processId); return !process.HasExited; }
        catch { return false; }
    }

    private static bool PathEquals(string left, string right) =>
        !string.IsNullOrWhiteSpace(left) && !string.IsNullOrWhiteSpace(right) &&
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        _stop.Cancel();
        _scanSignal.Set();
        try { _worker?.Wait(3000); } catch { }
        _scanSignal.Dispose();
        _stop.Dispose();
    }
}

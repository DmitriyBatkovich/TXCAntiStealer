using System.Text.Json;

namespace AntiStealer;

internal sealed class IntegrityGuard
{
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "opera_gx",
        "telegram", "steam", "steamwebhelper", "discord", "discordcanary", "discordptb"
    };

    private readonly object _gate = new();
    private readonly string _baselineFile;
    private readonly Dictionary<string, IntegrityBaseline> _baselines = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastLoadedWriteUtc;

    public IntegrityGuard(string dataDirectory)
    {
        _baselineFile = Path.Combine(dataDirectory, "integrity-baseline.json");
        Load();
    }

    public IntegrityFinding? Observe(ProcessFacts facts)
    {
        if (!ProtectedProcessNames.Contains(facts.ProcessName))
            return null;
        return InspectFile(facts.FilePath, facts.ProcessName, facts.IsTrustedSignature);
    }

    public void RegisterSelf(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return;
        lock (_gate)
        {
            RefreshIfChangedLocked();
            var hash = ProcessInspector.Sha256(filePath);
            if (_baselines.TryGetValue(filePath, out var existing) &&
                string.Equals(existing.Sha256, hash, StringComparison.OrdinalIgnoreCase))
                return;

            // A development build lives in a user-writable directory and changes on every rebuild.
            // The binary which is already executing is the version the developer explicitly launched.
            // Installed copies under Program Files keep the old baseline and must be updated by the
            // elevated installer instead of silently trusting a replacement.
            if (existing is not null && IsProtectedInstallPath(filePath))
                return;

            _baselines[filePath] = new IntegrityBaseline(
                filePath, "AntiStealer", hash, DateTimeOffset.Now);
            _reported.RemoveWhere(key => key.StartsWith(filePath + "|", StringComparison.OrdinalIgnoreCase));
            Save();
        }
    }

    public void AcceptCurrentVersion(string filePath)
    {
        if (!File.Exists(filePath))
            return;
        lock (_gate)
        {
            RefreshIfChangedLocked();
            var processName = _baselines.TryGetValue(filePath, out var previous)
                ? previous.ProcessName
                : Path.GetFileNameWithoutExtension(filePath);
            _baselines[filePath] = new IntegrityBaseline(
                filePath, processName, ProcessInspector.Sha256(filePath), DateTimeOffset.Now);
            Save();
        }
    }

    public IReadOnlyList<IntegrityFinding> CheckKnownFiles()
    {
        lock (_gate)
        {
            RefreshIfChangedLocked();
            var findings = new List<IntegrityFinding>();
            foreach (var baseline in _baselines.Values.ToArray())
            {
                if (!File.Exists(baseline.FilePath))
                    continue;
                var finding = InspectFileLocked(baseline.FilePath, baseline.ProcessName, SignatureVerifier.IsTrusted(baseline.FilePath));
                if (finding is not null)
                    findings.Add(finding);
            }
            return findings;
        }
    }

    private IntegrityFinding? InspectFile(string filePath, string processName, bool trusted)
    {
        lock (_gate)
        {
            RefreshIfChangedLocked();
            return InspectFileLocked(filePath, processName, trusted);
        }
    }

    private IntegrityFinding? InspectFileLocked(string filePath, string processName, bool trusted)
    {
        string hash;
        try { hash = ProcessInspector.Sha256(filePath); }
        catch { return null; }

        if (!_baselines.TryGetValue(filePath, out var previous))
        {
            if (trusted)
            {
                _baselines[filePath] = new IntegrityBaseline(filePath, processName, hash, DateTimeOffset.Now);
                Save();
                return null;
            }

            return ReportOnce(filePath, processName, hash,
                "защищаемое приложение впервые обнаружено без доверенной цифровой подписи");
        }

        if (string.Equals(previous.Sha256, hash, StringComparison.OrdinalIgnoreCase))
            return null;

        if (trusted)
        {
            // Подписанные обновления браузеров и клиентов считаются штатными.
            _baselines[filePath] = previous with { Sha256 = hash, UpdatedAt = DateTimeOffset.Now };
            Save();
            return null;
        }

        return ReportOnce(filePath, processName, hash,
            "EXE изменился после создания контрольной суммы и новая версия не имеет доверенной подписи");
    }

    private IntegrityFinding? ReportOnce(string filePath, string processName, string hash, string reason)
    {
        var key = filePath + "|" + hash;
        if (!_reported.Add(key))
            return null;
        return new IntegrityFinding(filePath, processName, reason);
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_baselineFile)) return;
            _baselines.Clear();
            var items = JsonSerializer.Deserialize<IntegrityBaseline[]>(File.ReadAllText(_baselineFile)) ?? [];
            foreach (var item in items)
                _baselines[item.FilePath] = item;
            _lastLoadedWriteUtc = File.GetLastWriteTimeUtc(_baselineFile);
        }
        catch { }
    }

    private void Save()
    {
        File.WriteAllText(_baselineFile,
            JsonSerializer.Serialize(_baselines.Values.OrderBy(x => x.FilePath), new JsonSerializerOptions { WriteIndented = true }));
        _lastLoadedWriteUtc = File.GetLastWriteTimeUtc(_baselineFile);
    }

    private void RefreshIfChangedLocked()
    {
        try
        {
            if (File.Exists(_baselineFile) && File.GetLastWriteTimeUtc(_baselineFile) != _lastLoadedWriteUtc)
                Load();
        }
        catch { }
    }

    private static bool IsProtectedInstallPath(string filePath)
    {
        var fullPath = Path.GetFullPath(filePath);
        foreach (var root in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                 })
        {
            if (string.IsNullOrWhiteSpace(root))
                continue;
            var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}

internal sealed record IntegrityBaseline(string FilePath, string ProcessName, string Sha256, DateTimeOffset UpdatedAt);
internal sealed record IntegrityFinding(string FilePath, string ProcessName, string Reason);

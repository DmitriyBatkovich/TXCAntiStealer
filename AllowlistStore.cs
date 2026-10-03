using System.Text.Json;

namespace AntiStealer;

internal sealed class AllowlistStore
{
    private readonly object _gate = new();
    private readonly string _filePath;
    private readonly HashSet<string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastLoadedWriteUtc;

    public AllowlistStore(string dataDirectory)
    {
        Directory.CreateDirectory(dataDirectory);
        _filePath = Path.Combine(dataDirectory, "allowlist.json");
        Load();
    }

    public bool Contains(string filePath)
    {
        try
        {
            var hash = ProcessInspector.Sha256(filePath);
            lock (_gate)
            {
                RefreshIfChangedLocked();
                return _hashes.Contains(hash);
            }
        }
        catch { return false; }
    }

    public void Add(string filePath)
    {
        var hash = ProcessInspector.Sha256(filePath);
        lock (_gate)
        {
            RefreshIfChangedLocked();
            _hashes.Add(hash);
            File.WriteAllText(_filePath, JsonSerializer.Serialize(_hashes.OrderBy(x => x), new JsonSerializerOptions { WriteIndented = true }));
            _lastLoadedWriteUtc = File.GetLastWriteTimeUtc(_filePath);
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;
            _hashes.Clear();
            foreach (var hash in JsonSerializer.Deserialize<string[]>(File.ReadAllText(_filePath)) ?? [])
                _hashes.Add(hash);
            _lastLoadedWriteUtc = File.GetLastWriteTimeUtc(_filePath);
        }
        catch { }
    }

    private void RefreshIfChangedLocked()
    {
        try
        {
            if (File.Exists(_filePath) && File.GetLastWriteTimeUtc(_filePath) != _lastLoadedWriteUtc)
                Load();
        }
        catch { }
    }
}

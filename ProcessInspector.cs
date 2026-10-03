using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AntiStealer;

internal static partial class ProcessInspector
{
    private const uint Th32csSnapProcess = 0x00000002;
    private static readonly string WindowsPath = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    private static readonly string UserProfile = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    private static readonly HashSet<string> SystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "csrss", "winlogon", "services", "taskhostw", "runtimebroker", "securityhealthservice"
    };
    private static readonly HashSet<string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32"
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static ProcessFacts? Inspect(Process process, IReadOnlyDictionary<int, string> parentNames)
    {
        string path;
        try
        {
            path = process.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;

        path = Path.GetFullPath(path);
        var parentName = parentNames.TryGetValue(process.Id, out var foundParent) ? foundParent : null;
        var processName = process.ProcessName;
        long startTimeUtcTicks;
        try { startTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks; }
        catch { startTimeUtcTicks = 0; }
        var highRisk = IsInside(path, Path.GetTempPath()) ||
                       IsInside(path, Path.Combine(UserProfile, "Downloads")) ||
                       IsInside(path, Path.Combine(UserProfile, "AppData", "Roaming"));
        var userWritable = IsInside(path, UserProfile) ||
                           IsInside(path, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var outsideWindows = !IsInside(path, WindowsPath);
        var signature = SignatureVerifier.GetInfo(path);

        return new ProcessFacts
        {
            ProcessId = process.Id,
            ProcessName = processName,
            FilePath = path,
            StartTimeUtcTicks = startTimeUtcTicks,
            ParentName = parentName,
            IsTrustedSignature = signature.IsTrusted,
            SignerSubject = signature.SignerSubject,
            IsHighRiskPath = highRisk,
            IsUserWritablePath = userWritable,
            HasInternetZoneMarker = HasZoneIdentifier(path),
            IsRecentlyWritten = WasWrittenRecently(path),
            LooksRandomNamed = LooksRandom(processName),
            MasqueradesAsWindows = outsideWindows && SystemNames.Contains(processName),
            HasSuspiciousParent = parentName is not null && SuspiciousParents.Contains(parentName)
        };
    }

    public static Dictionary<int, string> GetParentNames()
    {
        var entries = new Dictionary<int, (int ParentId, string Name)>();
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == new IntPtr(-1))
            return new Dictionary<int, string>();

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry))
                return new Dictionary<int, string>();

            do
            {
                entries[unchecked((int)entry.ProcessId)] =
                    (unchecked((int)entry.ParentProcessId), Path.GetFileNameWithoutExtension(entry.ExeFile));
                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            } while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return entries.ToDictionary(
            pair => pair.Key,
            pair => entries.TryGetValue(pair.Value.ParentId, out var parent) ? parent.Name : string.Empty);
    }

    public static bool IsQuarantinable(string filePath)
    {
        var full = Path.GetFullPath(filePath);
        var programFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var programFilesX86 = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        return !IsInside(full, WindowsPath) && !IsInside(full, programFiles) && !IsInside(full, programFilesX86);
    }

    public static string Sha256(string filePath)
    {
        using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool IsInside(string filePath, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
            return false;
        var root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(filePath).StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasZoneIdentifier(string filePath)
    {
        try { return File.Exists(filePath + ":Zone.Identifier"); }
        catch { return false; }
    }

    private static bool WasWrittenRecently(string filePath)
    {
        try { return File.GetLastWriteTimeUtc(filePath) >= DateTime.UtcNow.AddDays(-3); }
        catch { return false; }
    }

    private static bool LooksRandom(string name)
    {
        if (name.Length < 10)
            return false;
        return HexNameRegex().IsMatch(name) || MixedRandomRegex().IsMatch(name);
    }

    [GeneratedRegex("^[a-f0-9]{10,}$", RegexOptions.IgnoreCase)]
    private static partial Regex HexNameRegex();

    [GeneratedRegex("^(?=.*[a-z])(?=.*[0-9])[a-z0-9]{14,}$", RegexOptions.IgnoreCase)]
    private static partial Regex MixedRandomRegex();
}

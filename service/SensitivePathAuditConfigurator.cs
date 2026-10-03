using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AntiStealer;

internal static class SensitivePathAuditConfigurator
{
    public static void Apply()
    {
        if (!EnablePrivilege("SeSecurityPrivilege"))
        {
            ServiceLog.Write("SeSecurityPrivilege could not be enabled; SACL setup skipped");
            return;
        }

        foreach (var path in EnumerateSensitiveDirectories().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (!Directory.Exists(path))
                    continue;
                var directory = new DirectoryInfo(path);
                var security = directory.GetAccessControl(AccessControlSections.Audit);
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                var rule = new FileSystemAuditRule(
                    everyone,
                    FileSystemRights.ReadData | FileSystemRights.ReadAttributes | FileSystemRights.ReadExtendedAttributes,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AuditFlags.Success);
                security.AddAuditRule(rule);
                directory.SetAccessControl(security);
            }
            catch (Exception ex)
            {
                ServiceLog.Write($"SACL failed for {path}: {ex.Message}");
            }
        }
    }

    private static IEnumerable<string> EnumerateSensitiveDirectories()
    {
        const string usersRoot = @"C:\Users";
        if (Directory.Exists(usersRoot))
        {
            foreach (var profile in Directory.EnumerateDirectories(usersRoot))
            {
                yield return Path.Combine(profile, @"AppData\Local\Google\Chrome\User Data");
                yield return Path.Combine(profile, @"AppData\Local\Microsoft\Edge\User Data");
                yield return Path.Combine(profile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
                yield return Path.Combine(profile, @"AppData\Roaming\Telegram Desktop\tdata");
                yield return Path.Combine(profile, @"AppData\Roaming\discord\Local Storage\leveldb");
                yield return Path.Combine(profile, @"AppData\Roaming\Microsoft\Credentials");
                yield return Path.Combine(profile, @"AppData\Roaming\Microsoft\Protect");
                yield return Path.Combine(profile, @"AppData\Roaming\Exodus\exodus.wallet");
                yield return Path.Combine(profile, @"AppData\Roaming\Electrum\wallets");
            }
        }

        yield return @"C:\Program Files (x86)\Steam\config";
        yield return @"C:\Program Files\Steam\config";
    }

    private const uint TokenAdjustPrivileges = 0x20;
    private const uint TokenQuery = 0x8;
    private const uint SePrivilegeEnabled = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges { public uint PrivilegeCount; public Luid Luid; public uint Attributes; }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll, ref TokenPrivileges newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static bool EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            return false;
        try
        {
            if (!LookupPrivilegeValueW(null, name, out var luid))
                return false;
            var privileges = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
            return AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }
}

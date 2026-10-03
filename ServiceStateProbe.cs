using System.Runtime.InteropServices;

namespace AntiStealer;

internal static class ServiceStateProbe
{
    private const string ServiceName = "AntiStealerService";
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceUserDefinedControl = 0x0100;
    private const uint ServiceRunning = 0x00000004;
    private const uint RescanControl = 128;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr service, uint control, out ServiceStatus status);

    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);

    public static bool IsRunning()
    {
        var manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) return false;
        try
        {
            var service = OpenServiceW(manager, ServiceName, ServiceQueryStatus);
            if (service == IntPtr.Zero) return false;
            try { return QueryServiceStatus(service, out var status) && status.CurrentState == ServiceRunning; }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    public static bool RequestRescan()
    {
        var manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) return false;
        try
        {
            var service = OpenServiceW(manager, ServiceName, ServiceQueryStatus | ServiceUserDefinedControl);
            if (service == IntPtr.Zero) return false;
            try { return ControlService(service, RescanControl, out _); }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
}
